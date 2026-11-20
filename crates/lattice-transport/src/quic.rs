//! iroh QUIC backend for [`Transport`] (DESIGN.md ADR-001).
//!
//! `IrohTransport` binds an iroh endpoint (n0 relays + discovery) and yields
//! `IrohConn`s — framed (`u32`-BE length prefix) over a single QUIC bi-stream,
//! preserving in-order delivery for the Double Ratchet. Tickets carry our
//! iroh address, an opaque app-identity blob, and an opaque signature
//! (`app_sig`) over [`ticket_message`] (domain ‖ endpoint id ‖ identity), so the
//! dialer can verify — *before dialing* — that the ticket was issued by that
//! identity for that endpoint. The transport is identity-agnostic: the
//! app-identity bytes and the signature are opaque here and are never
//! interpreted or verified by this crate; the application does that.
//! Addresses ([`IrohEndpointId`]) are unauthenticated transport locators, not
//! Lattice identities; [`IrohConn::remote_endpoint_id`] exposes the
//! QUIC-authenticated remote endpoint id for channel binding. `read_frame`
//! rejects any frame whose declared length exceeds 64 KiB ([`MAX_FRAME_LEN`])
//! before allocating, and tickets longer than [`MAX_TICKET_LEN`] are rejected
//! before decoding.

use iroh::endpoint::presets;
use iroh::endpoint::Connection as IrohConnection;
pub use iroh::endpoint::{RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use lattice_core::{Connection, Error, Result, Topic, Transport};
use serde::{Deserialize, Serialize};

/// ALPN identifying the Lattice protocol on the wire.
pub const ALPN: &[u8] = b"lattice/0";

/// Max accepted ticket length in hex characters (after trim): 16 KiB.
pub const MAX_TICKET_LEN: usize = 16 * 1024;

const TICKET_DOMAIN: &[u8] = b"lattice-ticket-v1";

fn terr(ctx: &str, e: impl core::fmt::Display) -> Error {
    Error::Transport(format!("{ctx}: {e}"))
}

/// An iroh endpoint id (the 32-byte iroh public key) used as the
/// [`Transport::Addr`] of [`IrohTransport`]. NOT a Lattice identity.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct IrohEndpointId(pub [u8; 32]);

impl core::fmt::Debug for IrohEndpointId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IrohEndpointId({})", hex::encode(self.0))
    }
}

#[derive(Serialize, Deserialize)]
struct Ticket {
    addr: EndpointAddr,
    app_identity: Vec<u8>,
    app_sig: Vec<u8>,
}

/// The bytes a listener signs to issue a ticket:
/// `b"lattice-ticket-v1" ‖ endpoint_id ‖ u32le(app_identity.len()) ‖ app_identity`.
pub fn ticket_message(endpoint_id: &[u8; 32], app_identity: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(TICKET_DOMAIN.len() + 32 + 4 + app_identity.len());
    m.extend_from_slice(TICKET_DOMAIN);
    m.extend_from_slice(endpoint_id);
    m.extend_from_slice(&(app_identity.len() as u32).to_le_bytes());
    m.extend_from_slice(app_identity);
    m
}

fn encode_ticket(t: &Ticket) -> Result<String> {
    let bytes = postcard::to_allocvec(t).map_err(|e| terr("ticket encode", e))?;
    Ok(hex::encode(bytes))
}

fn decode_ticket(ticket: &str) -> Result<Ticket> {
    let ticket = ticket.trim();
    if ticket.len() > MAX_TICKET_LEN {
        return Err(Error::Transport(format!(
            "ticket too large: {} > {MAX_TICKET_LEN}",
            ticket.len()
        )));
    }
    let bytes = hex::decode(ticket).map_err(|e| terr("ticket hex", e))?;
    postcard::from_bytes(&bytes).map_err(|e| terr("ticket decode", e))
}

/// Pure (no network): bounded hex + postcard decode of a ticket string.
/// Returns `(app_identity, app_sig, ticket_endpoint_id)`. Does not verify the
/// signature.
pub fn parse_ticket(ticket: &str) -> Result<(Vec<u8>, Vec<u8>, [u8; 32])> {
    let t = decode_ticket(ticket)?;
    Ok((t.app_identity, t.app_sig, *t.addr.id.as_bytes()))
}

/// Largest frame body `read_frame` will accept (64 KiB).
pub const MAX_FRAME_LEN: usize = 65_536;

/// Validate a received length prefix before allocating. Pure; no I/O, no allocation.
fn check_frame_len(n: u32) -> Result<usize> {
    let n = n as usize;
    if n > MAX_FRAME_LEN {
        return Err(Error::Transport(format!(
            "frame too large: {n} > {MAX_FRAME_LEN}"
        )));
    }
    Ok(n)
}

/// Write one length-prefixed frame to a QUIC send stream.
pub async fn write_frame(s: &mut SendStream, msg: &[u8]) -> Result<()> {
    s.write_all(&(msg.len() as u32).to_be_bytes())
        .await
        .map_err(|e| terr("write len", e))?;
    s.write_all(msg).await.map_err(|e| terr("write body", e))?;
    Ok(())
}

/// Read one length-prefixed frame from a QUIC recv stream.
pub async fn read_frame(r: &mut RecvStream) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)
        .await
        .map_err(|e| terr("read len", e))?;
    let n = check_frame_len(u32::from_be_bytes(len))?;
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)
        .await
        .map_err(|e| terr("read body", e))?;
    Ok(buf)
}

/// A snapshot of a live connection's selected-path health.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkInfo {
    /// `true` if the selected path is a direct (hole-punched / LAN) IP path;
    /// `false` if traffic is currently relayed.
    pub direct: bool,
    /// Round-trip time in milliseconds on the selected path, once measured.
    pub rtt_ms: Option<u64>,
}

/// A lightweight, clonable handle for querying a live connection's link health
/// without owning its streams (the connection stays alive through the streams).
/// Lets a caller poll path + latency after [`IrohConn::into_split`].
#[derive(Clone)]
pub struct ConnHandle(IrohConnection);

impl ConnHandle {
    /// Snapshot the currently selected path's kind (direct vs relay) and RTT.
    /// Re-read live on each call, so it reflects a relay→direct upgrade.
    pub fn link(&self) -> LinkInfo {
        let paths = self.0.paths();
        let chosen = paths
            .iter()
            .find(|p| p.is_selected())
            .or_else(|| paths.iter().next());
        match chosen {
            Some(p) => {
                let ms = p.rtt().as_millis() as u64;
                LinkInfo {
                    direct: p.is_ip(),
                    rtt_ms: (ms != 0).then_some(ms),
                }
            }
            None => LinkInfo {
                direct: false,
                rtt_ms: None,
            },
        }
    }
}

/// A framed connection over an iroh QUIC bi-stream.
pub struct IrohConn {
    conn: IrohConnection,
    send: SendStream,
    recv: RecvStream,
}

impl IrohConn {
    /// Split into the raw QUIC streams for concurrent full-duplex I/O (framing
    /// stays compatible with [`write_frame`]/[`read_frame`]).
    pub fn into_split(self) -> (SendStream, RecvStream) {
        (self.send, self.recv)
    }

    /// Authenticated remote iroh endpoint id of the underlying QUIC connection.
    pub fn remote_endpoint_id(&self) -> [u8; 32] {
        *self.conn.remote_id().as_bytes()
    }

    /// A clonable handle to keep querying link health after [`IrohConn::into_split`].
    pub fn handle(&self) -> ConnHandle {
        ConnHandle(self.conn.clone())
    }
}

impl Connection for IrohConn {
    async fn send(&mut self, msg: &[u8]) -> Result<()> {
        write_frame(&mut self.send, msg).await
    }
    async fn recv(&mut self) -> Result<Vec<u8>> {
        read_frame(&mut self.recv).await
    }
}

/// A networked endpoint over iroh QUIC.
pub struct IrohTransport {
    ep: Endpoint,
}

impl IrohTransport {
    /// Bind a networked endpoint (n0 relays + discovery) that can accept.
    pub async fn bind() -> Result<Self> {
        let ep = Endpoint::builder(presets::N0)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .map_err(|e| terr("bind", e))?;
        Ok(Self { ep })
    }

    /// Our endpoint id (hex of the 32-byte iroh public key).
    pub fn endpoint_id(&self) -> String {
        hex::encode(self.ep.id().as_bytes())
    }

    /// Our iroh endpoint id as raw bytes.
    pub fn endpoint_id_bytes(&self) -> [u8; 32] {
        *self.ep.id().as_bytes()
    }

    /// A copy-pasteable ticket: our (online) address, an opaque app-identity
    /// blob, and the app's opaque signature over [`ticket_message`] for this
    /// endpoint id and identity.
    pub async fn ticket(&self, app_identity: &[u8], app_sig: &[u8]) -> Result<String> {
        self.ep.online().await;
        let t = Ticket {
            addr: self.ep.addr(),
            app_identity: app_identity.to_vec(),
            app_sig: app_sig.to_vec(),
        };
        encode_ticket(&t)
    }

    /// Dial a ticket. Returns `(app_identity, app_sig, ticket_endpoint_id, conn)`.
    /// Does NOT verify `app_sig`; callers should [`parse_ticket`] and verify first.
    pub async fn connect_ticket(
        &self,
        ticket: &str,
    ) -> Result<(Vec<u8>, Vec<u8>, [u8; 32], IrohConn)> {
        let t = decode_ticket(ticket)?;
        let ticket_id = *t.addr.id.as_bytes();
        let conn = self
            .ep
            .connect(t.addr, ALPN)
            .await
            .map_err(|e| terr("connect", e))?;
        let (send, recv) = conn.open_bi().await.map_err(|e| terr("open_bi", e))?;
        Ok((
            t.app_identity,
            t.app_sig,
            ticket_id,
            IrohConn { conn, send, recv },
        ))
    }

    /// Accept one inbound connection's first bi-stream.
    pub async fn accept_conn(&self) -> Result<IrohConn> {
        let incoming = self
            .ep
            .accept()
            .await
            .ok_or_else(|| Error::Transport("endpoint closed".into()))?;
        let conn = incoming.await.map_err(|e| terr("accept", e))?;
        let (send, recv) = conn.accept_bi().await.map_err(|e| terr("accept_bi", e))?;
        Ok(IrohConn { conn, send, recv })
    }
}

impl Transport for IrohTransport {
    type Addr = IrohEndpointId;
    type Conn = IrohConn;

    async fn connect(&self, addr: &IrohEndpointId) -> Result<IrohConn> {
        // Connect by endpoint id (relies on discovery to resolve the address).
        let id = EndpointId::from_bytes(&addr.0).map_err(|e| terr("endpoint id", e))?;
        let conn = self
            .ep
            .connect(id, ALPN)
            .await
            .map_err(|e| terr("connect", e))?;
        let (send, recv) = conn.open_bi().await.map_err(|e| terr("open_bi", e))?;
        Ok(IrohConn { conn, send, recv })
    }

    async fn accept(&self) -> Result<(IrohEndpointId, IrohConn)> {
        let incoming = self
            .ep
            .accept()
            .await
            .ok_or_else(|| Error::Transport("endpoint closed".into()))?;
        let conn = incoming.await.map_err(|e| terr("accept", e))?;
        let remote = IrohEndpointId(*conn.remote_id().as_bytes());
        let (send, recv) = conn.accept_bi().await.map_err(|e| terr("accept_bi", e))?;
        Ok((remote, IrohConn { conn, send, recv }))
    }

    async fn announce(&self, _topic: &Topic) -> Result<()> {
        Ok(()) // n0 discovery publishes our address automatically
    }

    async fn lookup(&self, _topic: &Topic) -> Result<Vec<IrohEndpointId>> {
        Ok(vec![]) // topic-based discovery is future work
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_frames_are_rejected() {
        assert!(matches!(
            check_frame_len(u32::MAX),
            Err(Error::Transport(_))
        ));
        assert!(matches!(check_frame_len(65_537), Err(Error::Transport(_))));
    }

    #[test]
    fn boundary_frames_are_accepted() {
        assert_eq!(check_frame_len(65_536).unwrap(), 65_536);
        assert_eq!(check_frame_len(0).unwrap(), 0);
    }

    fn test_id(seed: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[seed; 32]).public()
    }

    #[test]
    fn ticket_roundtrip() {
        let id = test_id(7);
        let t = Ticket {
            addr: EndpointAddr::new(id),
            app_identity: b"identity-bytes".to_vec(),
            app_sig: b"sig-bytes".to_vec(),
        };
        let s = encode_ticket(&t).unwrap();
        let (ident, sig, ep) = parse_ticket(&s).unwrap();
        assert_eq!(ident, b"identity-bytes");
        assert_eq!(sig, b"sig-bytes");
        assert_eq!(&ep, id.as_bytes());
        // Surrounding whitespace is tolerated.
        assert!(parse_ticket(&format!("  {s}\n")).is_ok());
    }

    #[test]
    fn ticket_message_layout() {
        let id = [9u8; 32];
        let mut want = b"lattice-ticket-v1".to_vec();
        want.extend_from_slice(&id);
        want.extend_from_slice(&[3, 0, 0, 0]);
        want.extend_from_slice(b"xyz");
        assert_eq!(ticket_message(&id, b"xyz"), want);
    }

    #[test]
    fn oversized_ticket_is_rejected_before_hex() {
        // Non-hex content proves the size check runs first.
        let big = "z".repeat(MAX_TICKET_LEN + 1);
        match parse_ticket(&big) {
            Err(Error::Transport(m)) => assert!(m.contains("too large"), "{m}"),
            other => panic!("unexpected: {other:?}"),
        }
        let big_hex = "ab".repeat(MAX_TICKET_LEN / 2 + 1);
        assert!(parse_ticket(&big_hex).is_err());
    }

    #[test]
    fn malformed_tickets_are_rejected() {
        assert!(parse_ticket("").is_err());
        assert!(parse_ticket("   ").is_err());
        assert!(parse_ticket("not hex at all!").is_err());
        assert!(parse_ticket("abc").is_err()); // odd length
        assert!(parse_ticket("00").is_err()); // valid hex, bad postcard
    }

    #[test]
    fn old_unsigned_ticket_is_rejected() {
        #[derive(Serialize)]
        struct OldTicket {
            addr: EndpointAddr,
            app_identity: Vec<u8>,
        }
        let old = OldTicket {
            addr: EndpointAddr::new(test_id(1)),
            app_identity: b"identity".to_vec(),
        };
        let s = hex::encode(postcard::to_allocvec(&old).unwrap());
        assert!(parse_ticket(&s).is_err());
    }

    #[test]
    fn endpoint_id_debug_is_full_hex() {
        let s = format!("{:?}", IrohEndpointId([0xcd; 32]));
        assert!(s.contains(&"cd".repeat(32)));
    }

    #[test]
    fn iroh_transport_addr_is_endpoint_id() {
        fn assert_addr<T: Transport<Addr = IrohEndpointId>>() {}
        assert_addr::<IrohTransport>();
    }
}
