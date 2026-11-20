//! iroh QUIC backend for [`Transport`] (DESIGN.md ADR-001).
//!
//! `IrohTransport` binds an iroh endpoint (n0 relays + discovery) and yields
//! `IrohConn`s — framed (`u32`-BE length prefix) over a single QUIC bi-stream,
//! preserving in-order delivery for the Double Ratchet. Tickets (version 3)
//! are compact and **unsigned**: our iroh address (the exact serialized
//! bytes) plus two opaque 32-byte ids (`root_id`, `device_id` — the app puts
//! PeerIds there). A ticket is an out-of-band bearer of those ids; its
//! security comes from the application verifying the peer's hello and
//! handshake against them, not from a signature on the ticket. Tickets stay
//! small enough for a QR code ([`COMPACT_TICKET_MAX_LEN`]). The transport is
//! identity-agnostic: the ids are opaque here. Version-2 (signed) tickets are
//! rejected with an "old ticket version" error.
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

/// Current ticket version (compact, unsigned).
pub const TICKET_VERSION: u8 = 3;

/// Target upper bound (hex chars) for a realistic ticket, so it fits a QR code.
/// Not enforced by [`encode_ticket`].
pub const COMPACT_TICKET_MAX_LEN: usize = 1024;

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

/// Wire struct, postcard-encoded then hex-encoded.
#[derive(Serialize, Deserialize)]
struct Ticket {
    /// Must equal [`TICKET_VERSION`].
    version: u8,
    /// The exact `postcard(EndpointAddr)` bytes.
    addr: Vec<u8>,
    root_id: [u8; 32],
    device_id: [u8; 32],
}

/// A frozen snapshot of an endpoint address and its exact serialized bytes.
#[derive(Clone, Debug)]
pub struct TicketAddr {
    addr: EndpointAddr,
    bytes: Vec<u8>,
}

impl TicketAddr {
    /// Serializes exactly once.
    fn from_addr(addr: EndpointAddr) -> Result<Self> {
        let bytes = postcard::to_allocvec(&addr).map_err(|e| terr("ticket addr encode", e))?;
        Ok(Self { addr, bytes })
    }

    /// Pure. Build from parts (for tests and tools). Errors on an invalid
    /// endpoint id, an unparsable relay URL, or a serialization failure.
    pub fn from_parts(
        endpoint_id: &[u8; 32],
        relay_urls: &[&str],
        direct_addrs: &[std::net::SocketAddr],
    ) -> Result<Self> {
        let id = EndpointId::from_bytes(endpoint_id).map_err(|e| terr("endpoint id", e))?;
        let mut addr = EndpointAddr::new(id);
        for u in relay_urls {
            let url: iroh::RelayUrl = u.parse().map_err(|e| terr("relay url", e))?;
            addr = addr.with_relay_url(url);
        }
        for a in direct_addrs {
            addr = addr.with_ip_addr(*a);
        }
        Self::from_addr(addr)
    }

    /// The iroh endpoint id inside the address.
    pub fn endpoint_id(&self) -> [u8; 32] {
        *self.addr.id.as_bytes()
    }

    /// The exact `postcard(EndpointAddr)` bytes that are put in the ticket.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A decoded ticket. Unsigned: nothing here is authenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedTicket {
    /// Decoded `EndpointAddr.id`.
    pub endpoint_id: [u8; 32],
    /// Raw address bytes exactly as carried by the ticket.
    pub addr_bytes: Vec<u8>,
    /// Opaque to this crate (the app puts a root PeerId here).
    pub root_id: [u8; 32],
    /// Opaque to this crate (the app puts a device PeerId here).
    pub device_id: [u8; 32],
}

/// Pure: `hex(postcard(Ticket { version: 3, addr: addr.as_bytes(), root_id, device_id }))`.
/// Deterministic.
pub fn encode_ticket(
    addr: &TicketAddr,
    root_id: &[u8; 32],
    device_id: &[u8; 32],
) -> Result<String> {
    let t = Ticket {
        version: TICKET_VERSION,
        addr: addr.as_bytes().to_vec(),
        root_id: *root_id,
        device_id: *device_id,
    };
    let bytes = postcard::to_allocvec(&t).map_err(|e| terr("ticket encode", e))?;
    Ok(hex::encode(bytes))
}

fn decode_ticket(ticket: &str) -> Result<(ParsedTicket, EndpointAddr)> {
    let ticket = ticket.trim();
    if ticket.len() > MAX_TICKET_LEN {
        return Err(Error::Transport(format!(
            "ticket too large: {} > {MAX_TICKET_LEN}",
            ticket.len()
        )));
    }
    let bytes = hex::decode(ticket).map_err(|e| terr("ticket hex", e))?;
    // The version is the first postcard field (a `u8` = one raw byte).
    match bytes.first() {
        None => return Err(Error::Transport("ticket is empty".into())),
        Some(&TICKET_VERSION) => {}
        Some(2) => {
            return Err(Error::Transport(
                "old ticket version 2 (signed ticket); ask your peer for a new ticket \
                 from an upgraded lattice-net"
                    .into(),
            ))
        }
        Some(v) => {
            return Err(Error::Transport(format!("unsupported ticket version {v}")));
        }
    }
    let (t, rest): (Ticket, &[u8]) =
        postcard::take_from_bytes(&bytes).map_err(|e| terr("ticket decode", e))?;
    if !rest.is_empty() {
        return Err(Error::Transport("ticket has trailing bytes".into()));
    }
    let (addr, rest): (EndpointAddr, &[u8]) =
        postcard::take_from_bytes(&t.addr).map_err(|e| terr("ticket addr decode", e))?;
    if !rest.is_empty() {
        return Err(Error::Transport("ticket addr has trailing bytes".into()));
    }
    let parsed = ParsedTicket {
        endpoint_id: *addr.id.as_bytes(),
        addr_bytes: t.addr,
        root_id: t.root_id,
        device_id: t.device_id,
    };
    Ok((parsed, addr))
}

/// Pure (no network): bounded hex + strict postcard decode of a ticket string.
/// The ticket is unsigned; the caller checks the ids it carries.
pub fn parse_ticket(ticket: &str) -> Result<ParsedTicket> {
    decode_ticket(ticket).map(|(p, _)| p)
}

/// Upper bound on finishing one inbound connection in [`Transport::accept`].
pub const TRAIT_ACCEPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

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

    /// Wait until online, then snapshot our address ONCE and pass that value
    /// to [`encode_ticket`].
    pub async fn ticket_addr(&self) -> Result<TicketAddr> {
        self.ep.online().await;
        TicketAddr::from_addr(self.ep.addr())
    }

    /// Dial the address decoded from a ticket. Returns the [`ParsedTicket`] and
    /// the connection. The ticket's ids are not checked here; the caller
    /// verifies the peer against them.
    pub async fn connect_ticket(&self, ticket: &str) -> Result<(ParsedTicket, IrohConn)> {
        let (parsed, addr) = decode_ticket(ticket)?;
        let conn = self
            .ep
            .connect(addr, ALPN)
            .await
            .map_err(|e| terr("connect", e))?;
        let (send, recv) = conn.open_bi().await.map_err(|e| terr("open_bi", e))?;
        Ok((parsed, IrohConn { conn, send, recv }))
    }

    /// Wait for the next inbound connection attempt and return it without
    /// awaiting its handshake. `Err(Error::Transport("endpoint closed"))` when
    /// the endpoint is closed.
    pub async fn accept_incoming(&self) -> Result<IncomingConn> {
        let incoming = self
            .ep
            .accept()
            .await
            .ok_or_else(|| Error::Transport("endpoint closed".into()))?;
        Ok(IncomingConn { incoming })
    }

    /// Accept one inbound connection's first bi-stream.
    ///
    /// **WARNING: no timeout.** A peer that never completes the QUIC handshake,
    /// or completes it but never opens a stream, makes this wait forever and
    /// blocks the caller. Prefer [`IrohTransport::accept_incoming`] plus a
    /// bounded [`IncomingConn::finish`].
    pub async fn accept_conn(&self) -> Result<IrohConn> {
        self.accept_incoming().await?.finish().await
    }
}

/// An inbound connection attempt that has not yet completed its QUIC
/// handshake or opened a stream. Obtained quickly from
/// [`IrohTransport::accept_incoming`]; dropping it refuses/abandons the attempt.
pub struct IncomingConn {
    incoming: iroh::endpoint::Incoming,
}

impl IncomingConn {
    /// Complete the QUIC handshake, then accept the peer's first bi-stream.
    ///
    /// Has NO timeout of its own: a peer that completes QUIC but never opens a
    /// stream makes this wait forever. Callers must bound it.
    pub async fn finish(self) -> Result<IrohConn> {
        let conn = self.incoming.await.map_err(|e| terr("accept", e))?;
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

    /// Accept the next inbound connection. Finishing it (QUIC handshake and
    /// the first bi-stream) is limited to [`TRAIT_ACCEPT_TIMEOUT`], so a peer
    /// that never opens a stream can't stall the caller forever. It is still
    /// serial: callers that need concurrent accepts should use
    /// [`IrohTransport::accept_incoming`] and finish each in its own task.
    async fn accept(&self) -> Result<(IrohEndpointId, IrohConn)> {
        let incoming = self
            .ep
            .accept()
            .await
            .ok_or_else(|| Error::Transport("endpoint closed".into()))?;
        let finish = async {
            let conn = incoming.await.map_err(|e| terr("accept", e))?;
            let remote = IrohEndpointId(*conn.remote_id().as_bytes());
            let (send, recv) = conn.accept_bi().await.map_err(|e| terr("accept_bi", e))?;
            Ok((remote, IrohConn { conn, send, recv }))
        };
        tokio::time::timeout(TRAIT_ACCEPT_TIMEOUT, finish)
            .await
            .map_err(|_| Error::Transport("accept timed out".into()))?
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

    /// Compile-only: the incoming-connection API exists with these shapes.
    #[test]
    fn incoming_api_is_exported() {
        fn _assert(t: &IrohTransport) {
            let _incoming = t.accept_incoming();
            let _conn = t.accept_conn();
        }
        fn _finish(i: IncomingConn) {
            let _fut = i.finish();
        }
        let _: fn(&IrohTransport) = _assert;
        let _: fn(IncomingConn) = _finish;
    }

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

    fn sample_addr(seed: u8) -> TicketAddr {
        TicketAddr::from_parts(
            test_id(seed).as_bytes(),
            &["https://relay.example.org./"],
            &["192.0.2.1:4433".parse().unwrap()],
        )
        .unwrap()
    }

    fn raw_ticket(version: u8, addr: Vec<u8>) -> Ticket {
        Ticket {
            version,
            addr,
            root_id: [0x11; 32],
            device_id: [0x22; 32],
        }
    }

    fn hex_of(t: &Ticket) -> String {
        hex::encode(postcard::to_allocvec(t).unwrap())
    }

    #[test]
    fn ticket_roundtrip() {
        let addr = sample_addr(7);
        let s = encode_ticket(&addr, &[0xaa; 32], &[0xbb; 32]).unwrap();
        let p = parse_ticket(&s).unwrap();
        assert_eq!(p.root_id, [0xaa; 32]);
        assert_eq!(p.device_id, [0xbb; 32]);
        assert_eq!(p.endpoint_id, addr.endpoint_id());
        assert_eq!(&p.endpoint_id, test_id(7).as_bytes());
        assert_eq!(p.addr_bytes, addr.as_bytes());
        // Surrounding whitespace is tolerated.
        assert_eq!(parse_ticket(&format!("  {s}\n")).unwrap(), p);
    }

    #[test]
    fn ticket_encoding_is_deterministic() {
        let s1 = encode_ticket(&sample_addr(7), &[1; 32], &[2; 32]).unwrap();
        let p = parse_ticket(&s1).unwrap();
        let s2 = encode_ticket(&sample_addr(7), &p.root_id, &p.device_id).unwrap();
        assert_eq!(s1, s2);
        assert!(s1.starts_with("03"), "version byte first");
    }

    #[test]
    fn realistic_ticket_is_compact() {
        let addr = TicketAddr::from_parts(
            test_id(3).as_bytes(),
            &["https://euc1-1.relay.n0.iroh.iroh.link./"],
            &[
                "192.0.2.1:4433".parse().unwrap(),
                "198.51.100.7:51234".parse().unwrap(),
                "[2001:db8::1]:4433".parse().unwrap(),
                "[2001:db8:1::2]:51234".parse().unwrap(),
            ],
        )
        .unwrap();
        let s = encode_ticket(&addr, &[1; 32], &[2; 32]).unwrap();
        assert!(s.len() < COMPACT_TICKET_MAX_LEN, "{}", s.len());
    }

    #[test]
    fn from_parts_rejects_bad_relay_url() {
        let r = TicketAddr::from_parts(test_id(1).as_bytes(), &["not a url"], &[]);
        assert!(matches!(r, Err(Error::Transport(_))));
        // id-only address is allowed.
        assert!(TicketAddr::from_parts(test_id(1).as_bytes(), &[], &[]).is_ok());
    }

    #[test]
    fn wrong_version_is_rejected() {
        let a = sample_addr(1);
        for v in [1u8, 4] {
            match parse_ticket(&hex_of(&raw_ticket(v, a.as_bytes().to_vec()))) {
                Err(Error::Transport(m)) => {
                    assert!(m.contains("unsupported ticket version"), "{m}")
                }
                other => panic!("unexpected: {other:?}"),
            }
        }
        assert!(parse_ticket(&hex_of(&raw_ticket(3, a.as_bytes().to_vec()))).is_ok());
    }

    #[test]
    fn v2_layout_gets_old_version_error() {
        #[derive(Serialize)]
        struct V2 {
            version: u8,
            addr: Vec<u8>,
            app_identity: Vec<u8>,
            app_sig: Vec<u8>,
        }
        let v2 = V2 {
            version: 2,
            addr: sample_addr(1).as_bytes().to_vec(),
            app_identity: b"identity".to_vec(),
            app_sig: b"sig".to_vec(),
        };
        let s = hex::encode(postcard::to_allocvec(&v2).unwrap());
        match parse_ticket(&s) {
            Err(Error::Transport(m)) => assert!(m.contains("old ticket version"), "{m}"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let a = sample_addr(1);
        // Extra byte inside the addr blob.
        let mut inner = a.as_bytes().to_vec();
        inner.push(0);
        assert!(parse_ticket(&hex_of(&raw_ticket(3, inner))).is_err());
        // Extra byte after the outer struct.
        let mut outer = postcard::to_allocvec(&raw_ticket(3, a.as_bytes().to_vec())).unwrap();
        outer.push(0);
        assert!(parse_ticket(&hex::encode(outer)).is_err());
    }

    #[test]
    fn v1_signed_layout_is_rejected() {
        #[derive(Serialize)]
        struct V1Ticket {
            addr: EndpointAddr,
            app_identity: Vec<u8>,
            app_sig: Vec<u8>,
        }
        let v1 = V1Ticket {
            addr: EndpointAddr::new(test_id(1)),
            app_identity: b"identity".to_vec(),
            app_sig: b"sig".to_vec(),
        };
        let s = hex::encode(postcard::to_allocvec(&v1).unwrap());
        assert!(parse_ticket(&s).is_err());
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
