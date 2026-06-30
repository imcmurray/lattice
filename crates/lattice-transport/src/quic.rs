//! iroh QUIC backend for [`Transport`] (DESIGN.md ADR-001).
//!
//! `IrohTransport` binds an iroh endpoint (n0 relays + discovery) and yields
//! `IrohConn`s — framed (`u32`-BE length prefix) over a single QUIC bi-stream,
//! preserving in-order delivery for the Double Ratchet. Tickets carry our
//! address plus an opaque app-identity blob so the dialer can authenticate the
//! handshake. The transport is identity-agnostic: the app-identity bytes are
//! opaque here (the `lattice-identity` `PublicIdentity` encoding).

use iroh::endpoint::presets;
pub use iroh::endpoint::{RecvStream, SendStream};
use iroh::endpoint::Connection as IrohConnection;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use lattice_core::{Connection, Error, PeerId, Result, Topic, Transport};
use serde::{Deserialize, Serialize};

/// ALPN identifying the Lattice protocol on the wire.
pub const ALPN: &[u8] = b"lattice/0";

fn terr(ctx: &str, e: impl core::fmt::Display) -> Error {
    Error::Transport(format!("{ctx}: {e}"))
}

#[derive(Serialize, Deserialize)]
struct Ticket {
    addr: EndpointAddr,
    app_identity: Vec<u8>,
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
    let n = u32::from_be_bytes(len) as usize;
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
            None => LinkInfo { direct: false, rtt_ms: None },
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

    /// A copy-pasteable ticket: our (online) address + an opaque app-identity
    /// blob the dialer needs to authenticate the handshake.
    pub async fn ticket(&self, app_identity: &[u8]) -> Result<String> {
        self.ep.online().await;
        let t = Ticket {
            addr: self.ep.addr(),
            app_identity: app_identity.to_vec(),
        };
        let bytes = postcard::to_allocvec(&t).map_err(|e| terr("ticket encode", e))?;
        Ok(hex::encode(bytes))
    }

    /// Dial a ticket. Returns the peer's app-identity blob and a connection.
    pub async fn connect_ticket(&self, ticket: &str) -> Result<(Vec<u8>, IrohConn)> {
        let bytes = hex::decode(ticket.trim()).map_err(|e| terr("ticket hex", e))?;
        let t: Ticket = postcard::from_bytes(&bytes).map_err(|e| terr("ticket decode", e))?;
        let conn = self
            .ep
            .connect(t.addr, ALPN)
            .await
            .map_err(|e| terr("connect", e))?;
        let (send, recv) = conn.open_bi().await.map_err(|e| terr("open_bi", e))?;
        Ok((t.app_identity, IrohConn { conn, send, recv }))
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
    type Conn = IrohConn;

    async fn connect(&self, peer: &PeerId) -> Result<IrohConn> {
        // Connect by endpoint id (relies on discovery to resolve the address).
        let id = EndpointId::from_bytes(&peer.0).map_err(|e| terr("endpoint id", e))?;
        let conn = self
            .ep
            .connect(id, ALPN)
            .await
            .map_err(|e| terr("connect", e))?;
        let (send, recv) = conn.open_bi().await.map_err(|e| terr("open_bi", e))?;
        Ok(IrohConn { conn, send, recv })
    }

    async fn accept(&self) -> Result<(PeerId, IrohConn)> {
        let incoming = self
            .ep
            .accept()
            .await
            .ok_or_else(|| Error::Transport("endpoint closed".into()))?;
        let conn = incoming.await.map_err(|e| terr("accept", e))?;
        let peer = PeerId(*conn.remote_id().as_bytes());
        let (send, recv) = conn.accept_bi().await.map_err(|e| terr("accept_bi", e))?;
        Ok((peer, IrohConn { conn, send, recv }))
    }

    async fn announce(&self, _topic: &Topic) -> Result<()> {
        Ok(()) // n0 discovery publishes our address automatically
    }

    async fn lookup(&self, _topic: &Topic) -> Result<Vec<PeerId>> {
        Ok(vec![]) // topic-based discovery is future work
    }
}
