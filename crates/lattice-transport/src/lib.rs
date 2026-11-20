//! `lattice-transport` — the [`Transport`]/`Connection` trait surface plus two
//! backends: an in-memory loopback ([`MemoryTransport`], always available) and an
//! iroh QUIC backend (`IrohTransport`, behind the `iroh` feature). See DESIGN.md
//! ADR-001.
//!
//! [`MemoryTransport`] is a real, working [`Transport`]: endpoints register on a
//! shared [`MemoryNetwork`], `connect` hands one end of an in-process duplex to
//! the peer's accept queue, and `accept` receives it. The upper layers (the
//! session handshake, the app) are written against the trait, so the iroh
//! backend (see `src/quic.rs`) drops in without touching them.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use lattice_core::{Connection, Error, PeerId, Result, Topic, Transport};
use tokio::sync::mpsc;
use tokio::sync::Mutex as AsyncMutex;

#[cfg(feature = "iroh")]
mod quic;
#[cfg(feature = "iroh")]
pub use quic::{
    encode_ticket, parse_ticket, read_frame, ticket_message, write_frame, ConnHandle, IrohConn,
    IrohEndpointId, IrohTransport, LinkInfo, ParsedTicket, RecvStream, SendStream, TicketAddr,
    ALPN, MAX_TICKET_LEN,
};

type Inbox = mpsc::UnboundedSender<(PeerId, MemoryConn)>;

/// A shared in-process network: a registry of endpoint inboxes by [`PeerId`].
#[derive(Clone, Default)]
pub struct MemoryNetwork {
    listeners: Arc<Mutex<HashMap<PeerId, Inbox>>>,
}

impl MemoryNetwork {
    /// Create an empty network.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an endpoint for `id` and return its [`MemoryTransport`] handle.
    pub fn endpoint(&self, id: PeerId) -> MemoryTransport {
        let (tx, rx) = mpsc::unbounded_channel();
        self.listeners.lock().unwrap().insert(id.clone(), tx);
        MemoryTransport {
            id,
            net: self.clone(),
            incoming: AsyncMutex::new(rx),
        }
    }
}

/// One end of an in-process duplex connection carrying framed messages.
pub struct MemoryConn {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl MemoryConn {
    /// Two cross-wired ends: a send on one is a receive on the other.
    fn pair() -> (Self, Self) {
        let (t1, r1) = mpsc::unbounded_channel();
        let (t2, r2) = mpsc::unbounded_channel();
        (Self { tx: t1, rx: r2 }, Self { tx: t2, rx: r1 })
    }
}

impl Connection for MemoryConn {
    async fn send(&mut self, msg: &[u8]) -> Result<()> {
        self.tx
            .send(msg.to_vec())
            .map_err(|_| Error::Transport("connection closed".into()))
    }

    async fn recv(&mut self) -> Result<Vec<u8>> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| Error::Transport("connection closed".into()))
    }
}

/// An endpoint on a [`MemoryNetwork`].
pub struct MemoryTransport {
    id: PeerId,
    net: MemoryNetwork,
    incoming: AsyncMutex<mpsc::UnboundedReceiver<(PeerId, MemoryConn)>>,
}

impl MemoryTransport {
    fn inbox_of(&self, peer: &PeerId) -> Result<Inbox> {
        self.net
            .listeners
            .lock()
            .unwrap()
            .get(peer)
            .cloned()
            .ok_or_else(|| Error::Transport("peer not registered".into()))
    }
}

impl Transport for MemoryTransport {
    type Addr = PeerId;
    type Conn = MemoryConn;

    async fn connect(&self, peer: &Self::Addr) -> Result<MemoryConn> {
        let inbox = self.inbox_of(peer)?;
        let (mine, theirs) = MemoryConn::pair();
        inbox
            .send((self.id.clone(), theirs))
            .map_err(|_| Error::Transport("peer not listening".into()))?;
        Ok(mine)
    }

    async fn accept(&self) -> Result<(Self::Addr, MemoryConn)> {
        self.incoming
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| Error::Transport("endpoint closed".into()))
    }

    async fn announce(&self, _topic: &Topic) -> Result<()> {
        Ok(()) // registration is implicit via `endpoint`
    }

    async fn lookup(&self, _topic: &Topic) -> Result<Vec<Self::Addr>> {
        Ok(self.net.listeners.lock().unwrap().keys().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_accept_roundtrip() {
        let net = MemoryNetwork::new();
        let alice = PeerId([1u8; 32]);
        let bob = PeerId([2u8; 32]);
        let a = net.endpoint(alice.clone());
        let b = net.endpoint(bob.clone());

        let mut a_conn = a.connect(&bob).await.unwrap();
        let (from, mut b_conn) = b.accept().await.unwrap();
        assert_eq!(from, alice);

        a_conn.send(b"ping").await.unwrap();
        assert_eq!(b_conn.recv().await.unwrap(), b"ping");
        b_conn.send(b"pong").await.unwrap();
        assert_eq!(a_conn.recv().await.unwrap(), b"pong");
    }

    #[tokio::test]
    async fn connect_unknown_peer_fails() {
        let net = MemoryNetwork::new();
        let a = net.endpoint(PeerId([1u8; 32]));
        assert!(a.connect(&PeerId([9u8; 32])).await.is_err());
    }
}
