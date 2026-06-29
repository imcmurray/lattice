//! `lattice-transport` — the [`Transport`] trait's default implementation over
//! iroh (QUIC + holepunch + relay fallback). Stub pending ADR-001 wiring.
//!
//! This is the single swap seam: alternative impls (libp2p, a Tor/mix relay for
//! metadata privacy) implement the same trait without touching upper layers.

use lattice_core::{PeerId, Result, Stream, Topic, Transport};

/// A connected duplex stream. Placeholder until the iroh bridge lands.
pub struct Conn;
impl Stream for Conn {}

/// Default transport: iroh QUIC with holepunching and relay fallback.
#[derive(Default)]
pub struct IrohTransport;

impl Transport for IrohTransport {
    type Stream = Conn;
    async fn connect(&self, _peer: &PeerId) -> Result<Conn> {
        todo!("iroh: resolve endpoint, holepunch (else relay), open stream")
    }
    async fn accept(&self) -> Result<(PeerId, Conn)> {
        todo!("iroh: accept inbound, verify peer")
    }
    async fn announce(&self, _topic: &Topic) -> Result<()> {
        todo!("iroh/DHT: announce topic membership")
    }
    async fn lookup(&self, _topic: &Topic) -> Result<Vec<PeerId>> {
        todo!("iroh/DHT: resolve peers for topic")
    }
}
