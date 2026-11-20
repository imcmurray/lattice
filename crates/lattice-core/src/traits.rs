//! Core trait contracts (DESIGN.md §4). Concrete impls live in sibling crates;
//! these traits are the seams that keep each layer swappable.

use crate::error::Result;
use crate::types::{Entry, PeerId, Seq, Signature, Topic};
/// An established bidirectional connection that carries whole **framed
/// messages** (not a raw byte stream — the transport owns framing). This keeps
/// the core dependency-free while the impls bring their own async runtime.
/// Impls: `MemoryConn` (in-memory loopback) and iroh QUIC streams
/// (`lattice-transport`, `iroh` feature).
#[allow(async_fn_in_trait)]
pub trait Connection: Send {
    /// Send one framed message to the peer.
    async fn send(&mut self, msg: &[u8]) -> Result<()>;
    /// Receive the next framed message from the peer.
    async fn recv(&mut self) -> Result<Vec<u8>>;
}

/// The signing half of an identity: holds secret key material and produces
/// signatures. Production identities are post-quantum hybrid (see `CryptoSuite`).
/// Object-safe, so `&dyn Identity` works (e.g. `Log::append`).
pub trait Identity {
    /// Stable identifier derived from the public key material.
    fn peer_id(&self) -> PeerId;
    /// Sign a message with the (hybrid) private key.
    fn sign(&self, msg: &[u8]) -> Signature;
}

/// The verifying half: a *published public identity* anyone can hold to check
/// signatures. Carries no secret material.
///
/// Verification lives here, not on [`Identity`], because a signature cannot be
/// checked against a [`PeerId`] alone — that's only a hash of the public keys.
/// You need the actual key bundle, which is exactly what a `Verify` impl holds.
pub trait Verify {
    /// The peer id this public identity commits to.
    fn peer_id(&self) -> PeerId;
    /// Check a signature over `msg`. A hybrid identity requires *every*
    /// component signature (classical AND post-quantum) to verify.
    fn verify(&self, msg: &[u8], sig: &Signature) -> bool;
}

/// The network substrate. The ONLY place the underlying P2P stack is named, so
/// iroh -> libp2p -> tor-relay is a contained swap (DESIGN.md ADR-001).
#[allow(async_fn_in_trait)]
///
/// Addresses are transport-level locators and are **not** Lattice identities:
/// an `Addr` is unauthenticated, and identity comes only from the session
/// handshake that runs over the resulting connection.
pub trait Transport {
    /// Transport-level locator. NOT authenticated as a Lattice identity.
    type Addr: Clone + core::fmt::Debug + PartialEq + Eq + core::hash::Hash + Send;
    /// The connection type this transport yields.
    type Conn: Connection;
    /// Open a connection to an address (direct/holepunched, else relayed).
    async fn connect(&self, addr: &Self::Addr) -> Result<Self::Conn>;
    /// Accept the next inbound connection, with the remote's transport address
    /// (unauthenticated as a Lattice identity).
    async fn accept(&self) -> Result<(Self::Addr, Self::Conn)>;
    /// Announce presence on a discovery topic.
    async fn announce(&self, topic: &Topic) -> Result<()>;
    /// Look up addresses announcing a topic.
    async fn lookup(&self, topic: &Topic) -> Result<Vec<Self::Addr>>;
}

/// An authenticated, encrypted, forward-secret channel over a
/// [`Transport::Conn`].
#[allow(async_fn_in_trait)]
pub trait Session {
    /// Encrypt-and-send, advancing the ratchet.
    async fn send(&mut self, plaintext: &[u8]) -> Result<()>;
    /// Receive-and-decrypt the next message.
    async fn recv(&mut self) -> Result<Vec<u8>>;
}

/// The append-only, signed log: Lattice's core state primitive (hand-built).
pub trait Log {
    /// Append a signed payload; returns its sequence number.
    fn append(&mut self, payload: &[u8], by: &dyn Identity) -> Result<Seq>;
    /// Verify the full hash/signature chain. Fails closed on any tamper.
    fn verify(&self) -> Result<()>;
    /// Fetch an entry by sequence.
    fn get(&self, seq: Seq) -> Result<Option<Entry>>;
    /// The next sequence number (== current length).
    fn head(&self) -> Seq;
}
