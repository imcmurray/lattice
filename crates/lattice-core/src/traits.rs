//! Core trait contracts (DESIGN.md §4). Concrete impls live in sibling crates;
//! these traits are the seams that keep each layer swappable.

use crate::error::Result;
use crate::types::{Entry, PeerId, Seq, Signature, Topic};

/// Minimal duplex byte-stream marker. Kept dependency-free in the scaffold;
/// the real impl will bridge to `tokio::io::{AsyncRead, AsyncWrite}`.
pub trait Stream: Send {}

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
pub trait Transport {
    /// Connected duplex stream type.
    type Stream: Stream;
    /// Open a direct (holepunched, else relayed) stream to a peer.
    async fn connect(&self, peer: &PeerId) -> Result<Self::Stream>;
    /// Accept the next inbound stream.
    async fn accept(&self) -> Result<(PeerId, Self::Stream)>;
    /// Announce presence on a discovery topic.
    async fn announce(&self, topic: &Topic) -> Result<()>;
    /// Look up peers announcing a topic.
    async fn lookup(&self, topic: &Topic) -> Result<Vec<PeerId>>;
}

/// An authenticated, encrypted, forward-secret channel over a
/// [`Transport::Stream`].
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
