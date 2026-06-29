//! Shared value types. All are placeholders in shape-final form: byte widths
//! and encodings will be pinned as the crypto layer lands.

use core::fmt;

/// Stable peer identifier, derived from an identity's public key material.
/// Placeholder: 32 bytes (will be `BLAKE3(hybrid public keys)`).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PeerId(pub [u8; 32]);

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId(")?;
        for b in &self.0[..4] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "\u{2026})")
    }
}

/// A hybrid signature (classical + post-quantum). Opaque bytes in the scaffold.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signature(pub Vec<u8>);

/// A discovery topic (e.g. a room key), 32 bytes.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Topic(pub [u8; 32]);

/// Monotonic sequence number within a single-writer log.
pub type Seq = u64;

/// A single appended, signed log entry — one link in the hash chain.
#[derive(Clone, Debug)]
pub struct Entry {
    /// Position in the author's single-writer log.
    pub seq: Seq,
    /// Who wrote it.
    pub author: PeerId,
    /// Opaque application payload.
    pub payload: Vec<u8>,
    /// Hash of the previous entry (`[0; 32]` for the genesis entry).
    pub prev_hash: [u8; 32],
    /// Hash committing to `prev_hash || payload`.
    pub hash: [u8; 32],
    /// Author's signature over `hash`.
    pub sig: Signature,
}

/// Cryptographic posture selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CryptoSuite {
    /// Classical only — bring-up / testing ONLY, never production.
    Classical,
    /// Classical + post-quantum hybrid. The default, and the only supported
    /// production posture (secure if *either* component holds).
    #[default]
    Hybrid,
}
