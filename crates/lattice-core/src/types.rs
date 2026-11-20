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

/// Full identity: 64 lowercase hex chars, no prefix or suffix.
impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl PeerId {
    /// First 20 bytes as 40 lowercase hex chars in 10 groups of 4, separated by
    /// single spaces (49 chars) — easy to compare out of band.
    pub fn fingerprint(&self) -> String {
        let mut s = String::with_capacity(49);
        for (i, b) in self.0[..20].iter().enumerate() {
            if i > 0 && i % 2 == 0 {
                s.push(' ');
            }
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

/// A hybrid signature (classical + post-quantum), carried as length-prefixed
/// opaque bytes (the classical and PQ component signatures concatenated).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_full_lowercase_hex() {
        let s = PeerId([0xab; 32]).to_string();
        assert_eq!(s, "ab".repeat(32));
        assert_eq!(s.len(), 64);
    }

    #[test]
    fn fingerprint_groups() {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = i as u8;
        }
        let fp = PeerId(b).fingerprint();
        assert_eq!(fp, "0001 0203 0405 0607 0809 0a0b 0c0d 0e0f 1011 1213");
        assert_eq!(fp.len(), 49);
    }

    #[test]
    fn debug_stays_short() {
        assert_eq!(
            format!("{:?}", PeerId([0x12; 32])),
            "PeerId(12121212\u{2026})"
        );
    }
}
