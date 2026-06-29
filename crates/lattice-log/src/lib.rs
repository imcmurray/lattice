//! `lattice-log` — the append-only, signed log: Lattice's core state primitive,
//! hand-built (DESIGN.md principle #4). A single-writer log is a hash chain;
//! every entry commits to the previous, so any tamper breaks verification.
//!
//! This scaffold provides a **working** in-memory log so the shape is testable
//! today. Two placeholders remain, clearly marked:
//!   1. `placeholder_hash` is deterministic but NOT cryptographic — replace
//!      with BLAKE3 once the dependency is pinned.
//!   2. Signatures come from whatever [`Identity`] is passed; real hybrid
//!      signing lands in `lattice-identity`.
//!
//! Multi-writer rooms are modeled as a *set* of single-writer logs merged
//! deterministically (CRDT) — that merge layer lands on top of this.

use lattice_core::{Entry, Error, Identity, Log, Result, Seq};

/// Deterministic, **non-cryptographic** placeholder hash (FNV-1a style).
/// TODO(hash): replace with `blake3::hash(prev || payload)`.
fn placeholder_hash(prev: &[u8; 32], payload: &[u8]) -> [u8; 32] {
    let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in prev.iter().chain(payload.iter()) {
        acc ^= b as u64;
        acc = acc.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = ((acc >> ((i % 8) * 8)) as u8) ^ (i as u8).wrapping_mul(31);
    }
    out
}

/// An in-memory single-writer log. On-disk storage and replication land later.
#[derive(Default)]
pub struct MemLog {
    entries: Vec<Entry>,
}

impl MemLog {
    /// Create an empty log.
    pub fn new() -> Self {
        Self::default()
    }
    /// Number of entries currently held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// Whether the log holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Log for MemLog {
    fn append(&mut self, payload: &[u8], by: &dyn Identity) -> Result<Seq> {
        let seq = self.entries.len() as Seq;
        let prev_hash = self.entries.last().map(|e| e.hash).unwrap_or([0u8; 32]);
        let hash = placeholder_hash(&prev_hash, payload);
        let sig = by.sign(&hash); // author signs the committing hash
        self.entries.push(Entry {
            seq,
            author: by.peer_id(),
            payload: payload.to_vec(),
            prev_hash,
            hash,
            sig,
        });
        Ok(seq)
    }

    fn verify(&self) -> Result<()> {
        let mut prev = [0u8; 32];
        for (i, e) in self.entries.iter().enumerate() {
            if e.seq != i as Seq {
                return Err(Error::Verify(format!("sequence gap at index {i}")));
            }
            if e.prev_hash != prev {
                return Err(Error::Verify(format!("broken chain link at seq {}", e.seq)));
            }
            if e.hash != placeholder_hash(&e.prev_hash, &e.payload) {
                return Err(Error::Verify(format!("hash mismatch at seq {}", e.seq)));
            }
            // TODO(sig): once identities are real, also verify e.sig over e.hash.
            prev = e.hash;
        }
        Ok(())
    }

    fn get(&self, seq: Seq) -> Result<Option<Entry>> {
        Ok(self.entries.get(seq as usize).cloned())
    }

    fn head(&self) -> Seq {
        self.entries.len() as Seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_core::{PeerId, Signature};

    /// A trivial identity so the log can be tested without real crypto.
    struct MockId;
    impl Identity for MockId {
        fn peer_id(&self) -> PeerId {
            PeerId([7u8; 32])
        }
        fn sign(&self, _msg: &[u8]) -> Signature {
            Signature(vec![])
        }
    }

    #[test]
    fn append_then_verify_ok() {
        let mut log = MemLog::new();
        let id = MockId;
        assert!(log.is_empty());
        log.append(b"hello", &id).unwrap();
        log.append(b"world", &id).unwrap();
        assert_eq!(log.head(), 2);
        assert_eq!(log.len(), 2);
        log.verify().expect("a clean chain must verify");
    }

    #[test]
    fn tamper_breaks_verify() {
        let mut log = MemLog::new();
        let id = MockId;
        log.append(b"hello", &id).unwrap();
        log.append(b"world", &id).unwrap();
        // Mutate a committed payload (a same-crate test may touch privates).
        log.entries[0].payload = b"HELLO".to_vec();
        assert!(
            log.verify().is_err(),
            "a tampered chain must fail closed (DESIGN.md principle #7)"
        );
    }

    #[test]
    fn get_returns_entries_and_none_past_head() {
        let mut log = MemLog::new();
        let id = MockId;
        log.append(b"only", &id).unwrap();
        assert!(log.get(0).unwrap().is_some());
        assert!(log.get(1).unwrap().is_none());
    }
}
