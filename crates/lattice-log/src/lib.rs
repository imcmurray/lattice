//! `lattice-log` — the append-only, signed log: Lattice's core state primitive,
//! hand-built (DESIGN.md principle #4).
//!
//! A single-writer log is a BLAKE3 hash chain bound to one author identity.
//! Each entry commits to `(seq, author, prev_hash, payload)` and the author
//! signs that commitment, so [`MemLog::verify`] fails closed on any tamper —
//! a flipped byte breaks the hash, a forged entry breaks the signature, a
//! reordering breaks the chain.
//!
//! The log depends only on `lattice_core` traits: it takes a [`Verify`] (the
//! author's public identity) to check signatures and a `&dyn Identity` to
//! append — it never depends on the concrete crypto crate. Multi-writer rooms
//! are modeled as a set of these single-writer logs merged via CRDT (later).

use lattice_core::{Entry, Error, Identity, Log, PeerId, Result, Seq, Verify};

const ENTRY_HASH_DOMAIN: &[u8] = b"lattice-log-entry-v1";

/// Compute an entry's commitment hash over all of its bound fields.
fn entry_hash(seq: Seq, author: &PeerId, prev: &[u8; 32], payload: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(ENTRY_HASH_DOMAIN);
    h.update(&seq.to_le_bytes());
    h.update(&author.0);
    h.update(prev);
    h.update(&(payload.len() as u64).to_le_bytes());
    h.update(payload);
    *h.finalize().as_bytes()
}

/// An in-memory single-writer log, bound to one author identity. On-disk
/// storage and peer replication land later.
pub struct MemLog {
    author: Box<dyn Verify>,
    entries: Vec<Entry>,
}

impl MemLog {
    /// Create an empty log owned by `author` (the writer's public identity).
    pub fn new(author: impl Verify + 'static) -> Self {
        Self {
            author: Box::new(author),
            entries: Vec::new(),
        }
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
        // Single-writer invariant: only the bound author may append.
        let author = by.peer_id();
        if author != self.author.peer_id() {
            return Err(Error::Capability(
                "append by an identity other than the log's author".into(),
            ));
        }
        let seq = self.entries.len() as Seq;
        let prev_hash = self.entries.last().map(|e| e.hash).unwrap_or([0u8; 32]);
        let hash = entry_hash(seq, &author, &prev_hash, payload);
        let sig = by.sign(&hash); // author signs the commitment
        self.entries.push(Entry {
            seq,
            author,
            payload: payload.to_vec(),
            prev_hash,
            hash,
            sig,
        });
        Ok(seq)
    }

    fn verify(&self) -> Result<()> {
        let author_id = self.author.peer_id();
        let mut prev = [0u8; 32];
        for (i, e) in self.entries.iter().enumerate() {
            if e.seq != i as Seq {
                return Err(Error::Verify(format!("sequence gap at index {i}")));
            }
            if e.author != author_id {
                return Err(Error::Verify(format!("foreign author at seq {}", e.seq)));
            }
            if e.prev_hash != prev {
                return Err(Error::Verify(format!("broken chain link at seq {}", e.seq)));
            }
            if e.hash != entry_hash(e.seq, &e.author, &e.prev_hash, &e.payload) {
                return Err(Error::Verify(format!("hash mismatch at seq {}", e.seq)));
            }
            if !self.author.verify(&e.hash, &e.sig) {
                return Err(Error::Verify(format!("bad signature at seq {}", e.seq)));
            }
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
    use lattice_core::Signature;

    /// A trivial signer (empty signatures) — pairs with [`AcceptingVerifier`].
    struct MockId(PeerId);
    impl Identity for MockId {
        fn peer_id(&self) -> PeerId {
            self.0.clone()
        }
        fn sign(&self, _msg: &[u8]) -> Signature {
            Signature(vec![])
        }
    }

    /// A verifier that accepts any signature for a fixed peer id. Lets us test
    /// the log's chain/flow logic without pulling in real crypto.
    struct AcceptingVerifier(PeerId);
    impl Verify for AcceptingVerifier {
        fn peer_id(&self) -> PeerId {
            self.0.clone()
        }
        fn verify(&self, _msg: &[u8], _sig: &Signature) -> bool {
            true
        }
    }

    /// A verifier that rejects every signature — proves `verify()` actually
    /// consults the author rather than trusting stored entries.
    struct RejectingVerifier(PeerId);
    impl Verify for RejectingVerifier {
        fn peer_id(&self) -> PeerId {
            self.0.clone()
        }
        fn verify(&self, _msg: &[u8], _sig: &Signature) -> bool {
            false
        }
    }

    fn pid() -> PeerId {
        PeerId([7u8; 32])
    }

    #[test]
    fn append_then_verify_ok() {
        let mut log = MemLog::new(AcceptingVerifier(pid()));
        let id = MockId(pid());
        assert!(log.is_empty());
        log.append(b"hello", &id).unwrap();
        log.append(b"world", &id).unwrap();
        assert_eq!(log.head(), 2);
        log.verify().expect("a clean chain must verify");
    }

    #[test]
    fn tamper_breaks_verify() {
        let mut log = MemLog::new(AcceptingVerifier(pid()));
        let id = MockId(pid());
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
    fn bad_signature_fails_verify() {
        // Chain is structurally valid, but the author rejects the signatures.
        let mut log = MemLog::new(RejectingVerifier(pid()));
        let id = MockId(pid());
        log.append(b"hello", &id).unwrap();
        assert!(
            log.verify().is_err(),
            "verify() must consult the author's signature check"
        );
    }

    #[test]
    fn foreign_author_cannot_append() {
        let mut log = MemLog::new(AcceptingVerifier(pid()));
        let stranger = MockId(PeerId([9u8; 32]));
        assert!(
            log.append(b"intrusion", &stranger).is_err(),
            "only the bound author may append"
        );
    }

    #[test]
    fn get_returns_entries_and_none_past_head() {
        let mut log = MemLog::new(AcceptingVerifier(pid()));
        let id = MockId(pid());
        log.append(b"only", &id).unwrap();
        assert!(log.get(0).unwrap().is_some());
        assert!(log.get(1).unwrap().is_none());
    }
}
