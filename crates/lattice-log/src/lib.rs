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

    // ---- real signatures (lattice-identity, dev-dependency only) ----

    use lattice_core::CryptoSuite;
    use lattice_identity::Keypair;

    fn keypair(suite: CryptoSuite) -> Keypair {
        Keypair::generate(suite).unwrap()
    }

    /// A 3-entry log appended by `kp`, bound to `kp`'s public identity.
    fn real_log(kp: &Keypair) -> MemLog {
        let mut log = MemLog::new(kp.public().clone());
        for p in [&b"one"[..], b"two", b"three"] {
            log.append(p, kp).unwrap();
        }
        log
    }

    #[test]
    fn real_hybrid_chain_verifies() {
        let kp = keypair(CryptoSuite::Hybrid);
        let log = real_log(&kp);
        assert_eq!(log.len(), 3);
        log.verify().expect("a genuine hybrid chain must verify");
    }

    #[test]
    fn zeroed_or_empty_signature_fails_at_every_index() {
        let kp = keypair(CryptoSuite::Hybrid);
        for i in 0..3 {
            let mut log = real_log(&kp);
            let len = log.entries[i].sig.0.len();
            log.entries[i].sig = Signature(vec![0u8; len]);
            assert!(log.verify().is_err(), "zero sig at {i}");

            let mut log = real_log(&kp);
            log.entries[i].sig = Signature(vec![]);
            assert!(log.verify().is_err(), "empty sig at {i}");
        }
    }

    #[test]
    fn signature_from_another_key_fails() {
        let (kp, other) = (keypair(CryptoSuite::Hybrid), keypair(CryptoSuite::Hybrid));
        for i in 0..3 {
            let mut log = real_log(&kp);
            let hash = log.entries[i].hash;
            log.entries[i].sig = other.sign(&hash);
            assert!(log.verify().is_err(), "foreign sig at {i}");
        }
    }

    #[test]
    fn changed_payload_or_hash_fails() {
        let kp = keypair(CryptoSuite::Hybrid);
        for i in 0..3 {
            let mut log = real_log(&kp);
            log.entries[i].payload = b"forged".to_vec();
            assert!(log.verify().is_err(), "payload at {i}");

            let mut log = real_log(&kp);
            log.entries[i].hash[0] ^= 1;
            assert!(log.verify().is_err(), "hash at {i}");

            // A forged hash re-signed by the real author still fails.
            let mut log = real_log(&kp);
            log.entries[i].hash = [0xAA; 32];
            let h = log.entries[i].hash;
            log.entries[i].sig = kp.sign(&h);
            assert!(log.verify().is_err(), "re-signed hash at {i}");
        }
    }

    #[test]
    fn chain_by_one_identity_fails_under_another() {
        let (a, b) = (keypair(CryptoSuite::Hybrid), keypair(CryptoSuite::Hybrid));
        let log = real_log(&a);
        let wrong = MemLog {
            author: Box::new(b.public().clone()),
            entries: log.entries.clone(),
        };
        assert!(wrong.verify().is_err());

        let mut a_log = MemLog::new(a.public().clone());
        assert!(a_log.append(b"x", &b).is_err());
    }

    #[test]
    fn classical_chain_does_not_verify_under_hybrid_twin() {
        let c = keypair(CryptoSuite::Classical);
        let h = Keypair::from_mnemonic(CryptoSuite::Hybrid, c.mnemonic()).unwrap();
        assert_ne!(c.peer_id(), h.peer_id());
        let log = real_log(&c);
        log.verify().expect("classical chain under classical key");

        // As-is: the author check fails.
        let twin = MemLog {
            author: Box::new(h.public().clone()),
            entries: log.entries.clone(),
        };
        assert!(twin.verify().is_err());

        // Re-chained onto the hybrid PeerId, keeping the classical signatures:
        // only the signature check can reject it.
        let mut entries = log.entries.clone();
        let mut prev = [0u8; 32];
        for e in entries.iter_mut() {
            e.author = h.peer_id();
            e.prev_hash = prev;
            e.hash = entry_hash(e.seq, &e.author, &e.prev_hash, &e.payload);
            prev = e.hash;
        }
        let rechained = MemLog {
            author: Box::new(h.public().clone()),
            entries,
        };
        match rechained.verify() {
            Err(Error::Verify(m)) => assert!(m.contains("bad signature"), "{m}"),
            other => panic!("expected a signature failure, got {other:?}"),
        }
    }
}
