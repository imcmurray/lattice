//! `lattice-session` — authenticated secure channels built on a **hybrid KEM
//! handshake** plus a **symmetric ratchet** for forward secrecy (DESIGN.md §5.1).
//!
//! Establishing a session combines two independent key exchanges:
//!
//! ```text
//! ss_x25519  = X25519(ephemeral_initiator, static_responder)   (classical)
//! ss_mlkem   = ML-KEM-768 encapsulate -> responder             (post-quantum)
//! root keys  = HKDF-SHA256( ikm = ss_x25519 ‖ ss_mlkem,
//!                           salt = transcript )                 (combiner, not XOR)
//! ```
//!
//! secure if **either** exchange holds (harvest-now-decrypt-later defense). The
//! two root keys seed a per-direction **KDF chain**. Each message derives a
//! fresh message key and advances the chain, overwriting its predecessor:
//!
//! ```text
//! message_key_n = HKDF(chain_key_n)["mk"]
//! chain_key_n+1 = HKDF(chain_key_n)["ck"]   (chain_key_n is then erased)
//! ```
//!
//! Because the KDF is one-way and old chain keys are deleted, compromising the
//! current state cannot recover *past* message keys — that's forward secrecy.
//!
//! Scope / honest boundary: this is the **symmetric** ratchet (forward secrecy)
//! over a one-pass hybrid-KEM handshake. The **DH ratchet** (post-compromise
//! security / healing) and skipped/out-of-order message-key storage are the
//! documented next step — v1 is strictly in-order. ML-KEM operations live in
//! `lattice-identity`; this crate owns X25519, the combiner, the ratchet, and
//! the AEAD.

use lattice_core::{Error, Identity, PeerId, Result, Verify};
use lattice_identity::{Keypair, PublicIdentity};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};
use zeroize::{Zeroize, Zeroizing};

const HS_DOMAIN: &[u8] = b"lattice-session-hs-v1";

/// The initiator's one-pass handshake message, sent to the responder.
#[derive(Clone, Debug)]
pub struct Handshake {
    /// Ephemeral X25519 public key.
    pub eph_x25519: [u8; 32],
    /// ML-KEM ciphertext (empty when the `pq` feature is off).
    pub mlkem_ct: Vec<u8>,
}

#[derive(Clone, Copy)]
enum Role {
    Initiator,
    Responder,
}

/// A one-directional KDF chain providing forward secrecy.
struct Chain {
    key: Zeroizing<[u8; 32]>,
    n: u64,
}

impl Chain {
    fn new(root: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(root),
            n: 0,
        }
    }

    /// Derive `(message_key, next_chain_key)` from the current chain key
    /// *without* mutating — the caller commits only after AEAD succeeds, so a
    /// bad/forged message can't desync the chain.
    fn derive(&self) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
        let hk = Hkdf::<Sha256>::new(None, &self.key[..]);
        let mut mk = [0u8; 32];
        let mut ck = [0u8; 32];
        hk.expand(b"lattice/ratchet/mk", &mut mk).expect("hkdf len");
        hk.expand(b"lattice/ratchet/ck", &mut ck).expect("hkdf len");
        (Zeroizing::new(mk), Zeroizing::new(ck))
    }

    /// Advance the chain: erase the old key, install the next, bump the index.
    fn commit(&mut self, next: &[u8; 32]) {
        self.key.copy_from_slice(next);
        self.n += 1;
    }
}

/// An established secure channel: a forward-secret KDF chain per direction.
pub struct SecureSession {
    send: Chain,
    recv: Chain,
}

impl SecureSession {
    /// Initiator side: produce a [`Handshake`] for `peer` and the local session.
    pub fn initiate(me: &Keypair, peer: &PublicIdentity) -> Result<(Handshake, Self)> {
        let mut eb = [0u8; 32];
        getrandom::getrandom(&mut eb).map_err(|e| Error::Crypto(format!("rng: {e}")))?;
        let eph = XStaticSecret::from(eb);
        eb.zeroize();
        let eph_pub = XPublicKey::from(&eph).to_bytes();
        let ss_x = Zeroizing::new(
            eph.diffie_hellman(&XPublicKey::from(peer.x25519_bytes()))
                .to_bytes(),
        );

        #[cfg(feature = "pq")]
        let (mlkem_ct, ss_pq) = {
            let (ct, ss) = peer.pq_encapsulate()?;
            (ct, Some(ss))
        };
        #[cfg(not(feature = "pq"))]
        let (mlkem_ct, ss_pq): (Vec<u8>, Option<Zeroizing<[u8; 32]>>) = (Vec::new(), None);

        let transcript = transcript(&me.peer_id(), &peer.peer_id(), &eph_pub, &mlkem_ct);
        let ikm = build_ikm(&ss_x, ss_pq.as_ref());
        let session = Self::derive(&ikm, &transcript, Role::Initiator);
        Ok((
            Handshake {
                eph_x25519: eph_pub,
                mlkem_ct,
            },
            session,
        ))
    }

    /// Responder side: consume the initiator's [`Handshake`] and derive the session.
    pub fn accept(me: &Keypair, peer: &PublicIdentity, hs: &Handshake) -> Result<Self> {
        let ss_x = me.x25519_dh(&hs.eph_x25519);

        #[cfg(feature = "pq")]
        let ss_pq = Some(me.pq_decapsulate(&hs.mlkem_ct)?);
        #[cfg(not(feature = "pq"))]
        let ss_pq: Option<Zeroizing<[u8; 32]>> = None;

        let transcript = transcript(&peer.peer_id(), &me.peer_id(), &hs.eph_x25519, &hs.mlkem_ct);
        let ikm = build_ikm(&ss_x, ss_pq.as_ref());
        Ok(Self::derive(&ikm, &transcript, Role::Responder))
    }

    fn derive(ikm: &[u8], transcript: &[u8], role: Role) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(transcript), ikm);
        let mut k_i2r = [0u8; 32];
        let mut k_r2i = [0u8; 32];
        hk.expand(b"lattice/session/i2r", &mut k_i2r).expect("hkdf len");
        hk.expand(b"lattice/session/r2i", &mut k_r2i).expect("hkdf len");

        let session = match role {
            Role::Initiator => Self {
                send: Chain::new(k_i2r),
                recv: Chain::new(k_r2i),
            },
            Role::Responder => Self {
                send: Chain::new(k_r2i),
                recv: Chain::new(k_i2r),
            },
        };
        k_i2r.zeroize();
        k_r2i.zeroize();
        session
    }

    /// Encrypt the next outbound message. Output is `index_le(8) ‖ ciphertext`;
    /// the index is authenticated as associated data.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let (mk, next) = self.send.derive();
        let n = self.send.n;
        let aad = n.to_le_bytes();
        let cipher = ChaCha20Poly1305::new_from_slice(&mk[..]).expect("32-byte key");
        // Fresh single-use key per message => a constant nonce is safe.
        let ct = cipher
            .encrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg: plaintext, aad: &aad })
            .map_err(|_| Error::Crypto("AEAD seal failed".into()))?;
        self.send.commit(&next);

        let mut out = Vec::with_capacity(8 + ct.len());
        out.extend_from_slice(&aad);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypt the next inbound message. In-order only: rejects gaps, reorders,
    /// and tampering, and does not advance the chain on failure.
    pub fn open(&mut self, framed: &[u8]) -> Result<Vec<u8>> {
        if framed.len() < 8 {
            return Err(Error::Verify("truncated frame".into()));
        }
        let n = u64::from_le_bytes(framed[..8].try_into().expect("8 bytes"));
        if n != self.recv.n {
            return Err(Error::Verify("out-of-order or replayed message".into()));
        }
        let (mk, next) = self.recv.derive();
        let aad = n.to_le_bytes();
        let cipher = ChaCha20Poly1305::new_from_slice(&mk[..]).expect("32-byte key");
        let pt = cipher
            .decrypt(
                Nonce::from_slice(&[0u8; 12]),
                Payload { msg: &framed[8..], aad: &aad },
            )
            .map_err(|_| Error::Verify("AEAD open failed (tampered or wrong key)".into()))?;
        self.recv.commit(&next); // advance only after success
        Ok(pt)
    }
}

fn transcript(initiator: &PeerId, responder: &PeerId, eph: &[u8; 32], ct: &[u8]) -> Vec<u8> {
    let mut t = Vec::with_capacity(HS_DOMAIN.len() + 32 * 3 + 4 + ct.len());
    t.extend_from_slice(HS_DOMAIN);
    t.extend_from_slice(&initiator.0);
    t.extend_from_slice(&responder.0);
    t.extend_from_slice(eph);
    t.extend_from_slice(&(ct.len() as u32).to_le_bytes());
    t.extend_from_slice(ct);
    t
}

fn build_ikm(ss_x: &[u8; 32], ss_pq: Option<&Zeroizing<[u8; 32]>>) -> Zeroizing<Vec<u8>> {
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(ss_x);
    if let Some(pq) = ss_pq {
        ikm.extend_from_slice(&pq[..]);
    }
    Zeroizing::new(ikm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_core::CryptoSuite;

    fn id() -> Keypair {
        Keypair::generate(CryptoSuite::Hybrid).unwrap()
    }

    fn pair() -> (SecureSession, SecureSession) {
        let (alice, bob) = (id(), id());
        let (hs, a) = SecureSession::initiate(&alice, bob.public()).unwrap();
        let b = SecureSession::accept(&bob, alice.public(), &hs).unwrap();
        (a, b)
    }

    #[test]
    fn bidirectional_messaging() {
        let (mut a, mut b) = pair();
        let ct = a.seal(b"hello bob").unwrap();
        assert_eq!(b.open(&ct).unwrap(), b"hello bob");
        let ct2 = b.seal(b"hi alice").unwrap();
        assert_eq!(a.open(&ct2).unwrap(), b"hi alice");
    }

    #[test]
    fn ratchet_advances_over_many_messages() {
        let (mut a, mut b) = pair();
        for i in 0..5u8 {
            let msg = [b'm', i];
            let ct = a.seal(&msg).unwrap();
            assert_eq!(b.open(&ct).unwrap(), msg);
        }
        // Each message used a distinct key: identical plaintext -> different ct.
        let c1 = a.seal(b"dup").unwrap();
        let c2 = a.seal(b"dup").unwrap();
        assert_ne!(c1, c2, "ratchet must use a fresh key per message");
    }

    #[test]
    fn out_of_order_is_rejected() {
        let (mut a, mut b) = pair();
        let _m0 = a.seal(b"first").unwrap();
        let m1 = a.seal(b"second").unwrap();
        assert!(b.open(&m1).is_err(), "skipping m0 must be rejected");
    }

    #[test]
    fn tampered_ciphertext_fails_and_does_not_desync() {
        let (mut a, mut b) = pair();
        let m0 = a.seal(b"zero").unwrap();
        let m1 = a.seal(b"one").unwrap();
        assert_eq!(b.open(&m0).unwrap(), b"zero");

        let mut bad = m1.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert!(b.open(&bad).is_err(), "tampered frame must fail");

        // The failed open did not advance the chain: the genuine #1 still opens.
        assert_eq!(b.open(&m1).unwrap(), b"one");
    }

    #[test]
    fn wrong_responder_cannot_read() {
        let (alice, bob, eve) = (id(), id(), id());
        let (hs, mut a) = SecureSession::initiate(&alice, bob.public()).unwrap();
        let mut e = SecureSession::accept(&eve, alice.public(), &hs).unwrap();
        let ct = a.seal(b"for bob only").unwrap();
        assert!(e.open(&ct).is_err(), "non-intended responder must not decrypt");
    }
}
