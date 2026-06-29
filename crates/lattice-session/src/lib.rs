//! `lattice-session` — authenticated, forward-looking secure channels built on
//! a **hybrid KEM handshake** (DESIGN.md §5.1).
//!
//! Establishing a session combines two independent key exchanges:
//!
//! ```text
//! ss_x25519  = X25519(ephemeral_initiator, static_responder)   (classical)
//! ss_mlkem   = ML-KEM-768 encapsulate -> responder             (post-quantum)
//! session    = HKDF-SHA256( ikm = ss_x25519 ‖ ss_mlkem,
//!                           salt = transcript )                 (combiner)
//! ```
//!
//! The KDF combiner (never XOR) means the channel is secure if **either** the
//! classical or the post-quantum exchange holds — this is the harvest-now-
//! decrypt-later defense. The `transcript` (domain, both peer ids, ephemeral
//! public key, ciphertext) is the HKDF salt, binding the keys to this exact
//! handshake. Per direction we derive a ChaCha20-Poly1305 key with a counter
//! nonce.
//!
//! Scope: this is the one-pass KEM handshake + AEAD record layer. Per-message
//! ratcheting (full forward secrecy) layers on top later; see DESIGN.md §5.1
//! ("PQ ≠ forward secrecy"). The ML-KEM operations live in `lattice-identity`
//! (which owns the typed keys); this crate orchestrates X25519, the combiner,
//! and the AEAD.

use lattice_core::{Error, Identity, PeerId, Result, Verify};
use lattice_identity::{Keypair, PublicIdentity};

use chacha20poly1305::aead::Aead;
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

/// An established secure channel: directional AEAD keys + counter nonces.
pub struct SecureSession {
    send: ChaCha20Poly1305,
    recv: ChaCha20Poly1305,
    send_ctr: u64,
    recv_ctr: u64,
}

impl SecureSession {
    /// Initiator side: produce a [`Handshake`] for `peer` and the local session.
    pub fn initiate(me: &Keypair, peer: &PublicIdentity) -> Result<(Handshake, Self)> {
        // Classical: ephemeral X25519 DH against the peer's static key.
        let mut eb = [0u8; 32];
        getrandom::getrandom(&mut eb).map_err(|e| Error::Crypto(format!("rng: {e}")))?;
        let eph = XStaticSecret::from(eb);
        eb.zeroize();
        let eph_pub = XPublicKey::from(&eph).to_bytes();
        let ss_x = Zeroizing::new(
            eph.diffie_hellman(&XPublicKey::from(peer.x25519_bytes()))
                .to_bytes(),
        );

        // Post-quantum: encapsulate to the peer's ML-KEM key.
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

        // Same transcript: peer is the initiator, we are the responder.
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

        let (send_ref, recv_ref) = match role {
            Role::Initiator => (&k_i2r, &k_r2i),
            Role::Responder => (&k_r2i, &k_i2r),
        };
        let send = ChaCha20Poly1305::new_from_slice(send_ref).expect("32-byte key");
        let recv = ChaCha20Poly1305::new_from_slice(recv_ref).expect("32-byte key");
        k_i2r.zeroize();
        k_r2i.zeroize();

        Self {
            send,
            recv,
            send_ctr: 0,
            recv_ctr: 0,
        }
    }

    /// Encrypt-and-authenticate the next outbound message.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = nonce_for(self.send_ctr);
        self.send_ctr += 1;
        self.send
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| Error::Crypto("AEAD seal failed".into()))
    }

    /// Decrypt-and-verify the next inbound message. Fails closed on tamper or
    /// out-of-order delivery.
    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = nonce_for(self.recv_ctr);
        self.recv_ctr += 1;
        self.recv
            .decrypt(Nonce::from_slice(&nonce), ciphertext)
            .map_err(|_| Error::Verify("AEAD open failed (tampered or out-of-order)".into()))
    }
}

fn nonce_for(ctr: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&ctr.to_le_bytes());
    n
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

    #[test]
    fn handshake_then_bidirectional_messaging() {
        let (alice, bob) = (id(), id());
        let (hs, mut a) = SecureSession::initiate(&alice, bob.public()).unwrap();
        let mut b = SecureSession::accept(&bob, alice.public(), &hs).unwrap();

        let ct = a.seal(b"hello bob").unwrap();
        assert_eq!(b.open(&ct).unwrap(), b"hello bob");

        let ct2 = b.seal(b"hi alice").unwrap();
        assert_eq!(a.open(&ct2).unwrap(), b"hi alice");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (alice, bob) = (id(), id());
        let (hs, mut a) = SecureSession::initiate(&alice, bob.public()).unwrap();
        let mut b = SecureSession::accept(&bob, alice.public(), &hs).unwrap();

        let mut ct = a.seal(b"secret").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(b.open(&ct).is_err(), "tampered ciphertext must fail");
    }

    #[test]
    fn wrong_responder_cannot_read() {
        let (alice, bob, eve) = (id(), id(), id());
        let (hs, mut a) = SecureSession::initiate(&alice, bob.public()).unwrap();
        // Eve accepts a handshake meant for Bob: her keys yield a different
        // shared secret, so she cannot open Alice's messages.
        let mut e = SecureSession::accept(&eve, alice.public(), &hs).unwrap();
        let ct = a.seal(b"for bob only").unwrap();
        assert!(e.open(&ct).is_err(), "non-intended responder must not decrypt");
    }
}
