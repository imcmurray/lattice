//! `lattice-session` — authenticated secure channels with a **Double Ratchet**
//! over a hybrid-KEM handshake (DESIGN.md §5.1).
//!
//! Establishing a session combines two independent key exchanges into a root key:
//!
//! ```text
//! ss_x25519  = X25519(ephemeral_initiator, static_responder)   (classical)
//! ss_mlkem   = ML-KEM-768 encapsulate -> responder             (post-quantum)
//! root_key   = HKDF( ikm = ss_x25519 ‖ ss_mlkem, salt = transcript )
//! ```
//!
//! secure if **either** exchange holds (harvest-now-decrypt-later defense). The
//! root key then seeds a Double Ratchet:
//!
//! - **Symmetric ratchet** — each message derives a fresh key from a one-way
//!   KDF chain, erasing its predecessor → *forward secrecy*.
//! - **DH ratchet** — each time the direction flips, the sender mixes a fresh
//!   X25519 ratchet key into the root via `KDF_RK`, so a state compromise heals
//!   after one round trip → *post-compromise security*. Message headers carry
//!   the sender's current ratchet public key.
//!
//! Honest boundary: delivery is **in-order** (no skipped-message-key storage),
//! so out-of-order or dropped messages are rejected rather than buffered — the
//! documented follow-on. ML-KEM ops live in `lattice-identity`; this crate owns
//! X25519, the ratchet, and the AEAD.

use lattice_core::{Connection, Error, Identity, PeerId, Result, Session, Verify};
use lattice_identity::{Keypair, PublicIdentity};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};
use zeroize::{Zeroize, Zeroizing};

const HS_DOMAIN: &[u8] = b"lattice-session-hs-v1";
const HEADER_LEN: usize = 32 + 8 + 8; // ratchet pubkey ‖ prev-chain-len ‖ msg-index

/// The initiator's one-pass handshake message, sent to the responder.
#[derive(Clone, Debug)]
pub struct Handshake {
    /// Ephemeral X25519 public key (KEM handshake).
    pub eph_x25519: [u8; 32],
    /// ML-KEM ciphertext (empty when the `pq` feature is off).
    pub mlkem_ct: Vec<u8>,
}

/// An established secure channel running a Double Ratchet.
pub struct SecureSession {
    rk: Zeroizing<[u8; 32]>,            // root key
    dhs: XStaticSecret,                 // our current ratchet secret
    dhs_pub: [u8; 32],                  // our current ratchet public
    dhr: Option<[u8; 32]>,              // their current ratchet public
    cks: Option<Zeroizing<[u8; 32]>>,   // sending chain key
    ckr: Option<Zeroizing<[u8; 32]>>,   // receiving chain key
    ns: u64,                            // messages sent in current chain
    nr: u64,                            // messages received in current chain
    pn: u64,                            // messages in previous sending chain
}

/// Output of the initiator's hybrid-KEM handshake.
struct KemInit {
    eph_pub: [u8; 32],
    mlkem_ct: Vec<u8>,
    root: Zeroizing<[u8; 32]>,
}

impl SecureSession {
    /// Initiator side: produce a [`Handshake`] and the local session.
    pub fn initiate(me: &Keypair, peer: &PublicIdentity) -> Result<(Handshake, Self)> {
        let KemInit { eph_pub, mlkem_ct, root: sk } = kem_initiate(me, peer)?;

        // Double Ratchet init (Alice): fresh ratchet key, peer's static as DHr.
        let (dhs, dhs_pub) = gen_ratchet_key()?;
        let dhr = peer.x25519_bytes();
        let (rk, cks) = kdf_rk(&sk, &dh(&dhs, &dhr));

        let session = Self {
            rk,
            dhs,
            dhs_pub,
            dhr: Some(dhr),
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
        };
        Ok((Handshake { eph_x25519: eph_pub, mlkem_ct }, session))
    }

    /// Responder side: consume the [`Handshake`] and derive the session. The
    /// responder has no sending chain until it receives the first message.
    pub fn accept(me: &Keypair, peer: &PublicIdentity, hs: &Handshake) -> Result<Self> {
        let sk = kem_accept(me, peer, hs)?;
        Ok(Self {
            rk: sk,
            dhs: me.x25519_secret(),            // initial ratchet key = identity X25519
            dhs_pub: me.public().x25519_bytes(),
            dhr: None,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
        })
    }

    /// Encrypt the next outbound message. Output is `header ‖ ciphertext`, with
    /// the header (ratchet pubkey, counters) authenticated as AAD.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let ck = self
            .cks
            .clone()
            .ok_or_else(|| Error::Crypto("no sending chain yet (receive a message first)".into()))?;
        let (mk, next) = chain_step(&ck);

        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(&self.dhs_pub);
        header.extend_from_slice(&self.pn.to_le_bytes());
        header.extend_from_slice(&self.ns.to_le_bytes());

        let ct = aead_seal(&mk, &header, plaintext)?;
        self.cks = Some(next);
        self.ns += 1;

        let mut out = header;
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypt the next inbound message. In-order only: rejects gaps, reorders,
    /// and tampering, and never advances state on failure.
    pub fn open(&mut self, framed: &[u8]) -> Result<Vec<u8>> {
        if framed.len() < HEADER_LEN {
            return Err(Error::Verify("truncated frame".into()));
        }
        let header = &framed[..HEADER_LEN];
        let ct = &framed[HEADER_LEN..];
        let mut their_pub = [0u8; 32];
        their_pub.copy_from_slice(&framed[..32]);
        let their_ns = u64::from_le_bytes(framed[40..48].try_into().expect("8 bytes"));

        if self.dhr.as_ref() == Some(&their_pub) {
            // Same DH chain: pure symmetric ratchet step (no desync on failure).
            if their_ns != self.nr {
                return Err(Error::Verify("out-of-order or replayed message".into()));
            }
            let ck = self
                .ckr
                .clone()
                .ok_or_else(|| Error::Verify("no receiving chain".into()))?;
            let (mk, next) = chain_step(&ck);
            let pt = aead_open(&mk, header, ct)?;
            self.ckr = Some(next);
            self.nr += 1;
            Ok(pt)
        } else {
            // New DH chain: ratchet step. In-order => must be its first message.
            if their_ns != 0 {
                return Err(Error::Verify(
                    "skipped messages across a ratchet step are not supported".into(),
                ));
            }
            // Compute the receiving side tentatively; commit only if AEAD passes.
            let (rk1, ckr_new) = kdf_rk(&self.rk, &dh(&self.dhs, &their_pub));
            let (mk, next_ckr) = chain_step(&ckr_new);
            let pt = aead_open(&mk, header, ct)?;

            // Commit receiving side.
            self.pn = self.ns;
            self.ns = 0;
            self.nr = 1;
            self.dhr = Some(their_pub);
            self.rk = rk1;
            self.ckr = Some(next_ckr);

            // Advance the sending side: fresh ratchet key mixed into the root.
            let (new_dhs, new_pub) = gen_ratchet_key()?;
            let (rk2, cks_new) = kdf_rk(&self.rk, &dh(&new_dhs, &their_pub));
            self.rk = rk2;
            self.cks = Some(cks_new);
            self.dhs = new_dhs;
            self.dhs_pub = new_pub;

            Ok(pt)
        }
    }
}

// --- handshake (hybrid KEM) ------------------------------------------------

fn kem_initiate(me: &Keypair, peer: &PublicIdentity) -> Result<KemInit> {
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
    let root = root_key(&build_ikm(&ss_x, ss_pq.as_ref()), &transcript);
    Ok(KemInit { eph_pub, mlkem_ct, root })
}

fn kem_accept(me: &Keypair, peer: &PublicIdentity, hs: &Handshake) -> Result<Zeroizing<[u8; 32]>> {
    let ss_x = me.x25519_dh(&hs.eph_x25519);

    #[cfg(feature = "pq")]
    let ss_pq = Some(me.pq_decapsulate(&hs.mlkem_ct)?);
    #[cfg(not(feature = "pq"))]
    let ss_pq: Option<Zeroizing<[u8; 32]>> = None;

    let transcript = transcript(&peer.peer_id(), &me.peer_id(), &hs.eph_x25519, &hs.mlkem_ct);
    Ok(root_key(&build_ikm(&ss_x, ss_pq.as_ref()), &transcript))
}

// --- key schedule primitives ----------------------------------------------

/// Root KDF: mix a DH output into the root key, yielding `(root', chain)`.
fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let hk = Hkdf::<Sha256>::new(Some(rk), dh_out);
    let mut okm = [0u8; 64];
    hk.expand(b"lattice/dr/root", &mut okm).expect("hkdf len");
    let mut root = [0u8; 32];
    let mut chain = [0u8; 32];
    root.copy_from_slice(&okm[..32]);
    chain.copy_from_slice(&okm[32..]);
    okm.zeroize();
    (Zeroizing::new(root), Zeroizing::new(chain))
}

/// Symmetric chain step: `(message_key, next_chain_key)` from a chain key.
fn chain_step(ck: &[u8; 32]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let hk = Hkdf::<Sha256>::new(None, ck);
    let mut mk = [0u8; 32];
    let mut next = [0u8; 32];
    hk.expand(b"lattice/ratchet/mk", &mut mk).expect("hkdf len");
    hk.expand(b"lattice/ratchet/ck", &mut next).expect("hkdf len");
    (Zeroizing::new(mk), Zeroizing::new(next))
}

fn dh(secret: &XStaticSecret, their_public: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(
        secret
            .diffie_hellman(&XPublicKey::from(*their_public))
            .to_bytes(),
    )
}

fn gen_ratchet_key() -> Result<(XStaticSecret, [u8; 32])> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).map_err(|e| Error::Crypto(format!("rng: {e}")))?;
    let s = XStaticSecret::from(b);
    b.zeroize();
    let p = XPublicKey::from(&s).to_bytes();
    Ok((s, p))
}

fn root_key(ikm: &[u8], transcript: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(transcript), ikm);
    let mut sk = [0u8; 32];
    hk.expand(b"lattice/session/root", &mut sk).expect("hkdf len");
    Zeroizing::new(sk)
}

// --- AEAD record layer (fresh single-use key per message => constant nonce) -

fn aead_seal(mk: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    ChaCha20Poly1305::new_from_slice(mk)
        .expect("32-byte key")
        .encrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg: plaintext, aad })
        .map_err(|_| Error::Crypto("AEAD seal failed".into()))
}

fn aead_open(mk: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    ChaCha20Poly1305::new_from_slice(mk)
        .expect("32-byte key")
        .decrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg: ciphertext, aad })
        .map_err(|_| Error::Verify("AEAD open failed (tampered or wrong key)".into()))
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

// --- session bound to a transport Connection ------------------------------

fn encode_handshake(hs: &Handshake) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 + hs.mlkem_ct.len());
    v.extend_from_slice(&hs.eph_x25519);
    v.extend_from_slice(&hs.mlkem_ct);
    v
}

fn decode_handshake(b: &[u8]) -> Result<Handshake> {
    if b.len() < 32 {
        return Err(Error::Verify("short handshake".into()));
    }
    let mut eph = [0u8; 32];
    eph.copy_from_slice(&b[..32]);
    Ok(Handshake {
        eph_x25519: eph,
        mlkem_ct: b[32..].to_vec(),
    })
}

/// A [`SecureSession`] bound to a transport [`Connection`]: it performs the
/// handshake over the wire and then implements the core async [`Session`]
/// (seal-and-send / receive-and-open). This is the join point between the
/// crypto and the transport layers.
pub struct ConnectedSession<C: Connection> {
    conn: C,
    session: SecureSession,
}

impl<C: Connection> ConnectedSession<C> {
    /// Initiator: send the handshake over `conn`, return the live session.
    pub async fn initiate(mut conn: C, me: &Keypair, peer: &PublicIdentity) -> Result<Self> {
        let (hs, session) = SecureSession::initiate(me, peer)?;
        conn.send(&encode_handshake(&hs)).await?;
        Ok(Self { conn, session })
    }

    /// Responder: receive the handshake from `conn`, return the live session.
    pub async fn accept(mut conn: C, me: &Keypair, peer: &PublicIdentity) -> Result<Self> {
        let hs = decode_handshake(&conn.recv().await?)?;
        let session = SecureSession::accept(me, peer, &hs)?;
        Ok(Self { conn, session })
    }
}

impl<C: Connection> Session for ConnectedSession<C> {
    async fn send(&mut self, plaintext: &[u8]) -> Result<()> {
        let frame = self.session.seal(plaintext)?;
        self.conn.send(&frame).await
    }

    async fn recv(&mut self) -> Result<Vec<u8>> {
        let frame = self.conn.recv().await?;
        self.session.open(&frame)
    }
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
    fn many_turns_drive_dh_ratchet() {
        // Each direction flip triggers a DH-ratchet step (post-compromise sec).
        let (mut a, mut b) = pair();
        for turn in 0..4u8 {
            let m = [b'a', turn];
            let ct = a.seal(&m).unwrap();
            assert_eq!(b.open(&ct).unwrap(), m);
            let r = [b'b', turn];
            let ct2 = b.seal(&r).unwrap();
            assert_eq!(a.open(&ct2).unwrap(), r);
        }
    }

    #[test]
    fn multiple_messages_same_chain() {
        let (mut a, mut b) = pair();
        for i in 0..5u8 {
            let m = [b'm', i];
            let ct = a.seal(&m).unwrap();
            assert_eq!(b.open(&ct).unwrap(), m);
        }
        let c1 = a.seal(b"dup").unwrap();
        let c2 = a.seal(b"dup").unwrap();
        assert_ne!(c1, c2, "fresh key per message");
    }

    #[test]
    fn out_of_order_is_rejected() {
        let (mut a, mut b) = pair();
        let _m0 = a.seal(b"first").unwrap();
        let m1 = a.seal(b"second").unwrap();
        assert!(b.open(&m1).is_err(), "skipping m0 must be rejected");
    }

    #[test]
    fn tampered_ciphertext_fails_without_desync() {
        let (mut a, mut b) = pair();
        let m0 = a.seal(b"zero").unwrap();
        let m1 = a.seal(b"one").unwrap();
        assert_eq!(b.open(&m0).unwrap(), b"zero");

        let mut bad = m1.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert!(b.open(&bad).is_err(), "tampered frame must fail");
        assert_eq!(b.open(&m1).unwrap(), b"one", "chain not desynced by failure");
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
