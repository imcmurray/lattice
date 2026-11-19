//! `lattice-session` — authenticated secure channels with a **Double Ratchet**
//! over a hybrid-KEM handshake (DESIGN.md §5.1).
//!
//! Establishing a session combines two independent key exchanges into a root key:
//!
//! ```text
//! ss_x25519  = X25519(ephemeral_initiator, static_responder)   (classical)
//! ss_mlkem   = ML-KEM-768 encapsulate -> responder             (post-quantum)
//! transcript = "lattice-session-hs-v2" ‖ initiator ‖ responder ‖ eph ‖ ratchet_pub ‖ ct
//! root_key   = HKDF( ikm = ss_x25519 ‖ ss_mlkem, salt = transcript )
//! sig        = initiator.sign(transcript)        (hybrid: Ed25519 + ML-DSA)
//! ```
//!
//! secure if **either** exchange holds (harvest-now-decrypt-later defense).
//! [`SecureSession::accept`] rejects a handshake whose hybrid signature does not
//! verify under the claimed initiator, so a third party cannot impersonate the
//! initiator. Compromise of a long-term identity key still decrypts recorded
//! sessions. The root key then seeds a Double Ratchet:
//!
//! - **Symmetric ratchet** — each message derives a fresh key from a one-way
//!   KDF chain, erasing its predecessor → *forward secrecy*.
//! - **DH ratchet** — each time the direction flips, the sender mixes a fresh
//!   X25519 ratchet key into the root via `KDF_RK`, so a state compromise heals
//!   after one round trip → *post-compromise security*. Message headers carry
//!   the sender's current ratchet public key.
//!
//! Out-of-order and dropped messages are handled by a **bounded skipped-key
//! cache**: when a message arrives ahead of the expected index, the intervening
//! message keys are derived and stashed (capped at `MAX_SKIP` per step and
//! `MAX_SKIPPED_KEYS` total, FIFO-evicted, so a forged header can't force
//! unbounded work). [`SecureSession::open`] performs the skip + ratchet on a
//! *scratch copy* of the state and commits only after the AEAD verifies, so a
//! forged or tampered frame can never advance or desync the ratchet.
//!
//! ML-KEM ops live in `lattice-identity`; this crate owns X25519, the ratchet,
//! and the AEAD.

use std::collections::{HashMap, VecDeque};

use lattice_core::{Connection, Error, Identity, Result, Session, Signature, Verify};
use lattice_identity::{Keypair, PublicIdentity};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};
use zeroize::{Zeroize, Zeroizing};

const HS_DOMAIN: &[u8] = b"lattice-session-hs-v2";
/// Max encoded handshake size (bytes), also the per-field cap.
const MAX_HANDSHAKE_LEN: usize = 65_536;
const HEADER_LEN: usize = 32 + 8 + 8; // ratchet pubkey ‖ prev-chain-len ‖ msg-index

/// Max messages skipped (keys derived) in a single ratchet step — DoS guard.
const MAX_SKIP: u64 = 1000;
/// Max skipped message keys retained across the session — FIFO-evicted.
const MAX_SKIPPED_KEYS: usize = 2048;

/// A symmetric message key.
type MessageKey = Zeroizing<[u8; 32]>;
/// Identifies a skipped message: `(sender ratchet pubkey, message index)`.
type SkippedId = ([u8; 32], u64);

/// The initiator's one-pass handshake message, sent to the responder.
#[derive(Clone, Debug)]
pub struct Handshake {
    /// Ephemeral X25519 public key (KEM handshake).
    pub eph_x25519: [u8; 32],
    /// Initiator's initial DH-ratchet public key — lets the responder ratchet
    /// immediately at accept, so either side may send first.
    pub ratchet_pub: [u8; 32],
    /// ML-KEM ciphertext (empty when the `pq` feature is off).
    pub mlkem_ct: Vec<u8>,
    /// Initiator's hybrid signature over the v2 transcript.
    pub sig: Signature,
}

/// The mutable Double-Ratchet state. Cloned into a scratch copy on `open` so
/// changes can be discarded if the message fails to authenticate.
#[derive(Clone)]
struct RatchetCore {
    rk: Zeroizing<[u8; 32]>,          // root key
    dhs: XStaticSecret,               // our current ratchet secret
    dhs_pub: [u8; 32],                // our current ratchet public
    dhr: Option<[u8; 32]>,            // their current ratchet public
    cks: Option<Zeroizing<[u8; 32]>>, // sending chain key
    ckr: Option<Zeroizing<[u8; 32]>>, // receiving chain key
    ns: u64,                          // messages sent in current chain
    nr: u64,                          // messages received in current chain
    pn: u64,                          // messages in previous sending chain
}

/// Bounded store of skipped message keys, keyed by `(ratchet pubkey, index)`.
#[derive(Default)]
struct Skipped {
    map: HashMap<SkippedId, MessageKey>,
    order: VecDeque<SkippedId>, // insertion order for FIFO eviction
}

impl Skipped {
    fn insert(&mut self, key: SkippedId, mk: MessageKey) {
        if self.map.contains_key(&key) {
            return;
        }
        while self.map.len() >= MAX_SKIPPED_KEYS {
            match self.order.pop_front() {
                Some(old) => {
                    self.map.remove(&old);
                }
                None => break,
            }
        }
        self.order.push_back(key);
        self.map.insert(key, mk);
    }

    fn get(&self, key: &SkippedId) -> Option<MessageKey> {
        self.map.get(key).cloned()
    }

    fn remove(&mut self, key: &SkippedId) {
        self.map.remove(key); // stale `order` entry is harmless (no-op on evict)
    }
}

/// An established secure channel running a Double Ratchet.
pub struct SecureSession {
    core: RatchetCore,
    skipped: Skipped,
}

/// Output of the initiator's hybrid-KEM handshake.
struct KemInit {
    eph_pub: [u8; 32],
    mlkem_ct: Vec<u8>,
    transcript: Vec<u8>,
    root: Zeroizing<[u8; 32]>,
}

impl SecureSession {
    /// Initiator side: produce a [`Handshake`] and the local session.
    pub fn initiate(me: &Keypair, peer: &PublicIdentity) -> Result<(Handshake, Self)> {
        // Ratchet key first: its public half is bound into the signed transcript.
        let (dhs, dhs_pub) = gen_ratchet_key()?;
        let KemInit {
            eph_pub,
            mlkem_ct,
            transcript,
            root: sk,
        } = kem_initiate(me, peer, &dhs_pub)?;
        let sig = me.sign(&transcript);

        // Double Ratchet init (Alice): peer's static as DHr.
        let dhr = peer.x25519_bytes();
        let (rk, cks) = kdf_rk(&sk, &dh(&dhs, &dhr));

        let core = RatchetCore {
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
        let session = Self {
            core,
            skipped: Skipped::default(),
        };
        Ok((
            Handshake {
                eph_x25519: eph_pub,
                ratchet_pub: dhs_pub,
                mlkem_ct,
                sig,
            },
            session,
        ))
    }

    /// Responder side: consume the [`Handshake`] and derive the session. The
    /// handshake carries the initiator's initial ratchet key, so the responder
    /// performs its first DH-ratchet step right away — giving it a sending chain
    /// immediately, so either party may send first.
    ///
    /// The initiator's hybrid signature over the v2 transcript is verified under
    /// `peer` **before** any KEM or ratchet work.
    pub fn accept(me: &Keypair, peer: &PublicIdentity, hs: &Handshake) -> Result<Self> {
        if hs.mlkem_ct.len() > MAX_HANDSHAKE_LEN || hs.sig.0.len() > MAX_HANDSHAKE_LEN {
            return Err(Error::Verify("handshake field too large".into()));
        }
        let t = transcript(
            peer,
            me.public(),
            &hs.eph_x25519,
            &hs.ratchet_pub,
            &hs.mlkem_ct,
        );
        if !peer.verify(&t, &hs.sig) {
            return Err(Error::Verify(
                "handshake signature does not verify under claimed initiator".into(),
            ));
        }
        let sk = kem_accept(me, hs, &t)?;
        let mut core = RatchetCore {
            rk: sk,
            dhs: me.x25519_secret(), // initial ratchet key = identity X25519
            dhs_pub: me.public().x25519_bytes(),
            dhr: None,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
        };
        // Eager first ratchet against the initiator's ratchet key: sets up our
        // receiving chain (matching the initiator's sending chain) and a fresh
        // sending chain, so we can send before receiving.
        dh_ratchet(&mut core, hs.ratchet_pub)?;
        Ok(Self {
            core,
            skipped: Skipped::default(),
        })
    }

    /// Encrypt the next outbound message. Output is `header ‖ ciphertext`, with
    /// the header (ratchet pubkey, counters) authenticated as AAD.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let c = &mut self.core;
        let ck = c.cks.clone().ok_or_else(|| {
            Error::Crypto("no sending chain yet (receive a message first)".into())
        })?;
        let (mk, next) = chain_step(&ck);

        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(&c.dhs_pub);
        header.extend_from_slice(&c.pn.to_le_bytes());
        header.extend_from_slice(&c.ns.to_le_bytes());

        let ct = aead_seal(&mk, &header, plaintext)?;
        c.cks = Some(next);
        c.ns += 1;

        let mut out = header;
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypt the next inbound message. Handles in-order, out-of-order, and
    /// across-ratchet delivery via the bounded skipped-key cache. All state
    /// changes happen on a scratch copy and are committed only after the AEAD
    /// verifies — a tampered/forged frame never advances or desyncs the ratchet.
    pub fn open(&mut self, framed: &[u8]) -> Result<Vec<u8>> {
        if framed.len() < HEADER_LEN {
            return Err(Error::Verify("truncated frame".into()));
        }
        let header = &framed[..HEADER_LEN];
        let ct = &framed[HEADER_LEN..];
        let mut their_pub = [0u8; 32];
        their_pub.copy_from_slice(&framed[..32]);
        let their_pn = u64::from_le_bytes(framed[32..40].try_into().expect("8 bytes"));
        let their_ns = u64::from_le_bytes(framed[40..48].try_into().expect("8 bytes"));

        // 1) Already-skipped key (out-of-order arrival of a previously-skipped
        //    message). Get + verify + remove-on-success: a failure keeps the key.
        let sk_key = (their_pub, their_ns);
        if let Some(mk) = self.skipped.get(&sk_key) {
            let pt = aead_open(&mk, header, ct)?;
            self.skipped.remove(&sk_key);
            return Ok(pt);
        }

        // 2) Work on a scratch copy; collect newly-skipped keys to commit later.
        let mut w = self.core.clone();
        let mut fresh: Vec<(SkippedId, MessageKey)> = Vec::new();

        if w.dhr.as_ref() != Some(&their_pub) {
            // New DH chain: drain the rest of the current receiving chain (its
            // length is `their_pn`), then perform the DH ratchet step.
            skip_recv(&mut w, &mut fresh, their_pn)?;
            dh_ratchet(&mut w, their_pub)?;
        }
        // Skip within the current receiving chain up to the message index.
        skip_recv(&mut w, &mut fresh, their_ns)?;

        // 3) Derive the target message key (index == their_ns) and decrypt.
        let ckr = w
            .ckr
            .clone()
            .ok_or_else(|| Error::Verify("no receiving chain".into()))?;
        let (mk, next) = chain_step(&ckr);
        let pt = aead_open(&mk, header, ct)?; // failure → discard `w` and `fresh`

        // 4) Commit: advance the scratch state, then store skipped keys.
        w.ckr = Some(next);
        w.nr += 1;
        self.core = w;
        for (k, mk) in fresh {
            self.skipped.insert(k, mk);
        }
        Ok(pt)
    }
}

/// Derive (and stash) receiving-chain message keys for indices `[nr, until)`,
/// advancing the chain. Bounded by `MAX_SKIP` to prevent a forged header from
/// forcing unbounded key derivation.
fn skip_recv(
    w: &mut RatchetCore,
    fresh: &mut Vec<(SkippedId, MessageKey)>,
    until: u64,
) -> Result<()> {
    if until <= w.nr {
        return Ok(()); // target is current or already passed (replay handled in open)
    }
    if until - w.nr > MAX_SKIP {
        return Err(Error::Verify("too many skipped messages".into()));
    }
    let (dhr, mut ck) = match (w.dhr, &w.ckr) {
        (Some(p), Some(c)) => (p, c.clone()),
        _ => return Ok(()), // no receiving chain yet
    };
    while w.nr < until {
        let (mk, next) = chain_step(&ck);
        fresh.push(((dhr, w.nr), mk));
        ck = next;
        w.nr += 1;
    }
    w.ckr = Some(ck);
    Ok(())
}

/// Perform a DH ratchet step on the scratch state: re-key the root from the
/// peer's new ratchet public key, reset chains, and generate our next key.
fn dh_ratchet(w: &mut RatchetCore, their_pub: [u8; 32]) -> Result<()> {
    w.pn = w.ns;
    w.ns = 0;
    w.nr = 0;
    w.dhr = Some(their_pub);

    let (rk1, ckr) = kdf_rk(&w.rk, &dh(&w.dhs, &their_pub));
    w.rk = rk1;
    w.ckr = Some(ckr);

    let (new_dhs, new_pub) = gen_ratchet_key()?;
    let (rk2, cks) = kdf_rk(&w.rk, &dh(&new_dhs, &their_pub));
    w.rk = rk2;
    w.cks = Some(cks);
    w.dhs = new_dhs;
    w.dhs_pub = new_pub;
    Ok(())
}

// --- handshake (hybrid KEM) ------------------------------------------------

fn kem_initiate(me: &Keypair, peer: &PublicIdentity, ratchet_pub: &[u8; 32]) -> Result<KemInit> {
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

    let transcript = transcript(me.public(), peer, &eph_pub, ratchet_pub, &mlkem_ct);
    let root = root_key(&build_ikm(&ss_x, ss_pq.as_ref()), &transcript);
    Ok(KemInit {
        eph_pub,
        mlkem_ct,
        transcript,
        root,
    })
}

fn kem_accept(me: &Keypair, hs: &Handshake, transcript: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let ss_x = me.x25519_dh(&hs.eph_x25519);

    #[cfg(feature = "pq")]
    let ss_pq = Some(me.pq_decapsulate(&hs.mlkem_ct)?);
    #[cfg(not(feature = "pq"))]
    let ss_pq: Option<Zeroizing<[u8; 32]>> = None;

    Ok(root_key(&build_ikm(&ss_x, ss_pq.as_ref()), transcript))
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
    hk.expand(b"lattice/ratchet/ck", &mut next)
        .expect("hkdf len");
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
    hk.expand(b"lattice/session/root", &mut sk)
        .expect("hkdf len");
    Zeroizing::new(sk)
}

// --- AEAD record layer (fresh single-use key per message => constant nonce) -

fn aead_seal(mk: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    ChaCha20Poly1305::new_from_slice(mk)
        .expect("32-byte key")
        .encrypt(
            Nonce::from_slice(&[0u8; 12]),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto("AEAD seal failed".into()))
}

fn aead_open(mk: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    ChaCha20Poly1305::new_from_slice(mk)
        .expect("32-byte key")
        .decrypt(
            Nonce::from_slice(&[0u8; 12]),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Verify("AEAD open failed (tampered or wrong key)".into()))
}

fn transcript(
    initiator: &PublicIdentity,
    responder: &PublicIdentity,
    eph: &[u8; 32],
    ratchet_pub: &[u8; 32],
    ct: &[u8],
) -> Vec<u8> {
    let init = initiator.to_bytes();
    let resp = responder.to_bytes();
    let mut t =
        Vec::with_capacity(HS_DOMAIN.len() + 4 + init.len() + 4 + resp.len() + 64 + 4 + ct.len());
    t.extend_from_slice(HS_DOMAIN);
    t.extend_from_slice(&(init.len() as u32).to_le_bytes());
    t.extend_from_slice(&init);
    t.extend_from_slice(&(resp.len() as u32).to_le_bytes());
    t.extend_from_slice(&resp);
    t.extend_from_slice(eph);
    t.extend_from_slice(ratchet_pub);
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
    let mut v = Vec::with_capacity(72 + hs.mlkem_ct.len() + hs.sig.0.len());
    v.extend_from_slice(&hs.eph_x25519);
    v.extend_from_slice(&hs.ratchet_pub);
    v.extend_from_slice(&(hs.mlkem_ct.len() as u32).to_le_bytes());
    v.extend_from_slice(&hs.mlkem_ct);
    v.extend_from_slice(&(hs.sig.0.len() as u32).to_le_bytes());
    v.extend_from_slice(&hs.sig.0);
    v
}

/// Read a `u32le` length at `*pos`, bounded by `MAX_HANDSHAKE_LEN`, then the
/// bytes it describes. Never panics; consumes exactly what it returns.
fn take_field<'a>(b: &'a [u8], pos: &mut usize) -> Result<&'a [u8]> {
    let end = pos
        .checked_add(4)
        .filter(|e| *e <= b.len())
        .ok_or_else(|| Error::Verify("truncated handshake".into()))?;
    let n = u32::from_le_bytes(b[*pos..end].try_into().expect("4 bytes")) as usize;
    if n > MAX_HANDSHAKE_LEN {
        return Err(Error::Verify("handshake field too large".into()));
    }
    let stop = end
        .checked_add(n)
        .filter(|e| *e <= b.len())
        .ok_or_else(|| Error::Verify("truncated handshake".into()))?;
    *pos = stop;
    Ok(&b[end..stop])
}

fn decode_handshake(b: &[u8]) -> Result<Handshake> {
    if b.len() > MAX_HANDSHAKE_LEN {
        return Err(Error::Verify("handshake too large".into()));
    }
    if b.len() < 68 {
        return Err(Error::Verify("short handshake".into()));
    }
    let mut eph = [0u8; 32];
    let mut ratchet_pub = [0u8; 32];
    eph.copy_from_slice(&b[..32]);
    ratchet_pub.copy_from_slice(&b[32..64]);
    let mut pos = 64;
    let ct = take_field(b, &mut pos)?.to_vec();
    let sig = take_field(b, &mut pos)?.to_vec();
    if pos != b.len() {
        return Err(Error::Verify("trailing data after handshake".into()));
    }
    Ok(Handshake {
        eph_x25519: eph,
        ratchet_pub,
        mlkem_ct: ct,
        sig: Signature(sig),
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

    /// Split into the underlying connection and the ratchet session, e.g. to
    /// drive full-duplex I/O on the two halves of the connection concurrently.
    pub fn into_parts(self) -> (C, SecureSession) {
        (self.conn, self.session)
    }

    /// Resume an existing [`SecureSession`] over a fresh connection **without
    /// re-handshaking** (session resumption after a transport drop).
    ///
    /// The ratchet is transport-independent, so the channel simply continues:
    /// counters and chains carry over, and the skipped-key cache absorbs any
    /// frames lost during the gap (no desync). Both peers must still hold their
    /// ratchet state — if either restarted (lost its in-memory session), do a
    /// fresh [`ConnectedSession::initiate`]/[`ConnectedSession::accept`] instead.
    /// Note: a message in flight at the moment of the drop is *not* recovered;
    /// reliable redelivery (acks/resend) is a separate layer.
    pub fn resume(conn: C, session: SecureSession) -> Self {
        Self { conn, session }
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
    fn responder_can_send_first() {
        // Regression: the responder (b) must be able to send before receiving.
        let (mut a, mut b) = pair();
        let ct = b.seal(b"responder speaks first").unwrap();
        assert_eq!(a.open(&ct).unwrap(), b"responder speaks first");
        // And the initiator can still reply afterwards.
        let ct2 = a.seal(b"initiator replies").unwrap();
        assert_eq!(b.open(&ct2).unwrap(), b"initiator replies");
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
    fn out_of_order_within_chain_is_delivered() {
        let (mut a, mut b) = pair();
        let m0 = a.seal(b"first").unwrap();
        let m1 = a.seal(b"second").unwrap();
        let m2 = a.seal(b"third").unwrap();
        // Deliver out of order: 2, then 0, then 1.
        assert_eq!(b.open(&m2).unwrap(), b"third"); // skips + caches keys 0,1
        assert_eq!(b.open(&m0).unwrap(), b"first"); // from cache
        assert_eq!(b.open(&m1).unwrap(), b"second"); // from cache
    }

    #[test]
    fn out_of_order_across_ratchet_is_delivered() {
        let (mut a, mut b) = pair();
        // Establish the chains in both directions first.
        let a0 = a.seal(b"a0").unwrap();
        assert_eq!(b.open(&a0).unwrap(), b"a0");
        let b0 = b.seal(b"b0").unwrap();
        assert_eq!(a.open(&b0).unwrap(), b"b0");
        // Alice sends two on her new chain; deliver the second one first.
        let a1 = a.seal(b"a1").unwrap();
        let a2 = a.seal(b"a2").unwrap();
        assert_eq!(b.open(&a2).unwrap(), b"a2");
        assert_eq!(b.open(&a1).unwrap(), b"a1"); // from skipped cache
    }

    #[test]
    fn replay_is_rejected() {
        let (mut a, mut b) = pair();
        let m0 = a.seal(b"once").unwrap();
        assert_eq!(b.open(&m0).unwrap(), b"once");
        assert!(b.open(&m0).is_err(), "a consumed message must not replay");
    }

    #[test]
    fn gap_beyond_max_skip_is_rejected() {
        let (mut a, mut b) = pair();
        let mut last = Vec::new();
        for i in 0..(MAX_SKIP + 2) {
            last = a.seal(format!("m{i}").as_bytes()).unwrap();
        }
        // First message Bob sees is index MAX_SKIP+1 → gap exceeds the cap.
        assert!(
            b.open(&last).is_err(),
            "gap beyond MAX_SKIP must be rejected"
        );
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
        assert_eq!(
            b.open(&m1).unwrap(),
            b"one",
            "chain not desynced by failure"
        );
    }

    #[test]
    fn wrong_responder_cannot_read() {
        let (alice, bob, eve) = (id(), id(), id());
        let (hs, mut a) = SecureSession::initiate(&alice, bob.public()).unwrap();
        assert!(
            SecureSession::accept(&eve, alice.public(), &hs).is_err(),
            "non-intended responder must not accept"
        );
        let _ = a.seal(b"for bob only").unwrap();
    }

    fn valid() -> (Keypair, Keypair, Keypair, Handshake) {
        let (alice, bob, eve) = (id(), id(), id());
        let (hs, _) = SecureSession::initiate(&alice, bob.public()).unwrap();
        (alice, bob, eve, hs)
    }

    #[test]
    fn impersonation_is_rejected() {
        let (alice, bob, eve, _) = valid();
        let (hs, _) = SecureSession::initiate(&eve, bob.public()).unwrap();
        assert!(SecureSession::accept(&bob, alice.public(), &hs).is_err());
    }

    #[test]
    fn signature_by_wrong_key_is_rejected() {
        let (alice, bob, eve, mut hs) = valid();
        let t = transcript(
            alice.public(),
            bob.public(),
            &hs.eph_x25519,
            &hs.ratchet_pub,
            &hs.mlkem_ct,
        );
        hs.sig = eve.sign(&t);
        assert!(SecureSession::accept(&bob, alice.public(), &hs).is_err());
    }

    #[test]
    fn tampered_ratchet_pub_is_rejected() {
        let (alice, bob, _, mut hs) = valid();
        hs.ratchet_pub[0] ^= 1;
        assert!(SecureSession::accept(&bob, alice.public(), &hs).is_err());
    }

    #[test]
    fn handshake_under_wrong_claimed_initiator_is_rejected() {
        let (_, bob, eve, hs) = valid();
        assert!(SecureSession::accept(&bob, eve.public(), &hs).is_err());
    }

    #[test]
    fn genuine_handshake_roundtrips_and_messages() {
        let (alice, bob) = (id(), id());
        let (hs, mut a) = SecureSession::initiate(&alice, bob.public()).unwrap();
        let mut b = SecureSession::accept(&bob, alice.public(), &hs).unwrap();
        let ct = a.seal(b"hi").unwrap();
        assert_eq!(b.open(&ct).unwrap(), b"hi");
    }

    #[test]
    fn wire_roundtrip_is_accepted() {
        let (alice, bob, _, hs) = valid();
        let d = decode_handshake(&encode_handshake(&hs)).unwrap();
        assert_eq!(d.eph_x25519, hs.eph_x25519);
        assert_eq!(d.ratchet_pub, hs.ratchet_pub);
        assert_eq!(d.mlkem_ct, hs.mlkem_ct);
        assert_eq!(d.sig.0, hs.sig.0);
        assert!(SecureSession::accept(&bob, alice.public(), &d).is_ok());
    }

    #[test]
    fn malformed_wire_is_rejected() {
        let (_, _, _, hs) = valid();
        let enc = encode_handshake(&hs);
        assert!(decode_handshake(&enc[..enc.len() - 1]).is_err());
        for n in [0usize, 63, 67] {
            assert!(decode_handshake(&enc[..n]).is_err());
        }
        let mut extra = enc.clone();
        extra.push(0);
        assert!(decode_handshake(&extra).is_err());

        let mut big_ct = vec![0u8; 68];
        big_ct[64..68].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_handshake(&big_ct).is_err());

        let mut big_sig = vec![0u8; 72];
        big_sig[68..72].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_handshake(&big_sig).is_err());

        assert!(decode_handshake(&vec![0u8; MAX_HANDSHAKE_LEN + 1]).is_err());
    }

    #[test]
    fn transcript_layout() {
        let (alice, bob, _, hs) = valid();
        let t = transcript(
            alice.public(),
            bob.public(),
            &hs.eph_x25519,
            &hs.ratchet_pub,
            &hs.mlkem_ct,
        );
        assert!(t.starts_with(b"lattice-session-hs-v2"));
        let (i, r) = (alice.public().to_bytes(), bob.public().to_bytes());
        assert_eq!(
            t.len(),
            21 + 4 + i.len() + 4 + r.len() + 32 + 32 + 4 + hs.mlkem_ct.len()
        );
    }
}
