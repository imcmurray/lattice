//! `lattice-session` — authenticated secure channels with a **Double Ratchet**
//! over a hybrid-KEM handshake (DESIGN.md §5.1).
//!
//! Establishing a session is a **two-message handshake** (v3) that mixes four
//! shared secrets — two to the responder's static keys, two between fresh
//! ephemerals — into a root key:
//!
//! ```text
//!   Initiator (I)                                   Responder (R)
//!   eph_i, ratchet_i, ephemeral ML-KEM (ek_i)
//!   ss1 = X25519(eph_i, R.static)
//!   (ct_s, ss2) = ML-KEM-encaps(R.static ek)
//!   T1  = "lattice-session-hs-v3" ‖ lp(binding) ‖ I ‖ R
//!         ‖ eph_i ‖ ratchet_i ‖ lp(ct_s) ‖ lp(ek_i)
//!   sig_i = I.sign(T1)
//!                  ── msg1: eph_i, ratchet_i, ct_s, ek_i, sig_i ──▶
//!                                                   verify sig_i under I (first!)
//!                                                   ss1, ss2 from static keys
//!                                                   eph_r fresh; ss3 = X25519(eph_r, eph_i)
//!                                                   (ct_e, ss4) = ML-KEM-encaps(ek_i)
//!                                                   T2  = T1 ‖ lp(sig_i) ‖ eph_r ‖ lp(ct_e)
//!                                                   sig_r = R.sign(T2)
//!                  ◀── msg2: eph_r, ct_e, sig_r ──────────────────
//!   verify sig_r under R (before any decapsulation)
//!   ss3 = X25519(eph_i, eph_r); ss4 = ML-KEM-decaps(ek_i's dk, ct_e)
//!
//!   T    = T2 ‖ lp(sig_r)
//!   root = HKDF( salt = T, ikm = ss1 ‖ ss2 ‖ ss3 ‖ ss4 )
//! ```
//!
//! (`lp(x)` is `u32le(len) ‖ x`; the ML-KEM legs are present only for a
//! `Hybrid` responder.) Both sides sign the transcript with hybrid signatures
//! (Ed25519 + ML-DSA), and a caller-supplied `binding` byte string (e.g. the
//! transport channel's endpoint ids) is mixed in, so a handshake cannot be
//! replayed onto another channel. The root is secure if **either** the
//! classical or the post-quantum exchange holds (harvest-now-decrypt-later
//! defense). Because both sides contribute fresh ephemerals that are erased
//! after the handshake, a later compromise of a long-term identity key does
//! **not** decrypt recorded sessions (forward secrecy); it does let the
//! attacker impersonate the owner in *new* sessions. The root key then seeds a
//! Double Ratchet:
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

use lattice_core::{Connection, CryptoSuite, Error, Identity, Result, Session, Signature, Verify};
use lattice_identity::{Keypair, PublicIdentity};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};
use zeroize::{Zeroize, Zeroizing};

const HS_DOMAIN: &[u8] = b"lattice-session-hs-v3";
const RESUME_KEY_INFO: &[u8] = b"lattice-session-resume-v1";
const RESUME_DOMAIN: &[u8] = b"lattice-resume-v2";

/// Which side of a resume negotiation a tag is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResumeRole {
    /// The side that dialed (role byte `0x01`).
    Dialer,
    /// The side that accepted (role byte `0x02`).
    Listener,
}
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

/// Message 1 of the v3 handshake, initiator → responder.
#[derive(Clone, Debug)]
pub struct HandshakeInit {
    /// Fresh X25519 ephemeral public key.
    pub eph_i: [u8; 32],
    /// Initiator's first DH-ratchet public key — lets the responder ratchet
    /// immediately, so either side may send first.
    pub ratchet_pub_i: [u8; 32],
    /// ML-KEM ciphertext to the responder's STATIC key (empty when PQ is off).
    pub kem_ct_s: Vec<u8>,
    /// Fresh EPHEMERAL ML-KEM-768 encapsulation key (empty when PQ is off).
    pub kem_ek_i: Vec<u8>,
    /// Initiator's hybrid signature over transcript `T1`.
    pub sig_i: Signature,
}

/// Message 2 of the v3 handshake, responder → initiator.
#[derive(Clone, Debug)]
pub struct HandshakeResp {
    /// Fresh X25519 ephemeral public key; also the responder's first ratchet
    /// public key.
    pub eph_r: [u8; 32],
    /// ML-KEM ciphertext to the initiator's ephemeral key (empty when PQ is off).
    pub kem_ct_e: Vec<u8>,
    /// Responder's hybrid signature over transcript `T2`.
    pub sig_r: Signature,
}

fn handshake_err(msg: &str) -> Error {
    Error::Verify(msg.into())
}

/// Little-endian length prefix + bytes.
fn put_lp(out: &mut Vec<u8>, x: &[u8]) {
    out.extend_from_slice(&(x.len() as u32).to_le_bytes());
    out.extend_from_slice(x);
}

impl HandshakeInit {
    /// Wire encoding: `eph_i ‖ ratchet_pub_i ‖ lp(kem_ct_s) ‖ lp(kem_ek_i) ‖ lp(sig_i)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(76 + self.kem_ct_s.len());
        v.extend_from_slice(&self.eph_i);
        v.extend_from_slice(&self.ratchet_pub_i);
        put_lp(&mut v, &self.kem_ct_s);
        put_lp(&mut v, &self.kem_ek_i);
        put_lp(&mut v, &self.sig_i.0);
        v
    }

    /// Parse [`HandshakeInit::to_bytes`]. Never panics; every error is
    /// [`Error::Verify`].
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() > MAX_HANDSHAKE_LEN {
            return Err(handshake_err("handshake too large"));
        }
        if b.len() < 76 {
            return Err(handshake_err("short handshake"));
        }
        let mut eph_i = [0u8; 32];
        let mut ratchet_pub_i = [0u8; 32];
        eph_i.copy_from_slice(&b[..32]);
        ratchet_pub_i.copy_from_slice(&b[32..64]);
        let mut pos = 64;
        let kem_ct_s = take_field(b, &mut pos)?.to_vec();
        let kem_ek_i = take_field(b, &mut pos)?.to_vec();
        let sig_i = Signature(take_field(b, &mut pos)?.to_vec());
        if pos != b.len() {
            return Err(handshake_err("trailing data after handshake"));
        }
        Ok(Self {
            eph_i,
            ratchet_pub_i,
            kem_ct_s,
            kem_ek_i,
            sig_i,
        })
    }
}

impl HandshakeResp {
    /// Wire encoding: `eph_r ‖ lp(kem_ct_e) ‖ lp(sig_r)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(40 + self.kem_ct_e.len() + self.sig_r.0.len());
        v.extend_from_slice(&self.eph_r);
        put_lp(&mut v, &self.kem_ct_e);
        put_lp(&mut v, &self.sig_r.0);
        v
    }

    /// Parse [`HandshakeResp::to_bytes`]. Never panics; every error is
    /// [`Error::Verify`].
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() > MAX_HANDSHAKE_LEN {
            return Err(handshake_err("handshake too large"));
        }
        if b.len() < 40 {
            return Err(handshake_err("short handshake"));
        }
        let mut eph_r = [0u8; 32];
        eph_r.copy_from_slice(&b[..32]);
        let mut pos = 32;
        let kem_ct_e = take_field(b, &mut pos)?.to_vec();
        let sig_r = Signature(take_field(b, &mut pos)?.to_vec());
        if pos != b.len() {
            return Err(handshake_err("trailing data after handshake"));
        }
        Ok(Self {
            eph_r,
            kem_ct_e,
            sig_r,
        })
    }
}

#[cfg(feature = "pq")]
type EphKem = lattice_identity::EphemeralKem;
#[cfg(not(feature = "pq"))]
type EphKem = ();

/// Initiator state between msg1 and msg2. Holds the ephemeral secrets, which
/// are zeroized when [`PendingInitiator::finish`] consumes it or it is dropped.
/// Deliberately neither `Clone` nor `Debug`.
pub struct PendingInitiator {
    eph_secret: XStaticSecret,
    ratchet_secret: XStaticSecret,
    ratchet_pub: [u8; 32],
    kem: Option<EphKem>,
    ss1: Zeroizing<[u8; 32]>,
    ss2: Option<Zeroizing<[u8; 32]>>,
    peer: PublicIdentity,
    /// `T1 ‖ lp(sig_i)`.
    t2_prefix: Vec<u8>,
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
    /// Per-session key for resume proofs; derived from the handshake root key,
    /// fixed for the session lifetime (never ratcheted).
    resume_key: Zeroizing<[u8; 32]>,
}

impl PendingInitiator {
    /// Complete the handshake with the responder's msg2. The responder's
    /// signature is verified **before** any decapsulation or DH. Every failure
    /// is [`Error::Verify`]; the ephemeral secrets are dropped either way.
    pub fn finish(self, resp: &HandshakeResp) -> Result<SecureSession> {
        let Self {
            eph_secret,
            ratchet_secret,
            ratchet_pub,
            kem,
            ss1,
            ss2,
            peer,
            t2_prefix,
        } = self;

        if resp.kem_ct_e.len() > MAX_HANDSHAKE_LEN || resp.sig_r.0.len() > MAX_HANDSHAKE_LEN {
            return Err(handshake_err("handshake field too large"));
        }
        let t2 = transcript_t2(&t2_prefix, &resp.eph_r, &resp.kem_ct_e);
        if !peer.verify(&t2, &resp.sig_r) {
            return Err(handshake_err(
                "handshake signature does not verify under expected responder",
            ));
        }
        let pq = pq_on(&peer);
        check_kem_fields(pq, &[&resp.kem_ct_e])?;

        let ss3 = nonzero(dh(&eph_secret, &resp.eph_r))?;
        let ss4 = if pq {
            let kem = kem.ok_or_else(|| handshake_err("missing ephemeral KEM"))?;
            Some(eph_kem_decapsulate(kem, &resp.kem_ct_e)?)
        } else {
            None
        };
        drop(eph_secret);

        let t = transcript_final(&t2, &resp.sig_r);
        let ikm = build_ikm([Some(&ss1), ss2.as_ref(), Some(&ss3), ss4.as_ref()]);
        let sk = root_key(&ikm, &t);
        let resume_key = derive_resume_key(&sk);

        // Double Ratchet init (initiator): the responder's ephemeral is DHr.
        let dhr = resp.eph_r;
        let dh_first = nonzero(dh(&ratchet_secret, &dhr))?;
        let (rk, cks) = kdf_rk(&sk, &dh_first);
        Ok(SecureSession {
            core: RatchetCore {
                rk,
                dhs: ratchet_secret,
                dhs_pub: ratchet_pub,
                dhr: Some(dhr),
                cks: Some(cks),
                ckr: None,
                ns: 0,
                nr: 0,
                pn: 0,
            },
            skipped: Skipped::default(),
            resume_key,
        })
    }
}

impl SecureSession {
    /// Initiator side, step 1: produce msg1 and the [`PendingInitiator`] state.
    /// `binding` is opaque caller-supplied channel-binding data (may be empty,
    /// at most `MAX_HANDSHAKE_LEN` bytes); both sides must pass the same bytes.
    pub fn initiate(
        me: &Keypair,
        peer: &PublicIdentity,
        binding: &[u8],
    ) -> Result<(HandshakeInit, PendingInitiator)> {
        if binding.len() > MAX_HANDSHAKE_LEN {
            return Err(handshake_err("binding too large"));
        }
        let (ratchet_secret, ratchet_pub) = gen_ratchet_key()?;
        let (eph_secret, eph_i) = gen_ratchet_key()?;

        let pq = pq_on(peer);
        let (kem_ct_s, ss2, kem, kem_ek_i) = if pq {
            let (ct, ss2) = pq_encapsulate_static(peer)?;
            let (kem, ek) = eph_kem_generate()?;
            (ct, Some(ss2), Some(kem), ek)
        } else {
            (Vec::new(), None, None, Vec::new())
        };
        let ss1 = nonzero(dh(&eph_secret, &peer.x25519_bytes()))?;

        let t1 = transcript_t1(
            binding,
            me.public(),
            peer,
            &eph_i,
            &ratchet_pub,
            &kem_ct_s,
            &kem_ek_i,
        );
        let sig_i = me.sign(&t1);
        let mut t2_prefix = t1;
        put_lp(&mut t2_prefix, &sig_i.0);

        let init = HandshakeInit {
            eph_i,
            ratchet_pub_i: ratchet_pub,
            kem_ct_s,
            kem_ek_i,
            sig_i,
        };
        let pending = PendingInitiator {
            eph_secret,
            ratchet_secret,
            ratchet_pub,
            kem,
            ss1,
            ss2,
            peer: peer.clone(),
            t2_prefix,
        };
        Ok((init, pending))
    }

    /// Responder side: verify msg1 and produce msg2 plus the live session. The
    /// initiator's signature over `T1` is verified under `peer` **before** any
    /// DH or decapsulation. The responder's first ratchet key is its fresh
    /// `eph_r` (never the static key), and it ratchets eagerly against the
    /// initiator's ratchet key, so either party may send first.
    pub fn respond(
        me: &Keypair,
        peer: &PublicIdentity,
        binding: &[u8],
        init: &HandshakeInit,
    ) -> Result<(HandshakeResp, Self)> {
        if binding.len() > MAX_HANDSHAKE_LEN
            || init.kem_ct_s.len() > MAX_HANDSHAKE_LEN
            || init.kem_ek_i.len() > MAX_HANDSHAKE_LEN
            || init.sig_i.0.len() > MAX_HANDSHAKE_LEN
        {
            return Err(handshake_err("handshake field too large"));
        }
        let t1 = transcript_t1(
            binding,
            peer,
            me.public(),
            &init.eph_i,
            &init.ratchet_pub_i,
            &init.kem_ct_s,
            &init.kem_ek_i,
        );
        if !peer.verify(&t1, &init.sig_i) {
            return Err(handshake_err(
                "handshake signature does not verify under claimed initiator",
            ));
        }
        let pq = pq_on(me.public());
        check_kem_fields(pq, &[&init.kem_ct_s, &init.kem_ek_i])?;

        let ss1 = nonzero(me.x25519_dh(&init.eph_i))?;
        let ss2 = if pq {
            Some(pq_decapsulate_static(me, &init.kem_ct_s)?)
        } else {
            None
        };
        let (eph_secret, eph_r) = gen_ratchet_key()?;
        let ss3 = nonzero(dh(&eph_secret, &init.eph_i))?;
        let (kem_ct_e, ss4) = if pq {
            let (ct, ss) = pq_encapsulate_to_ek(&init.kem_ek_i)?;
            (ct, Some(ss))
        } else {
            (Vec::new(), None)
        };

        let mut t2_prefix = t1;
        put_lp(&mut t2_prefix, &init.sig_i.0);
        let t2 = transcript_t2(&t2_prefix, &eph_r, &kem_ct_e);
        let sig_r = me.sign(&t2);
        let t = transcript_final(&t2, &sig_r);

        let ikm = build_ikm([Some(&ss1), ss2.as_ref(), Some(&ss3), ss4.as_ref()]);
        let sk = root_key(&ikm, &t);
        let resume_key = derive_resume_key(&sk);

        let mut core = RatchetCore {
            rk: sk,
            dhs: eph_secret, // initial ratchet key = fresh eph_r (replaced below)
            dhs_pub: eph_r,
            dhr: None,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
        };
        // Eager first ratchet against the initiator's ratchet key: sets up our
        // receiving chain (matching the initiator's sending chain) and a fresh
        // sending chain. This replaces `dhs`, so the eph_r secret is gone.
        dh_ratchet(&mut core, init.ratchet_pub_i)?;
        Ok((
            HandshakeResp {
                eph_r,
                kem_ct_e,
                sig_r,
            },
            Self {
                core,
                skipped: Skipped::default(),
                resume_key,
            },
        ))
    }

    /// HMAC tag proving possession of this session's secret for a resume
    /// negotiation. Does not touch the ratchet state.
    pub fn resume_tag(
        &self,
        role: ResumeRole,
        dialer: &PublicIdentity,
        listener: &PublicIdentity,
        dialer_nonce: &[u8; 32],
        listener_nonce: &[u8; 32],
        binding: &[u8],
    ) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&self.resume_key[..])
            .expect("hmac accepts any key length");
        mac.update(&resume_msg(
            role,
            dialer,
            listener,
            dialer_nonce,
            listener_nonce,
            binding,
        ));
        let out = mac.finalize().into_bytes();
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&out);
        tag
    }

    /// Verify a peer's resume tag in constant time. Fails with
    /// [`Error::Verify`] on any mismatch or a tag whose length is not 32.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_resume_tag(
        &self,
        role: ResumeRole,
        dialer: &PublicIdentity,
        listener: &PublicIdentity,
        dialer_nonce: &[u8; 32],
        listener_nonce: &[u8; 32],
        binding: &[u8],
        tag: &[u8],
    ) -> Result<()> {
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&self.resume_key[..])
            .expect("hmac accepts any key length");
        mac.update(&resume_msg(
            role,
            dialer,
            listener,
            dialer_nonce,
            listener_nonce,
            binding,
        ));
        mac.verify_slice(tag)
            .map_err(|_| Error::Verify("resume proof failed".into()))
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
    // Both DH outputs are checked before `w` is touched: an all-zero (low-order)
    // peer key is rejected without changing any state.
    let dh_recv = nonzero(dh(&w.dhs, &their_pub))?;
    let (new_dhs, new_pub) = gen_ratchet_key()?;
    let dh_send = nonzero(dh(&new_dhs, &their_pub))?;

    w.pn = w.ns;
    w.ns = 0;
    w.nr = 0;
    w.dhr = Some(their_pub);

    let (rk1, ckr) = kdf_rk(&w.rk, &dh_recv);
    w.rk = rk1;
    w.ckr = Some(ckr);

    let (rk2, cks) = kdf_rk(&w.rk, &dh_send);
    w.rk = rk2;
    w.cks = Some(cks);
    w.dhs = new_dhs;
    w.dhs_pub = new_pub;
    Ok(())
}

// --- handshake (hybrid KEM) ------------------------------------------------

/// PQ legs are on iff the `pq` feature is compiled in and the responder is a
/// `Hybrid` identity. Both sides evaluate this on the responder's public
/// identity, so they always agree.
fn pq_on(responder: &PublicIdentity) -> bool {
    cfg!(feature = "pq") && responder.suite() == CryptoSuite::Hybrid
}

/// The KEM fields must all be non-empty with PQ on, all empty with PQ off.
fn check_kem_fields(pq: bool, fields: &[&[u8]]) -> Result<()> {
    if fields.iter().all(|f| f.is_empty() != pq) {
        Ok(())
    } else {
        Err(handshake_err("KEM fields do not match the responder suite"))
    }
}

/// Reject an all-zero (non-contributory) X25519 output.
fn nonzero(ss: Zeroizing<[u8; 32]>) -> Result<Zeroizing<[u8; 32]>> {
    if ss.iter().all(|b| *b == 0) {
        Err(handshake_err("non-contributory X25519 output"))
    } else {
        Ok(ss)
    }
}

#[cfg(feature = "pq")]
fn pq_encapsulate_static(peer: &PublicIdentity) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    peer.pq_encapsulate()
}
#[cfg(not(feature = "pq"))]
fn pq_encapsulate_static(_peer: &PublicIdentity) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    Err(handshake_err("post-quantum support not compiled in"))
}

#[cfg(feature = "pq")]
fn pq_decapsulate_static(me: &Keypair, ct: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    me.pq_decapsulate(ct)
        .map_err(|_| handshake_err("ML-KEM decapsulation failed"))
}
#[cfg(not(feature = "pq"))]
fn pq_decapsulate_static(_me: &Keypair, _ct: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    Err(handshake_err("post-quantum support not compiled in"))
}

#[cfg(feature = "pq")]
fn pq_encapsulate_to_ek(ek: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    lattice_identity::pq_encapsulate_to(ek)
        .map_err(|_| handshake_err("invalid ephemeral ML-KEM key"))
}
#[cfg(not(feature = "pq"))]
fn pq_encapsulate_to_ek(_ek: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    Err(handshake_err("post-quantum support not compiled in"))
}

#[cfg(feature = "pq")]
fn eph_kem_generate() -> Result<(EphKem, Vec<u8>)> {
    let k = EphKem::generate()?;
    let ek = k.encapsulation_key_bytes();
    Ok((k, ek))
}
#[cfg(not(feature = "pq"))]
fn eph_kem_generate() -> Result<(EphKem, Vec<u8>)> {
    Err(handshake_err("post-quantum support not compiled in"))
}

#[cfg(feature = "pq")]
fn eph_kem_decapsulate(kem: EphKem, ct: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    kem.decapsulate(ct)
        .map_err(|_| handshake_err("ML-KEM decapsulation failed"))
}
#[cfg(not(feature = "pq"))]
fn eph_kem_decapsulate(_kem: EphKem, _ct: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    Err(handshake_err("post-quantum support not compiled in"))
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

/// 32 fresh random bytes for a resume nonce.
pub fn resume_nonce() -> Result<[u8; 32]> {
    let mut n = [0u8; 32];
    getrandom::getrandom(&mut n).map_err(|e| Error::Crypto(format!("rng: {e}")))?;
    Ok(n)
}

fn derive_resume_key(sk: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, sk);
    let mut k = [0u8; 32];
    hk.expand(RESUME_KEY_INFO, &mut k).expect("hkdf len");
    Zeroizing::new(k)
}

fn resume_msg(
    role: ResumeRole,
    dialer: &PublicIdentity,
    listener: &PublicIdentity,
    dialer_nonce: &[u8; 32],
    listener_nonce: &[u8; 32],
    binding: &[u8],
) -> Vec<u8> {
    let dp = dialer.to_bytes();
    let lp = listener.to_bytes();
    let mut m = Vec::with_capacity(
        RESUME_DOMAIN.len() + 1 + 64 + 4 + binding.len() + 4 + dp.len() + 4 + lp.len(),
    );
    m.extend_from_slice(RESUME_DOMAIN);
    m.push(match role {
        ResumeRole::Dialer => 0x01,
        ResumeRole::Listener => 0x02,
    });
    m.extend_from_slice(dialer_nonce);
    m.extend_from_slice(listener_nonce);
    m.extend_from_slice(&(binding.len() as u32).to_le_bytes());
    m.extend_from_slice(binding);
    m.extend_from_slice(&(dp.len() as u32).to_le_bytes());
    m.extend_from_slice(&dp);
    m.extend_from_slice(&(lp.len() as u32).to_le_bytes());
    m.extend_from_slice(&lp);
    m
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

/// `T1 = domain ‖ lp(binding) ‖ lp(initiator) ‖ lp(responder) ‖ eph_i ‖
/// ratchet_pub_i ‖ lp(kem_ct_s) ‖ lp(kem_ek_i)`.
fn transcript_t1(
    binding: &[u8],
    initiator: &PublicIdentity,
    responder: &PublicIdentity,
    eph_i: &[u8; 32],
    ratchet_pub_i: &[u8; 32],
    kem_ct_s: &[u8],
    kem_ek_i: &[u8],
) -> Vec<u8> {
    let init = initiator.to_bytes();
    let resp = responder.to_bytes();
    let mut t = Vec::with_capacity(256 + binding.len() + init.len() + resp.len());
    t.extend_from_slice(HS_DOMAIN);
    put_lp(&mut t, binding);
    put_lp(&mut t, &init);
    put_lp(&mut t, &resp);
    t.extend_from_slice(eph_i);
    t.extend_from_slice(ratchet_pub_i);
    put_lp(&mut t, kem_ct_s);
    put_lp(&mut t, kem_ek_i);
    t
}

/// `T2 = (T1 ‖ lp(sig_i)) ‖ eph_r ‖ lp(kem_ct_e)`; takes `T1 ‖ lp(sig_i)`.
fn transcript_t2(t1_sig: &[u8], eph_r: &[u8; 32], kem_ct_e: &[u8]) -> Vec<u8> {
    let mut t = Vec::with_capacity(t1_sig.len() + 32 + 4 + kem_ct_e.len());
    t.extend_from_slice(t1_sig);
    t.extend_from_slice(eph_r);
    put_lp(&mut t, kem_ct_e);
    t
}

/// `T = T2 ‖ lp(sig_r)`.
fn transcript_final(t2: &[u8], sig_r: &Signature) -> Vec<u8> {
    let mut t = Vec::with_capacity(t2.len() + 4 + sig_r.0.len());
    t.extend_from_slice(t2);
    put_lp(&mut t, &sig_r.0);
    t
}

/// Plain concatenation `ss1 ‖ ss2 ‖ ss3 ‖ ss4`, skipping absent (PQ-off) legs.
fn build_ikm(parts: [Option<&Zeroizing<[u8; 32]>>; 4]) -> Zeroizing<Vec<u8>> {
    let mut ikm = Vec::with_capacity(128);
    for p in parts.into_iter().flatten() {
        ikm.extend_from_slice(&p[..]);
    }
    Zeroizing::new(ikm)
}

// --- session bound to a transport Connection ------------------------------

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

/// A [`SecureSession`] bound to a transport [`Connection`]: it performs the
/// handshake over the wire and then implements the core async [`Session`]
/// (seal-and-send / receive-and-open). This is the join point between the
/// crypto and the transport layers.
pub struct ConnectedSession<C: Connection> {
    conn: C,
    session: SecureSession,
}

impl<C: Connection> ConnectedSession<C> {
    /// Initiator: send msg1 over `conn`, receive msg2, return the live session.
    /// Handshake-protocol failures are [`Error::Verify`]; transport errors
    /// propagate unchanged.
    pub async fn initiate(
        mut conn: C,
        me: &Keypair,
        peer: &PublicIdentity,
        binding: &[u8],
    ) -> Result<Self> {
        let (init, pending) = SecureSession::initiate(me, peer, binding)?;
        conn.send(&init.to_bytes()).await?;
        let resp = HandshakeResp::from_bytes(&conn.recv().await?)?;
        let session = pending.finish(&resp)?;
        Ok(Self { conn, session })
    }

    /// Responder: receive msg1 from `conn`, respond with msg2, return the live
    /// session. If the handshake is rejected nothing is sent.
    pub async fn accept(
        mut conn: C,
        me: &Keypair,
        peer: &PublicIdentity,
        binding: &[u8],
    ) -> Result<Self> {
        let init = HandshakeInit::from_bytes(&conn.recv().await?)?;
        let (resp, session) = SecureSession::respond(me, peer, binding, &init)?;
        conn.send(&resp.to_bytes()).await?;
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

    const B: &[u8] = b"test-binding";

    /// Run the full three-step handshake, returning both messages and sessions.
    fn handshake(
        alice: &Keypair,
        bob: &Keypair,
        binding: &[u8],
    ) -> (HandshakeInit, HandshakeResp, SecureSession, SecureSession) {
        let (m1, pending) = SecureSession::initiate(alice, bob.public(), binding).unwrap();
        let (m2, b) = SecureSession::respond(bob, alice.public(), binding, &m1).unwrap();
        let a = pending.finish(&m2).unwrap();
        (m1, m2, a, b)
    }

    fn pair() -> (SecureSession, SecureSession) {
        let (alice, bob) = (id(), id());
        let (_, _, a, b) = handshake(&alice, &bob, B);
        (a, b)
    }

    fn pair_ids() -> (Keypair, Keypair, SecureSession, SecureSession) {
        let (alice, bob) = (id(), id());
        let (_, _, a, b) = handshake(&alice, &bob, b"");
        (alice, bob, a, b)
    }

    fn classical() -> Keypair {
        Keypair::generate(CryptoSuite::Classical).unwrap()
    }

    /// `T1 ‖ lp(sig_i)` for a msg1, as the responder rebuilds it.
    fn t1_of(init: &HandshakeInit, binding: &[u8], a: &Keypair, b: &Keypair) -> Vec<u8> {
        transcript_t1(
            binding,
            a.public(),
            b.public(),
            &init.eph_i,
            &init.ratchet_pub_i,
            &init.kem_ct_s,
            &init.kem_ek_i,
        )
    }

    const D: ResumeRole = ResumeRole::Dialer;
    const L: ResumeRole = ResumeRole::Listener;

    const BND: &[u8] = b"binding-x";

    #[test]
    fn resume_tags_verify_across_genuine_pair() {
        let (alice, bob, a, b) = pair_ids();
        let (nd, nl) = ([1u8; 32], [2u8; 32]);
        let td = a.resume_tag(D, alice.public(), bob.public(), &nd, &nl, BND);
        b.verify_resume_tag(D, alice.public(), bob.public(), &nd, &nl, BND, &td)
            .unwrap();
        let tl = b.resume_tag(L, alice.public(), bob.public(), &nd, &nl, BND);
        a.verify_resume_tag(L, alice.public(), bob.public(), &nd, &nl, BND, &tl)
            .unwrap();
    }

    #[test]
    fn resume_tags_match_between_sides() {
        let (alice, bob, a, b) = pair_ids();
        let (nd, nl) = ([3u8; 32], [4u8; 32]);
        assert_eq!(
            a.resume_tag(D, alice.public(), bob.public(), &nd, &nl, BND),
            b.resume_tag(D, alice.public(), bob.public(), &nd, &nl, BND)
        );
    }

    #[test]
    fn resume_tag_from_other_session_is_rejected() {
        let (alice, bob, _a, b) = pair_ids();
        let eve = id();
        let (_, _, e, _) = handshake(&eve, &bob, b"");
        let (nd, nl) = ([5u8; 32], [6u8; 32]);
        let tag = e.resume_tag(D, alice.public(), bob.public(), &nd, &nl, BND);
        assert!(matches!(
            b.verify_resume_tag(D, alice.public(), bob.public(), &nd, &nl, BND, &tag),
            Err(Error::Verify(_))
        ));
    }

    #[test]
    fn resume_tag_role_mismatch_is_rejected() {
        let (alice, bob, a, b) = pair_ids();
        let (nd, nl) = ([7u8; 32], [8u8; 32]);
        let td = a.resume_tag(D, alice.public(), bob.public(), &nd, &nl, BND);
        assert!(b
            .verify_resume_tag(L, alice.public(), bob.public(), &nd, &nl, BND, &td)
            .is_err());
        let tl = a.resume_tag(L, alice.public(), bob.public(), &nd, &nl, BND);
        assert!(b
            .verify_resume_tag(D, alice.public(), bob.public(), &nd, &nl, BND, &tl)
            .is_err());
    }

    #[test]
    fn resume_tag_binds_nonces_and_identities() {
        let (alice, bob, a, b) = pair_ids();
        let eve = id();
        let (nd, nl) = ([9u8; 32], [10u8; 32]);
        let tag = a.resume_tag(D, alice.public(), bob.public(), &nd, &nl, BND);
        let mut nd2 = nd;
        nd2[0] ^= 1;
        let mut nl2 = nl;
        nl2[31] ^= 1;
        assert!(b
            .verify_resume_tag(D, alice.public(), bob.public(), &nd2, &nl, BND, &tag)
            .is_err());
        assert!(b
            .verify_resume_tag(D, alice.public(), bob.public(), &nd, &nl2, BND, &tag)
            .is_err());
        assert!(b
            .verify_resume_tag(D, eve.public(), bob.public(), &nd, &nl, BND, &tag)
            .is_err());
        assert!(b
            .verify_resume_tag(D, alice.public(), eve.public(), &nd, &nl, BND, &tag)
            .is_err());
        assert!(b
            .verify_resume_tag(D, bob.public(), alice.public(), &nd, &nl, BND, &tag)
            .is_err());
    }

    #[test]
    fn resume_tag_binds_channel_binding() {
        let (alice, bob, a, b) = pair_ids();
        let (nd, nl) = ([15u8; 32], [16u8; 32]);
        let tag = a.resume_tag(D, alice.public(), bob.public(), &nd, &nl, b"X");
        b.verify_resume_tag(D, alice.public(), bob.public(), &nd, &nl, b"X", &tag)
            .unwrap();
        for other in [&b"Y"[..], &b""[..], &b"XY"[..]] {
            assert!(matches!(
                b.verify_resume_tag(D, alice.public(), bob.public(), &nd, &nl, other, &tag),
                Err(Error::Verify(_))
            ));
        }
    }

    #[test]
    fn resume_tag_bad_lengths_are_rejected() {
        let (alice, bob, a, b) = pair_ids();
        let (nd, nl) = ([11u8; 32], [12u8; 32]);
        let tag = a.resume_tag(D, alice.public(), bob.public(), &nd, &nl, BND);
        for n in [0usize, 31, 33, 64] {
            let mut t = tag.to_vec();
            t.resize(n, 0);
            assert!(b
                .verify_resume_tag(D, alice.public(), bob.public(), &nd, &nl, BND, &t)
                .is_err());
        }
    }

    #[test]
    fn resume_proofs_do_not_disturb_ratchet() {
        let (alice, bob, mut a, mut b) = pair_ids();
        let (nd, nl) = ([13u8; 32], [14u8; 32]);
        for _ in 0..3 {
            let t = a.resume_tag(D, alice.public(), bob.public(), &nd, &nl, BND);
            b.verify_resume_tag(D, alice.public(), bob.public(), &nd, &nl, BND, &t)
                .unwrap();
            let t = b.resume_tag(L, alice.public(), bob.public(), &nd, &nl, BND);
            a.verify_resume_tag(L, alice.public(), bob.public(), &nd, &nl, BND, &t)
                .unwrap();
        }
        let ct = a.seal(b"x").unwrap();
        assert_eq!(b.open(&ct).unwrap(), b"x");
        let ct = b.seal(b"y").unwrap();
        assert_eq!(a.open(&ct).unwrap(), b"y");
    }

    #[test]
    fn resume_nonce_is_random() {
        let (x, y) = (resume_nonce().unwrap(), resume_nonce().unwrap());
        assert_ne!(x, y);
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
    fn wrong_responder_cannot_accept() {
        let (alice, bob, eve) = (id(), id(), id());
        let (m1, _pending) = SecureSession::initiate(&alice, bob.public(), B).unwrap();
        assert!(
            SecureSession::respond(&eve, alice.public(), B, &m1).is_err(),
            "non-intended responder must not accept"
        );
    }

    #[test]
    fn genuine_handshake_roundtrips_and_messages() {
        let (alice, bob) = (id(), id());
        let (_, _, mut a, mut b) = handshake(&alice, &bob, B);
        let ct = a.seal(b"hi").unwrap();
        assert_eq!(b.open(&ct).unwrap(), b"hi");
        let ct = b.seal(b"yo").unwrap();
        assert_eq!(a.open(&ct).unwrap(), b"yo");
    }

    #[test]
    fn responder_ratchet_key_is_ephemeral_not_static() {
        let (alice, bob) = (id(), id());
        let (_, m2, a, mut b) = handshake(&alice, &bob, B);
        assert_ne!(m2.eph_r, bob.public().x25519_bytes());
        assert_eq!(a.core.dhr, Some(m2.eph_r));
        // After respond's eager ratchet the eph_r secret is replaced, and the
        // first sealed header carries the *new* key — never the static one.
        let frame = b.seal(b"first").unwrap();
        assert_ne!(&frame[..32], &bob.public().x25519_bytes()[..]);
    }

    #[test]
    fn handshake_has_forward_secrecy_against_identity_compromise() {
        let (alice, bob) = (id(), id());
        let (m1, m2, mut a, mut b) = handshake(&alice, &bob, B);
        let first = a.seal(b"secret").unwrap();

        // Attacker: both long-term keys + the recorded messages.
        let ss1 = nonzero(bob.x25519_dh(&m1.eph_i)).unwrap();
        let ss2 = bob.pq_decapsulate(&m1.kem_ct_s).unwrap();
        let mut t2_prefix = t1_of(&m1, B, &alice, &bob);
        put_lp(&mut t2_prefix, &m1.sig_i.0);
        let t2 = transcript_t2(&t2_prefix, &m2.eph_r, &m2.kem_ct_e);
        let t = transcript_final(&t2, &m2.sig_r);
        let static_root = root_key(&build_ikm([Some(&ss1), Some(&ss2), None, None]), &t);
        assert_ne!(*derive_resume_key(&static_root), *a.resume_key);

        // A v2-style responder built from the static-only root cannot decrypt.
        let mut core = RatchetCore {
            rk: static_root.clone(),
            dhs: bob.x25519_secret(),
            dhs_pub: bob.public().x25519_bytes(),
            dhr: None,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
        };
        dh_ratchet(&mut core, m1.ratchet_pub_i).unwrap();
        let mut forged = SecureSession {
            core,
            skipped: Skipped::default(),
            resume_key: derive_resume_key(&static_root),
        };
        assert!(forged.open(&first).is_err());
        // The real responder can.
        assert_eq!(b.open(&first).unwrap(), b"secret");
    }

    #[test]
    fn initiator_impersonation_is_rejected() {
        let (alice, bob, eve) = (id(), id(), id());
        // Eve signs, Bob is told the peer is Alice.
        let (m1, _) = SecureSession::initiate(&eve, bob.public(), B).unwrap();
        assert!(matches!(
            SecureSession::respond(&bob, alice.public(), B, &m1),
            Err(Error::Verify(_))
        ));
        // sig_i is Eve's signature over the correct T1.
        let (mut m1, _) = SecureSession::initiate(&alice, bob.public(), B).unwrap();
        m1.sig_i = eve.sign(&t1_of(&m1, B, &alice, &bob));
        assert!(matches!(
            SecureSession::respond(&bob, alice.public(), B, &m1),
            Err(Error::Verify(_))
        ));
    }

    #[test]
    fn responder_impersonation_is_rejected() {
        let (alice, bob, eve) = (id(), id(), id());
        let (m1, pending) = SecureSession::initiate(&alice, bob.public(), B).unwrap();
        // Eve cannot even answer a msg1 meant for Bob.
        assert!(SecureSession::respond(&eve, alice.public(), B, &m1).is_err());
        // Forged msg2 signed by Eve over the right T2.
        let mut t2_prefix = t1_of(&m1, B, &alice, &bob);
        put_lp(&mut t2_prefix, &m1.sig_i.0);
        let eph_r = [9u8; 32];
        let t2 = transcript_t2(&t2_prefix, &eph_r, &[1u8; 8]);
        let forged = HandshakeResp {
            eph_r,
            kem_ct_e: vec![1u8; 8],
            sig_r: eve.sign(&t2),
        };
        assert!(matches!(pending.finish(&forged), Err(Error::Verify(_))));
    }

    #[test]
    fn tampering_with_any_msg1_field_is_rejected() {
        let (alice, bob) = (id(), id());
        let (m1, _) = SecureSession::initiate(&alice, bob.public(), B).unwrap();
        let mid = |v: &Vec<u8>| v.len() / 2;
        let mut cases: Vec<HandshakeInit> = Vec::new();
        let mut c = m1.clone();
        c.eph_i[0] ^= 1;
        cases.push(c);
        let mut c = m1.clone();
        c.ratchet_pub_i[0] ^= 1;
        cases.push(c);
        let mut c = m1.clone();
        let i = mid(&c.kem_ct_s);
        c.kem_ct_s[i] ^= 1;
        cases.push(c);
        let mut c = m1.clone();
        let i = mid(&c.kem_ek_i);
        c.kem_ek_i[i] ^= 1;
        cases.push(c);
        let mut c = m1.clone();
        let i = mid(&c.sig_i.0);
        c.sig_i.0[i] ^= 1;
        cases.push(c);
        for c in cases {
            assert!(SecureSession::respond(&bob, alice.public(), B, &c).is_err());
        }
    }

    #[test]
    fn tampering_with_any_msg2_field_is_rejected() {
        let (alice, bob) = (id(), id());
        let (m1, pending) = SecureSession::initiate(&alice, bob.public(), B).unwrap();
        let (m2, _) = SecureSession::respond(&bob, alice.public(), B, &m1).unwrap();
        // `finish` consumes the pending state, so re-run for each tampered copy.
        let mut cases: Vec<HandshakeResp> = Vec::new();
        let mut c = m2.clone();
        c.eph_r[0] ^= 1;
        cases.push(c);
        let mut c = m2.clone();
        let i = c.kem_ct_e.len() / 2;
        c.kem_ct_e[i] ^= 1;
        cases.push(c);
        let mut c = m2.clone();
        let i = c.sig_r.0.len() / 2;
        c.sig_r.0[i] ^= 1;
        cases.push(c);
        // First case uses the pending we have; the rest need fresh handshakes.
        assert!(pending.finish(&cases[0]).is_err());
        for which in 1..cases.len() {
            let (m1, pending) = SecureSession::initiate(&alice, bob.public(), B).unwrap();
            let (mut m2, _) = SecureSession::respond(&bob, alice.public(), B, &m1).unwrap();
            if which == 1 {
                let i = m2.kem_ct_e.len() / 2;
                m2.kem_ct_e[i] ^= 1;
            } else {
                let i = m2.sig_r.0.len() / 2;
                m2.sig_r.0[i] ^= 1;
            }
            assert!(pending.finish(&m2).is_err());
        }
    }

    #[test]
    fn binding_must_match() {
        let (alice, bob) = (id(), id());
        let (m1, _) = SecureSession::initiate(&alice, bob.public(), b"one").unwrap();
        assert!(SecureSession::respond(&bob, alice.public(), b"two", &m1).is_err());
        let (m1, _) = SecureSession::initiate(&alice, bob.public(), b"").unwrap();
        assert!(SecureSession::respond(&bob, alice.public(), b"x", &m1).is_err());
        // Identical bindings (empty and non-empty) succeed.
        let _ = handshake(&alice, &bob, b"");
        let _ = handshake(&alice, &bob, b"same");
        // Oversized binding is rejected up front.
        let big = vec![0u8; MAX_HANDSHAKE_LEN + 1];
        assert!(matches!(
            SecureSession::initiate(&alice, bob.public(), &big),
            Err(Error::Verify(_))
        ));
    }

    #[test]
    fn replayed_msg1_yields_an_incompatible_session() {
        let (alice, bob) = (id(), id());
        let (m1, pending) = SecureSession::initiate(&alice, bob.public(), B).unwrap();
        let (m2, mut b1) = SecureSession::respond(&bob, alice.public(), B, &m1).unwrap();
        let (m2b, mut b2) = SecureSession::respond(&bob, alice.public(), B, &m1).unwrap();
        assert_ne!(m2.eph_r, m2b.eph_r);
        let mut a = pending.finish(&m2).unwrap();
        // Replayed responder → original initiator: neither direction works.
        let from_b2 = b2.seal(b"replay").unwrap();
        assert!(a.open(&from_b2).is_err());
        let from_a = a.seal(b"orig").unwrap();
        assert!(b2.open(&from_a).is_err());
        // The first responder still works.
        assert_eq!(b1.open(&from_a).unwrap(), b"orig");
    }

    #[test]
    fn decoders_round_trip_and_complete_a_handshake() {
        let (alice, bob) = (id(), id());
        let (m1, pending) = SecureSession::initiate(&alice, bob.public(), B).unwrap();
        let d1 = HandshakeInit::from_bytes(&m1.to_bytes()).unwrap();
        assert_eq!(d1.eph_i, m1.eph_i);
        assert_eq!(d1.ratchet_pub_i, m1.ratchet_pub_i);
        assert_eq!(d1.kem_ct_s, m1.kem_ct_s);
        assert_eq!(d1.kem_ek_i, m1.kem_ek_i);
        assert_eq!(d1.sig_i.0, m1.sig_i.0);
        let (m2, mut b) = SecureSession::respond(&bob, alice.public(), B, &d1).unwrap();
        let d2 = HandshakeResp::from_bytes(&m2.to_bytes()).unwrap();
        assert_eq!(d2.eph_r, m2.eph_r);
        assert_eq!(d2.kem_ct_e, m2.kem_ct_e);
        assert_eq!(d2.sig_r.0, m2.sig_r.0);
        let mut a = pending.finish(&d2).unwrap();
        let ct = a.seal(b"decoded").unwrap();
        assert_eq!(b.open(&ct).unwrap(), b"decoded");
    }

    #[test]
    fn malformed_msg1_is_rejected_without_panic() {
        let (alice, bob) = (id(), id());
        let (m1, _) = SecureSession::initiate(&alice, bob.public(), B).unwrap();
        let enc = m1.to_bytes();
        assert!(HandshakeInit::from_bytes(&[]).is_err());
        for n in 0..enc.len() {
            assert!(HandshakeInit::from_bytes(&enc[..n]).is_err(), "len {n}");
        }
        let mut extra = enc.clone();
        extra.push(0);
        assert!(HandshakeInit::from_bytes(&extra).is_err());
        assert!(HandshakeInit::from_bytes(&vec![0u8; MAX_HANDSHAKE_LEN + 1]).is_err());
        // Each length prefix set to u32::MAX or MAX + 1.
        let p0 = 64;
        let p1 = p0 + 4 + m1.kem_ct_s.len();
        let p2 = p1 + 4 + m1.kem_ek_i.len();
        for p in [p0, p1, p2] {
            for bad in [u32::MAX, MAX_HANDSHAKE_LEN as u32 + 1] {
                let mut v = enc.clone();
                v[p..p + 4].copy_from_slice(&bad.to_le_bytes());
                assert!(HandshakeInit::from_bytes(&v).is_err());
            }
        }
    }

    #[test]
    fn malformed_msg2_is_rejected_without_panic() {
        let (alice, bob) = (id(), id());
        let (_, m2, _, _) = handshake(&alice, &bob, B);
        let enc = m2.to_bytes();
        assert!(HandshakeResp::from_bytes(&[]).is_err());
        for n in 0..enc.len() {
            assert!(HandshakeResp::from_bytes(&enc[..n]).is_err(), "len {n}");
        }
        let mut extra = enc.clone();
        extra.push(0);
        assert!(HandshakeResp::from_bytes(&extra).is_err());
        assert!(HandshakeResp::from_bytes(&vec![0u8; MAX_HANDSHAKE_LEN + 1]).is_err());
        let p0 = 32;
        let p1 = p0 + 4 + m2.kem_ct_e.len();
        for p in [p0, p1] {
            for bad in [u32::MAX, MAX_HANDSHAKE_LEN as u32 + 1] {
                let mut v = enc.clone();
                v[p..p + 4].copy_from_slice(&bad.to_le_bytes());
                assert!(HandshakeResp::from_bytes(&v).is_err());
            }
        }
    }

    #[test]
    fn classical_handshake_has_no_kem_fields_and_works() {
        let (alice, bob) = (classical(), classical());
        let (m1, m2, mut a, mut b) = handshake(&alice, &bob, B);
        assert!(m1.kem_ct_s.is_empty() && m1.kem_ek_i.is_empty() && m2.kem_ct_e.is_empty());
        let ct = a.seal(b"c2s").unwrap();
        assert_eq!(b.open(&ct).unwrap(), b"c2s");
        let ct = b.seal(b"s2c").unwrap();
        assert_eq!(a.open(&ct).unwrap(), b"s2c");
    }

    #[test]
    fn classical_responder_rejects_kem_fields() {
        let (alice, bob) = (classical(), classical());
        let (mut m1, _) = SecureSession::initiate(&alice, bob.public(), B).unwrap();
        m1.kem_ct_s = vec![1u8; 16];
        // Not re-signed: signature check fails.
        assert!(SecureSession::respond(&bob, alice.public(), B, &m1).is_err());
        // Correctly re-signed: the KEM-field check fails.
        m1.sig_i = alice.sign(&t1_of(&m1, B, &alice, &bob));
        assert!(matches!(
            SecureSession::respond(&bob, alice.public(), B, &m1),
            Err(Error::Verify(_))
        ));
    }

    #[test]
    fn hybrid_responder_rejects_missing_kem_fields() {
        let (alice, bob) = (id(), id());
        let (mut m1, _) = SecureSession::initiate(&alice, bob.public(), B).unwrap();
        m1.kem_ek_i.clear();
        m1.sig_i = alice.sign(&t1_of(&m1, B, &alice, &bob));
        assert!(matches!(
            SecureSession::respond(&bob, alice.public(), B, &m1),
            Err(Error::Verify(_))
        ));
    }

    // ---- handshake hardening ----

    #[test]
    fn zero_eph_i_is_rejected_even_when_resigned() {
        let (alice, bob) = (id(), id());
        let (mut m1, _) = SecureSession::initiate(&alice, bob.public(), B).unwrap();
        m1.eph_i = [0u8; 32];
        m1.sig_i = alice.sign(&t1_of(&m1, B, &alice, &bob));
        assert!(matches!(
            SecureSession::respond(&bob, alice.public(), B, &m1),
            Err(Error::Verify(_))
        ));
    }

    #[test]
    fn zero_ratchet_pub_i_is_rejected_even_when_resigned() {
        let (alice, bob) = (id(), id());
        let (mut m1, _) = SecureSession::initiate(&alice, bob.public(), B).unwrap();
        m1.ratchet_pub_i = [0u8; 32];
        m1.sig_i = alice.sign(&t1_of(&m1, B, &alice, &bob));
        assert!(matches!(
            SecureSession::respond(&bob, alice.public(), B, &m1),
            Err(Error::Verify(_))
        ));
    }

    /// Re-sign a msg2 under `bob` over the T2 built from its current fields.
    fn resign_m2(m1: &HandshakeInit, m2: &mut HandshakeResp, a: &Keypair, b: &Keypair) {
        let mut prefix = t1_of(m1, B, a, b);
        put_lp(&mut prefix, &m1.sig_i.0);
        m2.sig_r = b.sign(&transcript_t2(&prefix, &m2.eph_r, &m2.kem_ct_e));
    }

    #[test]
    fn zero_eph_r_is_rejected_even_when_resigned() {
        let (alice, bob) = (id(), id());
        let (m1, pending) = SecureSession::initiate(&alice, bob.public(), B).unwrap();
        let (mut m2, _) = SecureSession::respond(&bob, alice.public(), B, &m1).unwrap();
        m2.eph_r = [0u8; 32];
        resign_m2(&m1, &mut m2, &alice, &bob);
        assert!(matches!(pending.finish(&m2), Err(Error::Verify(_))));
    }

    #[test]
    fn zero_ratchet_header_is_rejected_without_desync() {
        let (mut a, mut b) = pair();
        let mut frame = vec![0u8; 32];
        frame.extend_from_slice(&0u64.to_le_bytes());
        frame.extend_from_slice(&0u64.to_le_bytes());
        frame.extend_from_slice(&[0u8; 32]);
        assert!(matches!(b.open(&frame), Err(Error::Verify(_))));
        let ct = a.seal(b"still fine").unwrap();
        assert_eq!(b.open(&ct).unwrap(), b"still fine");
        let ct = b.seal(b"and back").unwrap();
        assert_eq!(a.open(&ct).unwrap(), b"and back");
    }

    #[test]
    fn hybrid_responder_rejects_emptied_kem_ct_e() {
        let (alice, bob) = (id(), id());
        let (m1, pending) = SecureSession::initiate(&alice, bob.public(), B).unwrap();
        let (mut m2, _) = SecureSession::respond(&bob, alice.public(), B, &m1).unwrap();
        m2.kem_ct_e.clear();
        resign_m2(&m1, &mut m2, &alice, &bob);
        assert!(matches!(pending.finish(&m2), Err(Error::Verify(_))));
    }

    #[test]
    fn mixed_suite_classical_initiator_hybrid_responder_uses_pq_legs() {
        let (alice, bob) = (classical(), id());
        let (m1, m2, mut a, mut b) = handshake(&alice, &bob, B);
        assert!(!m1.kem_ct_s.is_empty());
        assert!(!m1.kem_ek_i.is_empty());
        assert!(!m2.kem_ct_e.is_empty());
        let ct = a.seal(b"c2h").unwrap();
        assert_eq!(b.open(&ct).unwrap(), b"c2h");
        let ct = b.seal(b"h2c").unwrap();
        assert_eq!(a.open(&ct).unwrap(), b"h2c");
    }

    #[test]
    fn reflected_msg1_is_rejected() {
        let (alice, bob) = (id(), id());
        let (m1, _) = SecureSession::initiate(&alice, bob.public(), B).unwrap();
        assert!(SecureSession::respond(&alice, bob.public(), B, &m1).is_err());
        assert!(SecureSession::respond(&alice, alice.public(), B, &m1).is_err());
    }

    #[test]
    fn transcript_layout() {
        let (alice, bob) = (id(), id());
        let (m1, _) = SecureSession::initiate(&alice, bob.public(), B).unwrap();
        let t = t1_of(&m1, B, &alice, &bob);
        assert!(t.starts_with(b"lattice-session-hs-v3"));
        let (i, r) = (alice.public().to_bytes(), bob.public().to_bytes());
        let var = [
            B.len(),
            i.len(),
            r.len(),
            m1.kem_ct_s.len(),
            m1.kem_ek_i.len(),
        ];
        // domain + 5 length prefixes + eph_i + ratchet_pub_i + variable parts.
        assert_eq!(t.len(), 21 + 5 * 4 + 64 + var.iter().sum::<usize>());
    }

    #[test]
    fn build_ikm_is_plain_concatenation() {
        let (a, b, c, d) = (
            Zeroizing::new([1u8; 32]),
            Zeroizing::new([2u8; 32]),
            Zeroizing::new([3u8; 32]),
            Zeroizing::new([4u8; 32]),
        );
        let ikm = build_ikm([Some(&a), Some(&b), Some(&c), Some(&d)]);
        assert_eq!(ikm.len(), 128);
        assert_eq!(&ikm[32..64], &[2u8; 32]);
        let classical = build_ikm([Some(&a), None, Some(&c), None]);
        assert_eq!(classical.len(), 64);
        assert_eq!(&classical[32..], &[3u8; 32]);
    }
}
