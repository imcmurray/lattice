//! `lattice-identity` — post-quantum hybrid keypair as identity (DESIGN.md
//! ADR-004).
//!
//! An identity is derived deterministically from a BIP39 mnemonic:
//!
//! ```text
//! mnemonic --to_seed--> 64-byte seed --HKDF-SHA256(domain-separated)-->
//!     ├─ Ed25519 signing key      (classical signatures)
//!     ├─ X25519 agreement key     (classical key exchange)
//!     ├─ ML-DSA signing key       (PQ signatures)      [feature = "pq"]
//!     └─ ML-KEM decapsulation key (PQ key exchange)    [feature = "pq"]
//! ```
//!
//! `PeerId = BLAKE3(domain || suite || each public key)`, so the same mnemonic
//! always reproduces the same identity — that *is* the recovery story. Keys are
//! derived from the seed on demand and never stored expanded; the seed and
//! mnemonic are held in `Zeroizing` and wiped on drop.
//!
//! Hybrid rule: a signature is valid only if **every** present component
//! (Ed25519 and, for `Hybrid`, ML-DSA) verifies — secure if *either* primitive
//! holds (DESIGN.md §5). Every component signs the same bound message
//! (`lattice-sig-v2 ‖ suite ‖ PeerId ‖ len ‖ msg`), so a signature cannot be
//! moved between the Classical and Hybrid identities of one mnemonic (which
//! share an Ed25519 key), and a `Classical` identity rejects any signature
//! carrying a PQ part.
//!
//! Devices are authorized by a root-signed [`DeviceCert`] (mandatory expiry).
//! A root can also sign a [`RevocationList`] (`lattice-revocation-v1`): a
//! monotonic-`seq`, sorted, capped ([`MAX_REVOKED`]) set of revoked device
//! PeerIds. Checking one is the caller's job
//! ([`DeviceCert::verify_with_revocation`]); distributing lists is up to the
//! application (`lattice-net` sends them lazily in its auth bundles).
//!
//! Two people can compare a symmetric 60-digit [`safety_number`] of their two
//! root identities instead of two hex fingerprints (DESIGN.md §5.2). It is
//! display-only: comparing it is a manual step.

use lattice_core::{CryptoSuite, Error, Identity, PeerId, Result, Signature, Verify};

/// At-rest identity storage (keychain / age-encrypted file). `storage` feature.
#[cfg(feature = "storage")]
pub mod storage;

use bip39::Mnemonic;
use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "pq")]
use ml_dsa::{
    EncodedVerifyingKey as DsaEncodedVk, Keypair as DsaKeypair, MlDsa65, Signature as DsaSignature,
    SignatureEncoding, Signer as DsaSigner, SigningKey as DsaSigningKey, Verifier as DsaVerifier,
    VerifyingKey as DsaVerifyingKey, B32,
};
#[cfg(feature = "pq")]
use ml_kem::{
    Decapsulate, DecapsulationKey, EncapsulationKey, Key as MlKemKey, KeyExport, MlKem768,
    Seed as MlKemSeed, B32 as MlKemB32,
};

#[cfg(feature = "pq")]
type MlKemDk = DecapsulationKey<MlKem768>;

const HKDF_SALT: &[u8] = b"lattice-hkdf-v1";
const PEERID_DOMAIN: &[u8] = b"lattice-id-v1";
const DEVICE_CERT_DOMAIN: &[u8] = b"lattice-device-cert-v2";
/// Hard cap on an encoded [`DeviceCert`] (bytes).
const MAX_DEVICE_CERT_LEN: usize = 64 * 1024;
const SIG_DOMAIN: &[u8] = b"lattice-sig-v2";

/// Domain string of the safety number.
pub const SAFETY_NUMBER_DOMAIN: &[u8] = b"lattice-safety-number-v1";
/// Number of 5-digit groups (12 × 5 = 60 decimal digits).
pub const SAFETY_NUMBER_GROUPS: usize = 12;

/// Exclusive bound for rejection sampling: 167 × 100 000, the largest multiple
/// of 100 000 below 2^24.
const SAFETY_NUMBER_LIMIT: u32 = 16_700_000;

/// Symmetric safety number of two (root) identities: 12 groups of 5 decimal
/// digits separated by single spaces (71 chars).
/// `safety_number(a, b) == safety_number(b, a)`.
///
/// Construction (DESIGN.md §5.2; the hash is not iterated):
/// 1. Order the identities canonically: `(x, y) = if a.peer_id().0 <= b.peer_id().0
///    { (a, b) } else { (b, a) }` (raw 32 bytes, lexicographic).
/// 2. `h = blake3::Hasher::new()`; `h.update(SAFETY_NUMBER_DOMAIN)`; then for
///    each `p` in `[x, y]` with `bytes = p.to_bytes()`: `h.update(u32le(bytes.len()))`
///    and `h.update(bytes)`.
/// 3. Read the BLAKE3 XOF `h.finalize_xof()` three bytes at a time;
///    `v = u32le([b0, b1, b2, 0])`; if `v < 16_700_000` the group value is
///    `v % 100_000`, otherwise draw again (unbiased rejection sampling).
/// 4. Format each of the 12 groups as `{:05}`, joined by single spaces.
///
/// Never panics and never fails; identities of either suite are accepted.
pub fn safety_number(a: &PublicIdentity, b: &PublicIdentity) -> String {
    let (x, y) = if a.peer_id().0 <= b.peer_id().0 {
        (a, b)
    } else {
        (b, a)
    };
    let mut h = blake3::Hasher::new();
    h.update(SAFETY_NUMBER_DOMAIN);
    for p in [x, y] {
        let bytes = p.to_bytes();
        h.update(&(bytes.len() as u32).to_le_bytes());
        h.update(&bytes);
    }
    let mut xof = h.finalize_xof();
    let mut groups = Vec::with_capacity(SAFETY_NUMBER_GROUPS);
    while groups.len() < SAFETY_NUMBER_GROUPS {
        let mut b = [0u8; 3];
        xof.fill(&mut b);
        let v = u32::from_le_bytes([b[0], b[1], b[2], 0]);
        if v < SAFETY_NUMBER_LIMIT {
            groups.push(format!("{:05}", v % 100_000));
        }
    }
    groups.join(" ")
}

/// Low-order / non-canonical X25519 u-coordinates (libsodium `has_small_order`
/// blacklist, little-endian). Kept explicitly for documentation; the range
/// checks in [`x25519_public_ok`] already cover `p` and `p + 1`.
const X25519_BLACKLIST: [[u8; 32]; 7] = [
    [0; 32],
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    x25519_p_plus(0xec),
    x25519_p_plus(0xed),
    x25519_p_plus(0xee),
];

/// `ff × 30 ‖ 7f` with the given first byte: p − 1 (`ec`), p (`ed`), p + 1 (`ee`).
const fn x25519_p_plus(first: u8) -> [u8; 32] {
    let mut k = [0xffu8; 32];
    k[0] = first;
    k[31] = 0x7f;
    k
}

/// True iff `k` is an acceptable X25519 public key: bit 255 clear, little-endian
/// value < p = 2^255 - 19, and not one of the low-order u-coordinates above.
fn x25519_public_ok(k: &[u8; 32]) -> bool {
    if k[31] & 0x80 != 0 {
        return false;
    }
    // value >= p  <=>  top byte 0x7f, middle bytes all 0xff, first byte >= 0xed.
    if k[31] == 0x7f && k[1..31].iter().all(|&b| b == 0xff) && k[0] >= 0xed {
        return false;
    }
    !X25519_BLACKLIST.iter().any(|bad| bad == k)
}

/// The exact bytes both signature halves cover:
/// `SIG_DOMAIN ‖ suite_tag (1) ‖ peer_id (32) ‖ u32le(msg.len()) ‖ msg`.
/// Binding the signer's suite and PeerId keeps a signature from moving between
/// the identities (Classical / Hybrid) derived from one mnemonic.
fn bound_message(suite: CryptoSuite, peer_id: &PeerId, msg: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(SIG_DOMAIN.len() + 1 + 32 + 4 + msg.len());
    v.extend_from_slice(SIG_DOMAIN);
    v.push(suite_tag(suite));
    v.extend_from_slice(&peer_id.0);
    v.extend_from_slice(&(msg.len() as u32).to_le_bytes());
    v.extend_from_slice(msg);
    v
}

// ---------------------------------------------------------------------------
// Key derivation (deterministic; no RNG — that's what makes recovery work).
// ---------------------------------------------------------------------------

fn hkdf_expand(seed: &[u8; 64], info: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), seed);
    hk.expand(info, out)
        .expect("HKDF expand length within bounds");
}

fn ed_signing(seed: &[u8; 64]) -> EdSigningKey {
    let mut b = [0u8; 32];
    hkdf_expand(seed, b"lattice/ed25519", &mut b);
    let k = EdSigningKey::from_bytes(&b);
    b.zeroize();
    k
}

fn x_secret(seed: &[u8; 64]) -> XStaticSecret {
    let mut b = [0u8; 32];
    hkdf_expand(seed, b"lattice/x25519", &mut b);
    let s = XStaticSecret::from(b);
    b.zeroize();
    s
}

#[cfg(feature = "pq")]
fn dsa_signing(seed: &[u8; 64]) -> DsaSigningKey<MlDsa65> {
    let mut b = [0u8; 32];
    hkdf_expand(seed, b"lattice/ml-dsa", &mut b);
    let mut xi = B32::default();
    xi.copy_from_slice(&b);
    b.zeroize();
    DsaSigningKey::<MlDsa65>::from_seed(&xi)
}

#[cfg(feature = "pq")]
fn mlkem_dk(seed: &[u8; 64]) -> MlKemDk {
    let mut b = [0u8; 64];
    hkdf_expand(seed, b"lattice/ml-kem", &mut b);
    let mut s = MlKemSeed::default();
    s.copy_from_slice(&b);
    b.zeroize();
    MlKemDk::from_seed(s)
}

// ---------------------------------------------------------------------------
// Hybrid signature wire format: [u32 ed_len | ed_sig | u32 pq_len | pq_sig]
// ---------------------------------------------------------------------------

fn encode_hybrid(ed: &[u8], pq: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + ed.len() + pq.len());
    v.extend_from_slice(&(ed.len() as u32).to_le_bytes());
    v.extend_from_slice(ed);
    v.extend_from_slice(&(pq.len() as u32).to_le_bytes());
    v.extend_from_slice(pq);
    v
}

fn decode_hybrid(b: &[u8]) -> Option<(&[u8], &[u8])> {
    if b.len() < 4 {
        return None;
    }
    let ed_len = u32::from_le_bytes(b[0..4].try_into().ok()?) as usize;
    let mid = 4usize.checked_add(ed_len)?;
    if b.len() < mid.checked_add(4)? {
        return None;
    }
    let ed = &b[4..mid];
    let pq_len = u32::from_le_bytes(b[mid..mid + 4].try_into().ok()?) as usize;
    let end = mid.checked_add(4)?.checked_add(pq_len)?;
    if b.len() != end {
        return None;
    }
    Some((ed, &b[mid + 4..end]))
}

/// Split `n` bytes off the front of `rest`, or fail if fewer remain.
fn take<'a>(rest: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if n > rest.len() {
        return Err(Error::Crypto("truncated input".into()));
    }
    let (head, tail) = rest.split_at(n);
    *rest = tail;
    Ok(head)
}

fn take_u32(rest: &mut &[u8]) -> Result<u32> {
    let b = take(rest, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

// ---------------------------------------------------------------------------
// Public identity (the verifying half — no secrets).
// ---------------------------------------------------------------------------

/// A published, shareable public identity. Holds the public key bundle and the
/// derived [`PeerId`]; implements [`Verify`].
#[derive(Clone, Debug)]
pub struct PublicIdentity {
    suite: CryptoSuite,
    ed25519: [u8; 32],
    x25519: [u8; 32],
    /// Encoded ML-DSA verifying key (empty under `Classical`; only read when
    /// the `pq` feature is enabled).
    #[cfg_attr(not(feature = "pq"), allow(dead_code))]
    ml_dsa: Vec<u8>,
    /// Encoded ML-KEM encapsulation key (empty under `Classical`).
    ml_kem: Vec<u8>,
    peer_id: PeerId,
}

impl PublicIdentity {
    /// The crypto posture this identity was generated under.
    pub fn suite(&self) -> CryptoSuite {
        self.suite
    }

    /// Canonical wire encoding of the public key bundle (for sharing over a
    /// transport or in a ticket): `suite ‖ ed25519 ‖ x25519 ‖ len·ml_dsa ‖ len·ml_kem`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + 64 + 8 + self.ml_dsa.len() + self.ml_kem.len());
        v.push(suite_tag(self.suite));
        v.extend_from_slice(&self.ed25519);
        v.extend_from_slice(&self.x25519);
        v.extend_from_slice(&(self.ml_dsa.len() as u32).to_le_bytes());
        v.extend_from_slice(&self.ml_dsa);
        v.extend_from_slice(&(self.ml_kem.len() as u32).to_le_bytes());
        v.extend_from_slice(&self.ml_kem);
        v
    }

    /// Parse a public identity from [`PublicIdentity::to_bytes`], recomputing
    /// (and thereby binding) the `PeerId` from the key material.
    ///
    /// Strict and canonical: lengths are checked against the remaining input,
    /// trailing bytes are rejected, keys are validated, and every accepted
    /// input re-encodes to itself.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let mut rest = b;
        let suite = suite_from_tag(take(&mut rest, 1)?[0])?;
        let mut ed25519 = [0u8; 32];
        let mut x25519 = [0u8; 32];
        ed25519.copy_from_slice(take(&mut rest, 32)?);
        x25519.copy_from_slice(take(&mut rest, 32)?);
        let dsa_len = take_u32(&mut rest)? as usize;
        let ml_dsa = take(&mut rest, dsa_len)?;
        let kem_len = take_u32(&mut rest)? as usize;
        let ml_kem = take(&mut rest, kem_len)?;
        if !rest.is_empty() {
            return Err(Error::Crypto("trailing bytes after public identity".into()));
        }

        match EdVerifyingKey::from_bytes(&ed25519) {
            Ok(vk) if !vk.is_weak() => {}
            _ => return Err(Error::Crypto("invalid Ed25519 public key".into())),
        }
        if !x25519_public_ok(&x25519) {
            return Err(Error::Crypto("invalid X25519 public key".into()));
        }

        match suite {
            CryptoSuite::Classical => {
                if !ml_dsa.is_empty() || !ml_kem.is_empty() {
                    return Err(Error::Crypto(
                        "Classical identity carries post-quantum keys".into(),
                    ));
                }
            }
            CryptoSuite::Hybrid => {
                #[cfg(feature = "pq")]
                {
                    DsaEncodedVk::<MlDsa65>::try_from(ml_dsa)
                        .map_err(|_| Error::Crypto("malformed ML-DSA verifying key".into()))?;
                    let key = MlKemKey::<EncapsulationKey<MlKem768>>::try_from(ml_kem)
                        .map_err(|_| Error::Crypto("malformed ML-KEM encapsulation key".into()))?;
                    EncapsulationKey::<MlKem768>::new(&key)
                        .map_err(|_| Error::Crypto("invalid ML-KEM encapsulation key".into()))?;
                }
                #[cfg(not(feature = "pq"))]
                {
                    return Err(Error::Crypto(
                        "Hybrid identity requires the `pq` feature to validate".into(),
                    ));
                }
            }
        }

        let (ml_dsa, ml_kem) = (ml_dsa.to_vec(), ml_kem.to_vec());
        let peer_id = Self::compute_peer_id(suite, &ed25519, &x25519, &ml_dsa, &ml_kem);
        Ok(Self {
            suite,
            ed25519,
            x25519,
            ml_dsa,
            ml_kem,
            peer_id,
        })
    }
    /// Ed25519 public key bytes.
    pub fn ed25519_bytes(&self) -> [u8; 32] {
        self.ed25519
    }
    /// X25519 public key bytes (for classical key agreement).
    pub fn x25519_bytes(&self) -> [u8; 32] {
        self.x25519
    }
    /// Encoded ML-KEM encapsulation key (for PQ key agreement); empty if classical.
    pub fn ml_kem_bytes(&self) -> &[u8] {
        &self.ml_kem
    }

    /// Encapsulate a fresh shared secret to this identity's ML-KEM public key,
    /// returning `(ciphertext_bytes, shared_secret)`. Used by the session
    /// initiator (DESIGN.md §5.1, hybrid KEM).
    #[cfg(feature = "pq")]
    pub fn pq_encapsulate(&self) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
        pq_encapsulate_to(&self.ml_kem)
    }

    fn compute_peer_id(
        suite: CryptoSuite,
        ed: &[u8; 32],
        x: &[u8; 32],
        ml_dsa: &[u8],
        ml_kem: &[u8],
    ) -> PeerId {
        let mut h = blake3::Hasher::new();
        h.update(PEERID_DOMAIN);
        h.update(&[suite_tag(suite)]);
        for part in [ed.as_slice(), x.as_slice(), ml_dsa, ml_kem] {
            h.update(&(part.len() as u32).to_le_bytes());
            h.update(part);
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(h.finalize().as_bytes());
        PeerId(id)
    }
}

/// Encapsulate to an arbitrary encoded ML-KEM-768 encapsulation key, returning
/// `(ciphertext_bytes, shared_secret)`. A wrong-length key or one that fails
/// ML-KEM key validation gives [`Error::Crypto`]. Never panics.
#[cfg(feature = "pq")]
pub fn pq_encapsulate_to(ek_bytes: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    let key = MlKemKey::<EncapsulationKey<MlKem768>>::try_from(ek_bytes)
        .map_err(|_| Error::Crypto("malformed ML-KEM encapsulation key".into()))?;
    let ek = EncapsulationKey::<MlKem768>::new(&key)
        .map_err(|_| Error::Crypto("invalid ML-KEM encapsulation key".into()))?;
    let mut m = [0u8; 32];
    getrandom::getrandom(&mut m).map_err(|e| Error::Crypto(format!("rng: {e}")))?;
    let mm = MlKemB32::try_from(&m[..]).map_err(|_| Error::Crypto("kem coin".into()))?;
    m.zeroize();
    let (ct, ss) = ek.encapsulate_deterministic(&mm);
    let mut ssb = [0u8; 32];
    ssb.copy_from_slice(ss.as_slice());
    Ok((ct.as_slice().to_vec(), Zeroizing::new(ssb)))
}

/// Fresh, single-use ML-KEM-768 keypair for the v3 handshake (initiator side).
/// Deliberately not `Clone`, and its `Debug` output prints no key material.
#[cfg(feature = "pq")]
pub struct EphemeralKem {
    dk: MlKemDk,
    ek: Vec<u8>,
}

#[cfg(feature = "pq")]
impl std::fmt::Debug for EphemeralKem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EphemeralKem(..)")
    }
}

#[cfg(feature = "pq")]
impl EphemeralKem {
    /// Generate a fresh keypair from a random 64-byte seed (zeroized after use).
    pub fn generate() -> Result<Self> {
        let mut b = [0u8; 64];
        getrandom::getrandom(&mut b).map_err(|e| Error::Crypto(format!("rng: {e}")))?;
        let mut s = MlKemSeed::default();
        s.copy_from_slice(&b);
        b.zeroize();
        let dk = MlKemDk::from_seed(s);
        let ek = dk.encapsulation_key().to_bytes().to_vec();
        Ok(Self { dk, ek })
    }

    /// Encoded encapsulation key (1184 bytes for ML-KEM-768).
    pub fn encapsulation_key_bytes(&self) -> Vec<u8> {
        self.ek.clone()
    }

    /// Decapsulate `ct`, consuming the keypair (the secret key is dropped on
    /// return). A wrong-length ciphertext gives [`Error::Crypto`].
    pub fn decapsulate(self, ct: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let ss = self
            .dk
            .decapsulate_slice(ct)
            .map_err(|_| Error::Crypto("ML-KEM decapsulation failed".into()))?;
        let mut b = [0u8; 32];
        b.copy_from_slice(ss.as_slice());
        Ok(Zeroizing::new(b))
    }
}

fn suite_tag(suite: CryptoSuite) -> u8 {
    match suite {
        CryptoSuite::Classical => 0,
        CryptoSuite::Hybrid => 1,
    }
}

fn suite_from_tag(tag: u8) -> Result<CryptoSuite> {
    match tag {
        0 => Ok(CryptoSuite::Classical),
        1 => Ok(CryptoSuite::Hybrid),
        _ => Err(Error::Crypto("unknown crypto-suite tag".into())),
    }
}

impl Verify for PublicIdentity {
    fn peer_id(&self) -> PeerId {
        self.peer_id.clone()
    }

    #[cfg_attr(not(feature = "pq"), allow(unused_variables))]
    fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
        let Some((ed_sig, pq_sig)) = decode_hybrid(&sig.0) else {
            return false;
        };

        // A Classical identity carries no PQ component; reject any extra part.
        if self.suite == CryptoSuite::Classical && !pq_sig.is_empty() {
            return false;
        }

        let bound = bound_message(self.suite, &self.peer_id, msg);

        // Classical half (always required).
        let ed_arr: [u8; 64] = match ed_sig.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let vk = match EdVerifyingKey::from_bytes(&self.ed25519) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let ed_signature = ed25519_dalek::Signature::from_bytes(&ed_arr);
        if vk.verify_strict(&bound, &ed_signature).is_err() {
            return false;
        }

        // Post-quantum half (required under Hybrid).
        if self.suite == CryptoSuite::Hybrid {
            #[cfg(feature = "pq")]
            {
                let enc = match DsaEncodedVk::<MlDsa65>::try_from(self.ml_dsa.as_slice()) {
                    Ok(e) => e,
                    Err(_) => return false,
                };
                let pq_vk = DsaVerifyingKey::<MlDsa65>::decode(&enc);
                let pq_signature = match DsaSignature::<MlDsa65>::try_from(pq_sig) {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                if pq_vk.verify(&bound, &pq_signature).is_err() {
                    return false;
                }
            }
            #[cfg(not(feature = "pq"))]
            {
                // Hybrid identity but PQ support compiled out: cannot verify.
                return false;
            }
        }

        true
    }
}

// ---------------------------------------------------------------------------
// Keypair (the signing half — holds the seed).
// ---------------------------------------------------------------------------

/// A root keypair / identity. Holds the master seed (zeroized on drop) and the
/// cached public bundle. Derives signing keys on demand.
pub struct Keypair {
    suite: CryptoSuite,
    seed: Zeroizing<[u8; 64]>,
    mnemonic: Zeroizing<String>,
    public: PublicIdentity,
}

impl Keypair {
    /// Generate a fresh identity (24-word mnemonic) under the given posture.
    pub fn generate(suite: CryptoSuite) -> Result<Self> {
        let m = Mnemonic::generate(24).map_err(|e| Error::Crypto(format!("mnemonic gen: {e}")))?;
        Self::from_parsed(suite, m)
    }

    /// Recover an identity from its BIP39 mnemonic. Reproduces the same keys
    /// and [`PeerId`] as the original (DESIGN.md ADR-004 recovery).
    pub fn from_mnemonic(suite: CryptoSuite, phrase: &str) -> Result<Self> {
        let m =
            Mnemonic::parse(phrase).map_err(|e| Error::Crypto(format!("mnemonic parse: {e}")))?;
        Self::from_parsed(suite, m)
    }

    fn from_parsed(suite: CryptoSuite, m: Mnemonic) -> Result<Self> {
        let seed = m.to_seed("");
        let public = derive_public(suite, &seed)?;
        Ok(Self {
            suite,
            seed: Zeroizing::new(seed),
            mnemonic: Zeroizing::new(m.to_string()),
            public,
        })
    }

    /// The public identity (verifying half) to share with peers.
    pub fn public(&self) -> &PublicIdentity {
        &self.public
    }

    /// The backup mnemonic. Treat as a long-lived root secret (ADR-004).
    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    /// X25519 Diffie-Hellman between our static agreement secret and a peer's
    /// public key (session responder / classical half of the hybrid KEM).
    pub fn x25519_dh(&self, their_public: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        let sk = x_secret(&self.seed);
        let ss = sk.diffie_hellman(&XPublicKey::from(*their_public));
        Zeroizing::new(ss.to_bytes())
    }

    /// The X25519 static agreement secret (re-derived from the seed). The
    /// session layer does not use it (the handshake uses [`Keypair::x25519_dh`],
    /// and ratchet keys are fresh ephemerals); it exists only so tests can
    /// rebuild handshake state. Sensitive — never log or persist it.
    #[doc(hidden)]
    pub fn x25519_secret(&self) -> XStaticSecret {
        x_secret(&self.seed)
    }

    /// Decapsulate the ML-KEM shared secret from a ciphertext (session
    /// responder, PQ half of the hybrid KEM).
    #[cfg(feature = "pq")]
    pub fn pq_decapsulate(&self, ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let dk = mlkem_dk(&self.seed);
        let ss = dk
            .decapsulate_slice(ciphertext)
            .map_err(|_| Error::Crypto("ML-KEM decapsulation failed".into()))?;
        let mut b = [0u8; 32];
        b.copy_from_slice(ss.as_slice());
        Ok(Zeroizing::new(b))
    }

    /// Authorize a device's full public identity under this root identity until
    /// `not_after` (Unix seconds), returning a signed [`DeviceCert`] (ADR-004).
    /// Fails if `not_after == 0`, if a Hybrid root targets a Classical device,
    /// or if the device is the root itself.
    pub fn authorize_device(&self, device: &PublicIdentity, not_after: u64) -> Result<DeviceCert> {
        if not_after == 0 {
            return Err(Error::Crypto("device cert expiry must be non-zero".into()));
        }
        if self.public.suite() == CryptoSuite::Hybrid && device.suite() == CryptoSuite::Classical {
            return Err(Error::Crypto(
                "a Hybrid root cannot delegate to a Classical device".into(),
            ));
        }
        let root = self.public.peer_id();
        if device.peer_id() == root {
            return Err(Error::Crypto("device must differ from the root".into()));
        }
        let sig = self.sign(&DeviceCert::message(&root, device, not_after));
        Ok(DeviceCert {
            root,
            device: device.clone(),
            not_after,
            sig,
        })
    }
}

impl Identity for Keypair {
    fn peer_id(&self) -> PeerId {
        self.public.peer_id()
    }

    fn sign(&self, msg: &[u8]) -> Signature {
        let bound = bound_message(self.suite, &self.public.peer_id, msg);
        let ed_sig = ed_signing(&self.seed).sign(&bound).to_bytes();

        let pq_sig: Vec<u8> = match self.suite {
            CryptoSuite::Classical => Vec::new(),
            CryptoSuite::Hybrid => {
                #[cfg(feature = "pq")]
                {
                    let s: DsaSignature<MlDsa65> = dsa_signing(&self.seed).sign(&bound);
                    s.to_bytes().to_vec()
                }
                #[cfg(not(feature = "pq"))]
                {
                    Vec::new()
                }
            }
        };

        Signature(encode_hybrid(&ed_sig, &pq_sig))
    }
}

fn derive_public(suite: CryptoSuite, seed: &[u8; 64]) -> Result<PublicIdentity> {
    let ed25519 = ed_signing(seed).verifying_key().to_bytes();
    let x25519 = XPublicKey::from(&x_secret(seed)).to_bytes();

    let (ml_dsa, ml_kem) = match suite {
        CryptoSuite::Classical => (Vec::new(), Vec::new()),
        CryptoSuite::Hybrid => {
            #[cfg(feature = "pq")]
            {
                let dsa_vk = dsa_signing(seed).verifying_key().encode().to_vec();
                let kem_ek = mlkem_dk(seed).encapsulation_key().to_bytes().to_vec();
                (dsa_vk, kem_ek)
            }
            #[cfg(not(feature = "pq"))]
            {
                return Err(Error::Crypto(
                    "CryptoSuite::Hybrid requires the `pq` feature".into(),
                ));
            }
        }
    };

    let peer_id = PublicIdentity::compute_peer_id(suite, &ed25519, &x25519, &ml_dsa, &ml_kem);
    Ok(PublicIdentity {
        suite,
        ed25519,
        x25519,
        ml_dsa,
        ml_kem,
        peer_id,
    })
}

// ---------------------------------------------------------------------------
// Device delegation (multi-device, ADR-004).
// ---------------------------------------------------------------------------

/// A root-signed authorization binding a device's full public identity to a
/// root identity, with a mandatory expiry. The day-to-day signer is the device
/// key; the root (recoverable from the mnemonic) is used only to issue certs.
#[derive(Clone, Debug)]
pub struct DeviceCert {
    root: PeerId,
    device: PublicIdentity,
    /// Unix seconds; never 0.
    not_after: u64,
    sig: Signature,
}

impl DeviceCert {
    /// `DOMAIN ‖ root[32] ‖ u32le(len(dev)) ‖ dev ‖ u64le(not_after)`.
    fn message(root: &PeerId, device: &PublicIdentity, not_after: u64) -> Vec<u8> {
        let dev = device.to_bytes();
        let mut m = Vec::with_capacity(DEVICE_CERT_DOMAIN.len() + 32 + 4 + dev.len() + 8);
        m.extend_from_slice(DEVICE_CERT_DOMAIN);
        m.extend_from_slice(&root.0);
        m.extend_from_slice(&(dev.len() as u32).to_le_bytes());
        m.extend_from_slice(&dev);
        m.extend_from_slice(&not_after.to_le_bytes());
        m
    }

    /// The authorized device's public identity.
    pub fn device(&self) -> &PublicIdentity {
        &self.device
    }

    /// The issuing root's PeerId.
    pub fn root(&self) -> &PeerId {
        &self.root
    }

    /// Expiry (Unix seconds); the cert is valid while `now <= not_after`.
    pub fn not_after(&self) -> u64 {
        self.not_after
    }

    /// Verify this cert was issued by `root` and is unexpired at `now`.
    pub fn verify(&self, root: &PublicIdentity, now: u64) -> bool {
        if root.peer_id() != self.root
            || self.not_after == 0
            || self.device.peer_id() == self.root
            || (root.suite() == CryptoSuite::Hybrid
                && self.device.suite() == CryptoSuite::Classical)
            || now > self.not_after
        {
            return false;
        }
        root.verify(
            &Self::message(&self.root, &self.device, self.not_after),
            &self.sig,
        )
    }

    /// `root[32] ‖ u32le(len(dev)) ‖ dev ‖ u64le(not_after) ‖ u32le(len(sig)) ‖ sig`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let dev = self.device.to_bytes();
        let mut v = Vec::with_capacity(32 + 4 + dev.len() + 8 + 4 + self.sig.0.len());
        v.extend_from_slice(&self.root.0);
        v.extend_from_slice(&(dev.len() as u32).to_le_bytes());
        v.extend_from_slice(&dev);
        v.extend_from_slice(&self.not_after.to_le_bytes());
        v.extend_from_slice(&(self.sig.0.len() as u32).to_le_bytes());
        v.extend_from_slice(&self.sig.0);
        v
    }

    /// Strict parser for [`DeviceCert::to_bytes`]. Does not check the signature
    /// (no root is available here); callers must call [`DeviceCert::verify`].
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() > MAX_DEVICE_CERT_LEN {
            return Err(Error::Crypto("device cert too large".into()));
        }
        let mut rest = b;
        let mut root = [0u8; 32];
        root.copy_from_slice(take(&mut rest, 32)?);
        let dev_len = take_u32(&mut rest)? as usize;
        let device = PublicIdentity::from_bytes(take(&mut rest, dev_len)?)?;
        let na = take(&mut rest, 8)?;
        let not_after =
            u64::from_le_bytes([na[0], na[1], na[2], na[3], na[4], na[5], na[6], na[7]]);
        if not_after == 0 {
            return Err(Error::Crypto("device cert expiry must be non-zero".into()));
        }
        let sig_len = take_u32(&mut rest)? as usize;
        let sig = take(&mut rest, sig_len)?.to_vec();
        if !rest.is_empty() {
            return Err(Error::Crypto("trailing bytes after device cert".into()));
        }
        Ok(Self {
            root: PeerId(root),
            device,
            not_after,
            sig: Signature(sig),
        })
    }

    /// [`DeviceCert::verify`] and, if `revocation` is given, that the list is
    /// issued by this cert's root, verifies under `root`, and does not list
    /// this cert's device.
    pub fn verify_with_revocation(
        &self,
        root: &PublicIdentity,
        now: u64,
        revocation: Option<&RevocationList>,
    ) -> bool {
        if !self.verify(root, now) {
            return false;
        }
        match revocation {
            None => true,
            Some(l) => {
                l.root == self.root
                    && l.root == root.peer_id()
                    && l.verify(root)
                    && !l.is_revoked(&self.device.peer_id())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Signed revocation lists (`lattice-revocation-v1`).
// ---------------------------------------------------------------------------

/// Max entries in a [`RevocationList`].
pub const MAX_REVOKED: usize = 1024;
/// Hard cap on an encoded [`RevocationList`] (checked before any parsing or
/// allocation). Larger than the largest valid Hybrid-signed list with
/// [`MAX_REVOKED`] entries.
pub const MAX_REVOCATION_LIST_LEN: usize = 40 * 1024;
const REVOCATION_DOMAIN: &[u8] = b"lattice-revocation-v1";

/// A root-signed, monotonically numbered set of revoked device PeerIds.
///
/// A higher `seq` from the same root supersedes a lower one (and may un-revoke
/// a device — the root is the authority). Lists are tiny and travel in the
/// peer auth bundle; propagation is lazy.
#[derive(Clone, Debug)]
pub struct RevocationList {
    root: PeerId,
    seq: u64,
    issued_at: u64,
    revoked: Vec<PeerId>,
    sig: Signature,
}

impl RevocationList {
    /// `REVOCATION_DOMAIN ‖ root[32] ‖ u64le(seq) ‖ u64le(issued_at) ‖ u32le(n) ‖ n×peer_id[32]`.
    fn message(root: &PeerId, seq: u64, issued_at: u64, revoked: &[PeerId]) -> Vec<u8> {
        let mut m =
            Vec::with_capacity(REVOCATION_DOMAIN.len() + 32 + 8 + 8 + 4 + 32 * revoked.len());
        m.extend_from_slice(REVOCATION_DOMAIN);
        m.extend_from_slice(&root.0);
        m.extend_from_slice(&seq.to_le_bytes());
        m.extend_from_slice(&issued_at.to_le_bytes());
        m.extend_from_slice(&(revoked.len() as u32).to_le_bytes());
        for p in revoked {
            m.extend_from_slice(&p.0);
        }
        m
    }

    /// The issuing root.
    pub fn root(&self) -> &PeerId {
        &self.root
    }

    /// Monotonic sequence number.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Unix seconds at which the root issued this list (informational).
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// Revoked device PeerIds, sorted ascending by bytes, no duplicates.
    pub fn revoked(&self) -> &[PeerId] {
        &self.revoked
    }

    /// Whether `device` is listed. Pure; does not check the signature.
    pub fn is_revoked(&self, device: &PeerId) -> bool {
        self.revoked
            .binary_search_by(|p| p.0.cmp(&device.0))
            .is_ok()
    }

    /// True iff same root and `self.seq > other.seq`.
    pub fn supersedes(&self, other: &RevocationList) -> bool {
        self.root == other.root && self.seq > other.seq
    }

    /// Verify the list was signed by `root` and is well-formed. Never panics.
    pub fn verify(&self, root: &PublicIdentity) -> bool {
        if root.peer_id() != self.root
            || self.revoked.len() > MAX_REVOKED
            || !self.revoked.windows(2).all(|w| w[0].0 < w[1].0)
            || self.is_revoked(&self.root)
        {
            return false;
        }
        root.verify(
            &Self::message(&self.root, self.seq, self.issued_at, &self.revoked),
            &self.sig,
        )
    }

    /// `root[32] ‖ u64le(seq) ‖ u64le(issued_at) ‖ u32le(n) ‖ n×32 ‖ u32le(sig_len) ‖ sig`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v =
            Vec::with_capacity(32 + 8 + 8 + 4 + 32 * self.revoked.len() + 4 + self.sig.0.len());
        v.extend_from_slice(&self.root.0);
        v.extend_from_slice(&self.seq.to_le_bytes());
        v.extend_from_slice(&self.issued_at.to_le_bytes());
        v.extend_from_slice(&(self.revoked.len() as u32).to_le_bytes());
        for p in &self.revoked {
            v.extend_from_slice(&p.0);
        }
        v.extend_from_slice(&(self.sig.0.len() as u32).to_le_bytes());
        v.extend_from_slice(&self.sig.0);
        v
    }

    /// Strict parser for [`RevocationList::to_bytes`]. Does not check the
    /// signature; callers must call [`RevocationList::verify`].
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() > MAX_REVOCATION_LIST_LEN {
            return Err(Error::Crypto("revocation list too large".into()));
        }
        let mut rest = b;
        let mut root = [0u8; 32];
        root.copy_from_slice(take(&mut rest, 32)?);
        let seq = u64::from_le_bytes(take(&mut rest, 8)?.try_into().expect("8 bytes"));
        let issued_at = u64::from_le_bytes(take(&mut rest, 8)?.try_into().expect("8 bytes"));
        let n = take_u32(&mut rest)? as usize;
        if n > MAX_REVOKED {
            return Err(Error::Crypto("too many revoked devices".into()));
        }
        let raw = take(&mut rest, n * 32)?;
        let mut revoked: Vec<PeerId> = Vec::with_capacity(n);
        let (chunks, _) = raw.as_chunks::<32>();
        for &id in chunks {
            if let Some(prev) = revoked.last() {
                if prev.0 >= id {
                    return Err(Error::Crypto("revocation list not strictly sorted".into()));
                }
            }
            revoked.push(PeerId(id));
        }
        let sig_len = take_u32(&mut rest)? as usize;
        let sig = take(&mut rest, sig_len)?.to_vec();
        if !rest.is_empty() {
            return Err(Error::Crypto("trailing bytes after revocation list".into()));
        }
        Ok(Self {
            root: PeerId(root),
            seq,
            issued_at,
            revoked,
            sig: Signature(sig),
        })
    }
}

impl Keypair {
    /// Sign a revocation list under this (root) keypair. `devices` may be in
    /// any order and contain duplicates; they are sorted and deduplicated.
    /// Fails if the root's own PeerId is listed or if more than
    /// [`MAX_REVOKED`] distinct entries remain. An empty list is allowed.
    pub fn revoke_devices(
        &self,
        seq: u64,
        issued_at: u64,
        devices: &[PeerId],
    ) -> Result<RevocationList> {
        let root = self.public.peer_id();
        let mut revoked: Vec<PeerId> = devices.to_vec();
        revoked.sort_by_key(|p| p.0);
        revoked.dedup_by(|a, b| a.0 == b.0);
        if revoked.contains(&root) {
            return Err(Error::Crypto("cannot revoke the root itself".into()));
        }
        if revoked.len() > MAX_REVOKED {
            return Err(Error::Crypto("too many revoked devices".into()));
        }
        let sig = self.sign(&RevocationList::message(&root, seq, issued_at, &revoked));
        Ok(RevocationList {
            root,
            seq,
            issued_at,
            revoked,
            sig,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(n: u8) -> PeerId {
        PeerId([n; 32])
    }

    fn revocation_suites() -> Vec<CryptoSuite> {
        #[cfg(feature = "pq")]
        {
            vec![CryptoSuite::Classical, CryptoSuite::Hybrid]
        }
        #[cfg(not(feature = "pq"))]
        {
            vec![CryptoSuite::Classical]
        }
    }

    #[test]
    fn revoke_sorts_dedups_and_verifies() {
        for suite in revocation_suites() {
            let root = Keypair::generate(suite).unwrap();
            let l = root
                .revoke_devices(3, 10, &[pid(9), pid(2), pid(9), pid(5)])
                .unwrap();
            assert_eq!(l.revoked(), &[pid(2), pid(5), pid(9)]);
            assert!(l.verify(root.public()));
            assert!(l.is_revoked(&pid(5)) && !l.is_revoked(&pid(6)));
            assert_eq!((l.seq(), l.issued_at()), (3, 10));
            let rt = RevocationList::from_bytes(&l.to_bytes()).unwrap();
            assert_eq!(rt.to_bytes(), l.to_bytes());
            assert!(rt.verify(root.public()));
            let other = Keypair::generate(suite).unwrap();
            assert!(!l.verify(other.public()));
        }
    }

    #[test]
    fn revoke_limits() {
        for suite in revocation_suites() {
            let root = Keypair::generate(suite).unwrap();
            assert!(root.revoke_devices(1, 1, &[]).is_ok());
            assert!(root.revoke_devices(1, 1, &[root.peer_id()]).is_err());
            let ids = |n: usize| -> Vec<PeerId> {
                (0..n)
                    .map(|i| {
                        let mut b = [0u8; 32];
                        b[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
                        PeerId(b)
                    })
                    .collect()
            };
            assert!(root.revoke_devices(1, 1, &ids(MAX_REVOKED + 1)).is_err());
            let max = root.revoke_devices(1, 1, &ids(MAX_REVOKED)).unwrap();
            assert!(max.to_bytes().len() <= MAX_REVOCATION_LIST_LEN);
            assert!(max.verify(root.public()));
        }
    }

    #[test]
    fn revocation_tamper_and_parse_rejections() {
        let root = Keypair::generate(CryptoSuite::Classical).unwrap();
        let l = root.revoke_devices(1, 2, &[pid(3), pid(4)]).unwrap();
        let good = l.to_bytes();
        // Flip one byte in every field region (root, seq, issued_at, entries, sig).
        for i in [0usize, 32, 40, 52, 84, good.len() - 1] {
            let mut t = good.clone();
            t[i] ^= 1;
            if let Ok(p) = RevocationList::from_bytes(&t) {
                assert!(!p.verify(root.public()), "byte {i}");
            }
        }
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(RevocationList::from_bytes(&trailing).is_err());
        assert!(RevocationList::from_bytes(&good[..good.len() - 1]).is_err());
        let mut huge = good[..52].to_vec();
        huge[48..52].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(RevocationList::from_bytes(&huge).is_err());
        assert!(RevocationList::from_bytes(&vec![0u8; MAX_REVOCATION_LIST_LEN + 1]).is_err());
        // Unsorted and duplicate entries.
        let mut unsorted = good.clone();
        unsorted[52..84].fill(4);
        unsorted[84..116].fill(3);
        assert!(RevocationList::from_bytes(&unsorted).is_err());
        let mut dup = good.clone();
        dup[84..116].fill(3);
        assert!(RevocationList::from_bytes(&dup).is_err());
    }

    #[test]
    fn supersedes_rules() {
        let a = Keypair::generate(CryptoSuite::Classical).unwrap();
        let b = Keypair::generate(CryptoSuite::Classical).unwrap();
        let l1 = a.revoke_devices(1, 0, &[]).unwrap();
        let l2 = a.revoke_devices(2, 0, &[]).unwrap();
        let m2 = b.revoke_devices(2, 0, &[]).unwrap();
        assert!(l2.supersedes(&l1));
        assert!(!l1.supersedes(&l2) && !l1.supersedes(&l1.clone()));
        assert!(!m2.supersedes(&l1));
    }

    #[test]
    fn verify_with_revocation_cases() {
        for suite in revocation_suites() {
            let root = Keypair::generate(suite).unwrap();
            let dev = Keypair::generate(suite).unwrap();
            let cert = root.authorize_device(dev.public(), 100).unwrap();
            assert!(cert.verify_with_revocation(root.public(), 50, None));
            let ok = root.revoke_devices(1, 0, &[pid(1)]).unwrap();
            assert!(cert.verify_with_revocation(root.public(), 50, Some(&ok)));
            let bad = root.revoke_devices(2, 0, &[dev.peer_id()]).unwrap();
            assert!(!cert.verify_with_revocation(root.public(), 50, Some(&bad)));
            let other = Keypair::generate(suite).unwrap();
            let foreign = other.revoke_devices(1, 0, &[]).unwrap();
            assert!(!cert.verify_with_revocation(root.public(), 50, Some(&foreign)));
            assert!(!cert.verify_with_revocation(root.public(), 101, None));
        }
    }

    #[cfg(feature = "pq")]
    #[test]
    fn sign_verify_roundtrip_hybrid() {
        let kp = Keypair::generate(CryptoSuite::Hybrid).unwrap();
        let msg = b"attack at dawn";
        let sig = kp.sign(msg);
        assert!(kp.public().verify(msg, &sig), "valid signature must verify");
        assert!(
            !kp.public().verify(b"attack at dusk", &sig),
            "wrong message must fail"
        );
    }

    #[test]
    fn sign_verify_roundtrip_classical() {
        let kp = Keypair::generate(CryptoSuite::Classical).unwrap();
        let msg = b"classical path";
        let sig = kp.sign(msg);
        assert!(kp.public().verify(msg, &sig));
        // Classical signatures carry no PQ component.
        let (_, pq) = decode_hybrid(&sig.0).unwrap();
        assert!(pq.is_empty());
    }

    fn mnemonic_recovery_for(suite: CryptoSuite) {
        let original = Keypair::generate(suite).unwrap();
        let phrase = original.mnemonic().to_string();

        let recovered = Keypair::from_mnemonic(suite, &phrase).unwrap();
        assert_eq!(
            original.peer_id(),
            recovered.peer_id(),
            "same mnemonic must reproduce the same PeerId"
        );

        // A signature from the original verifies under the recovered public id.
        let sig = original.sign(b"continuity");
        assert!(recovered.public().verify(b"continuity", &sig));
    }

    #[test]
    fn mnemonic_recovery_reproduces_identity_classical() {
        mnemonic_recovery_for(CryptoSuite::Classical);
    }

    #[cfg(feature = "pq")]
    #[test]
    fn mnemonic_recovery_reproduces_identity() {
        mnemonic_recovery_for(CryptoSuite::Hybrid);
    }

    fn tampered_signature_for(suite: CryptoSuite) {
        let kp = Keypair::generate(suite).unwrap();
        let mut sig = kp.sign(b"payload");
        let last = sig.0.len() - 1;
        sig.0[last] ^= 0x01;
        assert!(!kp.public().verify(b"payload", &sig));
    }

    #[test]
    fn tampered_signature_fails_classical() {
        tampered_signature_for(CryptoSuite::Classical);
    }

    #[cfg(feature = "pq")]
    #[test]
    fn tampered_signature_fails() {
        tampered_signature_for(CryptoSuite::Hybrid);
    }

    fn public_identity_roundtrip_for(suite: CryptoSuite) {
        let kp = Keypair::generate(suite).unwrap();
        let bytes = kp.public().to_bytes();
        let parsed = PublicIdentity::from_bytes(&bytes).unwrap();
        assert_eq!(
            parsed.peer_id(),
            kp.peer_id(),
            "round-trip preserves identity"
        );
        // A signature from the original verifies under the parsed public id.
        let sig = kp.sign(b"wire");
        assert!(parsed.verify(b"wire", &sig));
    }

    #[test]
    fn public_identity_serialization_roundtrip_classical() {
        public_identity_roundtrip_for(CryptoSuite::Classical);
    }

    #[cfg(feature = "pq")]
    #[test]
    fn public_identity_serialization_roundtrip() {
        public_identity_roundtrip_for(CryptoSuite::Hybrid);
    }

    const MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const MSG: &[u8] = b"bind me to my identity";

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    fn classical() -> Keypair {
        Keypair::from_mnemonic(CryptoSuite::Classical, MNEMONIC).unwrap()
    }

    #[cfg(feature = "pq")]
    fn pair() -> (Keypair, Keypair) {
        (
            classical(),
            Keypair::from_mnemonic(CryptoSuite::Hybrid, MNEMONIC).unwrap(),
        )
    }

    #[test]
    fn classical_peer_id_is_stable_for_fixed_mnemonic() {
        assert_eq!(
            classical().peer_id().0,
            hex32("39e4342c8705ea0a485f78880b94d5f19af0a2b4ffbbc945a4aaafe6c22e63ca")
        );
    }

    #[cfg(feature = "pq")]
    #[test]
    fn peer_ids_are_stable_for_fixed_mnemonic() {
        let (c, h) = pair();
        assert_eq!(
            c.peer_id().0,
            hex32("39e4342c8705ea0a485f78880b94d5f19af0a2b4ffbbc945a4aaafe6c22e63ca")
        );
        assert_eq!(
            h.peer_id().0,
            hex32("3a922421c64cc123866e6c7fa9e9a35a39918075134ff2ea3090eea283a219fe")
        );
        assert_ne!(c.peer_id(), h.peer_id());
        assert_eq!(c.public().ed25519_bytes(), h.public().ed25519_bytes());
    }

    #[test]
    fn bound_message_layout() {
        let pid = PeerId([7u8; 32]);
        let b = bound_message(CryptoSuite::Hybrid, &pid, b"abc");
        let mut want = b"lattice-sig-v2".to_vec();
        want.push(1);
        want.extend_from_slice(&[7u8; 32]);
        want.extend_from_slice(&3u32.to_le_bytes());
        want.extend_from_slice(b"abc");
        assert_eq!(b, want);
        assert_eq!(bound_message(CryptoSuite::Classical, &pid, b"")[14], 0);
    }

    #[cfg(feature = "pq")]
    #[test]
    fn cross_suite_strip_is_rejected() {
        let (c, h) = pair();
        let sig = h.sign(MSG);
        let (ed, _) = decode_hybrid(&sig.0).unwrap();
        let stripped = Signature(encode_hybrid(ed, &[]));
        assert!(!c.public().verify(MSG, &stripped));
    }

    #[cfg(feature = "pq")]
    #[test]
    fn signatures_do_not_cross_suites() {
        let (c, h) = pair();
        assert!(!h.public().verify(MSG, &c.sign(MSG)));
        assert!(!c.public().verify(MSG, &h.sign(MSG)));
    }

    #[test]
    fn classical_rejects_non_empty_pq_part() {
        let c = classical();
        let sig = c.sign(MSG);
        let (ed, _) = decode_hybrid(&sig.0).unwrap();
        assert!(c.public().verify(MSG, &sig));
        let padded = Signature(encode_hybrid(ed, &[0u8; 16]));
        assert!(!c.public().verify(MSG, &padded));
    }

    #[cfg(feature = "pq")]
    #[test]
    fn classical_rejects_hybrid_pq_part() {
        let (c, h) = pair();
        let csig = c.sign(MSG);
        let (ed, _) = decode_hybrid(&csig.0).unwrap();
        let hsig = h.sign(MSG);
        let (_, pq) = decode_hybrid(&hsig.0).unwrap();
        let with_pq = Signature(encode_hybrid(ed, pq));
        assert!(!c.public().verify(MSG, &with_pq));
    }

    #[test]
    fn raw_unbound_ed25519_is_rejected() {
        let c = classical();
        let raw = ed_signing(&c.seed).sign(MSG).to_bytes();
        let sig = Signature(encode_hybrid(&raw, &[]));
        assert!(!c.public().verify(MSG, &sig));
    }

    #[test]
    fn signature_does_not_verify_under_other_identity() {
        #[cfg(feature = "pq")]
        let suites = [CryptoSuite::Classical, CryptoSuite::Hybrid];
        #[cfg(not(feature = "pq"))]
        let suites = [CryptoSuite::Classical];
        for suite in suites {
            let a = Keypair::generate(suite).unwrap();
            let b = Keypair::generate(suite).unwrap();
            let sig = a.sign(MSG);
            assert!(a.public().verify(MSG, &sig));
            assert!(!b.public().verify(MSG, &sig));
        }
    }

    #[test]
    fn empty_message_roundtrip_and_wrong_message() {
        let c = classical();
        #[cfg(feature = "pq")]
        let kps = [c, pair().1];
        #[cfg(not(feature = "pq"))]
        let kps = [c];
        for kp in &kps {
            let sig = kp.sign(b"");
            assert!(kp.public().verify(b"", &sig));
            assert!(!kp.public().verify(b"x", &sig));
            let sig2 = kp.sign(MSG);
            assert!(!kp.public().verify(b"", &sig2));
        }
    }

    #[test]
    fn malformed_signatures_return_false() {
        let c = classical();
        assert!(!c.public().verify(MSG, &Signature(vec![])));
        assert!(!c.public().verify(MSG, &Signature(vec![1, 0, 0])));
        let short = Signature(encode_hybrid(&[0u8; 63], &[]));
        assert!(!c.public().verify(MSG, &short));
        let mut trunc = c.sign(MSG);
        trunc.0.truncate(trunc.0.len() - 1);
        assert!(!c.public().verify(MSG, &trunc));
    }

    #[cfg(feature = "pq")]
    #[test]
    fn ephemeral_kem_roundtrip() {
        let k = EphemeralKem::generate().unwrap();
        let ek = k.encapsulation_key_bytes();
        assert_eq!(ek.len(), 1184);
        let (ct, ss) = pq_encapsulate_to(&ek).unwrap();
        assert_eq!(*k.decapsulate(&ct).unwrap(), *ss);
    }

    #[cfg(feature = "pq")]
    #[test]
    fn ephemeral_kems_are_distinct() {
        let a = EphemeralKem::generate().unwrap();
        let b = EphemeralKem::generate().unwrap();
        assert_ne!(a.encapsulation_key_bytes(), b.encapsulation_key_bytes());
    }

    #[cfg(feature = "pq")]
    #[test]
    fn pq_encapsulate_to_rejects_bad_keys() {
        let ek = EphemeralKem::generate().unwrap().encapsulation_key_bytes();
        assert!(matches!(pq_encapsulate_to(&[]), Err(Error::Crypto(_))));
        assert!(matches!(
            pq_encapsulate_to(&ek[..ek.len() - 1]),
            Err(Error::Crypto(_))
        ));
        let mut long = ek.clone();
        long.push(0);
        assert!(matches!(pq_encapsulate_to(&long), Err(Error::Crypto(_))));
        assert!(matches!(
            pq_encapsulate_to(&vec![0xFFu8; 1184]),
            Err(Error::Crypto(_))
        ));
    }

    #[cfg(feature = "pq")]
    #[test]
    fn ephemeral_decapsulate_rejects_wrong_length_ct() {
        let k = EphemeralKem::generate().unwrap();
        assert!(matches!(k.decapsulate(&[0u8; 10]), Err(Error::Crypto(_))));
    }

    #[cfg(feature = "pq")]
    #[test]
    fn identity_pq_encapsulate_matches_decapsulate() {
        let kp = Keypair::generate(CryptoSuite::Hybrid).unwrap();
        let (ct, ss) = kp.public().pq_encapsulate().unwrap();
        assert_eq!(*kp.pq_decapsulate(&ct).unwrap(), *ss);
    }

    #[test]
    fn device_cert_roundtrip_classical() {
        let root = Keypair::generate(CryptoSuite::Classical).unwrap();
        let device = Keypair::generate(CryptoSuite::Classical).unwrap();
        let cert = root.authorize_device(device.public(), 1000).unwrap();

        assert!(cert.verify(root.public(), 1000));
        assert!(!cert.verify(root.public(), 1001));
        assert_eq!(cert.not_after(), 1000);
        assert_eq!(*cert.root(), root.peer_id());
        assert_eq!(cert.device().peer_id(), device.peer_id());

        let parsed = DeviceCert::from_bytes(&cert.to_bytes()).unwrap();
        assert_eq!(parsed.to_bytes(), cert.to_bytes());
        assert!(parsed.verify(root.public(), 5));

        let imposter = Keypair::generate(CryptoSuite::Classical).unwrap();
        assert!(!cert.verify(imposter.public(), 5));
        assert!(root.authorize_device(root.public(), 1000).is_err());
        assert!(root.authorize_device(device.public(), 0).is_err());
    }

    #[test]
    fn decode_hybrid_rejects_trailing_bytes() {
        let mut e = encode_hybrid(&[1, 2], &[3]);
        assert!(decode_hybrid(&e).is_some());
        e.push(0);
        assert!(decode_hybrid(&e).is_none());
    }

    #[test]
    fn public_identity_rejects_trailing_and_weak_key() {
        let kp = Keypair::generate(CryptoSuite::Classical).unwrap();
        let mut b = kp.public().to_bytes();
        assert_eq!(PublicIdentity::from_bytes(&b).unwrap().to_bytes(), b);
        b[1] = 1;
        b[2..33].fill(0);
        assert!(PublicIdentity::from_bytes(&b).is_err());
        let mut t = kp.public().to_bytes();
        t.push(0);
        assert!(PublicIdentity::from_bytes(&t).is_err());
    }

    #[cfg(feature = "pq")]
    #[test]
    fn device_cert_roundtrip_hybrid() {
        let root = Keypair::generate(CryptoSuite::Hybrid).unwrap();
        let device = Keypair::generate(CryptoSuite::Hybrid).unwrap();
        let cert = root.authorize_device(device.public(), 1000).unwrap();
        let parsed = DeviceCert::from_bytes(&cert.to_bytes()).unwrap();
        assert!(parsed.verify(root.public(), 1000));
        let classical = Keypair::generate(CryptoSuite::Classical).unwrap();
        assert!(root.authorize_device(classical.public(), 1000).is_err());
        assert_eq!(
            PublicIdentity::from_bytes(&device.public().to_bytes())
                .unwrap()
                .peer_id(),
            device.peer_id()
        );
    }

    // ----- safety numbers -----

    fn gen_classical() -> Keypair {
        Keypair::generate(CryptoSuite::Classical).unwrap()
    }

    fn well_formed(sn: &str) -> bool {
        sn.len() == 71
            && sn.split(' ').count() == SAFETY_NUMBER_GROUPS
            && sn
                .split(' ')
                .all(|g| g.len() == 5 && g.bytes().all(|c| c.is_ascii_digit()))
    }

    #[test]
    fn safety_number_constants() {
        assert_eq!(SAFETY_NUMBER_DOMAIN, b"lattice-safety-number-v1");
        assert_eq!(SAFETY_NUMBER_GROUPS, 12);
    }

    #[test]
    fn safety_number_is_symmetric_and_well_formed() {
        let (a, b) = (gen_classical(), gen_classical());
        let ab = safety_number(a.public(), b.public());
        assert_eq!(ab, safety_number(b.public(), a.public()));
        assert!(well_formed(&ab), "{ab}");
        #[cfg(feature = "pq")]
        {
            let (h1, h2) = (
                Keypair::generate(CryptoSuite::Hybrid).unwrap(),
                Keypair::generate(CryptoSuite::Hybrid).unwrap(),
            );
            assert_eq!(
                safety_number(h1.public(), h2.public()),
                safety_number(h2.public(), h1.public())
            );
        }
    }

    #[test]
    fn safety_number_same_identity_is_well_formed() {
        let a = gen_classical();
        assert!(well_formed(&safety_number(a.public(), a.public())));
    }

    #[test]
    fn safety_number_changes_with_either_input() {
        let (a, b, c) = (gen_classical(), gen_classical(), gen_classical());
        let ab = safety_number(a.public(), b.public());
        assert_ne!(ab, safety_number(a.public(), c.public()));
        assert_ne!(ab, safety_number(c.public(), b.public()));
    }

    #[test]
    fn safety_number_is_deterministic() {
        let a = classical();
        let b = Keypair::from_mnemonic(
            CryptoSuite::Classical,
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        )
        .unwrap();
        let n1 = safety_number(a.public(), b.public());
        let a2 = PublicIdentity::from_bytes(&a.public().to_bytes()).unwrap();
        let b2 = Keypair::from_mnemonic(CryptoSuite::Classical, b.mnemonic()).unwrap();
        assert_eq!(n1, safety_number(&a2, b2.public()));
        assert_eq!(n1, safety_number(a.public(), b.public()));
    }

    #[cfg(feature = "pq")]
    #[test]
    fn safety_number_differs_between_suites_of_one_mnemonic() {
        let (c, h) = pair();
        let peer = gen_classical();
        assert_ne!(
            safety_number(c.public(), peer.public()),
            safety_number(h.public(), peer.public())
        );
    }

    #[test]
    fn safety_number_matches_documented_construction() {
        let a = classical();
        let b = Keypair::from_mnemonic(
            CryptoSuite::Classical,
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        )
        .unwrap();
        let (x, y) = if a.public().peer_id().0 <= b.public().peer_id().0 {
            (a.public(), b.public())
        } else {
            (b.public(), a.public())
        };
        let mut h = blake3::Hasher::new();
        h.update(b"lattice-safety-number-v1");
        for p in [x, y] {
            let bytes = p.to_bytes();
            h.update(&(bytes.len() as u32).to_le_bytes());
            h.update(&bytes);
        }
        let mut xof = h.finalize_xof();
        let mut groups = Vec::new();
        while groups.len() < 12 {
            let mut buf = [0u8; 3];
            xof.fill(&mut buf);
            let v = u32::from(buf[0]) | (u32::from(buf[1]) << 8) | (u32::from(buf[2]) << 16);
            if v < 16_700_000 {
                groups.push(format!("{:05}", v % 100_000));
            }
        }
        let expected = groups.join(" ");
        assert_eq!(safety_number(a.public(), b.public()), expected);
        assert_eq!(safety_number(b.public(), a.public()), expected);
    }

    // ----- X25519 public key validation -----

    fn with_x25519(id: &PublicIdentity, k: [u8; 32]) -> Vec<u8> {
        let mut b = id.to_bytes();
        b[33..65].copy_from_slice(&k);
        b
    }

    #[test]
    fn from_bytes_rejects_blacklisted_x25519_keys() {
        let kp = gen_classical();
        for bad in X25519_BLACKLIST {
            assert!(matches!(
                PublicIdentity::from_bytes(&with_x25519(kp.public(), bad)),
                Err(Error::Crypto(_))
            ));
        }
        // The list matches the spec's hex (libsodium has_small_order).
        assert_eq!(
            X25519_BLACKLIST[2],
            hex32("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")
        );
        assert_eq!(
            X25519_BLACKLIST[3],
            hex32("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157")
        );
    }

    #[test]
    fn from_bytes_rejects_non_canonical_x25519_keys() {
        let kp = gen_classical();
        let mut p_plus_2 = [0xffu8; 32];
        p_plus_2[0] = 0xef;
        p_plus_2[31] = 0x7f;
        let mut all_ff_7f = [0xffu8; 32];
        all_ff_7f[31] = 0x7f;
        let mut high_bit = kp.public().x25519_bytes();
        high_bit[31] |= 0x80;
        for bad in [p_plus_2, all_ff_7f, high_bit] {
            assert!(matches!(
                PublicIdentity::from_bytes(&with_x25519(kp.public(), bad)),
                Err(Error::Crypto(_))
            ));
        }
    }

    #[test]
    fn generated_keys_round_trip_through_from_bytes() {
        for _ in 0..256 {
            let kp = gen_classical();
            assert!(PublicIdentity::from_bytes(&kp.public().to_bytes()).is_ok());
        }
        #[cfg(feature = "pq")]
        for _ in 0..16 {
            let kp = Keypair::generate(CryptoSuite::Hybrid).unwrap();
            assert!(PublicIdentity::from_bytes(&kp.public().to_bytes()).is_ok());
        }
    }

    /// Known-answer test pinning Lattice's post-quantum outputs across dependency
    /// updates (values generated with ml-dsa 0.1.1 / ml-kem 0.3.2 at main ece4d2d).
    /// A crate bump that changes key generation, signing, encapsulation or
    /// decapsulation output fails here instead of silently changing identities or
    /// breaking interop.
    #[cfg(feature = "pq")]
    #[test]
    fn pq_outputs_match_known_answers() {
        let hex = |b: &[u8]| blake3::hash(b).to_hex().to_string();
        // Hybrid signature: Ed25519 + ML-DSA-65, both deterministic.
        let (_, h) = pair();
        let sig = h.sign(b"lattice pq known-answer test");
        assert_eq!(sig.0.len(), 3381);
        assert_eq!(
            hex(&sig.0),
            "cdb15f61a5aa94e427b1b6f24aebfe1340eecf519a126668a4eef5f825cf6c08"
        );
        // ML-KEM-768: key generation from a fixed seed.
        let mut seed = MlKemSeed::default();
        seed.copy_from_slice(&[0x42u8; 64]);
        let dk = MlKemDk::from_seed(seed);
        let ek = dk.encapsulation_key().clone();
        assert_eq!(
            hex(&ek.to_bytes()),
            "fa88246c20b3b266f6dd762098c644f8758af78f1214964c87e50ac969082eb3"
        );
        // Deterministic encapsulation with fixed randomness.
        let (ct, ss) = ek.encapsulate_deterministic(&MlKemB32::from([0x24u8; 32]));
        assert_eq!(
            hex(ct.as_slice()),
            "6b9d7dd4f32be638ad2a2827bcd3c25dc1775227ce7cfffa6966f9aca01e366b"
        );
        let want_ss = "bcf2af3bd39ae7ab59ce584a3731e1b93fdefba36d30a828275d1aabf5d27d1e";
        assert_eq!(hex_encode(ss.as_slice()), want_ss);
        // Decapsulation through Lattice's own wrapper recovers the same secret.
        let kem = EphemeralKem {
            dk,
            ek: ek.to_bytes().to_vec(),
        };
        let got = kem.decapsulate(ct.as_slice()).unwrap();
        assert_eq!(hex_encode(&got[..]), want_ss);
    }

    #[cfg(feature = "pq")]
    fn hex_encode(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
