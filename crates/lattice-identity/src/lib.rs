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
//! holds (DESIGN.md §5).

use lattice_core::{CryptoSuite, Error, Identity, PeerId, Result, Signature, Verify};

use bip39::Mnemonic;
use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "pq")]
use ml_dsa::{
    B32, EncodedVerifyingKey as DsaEncodedVk, Keypair as DsaKeypair, MlDsa65,
    Signature as DsaSignature, SignatureEncoding, Signer as DsaSigner, SigningKey as DsaSigningKey,
    Verifier as DsaVerifier, VerifyingKey as DsaVerifyingKey,
};
#[cfg(feature = "pq")]
use ml_kem::{
    B32 as MlKemB32, Decapsulate, DecapsulationKey, EncapsulationKey, Key as MlKemKey, KeyExport,
    MlKem768, Seed as MlKemSeed,
};

#[cfg(feature = "pq")]
type MlKemDk = DecapsulationKey<MlKem768>;

const HKDF_SALT: &[u8] = b"lattice-hkdf-v1";
const PEERID_DOMAIN: &[u8] = b"lattice-id-v1";
const DEVICE_CERT_DOMAIN: &[u8] = b"lattice-device-cert-v1";

// ---------------------------------------------------------------------------
// Key derivation (deterministic; no RNG — that's what makes recovery work).
// ---------------------------------------------------------------------------

fn hkdf_expand(seed: &[u8; 64], info: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), seed);
    hk.expand(info, out).expect("HKDF expand length within bounds");
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
    if b.len() < mid + 4 {
        return None;
    }
    let ed = &b[4..mid];
    let pq_len = u32::from_le_bytes(b[mid..mid + 4].try_into().ok()?) as usize;
    let end = mid.checked_add(4)?.checked_add(pq_len)?;
    if b.len() < end {
        return None;
    }
    Some((ed, &b[mid + 4..end]))
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
        let key = MlKemKey::<EncapsulationKey<MlKem768>>::try_from(self.ml_kem.as_slice())
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

fn suite_tag(suite: CryptoSuite) -> u8 {
    match suite {
        CryptoSuite::Classical => 0,
        CryptoSuite::Hybrid => 1,
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
        if vk.verify_strict(msg, &ed_signature).is_err() {
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
                if pq_vk.verify(msg, &pq_signature).is_err() {
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
        let m = Mnemonic::parse(phrase).map_err(|e| Error::Crypto(format!("mnemonic parse: {e}")))?;
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
    /// session layer uses it to seed the responder's initial DH-ratchet key.
    /// Sensitive — for in-process handoff to the session only.
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

    /// Authorize a device's Ed25519 key under this root identity, returning a
    /// signed [`DeviceCert`] (ADR-004 multi-device delegation).
    pub fn authorize_device(&self, device_ed25519: [u8; 32]) -> DeviceCert {
        let root = self.public.peer_id();
        let sig = self.sign(&DeviceCert::message(&root, &device_ed25519));
        DeviceCert {
            root,
            device_ed25519,
            sig,
        }
    }
}

impl Identity for Keypair {
    fn peer_id(&self) -> PeerId {
        self.public.peer_id()
    }

    fn sign(&self, msg: &[u8]) -> Signature {
        let ed_sig = ed_signing(&self.seed).sign(msg).to_bytes();

        let pq_sig: Vec<u8> = match self.suite {
            CryptoSuite::Classical => Vec::new(),
            CryptoSuite::Hybrid => {
                #[cfg(feature = "pq")]
                {
                    let s: DsaSignature<MlDsa65> = dsa_signing(&self.seed).sign(msg);
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

/// A root-signed authorization binding a device's Ed25519 key to a root
/// identity. The day-to-day signer is the device key; the root (recoverable
/// from the mnemonic) is used only to issue or revoke device certs.
#[derive(Clone, Debug)]
pub struct DeviceCert {
    root: PeerId,
    device_ed25519: [u8; 32],
    sig: Signature,
}

impl DeviceCert {
    fn message(root: &PeerId, device: &[u8; 32]) -> Vec<u8> {
        let mut m = Vec::with_capacity(DEVICE_CERT_DOMAIN.len() + 64);
        m.extend_from_slice(DEVICE_CERT_DOMAIN);
        m.extend_from_slice(&root.0);
        m.extend_from_slice(device);
        m
    }

    /// The authorized device's Ed25519 public key.
    pub fn device_key(&self) -> [u8; 32] {
        self.device_ed25519
    }

    /// Verify this cert was issued by `root`.
    pub fn verify(&self, root: &PublicIdentity) -> bool {
        if root.peer_id() != self.root {
            return false;
        }
        root.verify(&Self::message(&self.root, &self.device_ed25519), &self.sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn mnemonic_recovery_reproduces_identity() {
        let original = Keypair::generate(CryptoSuite::Hybrid).unwrap();
        let phrase = original.mnemonic().to_string();

        let recovered = Keypair::from_mnemonic(CryptoSuite::Hybrid, &phrase).unwrap();
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
    fn tampered_signature_fails() {
        let kp = Keypair::generate(CryptoSuite::Hybrid).unwrap();
        let mut sig = kp.sign(b"payload");
        let last = sig.0.len() - 1;
        sig.0[last] ^= 0x01;
        assert!(!kp.public().verify(b"payload", &sig));
    }

    #[test]
    fn device_cert_roundtrip() {
        let root = Keypair::generate(CryptoSuite::Hybrid).unwrap();
        let device = Keypair::generate(CryptoSuite::Hybrid).unwrap();
        let cert = root.authorize_device(device.public().ed25519_bytes());

        assert!(cert.verify(root.public()), "cert must verify under its root");

        let imposter = Keypair::generate(CryptoSuite::Hybrid).unwrap();
        assert!(
            !cert.verify(imposter.public()),
            "cert must not verify under a different root"
        );
    }
}
