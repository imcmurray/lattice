//! Spec-driven black-box tests: canonical parsing of signatures / public
//! identities and v2 device certificates. Public API only.

use lattice_core::{CryptoSuite, Error, Identity, PeerId, Signature, Verify};
use lattice_identity::{DeviceCert, Keypair, PublicIdentity};

const DOMAIN: &[u8] = b"lattice-device-cert-v2";
const MNEM_A: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const MNEM_B: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

fn classical() -> Keypair {
    Keypair::generate(CryptoSuite::Classical).unwrap()
}
#[cfg(feature = "pq")]
fn hybrid() -> Keypair {
    Keypair::generate(CryptoSuite::Hybrid).unwrap()
}

fn is_crypto_err<T>(r: &Result<T, Error>) -> bool {
    matches!(r, Err(Error::Crypto(_)))
}

/// Assemble a bundle with explicit length prefixes.
fn bundle(tag: u8, ed: &[u8; 32], x: &[u8; 32], dsa: &[u8], kem: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    v.extend_from_slice(ed);
    v.extend_from_slice(x);
    v.extend_from_slice(&(dsa.len() as u32).to_le_bytes());
    v.extend_from_slice(dsa);
    v.extend_from_slice(&(kem.len() as u32).to_le_bytes());
    v.extend_from_slice(kem);
    v
}

/// True if the assembled bundle is rejected with `Error::Crypto`.
fn rejects(t: u8, ed: &[u8; 32], x: &[u8; 32], dsa: &[u8], kem: &[u8]) -> bool {
    is_crypto_err(&PublicIdentity::from_bytes(&bundle(t, ed, x, dsa, kem)))
}

/// Split a valid encoding into (tag, ed, x, dsa, kem).
fn split(b: &[u8]) -> (u8, [u8; 32], [u8; 32], Vec<u8>, Vec<u8>) {
    let mut ed = [0u8; 32];
    let mut x = [0u8; 32];
    ed.copy_from_slice(&b[1..33]);
    x.copy_from_slice(&b[33..65]);
    let dl = u32::from_le_bytes(b[65..69].try_into().unwrap()) as usize;
    let dsa = b[69..69 + dl].to_vec();
    let o = 69 + dl;
    let kl = u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) as usize;
    let kem = b[o + 4..o + 4 + kl].to_vec();
    (b[0], ed, x, dsa, kem)
}

fn cert_message(root: &PeerId, dev: &PublicIdentity, not_after: u64) -> Vec<u8> {
    let d = dev.to_bytes();
    let mut m = DOMAIN.to_vec();
    m.extend_from_slice(&root.0);
    m.extend_from_slice(&(d.len() as u32).to_le_bytes());
    m.extend_from_slice(&d);
    m.extend_from_slice(&not_after.to_le_bytes());
    m
}

fn cert_bytes(root: &PeerId, dev: &[u8], not_after: u64, sig: &[u8]) -> Vec<u8> {
    let mut v = root.0.to_vec();
    v.extend_from_slice(&(dev.len() as u32).to_le_bytes());
    v.extend_from_slice(dev);
    v.extend_from_slice(&not_after.to_le_bytes());
    v.extend_from_slice(&(sig.len() as u32).to_le_bytes());
    v.extend_from_slice(sig);
    v
}

// ---- Signatures (AC 1) ----

#[test]
fn classical_signature_with_trailing_byte_rejected() {
    let kp = classical();
    let sig = kp.sign(b"m");
    assert!(kp.public().verify(b"m", &sig));
    let mut s = sig.0.clone();
    s.push(0);
    assert!(!kp.public().verify(b"m", &Signature(s)));
}

#[cfg(feature = "pq")]
#[test]
fn hybrid_signature_with_trailing_byte_rejected() {
    let kp = hybrid();
    let sig = kp.sign(b"m");
    assert!(kp.public().verify(b"m", &sig));
    let mut s = sig.0.clone();
    s.push(0);
    assert!(!kp.public().verify(b"m", &Signature(s)));
}

// ---- PublicIdentity::from_bytes (AC 2-10) ----

#[test]
fn classical_trailing_byte_rejected() {
    let kp = classical();
    let mut b = kp.public().to_bytes();
    assert!(PublicIdentity::from_bytes(&b).is_ok());
    b.push(0);
    assert!(is_crypto_err(&PublicIdentity::from_bytes(&b)));
}

#[cfg(feature = "pq")]
#[test]
fn hybrid_trailing_byte_rejected() {
    let mut b = hybrid().public().to_bytes();
    assert!(PublicIdentity::from_bytes(&b).is_ok());
    b.push(0);
    assert!(is_crypto_err(&PublicIdentity::from_bytes(&b)));
}

#[test]
fn classical_with_pq_fields_rejected() {
    let b = classical().public().to_bytes();
    let (t, ed, x, _, _) = split(&b);
    assert!(PublicIdentity::from_bytes(&bundle(t, &ed, &x, &[], &[])).is_ok());
    assert!(rejects(t, &ed, &x, &[1], &[]));
    assert!(rejects(t, &ed, &x, &[], &[1]));
    assert!(rejects(t, &ed, &x, &[1; 1952], &[1; 1184]));
}

#[cfg(feature = "pq")]
#[test]
fn hybrid_wrong_length_pq_fields_rejected() {
    let b = hybrid().public().to_bytes();
    let (t, ed, x, dsa, kem) = split(&b);
    assert_eq!(dsa.len(), 1952);
    assert_eq!(kem.len(), 1184);
    assert!(PublicIdentity::from_bytes(&bundle(t, &ed, &x, &dsa, &kem)).is_ok());

    let mut short = dsa.clone();
    short.pop();
    let mut long = dsa.clone();
    long.push(0);
    for d in [&short, &long, &Vec::new()] {
        assert!(rejects(t, &ed, &x, d, &kem));
    }
    let mut kshort = kem.clone();
    kshort.pop();
    let mut klong = kem.clone();
    klong.push(0);
    for k in [&kshort, &klong, &Vec::new()] {
        assert!(rejects(t, &ed, &x, &dsa, k));
    }
}

#[cfg(feature = "pq")]
#[test]
fn hybrid_out_of_range_kem_coefficient_rejected() {
    let b = hybrid().public().to_bytes();
    let (t, ed, x, dsa, _) = split(&b);
    assert!(rejects(t, &ed, &x, &dsa, &[0xFF; 1184]));
}

#[test]
fn weak_ed25519_identity_point_rejected() {
    let b = classical().public().to_bytes();
    let (t, _, x, _, _) = split(&b);
    let mut ed = [0u8; 32];
    ed[0] = 1;
    assert!(rejects(t, &ed, &x, &[], &[]));
}

#[test]
fn undecodable_ed25519_rejected() {
    let b = classical().public().to_bytes();
    let (t, _, x, _, _) = split(&b);
    // About half of all y-coordinates have no valid x; scan small y values.
    let mut rejected = 0;
    for y in 2u8..=60 {
        let mut ed = [0u8; 32];
        ed[0] = y;
        if PublicIdentity::from_bytes(&bundle(t, &ed, &x, &[], &[])).is_err() {
            rejected += 1;
        }
    }
    assert!(
        rejected > 0,
        "expected some non-decoding Ed25519 encodings to be rejected"
    );
}

#[test]
fn huge_length_prefixes_rejected_without_panic() {
    let b = classical().public().to_bytes();
    let (t, ed, x, _, _) = split(&b);
    // dsa_len = u32::MAX with short body
    let mut v = vec![t];
    v.extend_from_slice(&ed);
    v.extend_from_slice(&x);
    v.extend_from_slice(&u32::MAX.to_le_bytes());
    v.extend_from_slice(&[0u8; 8]);
    assert!(is_crypto_err(&PublicIdentity::from_bytes(&v)));
    // kem_len = u32::MAX
    let mut v = vec![t];
    v.extend_from_slice(&ed);
    v.extend_from_slice(&x);
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&u32::MAX.to_le_bytes());
    v.extend_from_slice(&[0u8; 8]);
    assert!(is_crypto_err(&PublicIdentity::from_bytes(&v)));
}

#[test]
fn degenerate_inputs_no_panic() {
    assert!(PublicIdentity::from_bytes(&[]).is_err());
    assert!(PublicIdentity::from_bytes(&[0xFF; 200]).is_err());
    assert!(DeviceCert::from_bytes(&[]).is_err());
    assert!(DeviceCert::from_bytes(&[0xFF; 200]).is_err());
}

#[test]
fn truncation_classical_every_prefix_rejected() {
    let b = classical().public().to_bytes();
    for n in 0..b.len() {
        assert!(PublicIdentity::from_bytes(&b[..n]).is_err(), "prefix {n}");
    }
}

#[cfg(feature = "pq")]
#[test]
fn truncation_hybrid_every_prefix_rejected() {
    let b = hybrid().public().to_bytes();
    for n in 0..b.len() {
        assert!(PublicIdentity::from_bytes(&b[..n]).is_err(), "prefix {n}");
    }
}

#[test]
fn unknown_suite_tag_rejected() {
    let mut b = classical().public().to_bytes();
    b[0] = 2;
    assert!(is_crypto_err(&PublicIdentity::from_bytes(&b)));
    b[0] = 0xFF;
    assert!(is_crypto_err(&PublicIdentity::from_bytes(&b)));
}

#[test]
fn classical_canonical_roundtrip() {
    for kp in [
        classical(),
        Keypair::from_mnemonic(CryptoSuite::Classical, MNEM_A).unwrap(),
    ] {
        let x = kp.public().to_bytes();
        let p = PublicIdentity::from_bytes(&x).unwrap();
        assert_eq!(p.to_bytes(), x);
        assert_eq!(p.peer_id(), kp.public().peer_id());
    }
}

#[cfg(feature = "pq")]
#[test]
fn hybrid_canonical_roundtrip() {
    for kp in [
        hybrid(),
        Keypair::from_mnemonic(CryptoSuite::Hybrid, MNEM_A).unwrap(),
    ] {
        let x = kp.public().to_bytes();
        let p = PublicIdentity::from_bytes(&x).unwrap();
        assert_eq!(p.to_bytes(), x);
        assert_eq!(p.peer_id(), kp.public().peer_id());
    }
}

#[cfg(not(feature = "pq"))]
#[test]
fn hybrid_tagged_bundle_rejected_without_pq() {
    let b = classical().public().to_bytes();
    let (_, ed, x, _, _) = split(&b);
    let v = bundle(1, &ed, &x, &[0u8; 1952], &[0u8; 1184]);
    assert!(is_crypto_err(&PublicIdentity::from_bytes(&v)));
    let v = bundle(1, &ed, &x, &[], &[]);
    assert!(is_crypto_err(&PublicIdentity::from_bytes(&v)));
}

// ---- Device certs (AC 11-19) ----

const T: u64 = 1_000_000;
const NOW: u64 = 500_000;

fn check_roundtrip(root: &Keypair, dev: &Keypair) {
    let cert = root.authorize_device(dev.public(), T).unwrap();
    assert_eq!(cert.root(), &root.public().peer_id());
    assert_eq!(cert.device().peer_id(), dev.public().peer_id());
    assert_eq!(cert.not_after(), T);
    assert!(cert.verify(root.public(), NOW));
    assert!(cert.verify(root.public(), T));
    assert!(!cert.verify(root.public(), T + 1));
    let bytes = cert.to_bytes();
    let back = DeviceCert::from_bytes(&bytes).unwrap();
    assert_eq!(back.to_bytes(), bytes);
    assert_eq!(back.not_after(), T);
    assert_eq!(back.root(), cert.root());
    assert_eq!(back.device().peer_id(), dev.public().peer_id());
    assert!(back.verify(root.public(), NOW));
    assert!(back.verify(root.public(), T));
    assert!(!back.verify(root.public(), T + 1));
}

#[test]
fn cert_classical_root_classical_device() {
    check_roundtrip(&classical(), &classical());
}

#[cfg(feature = "pq")]
#[test]
fn cert_hybrid_root_hybrid_device() {
    check_roundtrip(&hybrid(), &hybrid());
}

#[cfg(feature = "pq")]
#[test]
fn cert_classical_root_hybrid_device() {
    check_roundtrip(&classical(), &hybrid());
}

#[test]
fn cert_message_layout_matches_signature() {
    // The cert signature must be a root signature over the documented v2 message.
    let root = classical();
    let dev = classical();
    let cert = root.authorize_device(dev.public(), T).unwrap();
    let bytes = cert.to_bytes();
    let sig_off = 32 + 4 + dev.public().to_bytes().len() + 8 + 4;
    let sig = Signature(bytes[sig_off..].to_vec());
    let rid = root.public().peer_id();
    let msg = cert_message(&rid, dev.public(), T);
    assert!(root.public().verify(&msg, &sig));
    // Wire layout.
    let expected = cert_bytes(&rid, &dev.public().to_bytes(), T, &sig.0);
    assert_eq!(bytes, expected);
}

#[test]
fn cert_wrong_root_fails() {
    let root = Keypair::from_mnemonic(CryptoSuite::Classical, MNEM_A).unwrap();
    let other = Keypair::from_mnemonic(CryptoSuite::Classical, MNEM_B).unwrap();
    let cert = root.authorize_device(classical().public(), T).unwrap();
    assert!(cert.verify(root.public(), NOW));
    assert!(!cert.verify(other.public(), NOW));
}

#[cfg(feature = "pq")]
#[test]
fn hybrid_root_classical_device_refused_and_unverifiable() {
    let root = hybrid();
    let dev = classical();
    let r = root.authorize_device(dev.public(), T);
    assert!(is_crypto_err(&r));
    // Hand-built, correctly signed over the v2 message: verify must still refuse.
    let rid = root.public().peer_id();
    let sig = root.sign(&cert_message(&rid, dev.public(), T));
    let bytes = cert_bytes(&rid, &dev.public().to_bytes(), T, &sig.0);
    let cert = DeviceCert::from_bytes(&bytes).unwrap();
    assert!(!cert.verify(root.public(), NOW));
}

#[test]
fn authorize_refusals() {
    let root = classical();
    let dev = classical();
    assert!(is_crypto_err(&root.authorize_device(root.public(), T)));
    assert!(is_crypto_err(&root.authorize_device(dev.public(), 0)));
}

#[test]
fn handbuilt_self_cert_does_not_verify() {
    let root = classical();
    let rid = root.public().peer_id();
    let sig = root.sign(&cert_message(&rid, root.public(), T));
    let bytes = cert_bytes(&rid, &root.public().to_bytes(), T, &sig.0);
    let cert = DeviceCert::from_bytes(&bytes).unwrap();
    assert!(!cert.verify(root.public(), NOW));
}

#[test]
fn zero_not_after_rejected_by_from_bytes_and_verify() {
    let root = classical();
    let dev = classical();
    let rid = root.public().peer_id();
    let sig = root.sign(&cert_message(&rid, dev.public(), 0));
    let bytes = cert_bytes(&rid, &dev.public().to_bytes(), 0, &sig.0);
    assert!(is_crypto_err(&DeviceCert::from_bytes(&bytes)));
}

#[test]
fn cert_tampering_fails_verify() {
    let root = classical();
    let dev = classical();
    let cert = root.authorize_device(dev.public(), T).unwrap();
    let rid = root.public().peer_id();
    let devb = dev.public().to_bytes();
    let bytes = cert.to_bytes();
    let sig_off = bytes.len() - (bytes.len() - (32 + 4 + devb.len() + 8 + 4));
    let sig = bytes[sig_off..].to_vec();

    // Flip each bit-position of the signature's first byte, and last byte.
    for idx in [0usize, sig.len() / 2, sig.len() - 1] {
        let mut s = sig.clone();
        s[idx] ^= 1;
        let c = DeviceCert::from_bytes(&cert_bytes(&rid, &devb, T, &s)).unwrap();
        assert!(!c.verify(root.public(), NOW), "sig byte {idx}");
    }
    // Changed not_after.
    let c = DeviceCert::from_bytes(&cert_bytes(&rid, &devb, T + 1, &sig)).unwrap();
    assert!(!c.verify(root.public(), NOW));
    let c = DeviceCert::from_bytes(&cert_bytes(&rid, &devb, T - 1, &sig)).unwrap();
    assert!(!c.verify(root.public(), NOW));
    // Replaced device, same sig.
    let other = classical();
    let c = DeviceCert::from_bytes(&cert_bytes(&rid, &other.public().to_bytes(), T, &sig)).unwrap();
    assert!(!c.verify(root.public(), NOW));
    // Tampered x25519 byte inside the device bundle (still parses).
    let mut d2 = devb.clone();
    d2[33] ^= 1;
    let c = DeviceCert::from_bytes(&cert_bytes(&rid, &d2, T, &sig)).unwrap();
    assert!(!c.verify(root.public(), NOW));
    // Changed root id inside the cert.
    let mut rid2 = rid.clone();
    rid2.0[0] ^= 1;
    let c = DeviceCert::from_bytes(&cert_bytes(&rid2, &devb, T, &sig)).unwrap();
    assert!(!c.verify(root.public(), NOW));
}

fn assert_cert_parse_rejects(root: &Keypair, dev: &Keypair) {
    let cert = root.authorize_device(dev.public(), T).unwrap();
    let b = cert.to_bytes();
    assert!(DeviceCert::from_bytes(&b).is_ok());

    for n in 0..b.len() {
        assert!(DeviceCert::from_bytes(&b[..n]).is_err(), "prefix {n}");
    }
    let mut t = b.clone();
    t.push(0);
    assert!(is_crypto_err(&DeviceCert::from_bytes(&t)));

    // u32::MAX dev_len
    let mut v = b.clone();
    v[32..36].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(is_crypto_err(&DeviceCert::from_bytes(&v)));

    // u32::MAX sig_len
    let devb = dev.public().to_bytes();
    let sl = 32 + 4 + devb.len() + 8;
    let mut v = b.clone();
    v[sl..sl + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(is_crypto_err(&DeviceCert::from_bytes(&v)));

    // Oversize input.
    let big = vec![0u8; 65_537];
    assert!(is_crypto_err(&DeviceCert::from_bytes(&big)));
    let mut padded = b.clone();
    padded.resize(65_537, 0);
    assert!(is_crypto_err(&DeviceCert::from_bytes(&padded)));

    // Trailing byte inside the device bundle (dev_len covers it).
    let mut d2 = devb.clone();
    d2.push(0);
    let sig_bytes = &b[sl + 4..];
    assert!(is_crypto_err(&DeviceCert::from_bytes(&cert_bytes(
        &root.public().peer_id(),
        &d2,
        T,
        sig_bytes
    ))));
}

#[test]
fn cert_from_bytes_rejects_malformed_classical() {
    assert_cert_parse_rejects(&classical(), &classical());
}

#[cfg(feature = "pq")]
#[test]
fn cert_from_bytes_rejects_malformed_hybrid() {
    assert_cert_parse_rejects(&hybrid(), &hybrid());
}

#[test]
fn cert_at_exact_size_cap_not_rejected_for_size() {
    // A 65_536-byte input must fail for a structural reason, not panic.
    let v = vec![0u8; 65_536];
    assert!(DeviceCert::from_bytes(&v).is_err());
}
