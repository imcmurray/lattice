//! Public-API tests for the v3 two-message handshake (spec ACs 1, 4, 6–12).

use lattice_core::{CryptoSuite, Error, Identity, Signature, Verify};
use lattice_identity::Keypair;
use lattice_session::{HandshakeInit, HandshakeResp, PendingInitiator, SecureSession};

const B: &[u8] = b"test-binding";
const MAX: usize = 65_536;

fn kp(s: CryptoSuite) -> Keypair {
    Keypair::generate(s).unwrap()
}

fn is_verify<T>(r: &Result<T, Error>) -> bool {
    matches!(r, Err(Error::Verify(_)))
}

fn lp(out: &mut Vec<u8>, x: &[u8]) {
    out.extend_from_slice(&(x.len() as u32).to_le_bytes());
    out.extend_from_slice(x);
}

/// Rebuild T1 from the spec.
fn t1(binding: &[u8], i: &Keypair, r: &Keypair, m: &HandshakeInit) -> Vec<u8> {
    let mut t = b"lattice-session-hs-v3".to_vec();
    lp(&mut t, binding);
    lp(&mut t, &i.public().to_bytes());
    lp(&mut t, &r.public().to_bytes());
    t.extend_from_slice(&m.eph_i);
    t.extend_from_slice(&m.ratchet_pub_i);
    lp(&mut t, &m.kem_ct_s);
    lp(&mut t, &m.kem_ek_i);
    t
}

type Pair = (SecureSession, SecureSession, HandshakeInit, HandshakeResp);

fn pair_with(a: &Keypair, b: &Keypair, binding: &[u8]) -> Pair {
    let (m1, pending) = SecureSession::initiate(a, b.public(), binding).unwrap();
    let (m2, rs) = SecureSession::respond(b, a.public(), binding, &m1).unwrap();
    let is = pending.finish(&m2).unwrap();
    (is, rs, m1, m2)
}

fn hybrid_pair() -> (Keypair, Keypair, Pair) {
    let a = kp(CryptoSuite::Hybrid);
    let b = kp(CryptoSuite::Hybrid);
    let p = pair_with(&a, &b, B);
    (a, b, p)
}

fn fresh_init(a: &Keypair, b: &Keypair) -> (HandshakeInit, PendingInitiator) {
    SecureSession::initiate(a, b.public(), B).unwrap()
}

fn flip(v: &mut [u8]) {
    v[0] ^= 1;
}

// ---- AC 1 ----

#[test]
fn ac1_initiator_sends_first_and_pingpong() {
    let (_a, _b, (mut i, mut r, _, _)) = hybrid_pair();
    for n in 0..5u8 {
        let f = i.seal(&[n; 7]).unwrap();
        assert_eq!(r.open(&f).unwrap(), vec![n; 7]);
        let f = r.seal(&[n + 100; 3]).unwrap();
        assert_eq!(i.open(&f).unwrap(), vec![n + 100; 3]);
    }
}

#[test]
fn ac1_responder_sends_first() {
    let (_a, _b, (mut i, mut r, _, _)) = hybrid_pair();
    let f = r.seal(b"from responder").unwrap();
    assert_eq!(i.open(&f).unwrap(), b"from responder");
    let f = i.seal(b"back").unwrap();
    assert_eq!(r.open(&f).unwrap(), b"back");
    let f = r.seal(b"again").unwrap();
    assert_eq!(i.open(&f).unwrap(), b"again");
}

// ---- AC 3 (resume tags across the pair) ----

#[test]
fn ac3_resume_tags_match_across_pair() {
    use lattice_session::ResumeRole;
    let (a, b, (i, r, _, _)) = hybrid_pair();
    let (dn, ln) = ([1u8; 32], [2u8; 32]);
    let t_i = i.resume_tag(ResumeRole::Dialer, a.public(), b.public(), &dn, &ln);
    let t_r = r.resume_tag(ResumeRole::Dialer, a.public(), b.public(), &dn, &ln);
    assert_eq!(t_i, t_r);
    r.verify_resume_tag(ResumeRole::Dialer, a.public(), b.public(), &dn, &ln, &t_i)
        .unwrap();
    i.verify_resume_tag(ResumeRole::Dialer, a.public(), b.public(), &dn, &ln, &t_r)
        .unwrap();
}

// ---- AC 4 ----

#[test]
fn ac4_responder_ratchet_key_is_not_static() {
    let (_a, b, (_i, mut r, _, m2)) = hybrid_pair();
    assert_ne!(m2.eph_r, b.public().x25519_bytes());
    let f = r.seal(b"x").unwrap();
    assert_ne!(&f[..32], &b.public().x25519_bytes()[..]);
}

// ---- Sanity of the rebuilt transcript (contract check) ----

#[test]
fn transcript_t1_matches_spec_and_sig_i_verifies() {
    let (a, b, (_, _, m1, _)) = hybrid_pair();
    assert!(a.public().verify(&t1(B, &a, &b, &m1), &m1.sig_i));
}

// ---- AC 6 ----

#[test]
fn ac6_eve_cannot_impersonate_initiator() {
    let alice = kp(CryptoSuite::Hybrid);
    let bob = kp(CryptoSuite::Hybrid);
    let eve = kp(CryptoSuite::Hybrid);
    // Eve signs her own msg1; Bob is told the peer is Alice.
    let (m1, _p) = SecureSession::initiate(&eve, bob.public(), B).unwrap();
    assert!(is_verify(&SecureSession::respond(
        &bob,
        alice.public(),
        B,
        &m1
    )));
}

#[test]
fn ac6_sig_i_from_eve_over_correct_t1_rejected() {
    let alice = kp(CryptoSuite::Hybrid);
    let bob = kp(CryptoSuite::Hybrid);
    let eve = kp(CryptoSuite::Hybrid);
    let (mut m1, _p) = fresh_init(&alice, &bob);
    let t = t1(B, &alice, &bob, &m1);
    m1.sig_i = eve.sign(&t);
    assert!(is_verify(&SecureSession::respond(
        &bob,
        alice.public(),
        B,
        &m1
    )));
}

// ---- AC 7 ----

#[test]
fn ac7_eve_cannot_impersonate_responder() {
    let alice = kp(CryptoSuite::Hybrid);
    let bob = kp(CryptoSuite::Hybrid);
    let eve = kp(CryptoSuite::Hybrid);
    let (m1, pending) = fresh_init(&alice, &bob);
    // msg1 intended for Bob is rejected by Eve.
    let r = SecureSession::respond(&eve, alice.public(), B, &m1);
    assert!(r.is_err());
    // Eve answers with a msg2 from an unrelated (valid) handshake with her.
    let (m1e, _pe) = SecureSession::initiate(&alice, eve.public(), B).unwrap();
    let (m2e, _) = SecureSession::respond(&eve, alice.public(), B, &m1e).unwrap();
    assert!(is_verify(&pending.finish(&m2e)));
}

#[test]
fn ac7_forged_msg2_with_eve_signature_rejected() {
    let alice = kp(CryptoSuite::Hybrid);
    let bob = kp(CryptoSuite::Hybrid);
    let eve = kp(CryptoSuite::Hybrid);
    let (m1, pending) = fresh_init(&alice, &bob);
    let (_, m2) = {
        let (m1b, _) = fresh_init(&alice, &bob);
        let (m2, s) = SecureSession::respond(&bob, alice.public(), B, &m1b).unwrap();
        (s, m2)
    };
    let forged = HandshakeResp {
        eph_r: m2.eph_r,
        kem_ct_e: m2.kem_ct_e.clone(),
        sig_r: eve.sign(b"whatever"),
    };
    let _ = &m1;
    assert!(is_verify(&pending.finish(&forged)));
}

// ---- AC 8 ----

#[test]
fn ac8_msg1_any_field_bitflip_rejected() {
    let alice = kp(CryptoSuite::Hybrid);
    let bob = kp(CryptoSuite::Hybrid);
    for field in 0..5 {
        let (mut m1, _p) = fresh_init(&alice, &bob);
        match field {
            0 => flip(&mut m1.eph_i),
            1 => flip(&mut m1.ratchet_pub_i),
            2 => flip(&mut m1.kem_ct_s),
            3 => flip(&mut m1.kem_ek_i),
            _ => flip(&mut m1.sig_i.0),
        }
        assert!(
            SecureSession::respond(&bob, alice.public(), B, &m1).is_err(),
            "msg1 field {field} tamper accepted"
        );
    }
}

#[test]
fn ac8_msg2_any_field_bitflip_rejected() {
    let alice = kp(CryptoSuite::Hybrid);
    let bob = kp(CryptoSuite::Hybrid);
    for field in 0..3 {
        let (m1, pending) = fresh_init(&alice, &bob);
        let (mut m2, _s) = SecureSession::respond(&bob, alice.public(), B, &m1).unwrap();
        match field {
            0 => flip(&mut m2.eph_r),
            1 => flip(&mut m2.kem_ct_e),
            _ => flip(&mut m2.sig_r.0),
        }
        assert!(
            pending.finish(&m2).is_err(),
            "msg2 field {field} tamper accepted"
        );
    }
}

// ---- AC 9 ----

#[test]
fn ac9_binding_mismatch_rejected() {
    let a = kp(CryptoSuite::Hybrid);
    let b = kp(CryptoSuite::Hybrid);
    let (m1, _p) = SecureSession::initiate(&a, b.public(), b"one").unwrap();
    assert!(SecureSession::respond(&b, a.public(), b"two", &m1).is_err());
    let (m1, _p) = SecureSession::initiate(&a, b.public(), b"").unwrap();
    assert!(SecureSession::respond(&b, a.public(), b"x", &m1).is_err());
}

#[test]
fn ac9_equal_bindings_succeed() {
    let a = kp(CryptoSuite::Hybrid);
    let b = kp(CryptoSuite::Hybrid);
    let _ = pair_with(&a, &b, b"non-empty");
    let _ = pair_with(&a, &b, b"");
}

#[test]
fn ac9_oversized_binding_rejected() {
    let a = kp(CryptoSuite::Hybrid);
    let b = kp(CryptoSuite::Hybrid);
    let big = vec![0u8; MAX + 1];
    assert!(is_verify(&SecureSession::initiate(&a, b.public(), &big)));
    let (m1, _p) = fresh_init(&a, &b);
    assert!(is_verify(&SecureSession::respond(
        &b,
        a.public(),
        &big,
        &m1
    )));
}

// ---- AC 10 ----

#[test]
fn ac10_replayed_msg1_gives_incompatible_session() {
    let a = kp(CryptoSuite::Hybrid);
    let b = kp(CryptoSuite::Hybrid);
    let (m1, pending) = fresh_init(&a, &b);
    let (m2, mut r1) = SecureSession::respond(&b, a.public(), B, &m1).unwrap();
    let (m2b, mut r2) = SecureSession::respond(&b, a.public(), B, &m1).unwrap();
    assert_ne!(m2.eph_r, m2b.eph_r);
    let mut i = pending.finish(&m2).unwrap();

    // second responder -> original initiator fails
    let f = r2.seal(b"replay").unwrap();
    assert!(i.open(&f).is_err());
    // original initiator -> second responder fails
    let f = i.seal(b"hi").unwrap();
    assert!(r2.open(&f).is_err());
    // the genuine pair still works afterwards
    assert_eq!(r1.open(&f).unwrap(), b"hi");
}

// ---- AC 11 ----

fn field_offsets_init(enc: &[u8]) -> Vec<usize> {
    let mut offs = Vec::new();
    let mut p = 64;
    for _ in 0..3 {
        offs.push(p);
        let n = u32::from_le_bytes(enc[p..p + 4].try_into().unwrap()) as usize;
        p += 4 + n;
    }
    offs
}

fn field_offsets_resp(enc: &[u8]) -> Vec<usize> {
    let mut offs = Vec::new();
    let mut p = 32;
    for _ in 0..2 {
        offs.push(p);
        let n = u32::from_le_bytes(enc[p..p + 4].try_into().unwrap()) as usize;
        p += 4 + n;
    }
    offs
}

#[test]
fn ac11_init_decoder_rejects_malformed() {
    let (_a, _b, (_, _, m1, _)) = hybrid_pair();
    let enc = m1.to_bytes();
    assert!(is_verify(&HandshakeInit::from_bytes(&[])));
    for n in 0..enc.len() {
        assert!(
            is_verify(&HandshakeInit::from_bytes(&enc[..n])),
            "truncation {n}"
        );
    }
    let mut t = enc.clone();
    t.push(0);
    assert!(is_verify(&HandshakeInit::from_bytes(&t)));
    assert!(is_verify(&HandshakeInit::from_bytes(&vec![0u8; MAX + 1])));
    for off in field_offsets_init(&enc) {
        for v in [u32::MAX, (MAX + 1) as u32] {
            let mut e = enc.clone();
            e[off..off + 4].copy_from_slice(&v.to_le_bytes());
            assert!(is_verify(&HandshakeInit::from_bytes(&e)), "off {off} v {v}");
        }
    }
}

#[test]
fn ac11_resp_decoder_rejects_malformed() {
    let (_a, _b, (_, _, _, m2)) = hybrid_pair();
    let enc = m2.to_bytes();
    assert!(is_verify(&HandshakeResp::from_bytes(&[])));
    for n in 0..enc.len() {
        assert!(
            is_verify(&HandshakeResp::from_bytes(&enc[..n])),
            "truncation {n}"
        );
    }
    let mut t = enc.clone();
    t.push(0);
    assert!(is_verify(&HandshakeResp::from_bytes(&t)));
    assert!(is_verify(&HandshakeResp::from_bytes(&vec![0u8; MAX + 1])));
    for off in field_offsets_resp(&enc) {
        for v in [u32::MAX, (MAX + 1) as u32] {
            let mut e = enc.clone();
            e[off..off + 4].copy_from_slice(&v.to_le_bytes());
            assert!(is_verify(&HandshakeResp::from_bytes(&e)), "off {off} v {v}");
        }
    }
}

#[test]
fn ac11_roundtrip_and_decoded_messages_complete_handshake() {
    let a = kp(CryptoSuite::Hybrid);
    let b = kp(CryptoSuite::Hybrid);
    let (m1, pending) = fresh_init(&a, &b);
    let d1 = HandshakeInit::from_bytes(&m1.to_bytes()).unwrap();
    assert_eq!(d1.eph_i, m1.eph_i);
    assert_eq!(d1.ratchet_pub_i, m1.ratchet_pub_i);
    assert_eq!(d1.kem_ct_s, m1.kem_ct_s);
    assert_eq!(d1.kem_ek_i, m1.kem_ek_i);
    assert_eq!(d1.sig_i.0, m1.sig_i.0);
    let (m2, mut r) = SecureSession::respond(&b, a.public(), B, &d1).unwrap();
    let d2 = HandshakeResp::from_bytes(&m2.to_bytes()).unwrap();
    assert_eq!(d2.eph_r, m2.eph_r);
    assert_eq!(d2.kem_ct_e, m2.kem_ct_e);
    assert_eq!(d2.sig_r.0, m2.sig_r.0);
    assert_eq!(d1.to_bytes(), m1.to_bytes());
    assert_eq!(d2.to_bytes(), m2.to_bytes());
    let mut i = pending.finish(&d2).unwrap();
    let f = i.seal(b"ok").unwrap();
    assert_eq!(r.open(&f).unwrap(), b"ok");
}

// ---- AC 12 ----

#[test]
fn ac12_classical_pair_has_no_kem_fields_and_works() {
    let a = kp(CryptoSuite::Classical);
    let b = kp(CryptoSuite::Classical);
    let (mut i, mut r, m1, m2) = pair_with(&a, &b, B);
    assert!(m1.kem_ct_s.is_empty());
    assert!(m1.kem_ek_i.is_empty());
    assert!(m2.kem_ct_e.is_empty());
    let f = i.seal(b"c1").unwrap();
    assert_eq!(r.open(&f).unwrap(), b"c1");
    let f = r.seal(b"c2").unwrap();
    assert_eq!(i.open(&f).unwrap(), b"c2");
}

#[test]
fn ac12_classical_responder_rejects_nonempty_kem_fields() {
    let a = kp(CryptoSuite::Classical);
    let b = kp(CryptoSuite::Classical);
    for field in 0..2 {
        let (mut m1, _p) = fresh_init(&a, &b);
        match field {
            0 => m1.kem_ct_s = vec![7u8; 16],
            _ => m1.kem_ek_i = vec![7u8; 16],
        }
        // Not re-signed.
        assert!(SecureSession::respond(&b, a.public(), B, &m1).is_err());
        // Correctly re-signed by the real initiator.
        let t = t1(B, &a, &b, &m1);
        m1.sig_i = a.sign(&t);
        assert!(
            SecureSession::respond(&b, a.public(), B, &m1).is_err(),
            "re-signed field {field}"
        );
    }
}

#[test]
fn ac12_hybrid_responder_rejects_empty_kem_fields() {
    let a = kp(CryptoSuite::Hybrid);
    let b = kp(CryptoSuite::Hybrid);
    for field in 0..2 {
        let (mut m1, _p) = fresh_init(&a, &b);
        match field {
            0 => m1.kem_ct_s = Vec::new(),
            _ => m1.kem_ek_i = Vec::new(),
        }
        let t = t1(B, &a, &b, &m1);
        m1.sig_i = a.sign(&t);
        assert!(
            SecureSession::respond(&b, a.public(), B, &m1).is_err(),
            "field {field}"
        );
    }
}

#[test]
fn signature_type_is_plain_bytes() {
    // Guards the assumption used by the tamper tests above.
    let s = Signature(vec![1, 2, 3]);
    assert_eq!(s.0.len(), 3);
}
