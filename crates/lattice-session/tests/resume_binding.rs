//! Resume-tag channel-binding tests through the public API (spec AC 4).

use lattice_core::{CryptoSuite, Error};
use lattice_identity::Keypair;
use lattice_session::{ResumeRole, SecureSession};

const BX: &[u8] = b"binding-x";
const BY: &[u8] = b"binding-y";
const DN: [u8; 32] = [1; 32];
const LN: [u8; 32] = [2; 32];

fn pair() -> (Keypair, Keypair, SecureSession, SecureSession) {
    let a = Keypair::generate(CryptoSuite::Hybrid).unwrap();
    let b = Keypair::generate(CryptoSuite::Hybrid).unwrap();
    let (m1, pending) = SecureSession::initiate(&a, b.public(), b"hs").unwrap();
    let (m2, rs) = SecureSession::respond(&b, a.public(), b"hs", &m1).unwrap();
    let is = pending.finish(&m2).unwrap();
    (a, b, is, rs)
}

fn verify(
    s: &SecureSession,
    a: &Keypair,
    b: &Keypair,
    binding: &[u8],
    tag: &[u8],
) -> Result<(), Error> {
    s.verify_resume_tag(
        ResumeRole::Dialer,
        a.public(),
        b.public(),
        &DN,
        &LN,
        binding,
        tag,
    )
}

#[test]
fn same_binding_verifies() {
    let (a, b, i, r) = pair();
    let tag = i.resume_tag(ResumeRole::Dialer, a.public(), b.public(), &DN, &LN, BX);
    verify(&r, &a, &b, BX, &tag).unwrap();
}

#[test]
fn different_binding_fails_with_verify() {
    let (a, b, i, r) = pair();
    let tag = i.resume_tag(ResumeRole::Dialer, a.public(), b.public(), &DN, &LN, BX);
    assert!(matches!(
        verify(&r, &a, &b, BY, &tag),
        Err(Error::Verify(_))
    ));
}

#[test]
fn empty_binding_fails_with_verify() {
    let (a, b, i, r) = pair();
    let tag = i.resume_tag(ResumeRole::Dialer, a.public(), b.public(), &DN, &LN, BX);
    assert!(matches!(
        verify(&r, &a, &b, b"", &tag),
        Err(Error::Verify(_))
    ));
}

#[test]
fn empty_binding_tag_does_not_verify_under_nonempty() {
    let (a, b, i, r) = pair();
    let tag = i.resume_tag(ResumeRole::Dialer, a.public(), b.public(), &DN, &LN, b"");
    verify(&r, &a, &b, b"", &tag).unwrap();
    assert!(matches!(
        verify(&r, &a, &b, BX, &tag),
        Err(Error::Verify(_))
    ));
}

#[test]
fn binding_is_length_delimited_not_ambiguous() {
    // A binding that is a prefix/extension of another must not collide.
    let (a, b, i, r) = pair();
    let tag = i.resume_tag(ResumeRole::Dialer, a.public(), b.public(), &DN, &LN, b"ab");
    assert!(verify(&r, &a, &b, b"abc", &tag).is_err());
    assert!(verify(&r, &a, &b, b"a", &tag).is_err());
}

#[test]
fn binding_tag_differs_per_binding() {
    let (a, b, i, _r) = pair();
    let t1 = i.resume_tag(ResumeRole::Dialer, a.public(), b.public(), &DN, &LN, BX);
    let t2 = i.resume_tag(ResumeRole::Dialer, a.public(), b.public(), &DN, &LN, BY);
    assert_ne!(t1, t2);
}

#[test]
fn wrong_length_tag_rejected() {
    let (a, b, i, r) = pair();
    let tag = i.resume_tag(ResumeRole::Dialer, a.public(), b.public(), &DN, &LN, BX);
    assert!(verify(&r, &a, &b, BX, &tag[..31]).is_err());
}
