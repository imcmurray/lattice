//! Black-box tests for `safety_number` and X25519 public-key validation
//! (spec AC 1-7, 9-11). Classical identities only unless `pq` is enabled.

use lattice_core::{CryptoSuite, Error};
use lattice_identity::{
    safety_number, Keypair, PublicIdentity, SAFETY_NUMBER_DOMAIN, SAFETY_NUMBER_GROUPS,
};

const MNEM_A: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const MNEM_B: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

fn classical() -> PublicIdentity {
    Keypair::generate(CryptoSuite::Classical)
        .unwrap()
        .public()
        .clone()
}

fn well_formed(s: &str) -> bool {
    s.len() == 71
        && s.split(' ').count() == 12
        && s.split(' ')
            .all(|g| g.len() == 5 && g.bytes().all(|b| b.is_ascii_digit()))
}

#[test]
fn symmetric_classical() {
    for _ in 0..8 {
        let (a, b) = (classical(), classical());
        assert_eq!(safety_number(&a, &b), safety_number(&b, &a));
    }
}

#[cfg(feature = "pq")]
#[test]
fn symmetric_hybrid() {
    let a = Keypair::generate(CryptoSuite::Hybrid).unwrap();
    let b = Keypair::generate(CryptoSuite::Hybrid).unwrap();
    assert_eq!(
        safety_number(a.public(), b.public()),
        safety_number(b.public(), a.public())
    );
}

#[test]
fn format_is_12_groups_of_5_digits() {
    for _ in 0..32 {
        let s = safety_number(&classical(), &classical());
        assert!(well_formed(&s), "bad format: {s:?}");
    }
}

#[test]
fn self_pair_is_well_formed() {
    let a = classical();
    assert!(well_formed(&safety_number(&a, &a)));
}

#[test]
fn replacing_either_input_changes_number() {
    let (a, b, c) = (classical(), classical(), classical());
    let ab = safety_number(&a, &b);
    assert_ne!(ab, safety_number(&a, &c));
    assert_ne!(ab, safety_number(&c, &b));
}

#[test]
fn deterministic_and_roundtrip() {
    let a = Keypair::from_mnemonic(CryptoSuite::Classical, MNEM_A).unwrap();
    let b = Keypair::from_mnemonic(CryptoSuite::Classical, MNEM_B).unwrap();
    let n1 = safety_number(a.public(), b.public());
    let a2 = Keypair::from_mnemonic(CryptoSuite::Classical, MNEM_A).unwrap();
    let b2 = PublicIdentity::from_bytes(&b.public().to_bytes()).unwrap();
    assert_eq!(n1, safety_number(a2.public(), &b2));
    assert_eq!(n1, safety_number(a.public(), b.public()));
}

#[cfg(feature = "pq")]
#[test]
fn suite_changes_number() {
    let peer = classical();
    let c = Keypair::from_mnemonic(CryptoSuite::Classical, MNEM_A).unwrap();
    let h = Keypair::from_mnemonic(CryptoSuite::Hybrid, MNEM_A).unwrap();
    assert_ne!(
        safety_number(c.public(), &peer),
        safety_number(h.public(), &peer)
    );
}

#[test]
fn constants() {
    assert_eq!(SAFETY_NUMBER_DOMAIN, b"lattice-safety-number-v1");
    assert_eq!(SAFETY_NUMBER_GROUPS, 12);
}

// ---- X25519 validation -------------------------------------------------

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn with_x25519(base: &[u8], k: &[u8; 32]) -> Vec<u8> {
    let mut v = base.to_vec();
    v[33..65].copy_from_slice(k);
    v
}

fn is_crypto_err(r: Result<PublicIdentity, Error>) -> bool {
    matches!(r, Err(Error::Crypto(_)))
}

fn pk_with(first: u8, mid: u8, last: u8) -> [u8; 32] {
    let mut k = [mid; 32];
    k[0] = first;
    k[31] = last;
    k
}

#[test]
fn blacklisted_x25519_rejected() {
    let base = classical().to_bytes();
    let mut list: Vec<[u8; 32]> = vec![
        [0u8; 32],
        pk_with(1, 0, 0),
        hex32("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        hex32("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        pk_with(0xec, 0xff, 0x7f),
        pk_with(0xed, 0xff, 0x7f),
        pk_with(0xee, 0xff, 0x7f),
    ];
    list.push(pk_with(0xef, 0xff, 0x7f)); // p+2, AC 10
    list.push(pk_with(0xff, 0xff, 0x7f));
    for k in &list {
        assert!(
            is_crypto_err(PublicIdentity::from_bytes(&with_x25519(&base, k))),
            "accepted bad key {k:02x?}"
        );
    }
}

#[test]
fn x25519_high_bit_rejected() {
    let kp = classical();
    let base = kp.to_bytes();
    let mut k = kp.x25519_bytes();
    k[31] |= 0x80;
    assert!(is_crypto_err(PublicIdentity::from_bytes(&with_x25519(
        &base, &k
    ))));
}

#[cfg(feature = "pq")]
#[test]
fn hybrid_bad_x25519_rejected() {
    let kp = Keypair::generate(CryptoSuite::Hybrid).unwrap();
    let base = kp.public().to_bytes();
    assert!(is_crypto_err(PublicIdentity::from_bytes(&with_x25519(
        &base, &[0u8; 32]
    ))));
}

#[test]
fn generated_keys_roundtrip() {
    for _ in 0..256 {
        let kp = Keypair::generate(CryptoSuite::Classical).unwrap();
        assert!(PublicIdentity::from_bytes(&kp.public().to_bytes()).is_ok());
    }
    #[cfg(feature = "pq")]
    for _ in 0..16 {
        let kp = Keypair::generate(CryptoSuite::Hybrid).unwrap();
        assert!(PublicIdentity::from_bytes(&kp.public().to_bytes()).is_ok());
    }
}
