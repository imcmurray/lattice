//! Public-API tests for `PeerId` Display / fingerprint / Debug (spec ACs 1-3).

use lattice_core::PeerId;

#[test]
fn display_is_64_lowercase_hex() {
    let s = PeerId([0xab; 32]).to_string();
    assert_eq!(s, "ab".repeat(32));
    assert_eq!(s.len(), 64);
    assert!(s
        .chars()
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
}

#[test]
fn display_zero_padding() {
    let mut b = [0u8; 32];
    b[0] = 0x01;
    b[31] = 0x0f;
    let s = PeerId(b).to_string();
    assert!(s.starts_with("01"));
    assert!(s.ends_with("0f"));
    assert_eq!(s.len(), 64);
}

#[test]
fn fingerprint_exact() {
    let mut b = [0u8; 32];
    for (i, x) in b.iter_mut().enumerate() {
        *x = i as u8;
    }
    let fp = PeerId(b).fingerprint();
    assert_eq!(fp, "0001 0203 0405 0607 0809 0a0b 0c0d 0e0f 1011 1213");
    assert_eq!(fp.len(), 49);
}

#[test]
fn fingerprint_is_prefix_of_display() {
    let p = PeerId([0xcd; 32]);
    let fp = p.fingerprint().replace(' ', "");
    assert_eq!(fp.len(), 40);
    assert!(p.to_string().starts_with(&fp));
}

#[test]
fn debug_stays_short() {
    let p = PeerId([0xab; 32]);
    let d = format!("{p:?}");
    assert!(d.starts_with("PeerId("));
    assert!(d.contains("abababab"));
    assert!(!d.contains(&"ab".repeat(32)));
    assert!(d.len() < 30);
}
