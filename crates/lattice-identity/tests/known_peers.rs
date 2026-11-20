#![cfg(feature = "storage")]
//! Black-box tests for peer-list parsing and the known/seen peer files
//! (spec AC 13-19).

use lattice_core::PeerId;
use lattice_identity::storage::{
    encode_peer_list, parse_peer_list, IdentityStore, MAX_KNOWN_PEERS, MAX_SEEN_PEERS,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

static N: AtomicU32 = AtomicU32::new(0);

struct Tmp(PathBuf);
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn setup() -> (IdentityStore, Tmp) {
    let dir = std::env::temp_dir().join(format!(
        "lattice-kp-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    (IdentityStore::with_dir(dir.clone()), Tmp(dir))
}

/// Deterministic distinct id for `n` (big-endian in the first bytes so that
/// numeric order == byte order).
fn id(n: u32) -> PeerId {
    let mut b = [0x11u8; 32];
    b[..4].copy_from_slice(&n.to_be_bytes());
    PeerId(b)
}

fn ids(r: std::ops::Range<u32>) -> Vec<PeerId> {
    r.map(id).collect()
}

#[test]
fn constants() {
    assert_eq!(MAX_KNOWN_PEERS, 1024);
    assert_eq!(MAX_SEEN_PEERS, 64);
}

#[test]
fn roundtrip_preserves_order() {
    for v in [vec![], ids(0..1), vec![id(5), id(2), id(9), id(1)]] {
        let enc = encode_peer_list(&v);
        assert_eq!(parse_peer_list(&enc, 16).unwrap(), v);
    }
}

#[test]
fn parse_rejects_malformed() {
    let a = format!("{}\n", id(1));
    let b = format!("{}\n", id(2));
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("non-ascii", "é".repeat(32).into_bytes()),
        (
            "uppercase",
            format!("{}\n", PeerId([0xab; 32]))
                .to_uppercase()
                .into_bytes(),
        ),
        ("short line", b"abcd\n".to_vec()),
        ("65 chars", format!("0{}", a).into_bytes()),
        ("no final newline", a.trim_end().as_bytes().to_vec()),
        ("blank line", format!("{a}\n{b}").into_bytes()),
        ("lone newline", b"\n".to_vec()),
        ("cr", format!("{}\r\n", id(1)).into_bytes()),
        ("leading space", format!(" {a}").into_bytes()),
        ("trailing space", format!("{} \n", id(1)).into_bytes()),
        ("duplicate", format!("{a}{a}").into_bytes()),
        ("non-hex", format!("{}\n", "g".repeat(64)).into_bytes()),
    ];
    for (name, bytes) in cases {
        assert!(parse_peer_list(&bytes, 16).is_err(), "accepted: {name}");
    }
    assert_eq!(parse_peer_list(b"", 16).unwrap(), vec![]);
}

#[test]
fn parse_enforces_max() {
    let ok = encode_peer_list(&ids(0..8));
    assert_eq!(parse_peer_list(&ok, 8).unwrap().len(), 8);
    let over = encode_peer_list(&ids(0..9));
    assert!(parse_peer_list(&over, 8).is_err());
}

#[test]
fn add_known_peer_idempotent() {
    let (s, t) = setup();
    let x = id(7);
    assert!(s.add_known_peer(&x).unwrap());
    assert!(!s.add_known_peer(&x).unwrap());
    assert_eq!(s.load_known_peers().unwrap(), vec![x]);
    let bytes = std::fs::read(t.0.join("known_peers")).unwrap();
    assert!(parse_peer_list(&bytes, MAX_KNOWN_PEERS).is_ok());
}

#[test]
fn known_peers_sorted() {
    let (s, _t) = setup();
    for n in [9, 3, 7, 1, 5, 8, 2] {
        s.add_known_peer(&id(n)).unwrap();
    }
    let got = s.load_known_peers().unwrap();
    let mut want = got.clone();
    want.sort_by_key(|a| a.0);
    assert_eq!(got, want);
    assert_eq!(got.len(), 7);
}

#[test]
fn missing_known_peers_is_empty() {
    let (s, _t) = setup();
    assert_eq!(s.load_known_peers().unwrap(), vec![]);
    assert_eq!(s.load_seen_peers().unwrap(), vec![]);
}

#[test]
fn corrupt_known_peers_errors_and_is_untouched() {
    let (s, t) = setup();
    s.add_known_peer(&id(1)).unwrap();
    let path = t.0.join("known_peers");
    let bad = format!("{}\n", PeerId([0xab; 32]))
        .to_uppercase()
        .into_bytes();
    std::fs::write(&path, &bad).unwrap();
    assert!(s.load_known_peers().is_err());
    assert!(s.add_known_peer(&id(3)).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bad);
}

#[test]
fn full_known_peers_rejects_add() {
    let (s, t) = setup();
    std::fs::create_dir_all(&t.0).unwrap();
    let path = t.0.join("known_peers");
    let full = encode_peer_list(&ids(0..MAX_KNOWN_PEERS as u32));
    std::fs::write(&path, &full).unwrap();
    assert_eq!(s.load_known_peers().unwrap().len(), MAX_KNOWN_PEERS);
    assert!(s.add_known_peer(&id(100_000)).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), full);
    // already-present id is still Ok(false)
    assert!(!s.add_known_peer(&id(5)).unwrap());
}

#[test]
fn oversized_files_rejected_on_load() {
    let (s, t) = setup();
    std::fs::create_dir_all(&t.0).unwrap();
    let big = encode_peer_list(&ids(0..(MAX_KNOWN_PEERS as u32 + 1)));
    std::fs::write(t.0.join("known_peers"), big).unwrap();
    assert!(s.load_known_peers().is_err());
    let big = encode_peer_list(&ids(0..(MAX_SEEN_PEERS as u32 + 1)));
    std::fs::write(t.0.join("seen_peers"), big).unwrap();
    assert!(s.load_seen_peers().is_err());
}

#[test]
fn seen_peers_bounded_oldest_first() {
    let (s, _t) = setup();
    for n in 0..70 {
        s.note_seen_peer(&id(n)).unwrap();
    }
    let got = s.load_seen_peers().unwrap();
    assert_eq!(got.len(), MAX_SEEN_PEERS);
    assert_eq!(got, ids(6..70));
    assert_eq!(got.last().unwrap(), &id(69));
}

#[test]
fn seen_peers_renote_moves_to_end() {
    let (s, _t) = setup();
    for n in 0..5 {
        s.note_seen_peer(&id(n)).unwrap();
    }
    s.note_seen_peer(&id(1)).unwrap();
    assert_eq!(
        s.load_seen_peers().unwrap(),
        vec![id(0), id(2), id(3), id(4), id(1)]
    );
}

#[test]
fn corrupt_seen_peers_replaced_and_known_untouched() {
    let (s, t) = setup();
    s.add_known_peer(&id(50)).unwrap();
    let known_before = std::fs::read(t.0.join("known_peers")).unwrap();
    std::fs::write(t.0.join("seen_peers"), b"garbage").unwrap();
    assert!(s.load_seen_peers().is_err());
    s.note_seen_peer(&id(1)).unwrap();
    assert_eq!(s.load_seen_peers().unwrap(), vec![id(1)]);
    assert_eq!(
        std::fs::read(t.0.join("known_peers")).unwrap(),
        known_before
    );
    assert_eq!(s.load_known_peers().unwrap(), vec![id(50)]);
}

#[cfg(unix)]
#[test]
fn known_peers_file_mode_0600() {
    use std::os::unix::fs::PermissionsExt;
    let (s, t) = setup();
    s.add_known_peer(&id(1)).unwrap();
    let m = std::fs::metadata(t.0.join("known_peers"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(m & 0o777, 0o600);
}
