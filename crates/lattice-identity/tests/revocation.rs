//! Black-box tests for `RevocationList` (spec criteria 1-8). Public API only.

use lattice_core::{CryptoSuite, Error, PeerId, Verify};
use lattice_identity::{DeviceCert, Keypair, RevocationList, MAX_REVOCATION_LIST_LEN, MAX_REVOKED};

fn suites() -> Vec<CryptoSuite> {
    #[allow(unused_mut)]
    let mut v = vec![CryptoSuite::Classical];
    #[cfg(feature = "pq")]
    v.push(CryptoSuite::Hybrid);
    v
}

fn pid(n: u32) -> PeerId {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&n.to_be_bytes());
    b[31] = 0x5a;
    PeerId(b)
}

fn is_crypto<T>(r: &Result<T, Error>) -> bool {
    matches!(r, Err(Error::Crypto(_)))
}

#[test]
fn sorted_dedup_and_verifies() {
    for s in suites() {
        let root = Keypair::generate(s).unwrap();
        let l = root
            .revoke_devices(3, 100, &[pid(9), pid(1), pid(9), pid(5), pid(1)])
            .unwrap();
        assert_eq!(l.revoked(), &[pid(1), pid(5), pid(9)]);
        assert!(l.revoked().windows(2).all(|w| w[0].0 < w[1].0));
        assert!(l.verify(root.public()));
        assert_eq!(l.seq(), 3);
        assert_eq!(l.issued_at(), 100);
        assert_eq!(l.root(), &root.public().peer_id());
    }
}

#[test]
fn root_in_list_and_cap() {
    for s in suites() {
        let root = Keypair::generate(s).unwrap();
        assert!(is_crypto(&root.revoke_devices(
            1,
            1,
            &[pid(1), root.public().peer_id()]
        )));
        let too_many: Vec<PeerId> = (0..=MAX_REVOKED as u32).map(pid).collect();
        assert!(is_crypto(&root.revoke_devices(1, 1, &too_many)));
        // duplicates collapse, so >MAX inputs with <=MAX distinct is fine
        let mut dups: Vec<PeerId> = (0..MAX_REVOKED as u32).map(pid).collect();
        dups.extend((0..10).map(pid));
        assert!(root.revoke_devices(1, 1, &dups).is_ok());
        let empty = root.revoke_devices(0, 0, &[]).unwrap();
        assert!(empty.revoked().is_empty());
        assert!(empty.verify(root.public()));
    }
}

#[test]
fn max_entries_fits_len_cap() {
    for s in suites() {
        let root = Keypair::generate(s).unwrap();
        let ids: Vec<PeerId> = (0..MAX_REVOKED as u32).map(pid).collect();
        let l = root.revoke_devices(u64::MAX, u64::MAX, &ids).unwrap();
        let b = l.to_bytes();
        assert!(b.len() <= MAX_REVOCATION_LIST_LEN, "{}", b.len());
        let back = RevocationList::from_bytes(&b).unwrap();
        assert!(back.verify(root.public()));
        assert_eq!(back.revoked().len(), MAX_REVOKED);
    }
}

#[test]
fn roundtrip_byte_identical() {
    for s in suites() {
        let root = Keypair::generate(s).unwrap();
        let l = root.revoke_devices(7, 8, &[pid(3), pid(2)]).unwrap();
        let b = l.to_bytes();
        let back = RevocationList::from_bytes(&b).unwrap();
        assert_eq!(back.to_bytes(), b);
        assert!(back.verify(root.public()));
    }
}

/// Offsets: root[0..32] seq[32..40] issued[40..48] n[48..52] entries[52..52+32n] sig_len sig
#[test]
fn tampering_any_field_breaks_verify() {
    for s in suites() {
        let root = Keypair::generate(s).unwrap();
        let l = root.revoke_devices(7, 8, &[pid(3), pid(2)]).unwrap();
        let b = l.to_bytes();
        let sig_start = 52 + 64 + 4;
        let positions = [
            0,              // root
            32,             // seq
            40,             // issued_at
            52,             // first entry
            52 + 32 + 5,    // second entry (stays sorted? maybe not; either way must fail)
            sig_start,      // first sig byte
            sig_start + 10, // mid sig
            b.len() - 1,    // last sig byte
        ];
        for p in positions {
            let mut t = b.clone();
            t[p] ^= 0x01;
            match RevocationList::from_bytes(&t) {
                Err(_) => {}
                Ok(l2) => assert!(!l2.verify(root.public()), "flip at {p} still verifies"),
            }
        }
    }
}

#[test]
fn wrong_root_does_not_verify() {
    for s in suites() {
        let a = Keypair::generate(s).unwrap();
        let b = Keypair::generate(s).unwrap();
        let l = a.revoke_devices(1, 1, &[pid(1)]).unwrap();
        assert!(l.verify(a.public()));
        assert!(!l.verify(b.public()));
    }
}

#[test]
fn from_bytes_rejects_malformed() {
    let root = Keypair::generate(CryptoSuite::Classical).unwrap();
    let l = root.revoke_devices(1, 1, &[pid(1), pid(2)]).unwrap();
    let b = l.to_bytes();

    // trailing byte
    let mut t = b.clone();
    t.push(0);
    assert!(is_crypto(&RevocationList::from_bytes(&t)));

    // truncated at every prefix length
    for n in 0..b.len() {
        assert!(RevocationList::from_bytes(&b[..n]).is_err(), "prefix {n}");
    }

    // huge declared count with a short body
    let mut t = b[..52].to_vec();
    t[48..52].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(RevocationList::from_bytes(&t).is_err());
    let mut t = b.clone();
    t[48..52].copy_from_slice(&(MAX_REVOKED as u32 + 1).to_le_bytes());
    assert!(RevocationList::from_bytes(&t).is_err());

    // oversized input
    let big = vec![0u8; MAX_REVOCATION_LIST_LEN + 1];
    assert!(RevocationList::from_bytes(&big).is_err());

    // unsorted entries
    let mut t = b.clone();
    let (first, second) = (b[52..84].to_vec(), b[84..116].to_vec());
    t[52..84].copy_from_slice(&second);
    t[84..116].copy_from_slice(&first);
    assert!(is_crypto(&RevocationList::from_bytes(&t)));

    // duplicate entries
    let mut t = b.clone();
    t[84..116].copy_from_slice(&first);
    assert!(is_crypto(&RevocationList::from_bytes(&t)));
}

#[test]
fn is_revoked_and_supersedes() {
    let root = Keypair::generate(CryptoSuite::Classical).unwrap();
    let other = Keypair::generate(CryptoSuite::Classical).unwrap();
    let l1 = root.revoke_devices(1, 1, &[pid(1), pid(2)]).unwrap();
    let l1b = root.revoke_devices(1, 5, &[pid(3)]).unwrap();
    let l2 = root.revoke_devices(2, 1, &[]).unwrap();
    let lo = other.revoke_devices(9, 1, &[]).unwrap();
    assert!(l1.is_revoked(&pid(1)));
    assert!(l1.is_revoked(&pid(2)));
    assert!(!l1.is_revoked(&pid(3)));
    assert!(l2.supersedes(&l1));
    assert!(!l1.supersedes(&l2));
    assert!(!l1.supersedes(&l1b));
    assert!(!l1.supersedes(&l1));
    assert!(!lo.supersedes(&l1));
    assert!(!l1.supersedes(&lo));
}

#[test]
fn cert_verify_with_revocation() {
    for s in suites() {
        let root = Keypair::generate(s).unwrap();
        let dev = Keypair::generate(s).unwrap();
        let cert: DeviceCert = root.authorize_device(dev.public(), 1000).unwrap();
        let now = 500;
        assert!(cert.verify_with_revocation(root.public(), now, None));

        let ok = root.revoke_devices(1, 1, &[pid(1)]).unwrap();
        assert!(cert.verify_with_revocation(root.public(), now, Some(&ok)));

        let bad = root
            .revoke_devices(2, 1, &[dev.public().peer_id()])
            .unwrap();
        assert!(!cert.verify_with_revocation(root.public(), now, Some(&bad)));

        let other = Keypair::generate(s).unwrap();
        let foreign = other.revoke_devices(1, 1, &[]).unwrap();
        assert!(!cert.verify_with_revocation(root.public(), now, Some(&foreign)));

        // expired
        assert!(!cert.verify_with_revocation(root.public(), 1001, None));
        assert!(!cert.verify_with_revocation(root.public(), 1001, Some(&ok)));
        // boundary: now == not_after still valid
        assert!(cert.verify_with_revocation(root.public(), 1000, None));
    }
}
