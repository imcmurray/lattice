#![cfg(feature = "storage")]
//! Black-box storage tests for device keys / root forgetting / revocation
//! caches (spec criteria 9-15). Age backend only, unique temp dir per test.

use lattice_core::{CryptoSuite, PeerId, Verify};
use lattice_identity::storage::{IdentityStore, MAX_PEER_REVOCATIONS};
use lattice_identity::Keypair;
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
    std::env::set_var("LATTICE_STORAGE", "age");
    std::env::set_var("LATTICE_PASSPHRASE", "correct horse battery staple");
    let dir = std::env::temp_dir().join(format!(
        "lattice-sd-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    (IdentityStore::with_dir(dir.clone()), Tmp(dir))
}

fn pid(n: u32) -> PeerId {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&n.to_be_bytes());
    PeerId(b)
}

const H: CryptoSuite = CryptoSuite::Hybrid;
const FAR: u64 = 4_000_000_000;

#[test]
fn device_roundtrip() {
    let (st, t) = setup();
    let root = st.load_or_create(H).unwrap();
    let d = st.provision_device(&root.keypair, H, FAR).unwrap();
    let l = st.load_device(H).unwrap().expect("device present");
    assert_eq!(l.keypair.public().peer_id(), d.keypair.public().peer_id());
    assert_eq!(l.cert.to_bytes(), d.cert.to_bytes());
    assert_eq!(l.root.peer_id(), root.keypair.public().peer_id());
    assert_ne!(
        l.keypair.public().peer_id(),
        root.keypair.public().peer_id()
    );
    for f in ["device.age", "device.cert", "root.pub", "identity.age"] {
        assert!(t.0.join(f).exists(), "{f}");
    }
}

#[test]
fn load_device_none_when_absent() {
    let (st, _t) = setup();
    assert!(st.load_device(H).unwrap().is_none());
    st.load_or_create(H).unwrap();
    assert!(st.load_device(H).unwrap().is_none());
}

#[test]
fn forget_root_flow_and_import() {
    let (st, t) = setup();
    let root = st.load_or_create(H).unwrap();
    let phrase = root.keypair.mnemonic().to_string();
    let rid = root.keypair.public().peer_id();
    let d = st.provision_device(&root.keypair, H, FAR).unwrap();
    assert!(st.has_root().unwrap());
    st.forget_root().unwrap();
    assert!(!st.has_root().unwrap());
    assert!(st.load_root(H).unwrap().is_none());
    assert!(!t.0.join("identity.age").exists());
    let l = st.load_device(H).unwrap().unwrap();
    assert_eq!(l.keypair.public().peer_id(), d.keypair.public().peer_id());
    assert!(st.load_or_create(H).is_err());
    assert!(!t.0.join("identity.age").exists());

    // different valid phrase / invalid phrase
    let other = Keypair::generate(H).unwrap();
    assert!(st.import_root(H, other.mnemonic()).is_err());
    assert!(st.import_root(H, "not a valid mnemonic phrase").is_err());
    assert!(!st.has_root().unwrap());

    let r = st.import_root(H, &phrase).unwrap();
    assert_eq!(r.keypair.public().peer_id(), rid);
    assert!(!r.created && !r.migrated);
    assert!(st.has_root().unwrap());
    assert_eq!(
        st.load_root(H).unwrap().unwrap().keypair.public().peer_id(),
        rid
    );
    // idempotent
    assert!(st.import_root(H, &phrase).is_ok());
}

#[test]
fn forget_root_without_device_errs_and_keeps_root() {
    let (st, _t) = setup();
    let root = st.load_or_create(H).unwrap();
    assert!(st.forget_root().is_err());
    assert!(st.has_root().unwrap());
    let l = st.load_root(H).unwrap().unwrap();
    assert_eq!(
        l.keypair.public().peer_id(),
        root.keypair.public().peer_id()
    );
}

#[test]
fn legacy_root_only_store_keeps_root() {
    let (st, _t) = setup();
    let root = st.load_or_create(H).unwrap();
    let rid = root.keypair.public().peer_id();
    assert!(st.load_device(H).unwrap().is_none());
    let again = st.load_root(H).unwrap().unwrap();
    assert_eq!(again.keypair.public().peer_id(), rid);
    st.provision_device(&again.keypair, H, FAR).unwrap();
    let d = st.load_device(H).unwrap().unwrap();
    assert_eq!(d.root.peer_id(), rid);
    assert_eq!(
        st.load_root(H).unwrap().unwrap().keypair.public().peer_id(),
        rid
    );
}

#[test]
fn load_device_rejects_mismatched_cert() {
    let (st, t) = setup();
    let root = st.load_or_create(H).unwrap();
    st.provision_device(&root.keypair, H, FAR).unwrap();

    // cert for another device, same root
    let other_dev = Keypair::generate(H).unwrap();
    let c = root
        .keypair
        .authorize_device(other_dev.public(), FAR)
        .unwrap();
    let orig = std::fs::read(t.0.join("device.cert")).unwrap();
    std::fs::write(t.0.join("device.cert"), c.to_bytes()).unwrap();
    assert!(st.load_device(H).is_err());

    // cert for this device but signed by another root
    std::fs::write(t.0.join("device.cert"), &orig).unwrap();
    assert!(st.load_device(H).unwrap().is_some());
    let imposter = Keypair::generate(H).unwrap();
    let c2 = imposter.authorize_device(other_dev.public(), FAR).unwrap();
    std::fs::write(t.0.join("device.cert"), c2.to_bytes()).unwrap();
    assert!(st.load_device(H).is_err());

    // garbage
    std::fs::write(t.0.join("device.cert"), b"garbage").unwrap();
    assert!(st.load_device(H).is_err());

    // tampered cert (flip last byte = signature)
    let mut tam = orig.clone();
    *tam.last_mut().unwrap() ^= 1;
    std::fs::write(t.0.join("device.cert"), &tam).unwrap();
    assert!(st.load_device(H).is_err());

    // missing cert while secret present
    std::fs::remove_file(t.0.join("device.cert")).unwrap();
    assert!(st.load_device(H).is_err());
}

#[test]
fn store_device_validates() {
    let (st, t) = setup();
    let root = Keypair::generate(H).unwrap();
    let dev = Keypair::generate(H).unwrap();
    let other = Keypair::generate(H).unwrap();
    let cert = root.authorize_device(other.public(), FAR).unwrap();
    // cert is for `other`, not `dev`
    assert!(st.store_device(&dev, &cert, root.public()).is_err());
    assert!(!t.0.join("device.age").exists());
    assert!(!t.0.join("device.cert").exists());
    // wrong root public
    let good = root.authorize_device(dev.public(), FAR).unwrap();
    assert!(st.store_device(&dev, &good, other.public()).is_err());
    assert!(!t.0.join("root.pub").exists());
    // ok
    st.store_device(&dev, &good, root.public()).unwrap();
    assert!(st.load_device(H).unwrap().is_some());
    assert_eq!(
        st.root_public().unwrap().unwrap().peer_id(),
        root.public().peer_id()
    );
}

#[test]
fn revocation_files() {
    let (st, t) = setup();
    let root = Keypair::generate(H).unwrap();
    assert!(st.load_revocation().unwrap().is_none());
    let l = root.revoke_devices(1, 1, &[pid(1)]).unwrap();
    st.store_revocation(&l).unwrap();
    assert_eq!(
        st.load_revocation().unwrap().unwrap().to_bytes(),
        l.to_bytes()
    );
    std::fs::write(t.0.join("revocation.bin"), b"junk").unwrap();
    assert!(st.load_revocation().is_err());
}

#[test]
fn peer_revocations() {
    let (st, t) = setup();
    assert!(st.load_peer_revocations().unwrap().is_empty());
    let root = Keypair::generate(H).unwrap();
    let l1 = root.revoke_devices(5, 1, &[pid(1)]).unwrap();
    let l1_eq = root.revoke_devices(5, 2, &[pid(2)]).unwrap();
    let l_lo = root.revoke_devices(4, 1, &[]).unwrap();
    let l_hi = root.revoke_devices(6, 1, &[pid(3)]).unwrap();
    assert!(st.store_peer_revocation(&l1).unwrap());
    assert!(!st.store_peer_revocation(&l1_eq).unwrap());
    assert!(!st.store_peer_revocation(&l_lo).unwrap());
    let got = st.load_peer_revocations().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].seq(), 5);
    assert!(got[0].is_revoked(&pid(1)));
    assert!(st.store_peer_revocation(&l_hi).unwrap());
    let got = st.load_peer_revocations().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].seq(), 6);

    // garbage and misnamed files are skipped
    std::fs::write(t.0.join("peers").join("garbage.rev"), b"xx").unwrap();
    let other = Keypair::generate(H).unwrap();
    let lo = other.revoke_devices(1, 1, &[]).unwrap();
    std::fs::write(
        t.0.join("peers").join(format!("{}.rev", "00".repeat(32))),
        lo.to_bytes(),
    )
    .unwrap();
    let got = st.load_peer_revocations().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].seq(), 6);
}

#[test]
fn peer_revocation_cap() {
    let (st, _t) = setup();
    // Classical keys keep this fast.
    for _ in 0..MAX_PEER_REVOCATIONS {
        let r = Keypair::generate(CryptoSuite::Classical).unwrap();
        assert!(st
            .store_peer_revocation(&r.revoke_devices(1, 1, &[]).unwrap())
            .unwrap());
    }
    let extra = Keypair::generate(CryptoSuite::Classical).unwrap();
    assert!(!st
        .store_peer_revocation(&extra.revoke_devices(1, 1, &[]).unwrap())
        .unwrap());
    assert_eq!(
        st.load_peer_revocations().unwrap().len(),
        MAX_PEER_REVOCATIONS
    );
}
