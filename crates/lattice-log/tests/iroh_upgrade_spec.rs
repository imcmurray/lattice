//! Manifest / lockfile / docs checks for the iroh 1.5.0 upgrade.

use std::fs;
use std::path::PathBuf;

fn read(name: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    fs::read_to_string(root.join(name)).expect(name)
}

/// All `(name, version)` pairs in Cargo.lock.
fn lock_packages() -> Vec<(String, String)> {
    let lock = read("Cargo.lock");
    let mut out = Vec::new();
    let mut name: Option<String> = None;
    for line in lock.lines() {
        if let Some(n) = line.strip_prefix("name = \"") {
            name = Some(n.trim_end_matches('"').to_string());
        } else if let Some(v) = line.strip_prefix("version = \"") {
            if let Some(n) = name.take() {
                out.push((n, v.trim_end_matches('"').to_string()));
            }
        }
    }
    out
}

#[test]
fn transport_manifest_requires_iroh_1_5() {
    let m = read("crates/lattice-transport/Cargo.toml");
    assert!(
        m.contains("iroh = { version = \"1.5\", optional = true }"),
        "iroh requirement not bumped to 1.5"
    );
}

#[test]
fn lock_resolves_iroh_at_least_1_5() {
    let pk = lock_packages();
    let irohs: Vec<_> = pk.iter().filter(|(n, _)| n == "iroh").collect();
    assert_eq!(irohs.len(), 1, "expected exactly one iroh: {irohs:?}");
    let v: Vec<u32> = irohs[0]
        .1
        .split('.')
        .map(|p| p.parse().expect("numeric version"))
        .collect();
    assert_eq!(v[0], 1, "iroh major must be 1");
    assert!(v[1] >= 5, "iroh must be >= 1.5.0, got {}", irohs[0].1);
}

#[test]
fn lock_has_no_rc_dalek() {
    for (n, v) in lock_packages() {
        if n == "ed25519-dalek" || n == "curve25519-dalek" {
            assert!(!v.contains("-rc"), "{n} {v} is a release candidate");
        }
    }
}

#[test]
fn design_does_not_claim_upgrade_removes_duplicate() {
    let d = read("DESIGN.md");
    assert!(!d.contains("goes away with an iroh upgrade"));
    assert!(!d.contains("iroh 1.0.1"));
    assert!(!d.contains("3.0.0-rc"));
}

#[test]
fn quic_docs_name_iroh_1_5() {
    let q = read("crates/lattice-transport/src/quic.rs");
    assert!(!q.contains("iroh 1.0.1"));
    assert!(q.contains("iroh 1.5.0"));
}

#[test]
fn no_stray_summary_files() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for f in ["Changes.md", "CHANGES.md", "CHANGELOG.md", "CHANGELOG"] {
        assert!(!root.join(f).exists(), "{f} must not exist");
    }
}
