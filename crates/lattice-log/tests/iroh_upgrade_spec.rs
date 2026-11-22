//! Dependency floor checks: lattice-transport must require and resolve an iroh
//! with the 1.5.0 security fixes, and no release-candidate dalek crate may be
//! in the lockfile. These check properties, not exact versions, so a later
//! compatible bump (iroh 1.6, dalek 3.0.x) keeps passing.

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

/// `(major, minor)` of a version or a caret requirement like "1.5" / "^1.5.2".
/// Panics with a clear message on anything else (e.g. a pre-release).
fn major_minor(v: &str) -> (u32, u32) {
    let v = v.trim_start_matches('^');
    let mut it = v.split('.').map(|p| {
        p.parse::<u32>()
            .unwrap_or_else(|_| panic!("not a plain numeric version: {v:?}"))
    });
    (it.next().unwrap(), it.next().unwrap_or(0))
}

#[test]
fn transport_manifest_requires_iroh_at_least_1_5() {
    let m = read("crates/lattice-transport/Cargo.toml");
    let line = m
        .lines()
        .find(|l| l.trim_start().starts_with("iroh = {"))
        .expect("lattice-transport must declare iroh");
    let req = line
        .split("version = \"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .expect("iroh requirement must have a version");
    let (major, minor) = major_minor(req);
    assert!(
        major == 1 && minor >= 5,
        "iroh requirement must be >= 1.5 (security fixes), got {req:?}"
    );
}

#[test]
fn lock_resolves_iroh_at_least_1_5() {
    let pk = lock_packages();
    let irohs: Vec<_> = pk.iter().filter(|(n, _)| n == "iroh").collect();
    assert_eq!(irohs.len(), 1, "expected exactly one iroh: {irohs:?}");
    let (major, minor) = major_minor(&irohs[0].1);
    assert!(
        major == 1 && minor >= 5,
        "iroh must resolve to >= 1.5.0, got {}",
        irohs[0].1
    );
}

#[test]
fn lock_has_no_rc_dalek() {
    for (n, v) in lock_packages() {
        if n == "ed25519-dalek" || n == "curve25519-dalek" {
            assert!(!v.contains("-rc"), "{n} {v} is a release candidate");
        }
    }
}
