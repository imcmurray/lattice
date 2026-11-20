//! Documentation acceptance checks (spec D1-D3) for DESIGN.md / SECURITY.md.

use std::fs;
use std::path::PathBuf;

fn read(name: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    fs::read_to_string(root.join(name)).expect(name)
}

#[test]
fn design_has_no_stale_claims() {
    let d = read("DESIGN.md");
    for bad in [
        "Noise",
        "snow",
        "identity-hiding",
        "Until the session KEM lands",
        "revocation via epoch bump",
    ] {
        assert!(!d.contains(bad), "DESIGN.md still contains {bad:?}");
    }
    let s = read("SECURITY.md");
    assert!(!s.contains("Noise") && !s.contains("snow"));
}

#[test]
fn design_mentions_required_terms() {
    let d = read("DESIGN.md");
    for need in [
        "lattice-session-hs-v3",
        "lattice-sig-v2",
        "lattice-resume-v2",
        "lattice-ticket-v1",
        "lattice-net-cb-v1",
        "ed25519-dalek 3.0.0-rc.0",
        "64 KiB",
        "not_after",
        "ADR-007",
        "ADR-008",
        "ADR-009",
        "ADR-010",
        "ADR-011",
        "ADR-012",
    ] {
        assert!(d.contains(need), "DESIGN.md missing {need:?}");
    }
}

#[test]
fn adrs_appear_in_order() {
    let d = read("DESIGN.md");
    let mut last = 0;
    for n in 6..=12 {
        let key = format!("ADR-{n:03}");
        // Earlier sections may cross-reference an ADR, so use the last mention
        // (the §8 entry).
        let pos = d.rfind(&key).unwrap_or_else(|| panic!("missing {key}"));
        assert!(pos >= last, "{key} out of order");
        last = pos;
    }
}

#[test]
fn security_md_has_new_limitations() {
    let s = read("SECURITY.md").to_lowercase();
    for kw in ["metadata", "identity hiding", "single-hop"] {
        let alt = kw.replace(' ', "-");
        assert!(
            s.contains(kw) || s.contains(&alt),
            "SECURITY.md missing limitation keyword {kw:?}"
        );
    }
    assert!(s.contains("revocation"));
    assert!(s.contains("fingerprint"));
    assert!(s.contains("bearer"));
}
