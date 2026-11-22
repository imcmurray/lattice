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
        "lattice-ticket-v2",
        "lattice-net-cb-v1",
        "ed25519-dalek 3.0.0",
        "64 KiB",
        "not_after",
        "ADR-007",
        "ADR-008",
        "ADR-009",
        "ADR-010",
        "ADR-011",
        "ADR-012",
        "ADR-013",
        "lattice-revocation-v1",
    ] {
        assert!(d.contains(need), "DESIGN.md missing {need:?}");
    }
}

#[test]
fn docs_drop_release_candidate_claims() {
    let d = read("DESIGN.md");
    let s = read("SECURITY.md");
    assert!(!d.contains("3.0.0-rc"), "DESIGN.md still mentions 3.0.0-rc");
    assert!(
        !s.contains("3.0.0-rc"),
        "SECURITY.md still mentions 3.0.0-rc"
    );
    assert!(
        !d.contains("iroh 1.0.1"),
        "DESIGN.md still mentions iroh 1.0.1"
    );
}

#[test]
fn adrs_appear_in_order() {
    let d = read("DESIGN.md");
    let mut last = 0;
    for n in 6..=13 {
        let key = format!("ADR-{n:03}");
        // Earlier sections may cross-reference an ADR, so use the last mention
        // (the §8 entry).
        let pos = d.rfind(&key).unwrap_or_else(|| panic!("missing {key}"));
        assert!(pos >= last, "{key} out of order");
        last = pos;
    }
}

fn collapsed(name: &str) -> String {
    read(name).split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn design_states_exact_transcript() {
    let d = collapsed("DESIGN.md");
    for need in [
        "\"lattice-session-hs-v3\" ‖ lp(binding) ‖ lp(initiator) ‖ lp(responder) ‖ eph_i ‖ ratchet_pub_i ‖ lp(kem_ct_s) ‖ lp(kem_ek_i)",
        "T1 ‖ lp(sig_i) ‖ eph_r ‖ lp(kem_ct_e)",
        "T2 ‖ lp(sig_r)",
        "classical-only security",
        "MAX_PENDING_ACCEPTS",
        "MAX_BUSY_REPLIES",
    ] {
        assert!(d.contains(need), "DESIGN.md missing {need:?}");
    }
}

#[test]
fn design_drops_overclaims() {
    let d = collapsed("DESIGN.md");
    for bad in [
        "classical-only (harvest-now-decrypt-later risk)",
        "Hybrid, never PQ-only or classical-only",
        "Each side verifies the peer's signature **before** any DH or decapsulation",
        "day-to-day signing via device subkeys",
        "plaintext backed up",
        "Residual: `IrohTransport::accept_conn` has no timeout",
        "lattice-ticket-v1`: signed",
        "lattice-net uses the root identity directly",
    ] {
        assert!(!d.contains(bad), "DESIGN.md still contains {bad:?}");
    }
    let s = collapsed("SECURITY.md");
    assert!(!s.contains("no revocation list yet"));
    assert!(!s.contains("uses the root identity directly"));
}

#[test]
fn design_unimplemented_items_follow_marker() {
    let d = collapsed("DESIGN.md");
    let marker = "**Not implemented (future):**";
    let first = d.find(marker).expect("marker missing");
    for term in ["proof-of-membership", "peer-scoring"] {
        for (pos, _) in d.match_indices(term) {
            assert!(pos > first, "{term:?} appears before the marker");
        }
    }
}

#[test]
fn adr004_mentions_root_identity_use() {
    let d = collapsed("DESIGN.md");
    let start = d.rfind("ADR-004").unwrap();
    let end = start + d[start..].find("ADR-005").unwrap();
    let adr = &d[start..end];
    assert!(adr.contains("root") && adr.contains("device subkeys"));
}

#[test]
fn security_md_qualifies_hybrid_handshake() {
    let s = collapsed("SECURITY.md").to_lowercase();
    assert!(s.contains("classical"));
    assert!(s.contains("responder is hybrid"));
}

#[test]
fn docs_mention_safety_numbers_and_hardening() {
    let d = read("DESIGN.md");
    for need in [
        "lattice-safety-number-v1",
        "known_peers",
        "MAX_KEPT_SESSIONS",
        "CONNECT_TIMEOUT",
    ] {
        assert!(d.contains(need), "DESIGN.md missing {need:?}");
    }
    let s = read("SECURITY.md").to_lowercase();
    for need in ["safety number", "verify-peer", "x25519"] {
        assert!(s.contains(need), "SECURITY.md missing {need:?}");
    }
}

/// The ADR-006 entry in §8 (from its last mention up to the next ADR).
fn adr006(d: &str) -> String {
    let start = d.rfind("ADR-006").unwrap();
    let end = start + d[start..].find("ADR-007").unwrap();
    d[start..end].to_string()
}

#[test]
fn adr006_describes_the_current_wire() {
    let adr = adr006(&collapsed("DESIGN.md"));
    for need in ["WIRE_VERSION", "resume_allowed", "hello", "ADR-013"] {
        assert!(adr.contains(need), "ADR-006 missing {need:?}");
    }
    for bad in ["1-byte mode prefix", "resumes if it holds the session"] {
        assert!(!adr.contains(bad), "ADR-006 still contains {bad:?}");
    }
}

#[test]
fn design_documents_flood_limits() {
    let d = collapsed("DESIGN.md");
    for need in [
        "RESERVED_VERIFIED_SLOTS",
        "MAX_FAILURES_BEFORE_BAN",
        "BAN_DURATION",
        "MAX_TRACKED_SOURCES",
        "GLOBAL_ACCEPT_REFILL",
        "PROVISIONAL_HANDSHAKE_TIMEOUT",
        "/64",
        "IncomingAddr",
        "share **one** source key",
        "never failure-tracked or banned",
        "provisionally",
        "MAX_PENDING_ACCEPTS",
        "MAX_BUSY_REPLIES",
    ] {
        assert!(d.contains(need), "DESIGN.md missing {need:?}");
    }
    for residual in [
        "botnet with many source IPs and fresh endpoint ids",
        "saturate the non-reserved slots and the global cap",
        "Relayed peers share one address and bucket",
        "Stalled handshakes can still churn the reserved slots",
        "Endpoint ids are free to generate",
        "forgets its ban",
        "in memory and per dialer process",
        "Source IPs are not authenticated before the handshake",
    ] {
        assert!(
            d.contains(residual),
            "DESIGN.md missing residual {residual:?}"
        );
    }
    assert!(!d.contains("there is no per-peer rate limiting"));
}

#[test]
fn security_md_documents_flood_limits_and_ticket_edit() {
    let raw = collapsed("SECURITY.md");
    let s = raw.to_lowercase();
    for need in ["rate limit", "ban", "reserved", "botnet", "relay"] {
        assert!(s.contains(need), "SECURITY.md missing {need:?}");
    }
    assert!(!s.contains("a signature added nothing"));
    assert!(!s.contains("this is not sybil or flood resistance"));
    assert!(s.contains("no longer rejected before dialing"));
    assert!(s.contains("can only deny service"));
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
