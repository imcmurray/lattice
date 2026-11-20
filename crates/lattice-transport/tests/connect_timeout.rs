#![cfg(feature = "iroh")]
//! AC 20 and 23: `CONNECT_TIMEOUT` is public and the `connect_ticket` docs
//! carry the required wording. Source-text checks are used so that a missing
//! re-export is a test failure rather than a compile error for the suite.

use std::path::PathBuf;

fn src(name: &str) -> String {
    std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join(name),
    )
    .unwrap()
}

#[test]
fn connect_timeout_is_15s_and_pub() {
    let q = src("quic.rs");
    assert!(q.contains(
        "pub const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);"
    ));
}

#[test]
fn connect_timeout_reexported_from_crate_root() {
    // Spec AC 20: "public const" — it must be nameable as
    // `lattice_transport::CONNECT_TIMEOUT` (callers/docs reference it).
    let lib = src("lib.rs");
    let start = lib.find("pub use quic::{").expect("pub use quic");
    let end = start + lib[start..].find("};").unwrap();
    assert!(
        lib[start..end].contains("CONNECT_TIMEOUT"),
        "CONNECT_TIMEOUT is not re-exported from lattice_transport"
    );
}

#[test]
fn connect_ticket_docs_state_no_authentication() {
    let src = src("quic.rs");
    let idx = src
        .find("pub async fn connect_ticket")
        .expect("connect_ticket");
    let docs: String = src[..idx]
        .lines()
        .rev()
        .take_while(|l| {
            let t = l.trim_start();
            t.starts_with("///") || t.starts_with("#[") || t.is_empty()
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(docs.contains("does NOT authenticate"), "docs: {docs}");
    assert!(docs.contains("CONNECT_TIMEOUT"));
}
