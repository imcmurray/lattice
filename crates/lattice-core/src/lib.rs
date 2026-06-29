//! `lattice-core` — shared types, error model, and trait contracts.
//!
//! Memory safety: `unsafe` is forbidden workspace-wide (root `Cargo.toml`
//! `[workspace.lints]`). This crate has **zero external dependencies** by
//! design; concrete implementations live in sibling crates. See `DESIGN.md`.

pub mod error;
pub mod traits;
pub mod types;

pub use error::{Error, Result};
pub use traits::{Connection, Identity, Log, Session, Transport, Verify};
pub use types::{CryptoSuite, Entry, PeerId, Seq, Signature, Topic};
