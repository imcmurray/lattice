//! `lattice` — security-forward, 100% Rust peer-to-peer application framework.
//!
//! Umbrella crate: it re-exports the layered crates and a [`prelude`] for app
//! authors. See `DESIGN.md` for the architecture and threat model.
//!
//! ```
//! use lattice::prelude::*;
//!
//! let mut log = MemLog::new();
//! assert_eq!(log.head(), 0);
//! ```

pub use lattice_caps as caps;
pub use lattice_core as kernel;
pub use lattice_identity as identity;
pub use lattice_log as log;
pub use lattice_session as session;
pub use lattice_transport as transport;

/// Common imports for building a Lattice app.
pub mod prelude {
    pub use lattice_core::{
        CryptoSuite, Entry, Error, Identity, Log, PeerId, Result, Seq, Session, Signature, Topic,
        Transport, Verify,
    };
    pub use lattice_identity::{DeviceCert, Keypair, PublicIdentity};
    pub use lattice_log::MemLog;
    pub use lattice_transport::IrohTransport;
}
