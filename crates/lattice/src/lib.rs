//! `lattice` — security-forward, 100% Rust peer-to-peer application framework.
//!
//! Umbrella crate: it re-exports the layered crates and a [`prelude`] for app
//! authors. See `DESIGN.md` for the architecture and threat model.
//!
//! ```
//! use lattice::prelude::*;
//!
//! let me = Keypair::generate(CryptoSuite::Hybrid).unwrap();
//! let mut log = MemLog::new(me.public().clone());
//! log.append(b"first message", &me).unwrap();
//! log.verify().unwrap(); // checks the BLAKE3 chain AND the hybrid signature
//! assert_eq!(log.head(), 1);
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
        Connection, CryptoSuite, Entry, Error, Identity, Log, PeerId, Result, Seq, Session,
        Signature, Topic, Transport, Verify,
    };
    pub use lattice_caps::{Action, Capability, ResourceId};
    pub use lattice_identity::{DeviceCert, Keypair, PublicIdentity};
    pub use lattice_log::MemLog;
    pub use lattice_session::{ConnectedSession, Handshake, SecureSession};
    pub use lattice_transport::{MemoryConn, MemoryNetwork, MemoryTransport};

    #[cfg(feature = "iroh")]
    pub use lattice_transport::{IrohConn, IrohTransport};
}
