//! `lattice-caps` — unforgeable, attenuable capability tokens (DESIGN.md
//! ADR-003). Access is by *holding a capability*, never by a server's say-so
//! (principle #6, "no ambient authority"). Tokens verify locally.
//!
//! Scaffold: token format (macaroons- vs UCAN-style) is an open decision.

use lattice_core::{PeerId, Result, Signature};

/// What a capability authorizes on a resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Read a log / room.
    Read,
    /// Append to a log / room.
    Append,
    /// Administer membership and capabilities.
    Admin,
}

/// A signed, attenuable authority over a resource. Verified locally — there is
/// no server to consult.
#[allow(dead_code)]
pub struct Capability {
    issuer: PeerId,
    audience: PeerId,
    action: Action,
    signature: Signature,
}

impl Capability {
    /// Verify the token's signature chain and that `action` is within the
    /// authority delegated to `audience`. Stub pending ADR-003.
    pub fn verify(&self) -> Result<()> {
        todo!("verify signed, attenuated capability chain (offline)")
    }
}
