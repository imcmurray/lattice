//! `lattice-caps` — unforgeable, signed capability tokens (DESIGN.md ADR-003).
//!
//! Access is by *holding a capability*, never by a server's say-so (principle
//! #6, "no ambient authority"). ADR-003 resolves the token format to
//! **UCAN-style**: each capability is a statement signed by the issuer's
//! identity key, verified offline against the issuer's public identity. This
//! reuses the hybrid signatures from `lattice-identity` and needs no shared
//! secret (unlike macaroons), which suits a no-central-server P2P model.
//!
//! v1 is a **single-hop grant**: a resource owner signs a capability for an
//! audience. The signed body binds issuer, audience, resource, and action, so
//! any tamper breaks verification. Multi-hop *delegation with attenuation*
//! (Alice→Bob→Carol, each link narrowing scope) is the documented next step;
//! the body layout and the `Action` ordering are already shaped for it.

use lattice_core::{Identity, PeerId, Result, Signature, Verify};

const CAP_DOMAIN: &[u8] = b"lattice-cap-v1";

/// A resource a capability applies to (e.g. a room/log id).
pub type ResourceId = [u8; 32];

/// What a capability authorizes. Ordered: `Admin` ⊇ `Append` ⊇ `Read`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Read a log / room.
    Read,
    /// Append to a log / room (implies read).
    Append,
    /// Administer membership and capabilities (implies append + read).
    Admin,
}

impl Action {
    fn rank(self) -> u8 {
        match self {
            Action::Read => 0,
            Action::Append => 1,
            Action::Admin => 2,
        }
    }

    /// Whether holding this action grants `required` (by the ordering above).
    pub fn allows(self, required: Action) -> bool {
        self.rank() >= required.rank()
    }
}

/// A signed, offline-verifiable capability: the `issuer` grants `audience` the
/// right to perform `action` on `resource`.
#[derive(Clone, Debug)]
pub struct Capability {
    issuer: PeerId,
    audience: PeerId,
    resource: ResourceId,
    action: Action,
    sig: Signature,
}

/// The canonical signed body. Stable across issue and verify.
fn body(issuer: &PeerId, audience: &PeerId, resource: &ResourceId, action: Action) -> Vec<u8> {
    let mut b = Vec::with_capacity(CAP_DOMAIN.len() + 32 * 3 + 1);
    b.extend_from_slice(CAP_DOMAIN);
    b.extend_from_slice(&issuer.0);
    b.extend_from_slice(&audience.0);
    b.extend_from_slice(resource);
    b.push(action.rank());
    b
}

impl Capability {
    /// Issue (sign) a capability. `owner` is the resource authority.
    pub fn issue(
        owner: &dyn Identity,
        audience: PeerId,
        resource: ResourceId,
        action: Action,
    ) -> Self {
        let issuer = owner.peer_id();
        let sig = owner.sign(&body(&issuer, &audience, &resource, action));
        Self {
            issuer,
            audience,
            resource,
            action,
            sig,
        }
    }

    /// Who issued this capability.
    pub fn issuer(&self) -> &PeerId {
        &self.issuer
    }

    /// Verify the issuer's signature over this capability. `owner` must be the
    /// issuer's public identity.
    pub fn verify(&self, owner: &dyn Verify) -> bool {
        owner.peer_id() == self.issuer
            && owner.verify(
                &body(&self.issuer, &self.audience, &self.resource, self.action),
                &self.sig,
            )
    }

    /// Whether this capability's scope covers the requested access (audience,
    /// resource, and an action at least as strong as `required`).
    pub fn permits(&self, audience: &PeerId, resource: &ResourceId, required: Action) -> bool {
        &self.audience == audience && &self.resource == resource && self.action.allows(required)
    }

    /// Full authorization check: the capability is validly signed by `owner`
    /// AND its scope covers the request. Returns `Ok(())` or a capability error.
    pub fn authorize(
        &self,
        owner: &dyn Verify,
        audience: &PeerId,
        resource: &ResourceId,
        required: Action,
    ) -> Result<()> {
        if !self.verify(owner) {
            return Err(lattice_core::Error::Capability("invalid signature".into()));
        }
        if !self.permits(audience, resource, required) {
            return Err(lattice_core::Error::Capability("out of scope".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_core::CryptoSuite;
    use lattice_identity::Keypair;

    fn setup() -> (Keypair, Keypair, ResourceId) {
        (
            Keypair::generate(CryptoSuite::Hybrid).unwrap(), // owner
            Keypair::generate(CryptoSuite::Hybrid).unwrap(), // grantee
            [42u8; 32],                                      // resource
        )
    }

    #[test]
    fn issue_and_verify() {
        let (owner, grantee, res) = setup();
        let cap = Capability::issue(&owner, grantee.peer_id(), res, Action::Append);
        assert!(
            cap.verify(owner.public()),
            "valid cap verifies under issuer"
        );

        let imposter = Keypair::generate(CryptoSuite::Hybrid).unwrap();
        assert!(
            !cap.verify(imposter.public()),
            "cap must not verify under a different identity"
        );
    }

    #[test]
    fn action_ordering() {
        assert!(Action::Admin.allows(Action::Read));
        assert!(Action::Admin.allows(Action::Append));
        assert!(Action::Append.allows(Action::Read));
        assert!(!Action::Read.allows(Action::Append));
        assert!(!Action::Append.allows(Action::Admin));
    }

    #[test]
    fn authorize_scope_and_strength() {
        let (owner, grantee, res) = setup();
        let cap = Capability::issue(&owner, grantee.peer_id(), res, Action::Append);

        // Append grant authorizes a Read request on the same resource/audience.
        assert!(cap
            .authorize(owner.public(), &grantee.peer_id(), &res, Action::Read)
            .is_ok());
        // ...but not an Admin request (insufficient strength).
        assert!(cap
            .authorize(owner.public(), &grantee.peer_id(), &res, Action::Admin)
            .is_err());
        // ...nor a different resource.
        assert!(cap
            .authorize(owner.public(), &grantee.peer_id(), &[0u8; 32], Action::Read)
            .is_err());
    }

    #[test]
    fn tampered_action_fails_verify() {
        let (owner, grantee, res) = setup();
        let mut cap = Capability::issue(&owner, grantee.peer_id(), res, Action::Read);
        // Try to escalate the action after signing.
        cap.action = Action::Admin;
        assert!(
            !cap.verify(owner.public()),
            "escalated action must break the signature"
        );
    }
}
