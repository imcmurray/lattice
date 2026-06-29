//! `lattice-session` — turns a raw [`lattice_core::Transport::Stream`] into an
//! authenticated, encrypted, forward-secret channel: a Noise handshake (over
//! the hybrid KEM) followed by a Double-Ratchet for per-message key evolution.
//!
//! Scaffold: bodies stubbed; the [`lattice_core::Session`] shape is final.

use lattice_core::{Result, Session};

/// An established secure channel (Noise-authenticated, ratcheting).
pub struct SecureSession;

impl Session for SecureSession {
    async fn send(&mut self, _plaintext: &[u8]) -> Result<()> {
        todo!("AEAD seal under current send chain key; advance ratchet")
    }
    async fn recv(&mut self) -> Result<Vec<u8>> {
        todo!("derive recv key; AEAD open; advance ratchet")
    }
}
