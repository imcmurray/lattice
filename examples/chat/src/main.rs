//! Lattice example: encrypted P2P group chat (scaffold).
//!
//! Exercises the layers that are real today end to end: a real PQ-hybrid
//! identity authors an append-only log, the hash chain verifies, and a
//! signature checks against the published public identity. Networking,
//! sessions, and a UI land as the stubbed layers are filled in.

use lattice::prelude::*;

fn main() -> Result<()> {
    // A real post-quantum-hybrid identity (Ed25519+ML-DSA / X25519+ML-KEM),
    // derived from a fresh 24-word mnemonic.
    let me = Keypair::generate(CryptoSuite::Hybrid)?;
    println!("Lattice chat — scaffold");
    println!("Identity peer_id: {:?}", me.peer_id());
    println!(
        "Backup mnemonic: {} words (kept secret; this is the recovery key)",
        me.mnemonic().split_whitespace().count()
    );

    // Author an append-only room log with the real identity.
    let mut room_log = MemLog::new();
    room_log.append(b"hello, lattice", &me)?;
    room_log.append(b"second message", &me)?;
    room_log.verify()?;
    println!("Appended {} entries; hash chain verified.", room_log.head());

    // Verify a signature against the published public identity.
    let msg = b"sign me";
    let sig = me.sign(msg);
    println!("Signature verifies: {}", me.public().verify(msg, &sig));

    Ok(())
}
