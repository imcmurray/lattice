//! Lattice local demo (`lattice-chat`) — the whole stack in one process.
//!
//! A PQ-hybrid identity authors a BLAKE3 signed log (verified), then two
//! identities establish a hybrid-KEM + Double-Ratchet session and exchange an
//! end-to-end-encrypted message. For the real networked version across two
//! machines, see the `lattice-net` binary.

use lattice::prelude::*;

fn main() -> Result<()> {
    // A real post-quantum-hybrid identity (Ed25519+ML-DSA / X25519+ML-KEM),
    // derived from a fresh 24-word mnemonic.
    let me = Keypair::generate(CryptoSuite::Hybrid)?;
    println!("Lattice local demo");
    println!("Identity peer_id: {:?}", me.peer_id());
    println!(
        "Backup mnemonic: {} words (kept secret; this is the recovery key)",
        me.mnemonic().split_whitespace().count()
    );

    // Author an append-only room log with the real identity. The log is bound
    // to our public identity, so verify() checks the hybrid signature on every
    // entry, not just the BLAKE3 chain.
    let mut room_log = MemLog::new(me.public().clone());
    room_log.append(b"hello, lattice", &me)?;
    room_log.append(b"second message", &me)?;
    room_log.verify()?;
    println!(
        "Appended {} entries; BLAKE3 chain + hybrid signatures verified.",
        room_log.head()
    );

    // Verify a signature against the published public identity.
    let msg = b"sign me";
    let sig = me.sign(msg);
    println!("Signature verifies: {}", me.public().verify(msg, &sig));

    // Establish a hybrid-KEM (X25519 + ML-KEM-768) secure session with a peer
    // and exchange an end-to-end encrypted message.
    let bob = Keypair::generate(CryptoSuite::Hybrid)?;
    let (handshake, mut alice_session) = SecureSession::initiate(&me, bob.public())?;
    let mut bob_session = SecureSession::accept(&bob, me.public(), &handshake)?;

    let ciphertext = alice_session.seal(b"meet at the usual place")?;
    let plaintext = bob_session.open(&ciphertext)?;
    println!(
        "Hybrid-KEM session established; Bob decrypted: {:?}",
        String::from_utf8_lossy(&plaintext)
    );

    Ok(())
}
