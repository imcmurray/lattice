//! End-to-end: two endpoints connect over the in-memory transport, run the
//! hybrid-KEM + Double-Ratchet handshake over the wire, and exchange
//! end-to-end-encrypted messages — exercising the full Transport → Connection
//! → Session stack against the trait surface (no backend-specific code).

use lattice::prelude::*;

#[tokio::test]
async fn encrypted_session_over_memory_transport() {
    let alice = Keypair::generate(CryptoSuite::Hybrid).unwrap();
    let bob = Keypair::generate(CryptoSuite::Hybrid).unwrap();

    // Both endpoints join a shared in-memory network.
    let net = MemoryNetwork::new();
    let alice_ep = net.endpoint(alice.peer_id());
    let bob_ep = net.endpoint(bob.peer_id());

    // Connect: Alice dials Bob; Bob accepts.
    let alice_conn = alice_ep.connect(&bob.peer_id()).await.unwrap();
    let (from, bob_conn) = bob_ep.accept().await.unwrap();
    assert_eq!(from, alice.peer_id(), "accepted connection reports the dialer");

    // Run the handshake over the connection.
    let mut a = ConnectedSession::initiate(alice_conn, &alice, bob.public())
        .await
        .unwrap();
    let mut b = ConnectedSession::accept(bob_conn, &bob, alice.public())
        .await
        .unwrap();

    // Exchange encrypted messages both ways (drives the Double Ratchet).
    a.send(b"hello over the wire").await.unwrap();
    assert_eq!(b.recv().await.unwrap(), b"hello over the wire");

    b.send(b"reply over the wire").await.unwrap();
    assert_eq!(a.recv().await.unwrap(), b"reply over the wire");

    a.send(b"and again").await.unwrap();
    assert_eq!(b.recv().await.unwrap(), b"and again");
}
