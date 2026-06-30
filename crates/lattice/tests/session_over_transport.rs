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
    assert_eq!(
        from,
        alice.peer_id(),
        "accepted connection reports the dialer"
    );

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

/// Session resumption: after a transport drop, the same `SecureSession`s rebind
/// to a fresh connection (no re-handshake) and the channel continues.
#[tokio::test]
async fn session_resumes_across_a_dropped_connection() {
    let alice = Keypair::generate(CryptoSuite::Hybrid).unwrap();
    let bob = Keypair::generate(CryptoSuite::Hybrid).unwrap();
    let net = MemoryNetwork::new();
    let alice_ep = net.endpoint(alice.peer_id());
    let bob_ep = net.endpoint(bob.peer_id());

    // Initial connect + handshake + a round-trip.
    let aconn = alice_ep.connect(&bob.peer_id()).await.unwrap();
    let (_, bconn) = bob_ep.accept().await.unwrap();
    let mut a = ConnectedSession::initiate(aconn, &alice, bob.public())
        .await
        .unwrap();
    let mut b = ConnectedSession::accept(bconn, &bob, alice.public())
        .await
        .unwrap();
    a.send(b"msg-1").await.unwrap();
    assert_eq!(b.recv().await.unwrap(), b"msg-1");
    b.send(b"reply-1").await.unwrap();
    assert_eq!(a.recv().await.unwrap(), b"reply-1");

    // "Drop": keep the ratchet sessions, discard the connections.
    let (_dead_a, a_sess) = a.into_parts();
    let (_dead_b, b_sess) = b.into_parts();

    // Reconnect on a fresh transport connection and RESUME (no re-handshake).
    let aconn2 = alice_ep.connect(&bob.peer_id()).await.unwrap();
    let (_, bconn2) = bob_ep.accept().await.unwrap();
    let mut a = ConnectedSession::resume(aconn2, a_sess);
    let mut b = ConnectedSession::resume(bconn2, b_sess);

    // The channel continues where it left off, both directions.
    a.send(b"msg-2").await.unwrap();
    assert_eq!(b.recv().await.unwrap(), b"msg-2");
    b.send(b"reply-2").await.unwrap();
    assert_eq!(a.recv().await.unwrap(), b"reply-2");
}

/// A frame lost in the gap doesn't desync a resumed session — the skipped-key
/// cache lets subsequent frames decrypt (the lost one is simply gone).
#[tokio::test]
async fn resume_tolerates_a_frame_lost_in_the_gap() {
    let alice = Keypair::generate(CryptoSuite::Hybrid).unwrap();
    let bob = Keypair::generate(CryptoSuite::Hybrid).unwrap();
    let net = MemoryNetwork::new();
    let alice_ep = net.endpoint(alice.peer_id());
    let bob_ep = net.endpoint(bob.peer_id());

    let aconn = alice_ep.connect(&bob.peer_id()).await.unwrap();
    let (_, bconn) = bob_ep.accept().await.unwrap();
    let mut a = ConnectedSession::initiate(aconn, &alice, bob.public())
        .await
        .unwrap();
    let mut b = ConnectedSession::accept(bconn, &bob, alice.public())
        .await
        .unwrap();
    a.send(b"delivered").await.unwrap();
    assert_eq!(b.recv().await.unwrap(), b"delivered");

    // Alice sends one more, but the connection drops before Bob reads it.
    a.send(b"lost-in-the-gap").await.unwrap();

    let (_dead_a, a_sess) = a.into_parts();
    let (_dead_b, b_sess) = b.into_parts(); // Bob never read the second frame

    let aconn2 = alice_ep.connect(&bob.peer_id()).await.unwrap();
    let (_, bconn2) = bob_ep.accept().await.unwrap();
    let mut a = ConnectedSession::resume(aconn2, a_sess);
    let mut b = ConnectedSession::resume(bconn2, b_sess);

    // The next frame is ahead by one index; Bob caches the missing key and
    // still decrypts — no desync, the lost frame is just gone.
    a.send(b"after-the-gap").await.unwrap();
    assert_eq!(b.recv().await.unwrap(), b"after-the-gap");
}
