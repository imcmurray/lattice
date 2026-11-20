//! AC 6: v3 handshake over MemoryConn with the lattice-net 81-byte channel
//! binding layout (local copy of the layout).

use lattice::prelude::*;

fn cb(d: &[u8; 32], l: &[u8; 32]) -> Vec<u8> {
    let mut v = b"lattice-net-cb-v1".to_vec();
    v.extend_from_slice(d);
    v.extend_from_slice(l);
    v
}

async fn run(dialer_view: Vec<u8>, listener_view: Vec<u8>) -> (Result<()>, Result<()>) {
    let alice = Keypair::generate(CryptoSuite::Hybrid).unwrap();
    let bob = Keypair::generate(CryptoSuite::Hybrid).unwrap();
    let net = MemoryNetwork::new();
    let a_ep = net.endpoint(alice.peer_id());
    let b_ep = net.endpoint(bob.peer_id());
    let aconn = a_ep.connect(&bob.peer_id()).await.unwrap();
    let (_, bconn) = b_ep.accept().await.unwrap();
    let (a, b) = tokio::join!(
        ConnectedSession::initiate(aconn, &alice, bob.public(), &dialer_view),
        ConnectedSession::accept(bconn, &bob, alice.public(), &listener_view)
    );
    (a.map(|_| ()), b.map(|_| ()))
}

#[test]
fn binding_layout_is_81_bytes_and_ordered() {
    let (d, l) = ([1u8; 32], [2u8; 32]);
    let b = cb(&d, &l);
    assert_eq!(b.len(), 81);
    assert!(b.starts_with(b"lattice-net-cb-v1"));
    assert_ne!(cb(&d, &l), cb(&l, &d));
}

#[tokio::test]
async fn matching_endpoint_ids_succeed() {
    let (d, l) = ([1u8; 32], [2u8; 32]);
    let (a, b) = run(cb(&d, &l), cb(&d, &l)).await;
    a.unwrap();
    b.unwrap();
}

#[tokio::test]
async fn different_listener_endpoint_fails() {
    let (d, l, other) = ([1u8; 32], [2u8; 32], [3u8; 32]);
    let (a, b) = run(cb(&d, &l), cb(&d, &other)).await;
    assert!(matches!(b, Err(Error::Verify(_))));
    assert!(a.is_err());
}

#[tokio::test]
async fn different_dialer_endpoint_fails() {
    let (d, l, other) = ([1u8; 32], [2u8; 32], [3u8; 32]);
    let (a, b) = run(cb(&d, &l), cb(&other, &l)).await;
    assert!(matches!(b, Err(Error::Verify(_))));
    assert!(a.is_err());
}

#[tokio::test]
async fn swapped_roles_fail() {
    let (d, l) = ([1u8; 32], [2u8; 32]);
    let (a, b) = run(cb(&d, &l), cb(&l, &d)).await;
    assert!(matches!(b, Err(Error::Verify(_))));
    assert!(a.is_err());
}
