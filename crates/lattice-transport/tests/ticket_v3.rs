#![cfg(feature = "iroh")]
//! Black-box tests for compact v3 tickets (spec criteria 17-20).

use lattice_core::Error;
use lattice_transport::{
    encode_ticket, parse_ticket, TicketAddr, COMPACT_TICKET_MAX_LEN, MAX_TICKET_LEN, TICKET_VERSION,
};

fn eid(seed: u8) -> [u8; 32] {
    *iroh::SecretKey::from_bytes(&[seed; 32]).public().as_bytes()
}

fn addr(seed: u8) -> TicketAddr {
    TicketAddr::from_parts(
        &eid(seed),
        &["https://relay.example.org./"],
        &["192.0.2.1:4433".parse().unwrap()],
    )
    .unwrap()
}

fn msg(r: Result<impl std::fmt::Debug, Error>) -> String {
    match r {
        Err(Error::Transport(s)) => s,
        other => panic!("expected Transport error, got {other:?}"),
    }
}

#[derive(serde::Serialize)]
struct V2 {
    version: u8,
    addr: Vec<u8>,
    app_identity: Vec<u8>,
    app_sig: Vec<u8>,
}

#[derive(serde::Serialize)]
struct V3 {
    version: u8,
    addr: Vec<u8>,
    root_id: [u8; 32],
    device_id: [u8; 32],
}

fn hx<T: serde::Serialize>(t: &T) -> String {
    hex::encode(postcard::to_allocvec(t).unwrap())
}

#[test]
fn version_constant() {
    assert_eq!(TICKET_VERSION, 3);
}

#[test]
fn roundtrip_deterministic_whitespace() {
    let a = addr(7);
    let s = encode_ticket(&a, &[0xaa; 32], &[0xbb; 32]).unwrap();
    assert_eq!(s, encode_ticket(&a, &[0xaa; 32], &[0xbb; 32]).unwrap());
    let p = parse_ticket(&s).unwrap();
    assert_eq!(p.endpoint_id, eid(7));
    assert_eq!(p.addr_bytes, a.as_bytes());
    assert_eq!(p.root_id, [0xaa; 32]);
    assert_eq!(p.device_id, [0xbb; 32]);
    assert_eq!(parse_ticket(&format!(" \n{s}\t\n")).unwrap(), p);
}

#[test]
fn realistic_ticket_is_compact() {
    let a = TicketAddr::from_parts(
        &eid(3),
        &["https://euc1-1.relay.n0.iroh.iroh.link./"],
        &[
            "192.0.2.1:4433".parse().unwrap(),
            "198.51.100.7:51234".parse().unwrap(),
            "[2001:db8::1]:4433".parse().unwrap(),
            "[2001:db8:1::2]:51234".parse().unwrap(),
        ],
    )
    .unwrap();
    let s = encode_ticket(&a, &[1; 32], &[2; 32]).unwrap();
    assert!(s.len() < COMPACT_TICKET_MAX_LEN, "{}", s.len());
}

#[test]
fn v2_layout_gives_old_version_error() {
    let t = V2 {
        version: 2,
        addr: addr(1).as_bytes().to_vec(),
        app_identity: vec![1; 40],
        app_sig: vec![2; 64],
    };
    let m = msg(parse_ticket(&hx(&t)));
    assert!(m.contains("old ticket version"), "{m}");
}

#[test]
fn other_versions_unsupported() {
    for v in [0u8, 1, 4, 255] {
        let t = V3 {
            version: v,
            addr: addr(1).as_bytes().to_vec(),
            root_id: [1; 32],
            device_id: [2; 32],
        };
        let m = msg(parse_ticket(&hx(&t)));
        assert!(m.contains("unsupported ticket version"), "v{v}: {m}");
    }
}

#[test]
fn trailing_bytes_rejected() {
    let ok = V3 {
        version: 3,
        addr: addr(1).as_bytes().to_vec(),
        root_id: [1; 32],
        device_id: [2; 32],
    };
    assert!(parse_ticket(&hx(&ok)).is_ok());
    // outer trailing byte
    let mut b = postcard::to_allocvec(&ok).unwrap();
    b.push(0);
    assert!(parse_ticket(&hex::encode(b)).is_err());
    // addr-blob trailing byte
    let mut a = addr(1).as_bytes().to_vec();
    a.push(0);
    let bad = V3 {
        version: 3,
        addr: a,
        root_id: [1; 32],
        device_id: [2; 32],
    };
    assert!(parse_ticket(&hx(&bad)).is_err());
}

#[test]
fn malformed_and_oversized_rejected() {
    assert!(parse_ticket("").is_err());
    assert!(parse_ticket("zz").is_err());
    assert!(parse_ticket("03").is_err());
    assert!(parse_ticket("0").is_err());
    let m = msg(parse_ticket(&"0".repeat(MAX_TICKET_LEN + 1)));
    assert!(m.contains("too large"), "{m}");
    // truncated valid ticket
    let s = encode_ticket(&addr(1), &[1; 32], &[2; 32]).unwrap();
    assert!(parse_ticket(&s[..s.len() - 2]).is_err());
}
