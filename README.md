# Lattice (working name)

[![CI](https://github.com/imcmurray/lattice/actions/workflows/ci.yml/badge.svg)](https://github.com/imcmurray/lattice/actions/workflows/ci.yml)
[![Live demo](https://img.shields.io/badge/demo-imcmurray.github.io%2Flattice-35e0d0?logo=github&logoColor=white)](https://imcmurray.github.io/lattice/)
[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-9d8bff?logo=rust&logoColor=white)](https://www.rust-lang.org)
[![status: experimental](https://img.shields.io/badge/status-experimental%20%C2%B7%20unaudited-e8a33d)](#status)

**🔗 Live demo &amp; docs: [imcmurray.github.io/lattice](https://imcmurray.github.io/lattice/)** — or build it yourself below.

A security-forward, 100% Rust peer-to-peer application framework — the
Holepunch/Keet model redesigned with clean trait seams, post-quantum-hybrid
identity, and a swappable transport substrate.

> **Not a lattice-cryptography library.** "Lattice" refers to the peer-to-peer
> *mesh* topology — not the lattice-based PQ crypto it happens to use under the
> hood (ML-KEM / ML-DSA). "Lattice" is a working codename and may be renamed.

> **Status: working v0.1** (public, experimental). The full stack is implemented
> and tested — PQ-hybrid identity with BIP39 recovery, a BLAKE3 signed log, a
> hybrid-KEM + Double-Ratchet secure channel, capability tokens, and both an
> in-memory and an iroh QUIC transport. The `lattice-net` CLI does real
> two-device chat. 25 tests; `clippy -D warnings` clean. *"Lattice" is a working
> codename.*

See [`DESIGN.md`](./DESIGN.md) for the full architecture and threat model.

## Workspace

| Crate | Role |
|---|---|
| `lattice-core` | Shared types, error model, trait contracts (zero deps) |
| `lattice-identity` | PQ-hybrid keypair = identity (Ed25519+ML-DSA, X25519+ML-KEM); BIP39 recovery; device certs |
| `lattice-log` | Append-only BLAKE3 hash chain with per-entry hybrid-signature verification |
| `lattice-session` | Hybrid-KEM handshake + Double Ratchet (forward secrecy + post-compromise security) |
| `lattice-caps` | UCAN-style signed capability tokens (single-hop) |
| `lattice-transport` | `Transport`/`Connection` traits + in-memory loopback + iroh QUIC backend (feature `iroh`) |
| `lattice` | Umbrella API crate + `prelude` |
| `examples/chat` | `lattice-chat` (local one-process demo) and `lattice-net` (real two-device P2P chat) |

## Build & test

```bash
cargo build --workspace
cargo test  --workspace
cargo run   -p lattice-chat-example --bin lattice-chat   # local in-process demo
```

## Try it between two devices

The `lattice-net` binary is a real P2P chat: PQ-hybrid identities, a hybrid-KEM
+ Double-Ratchet handshake, end-to-end encryption, over an iroh QUIC connection
(relay + holepunch, so it works across NATs). Build it on both machines:

```bash
cargo build -p lattice-chat-example --bin lattice-net   # pulls in the `iroh` feature
```

**Device A** (listener) — prints a ticket:

```bash
./target/debug/lattice-net listen
# === TICKET (copy to the other device) ===
# 03a1b2c3...   <- copy this whole blob
```

**Device B** (dialer) — paste A's ticket:

```bash
./target/debug/lattice-net connect 03a1b2c3...
```

Once both show "secure session established", type a line on either side and it
appears, decrypted, on the other. Each store has a **persistent root identity**
(a BIP39 mnemonic stored at rest under `~/.lattice/` — in the **OS keychain**
when available (service `lattice`, account `identity-mnemonic`), else an
**age-encrypted file** (`identity.age`, `0600`; passphrase via `LATTICE_PASSPHRASE`
or prompt — note an env passphrase is visible in the process environment;
`LATTICE_STORAGE=age` forces the file backend; `LATTICE_DIR` overrides the dir))
and a separate **device key** with a root-signed, 30-day certificate
(`device.age` / account `device-mnemonic`, `device.cert`, `root.pub`).
Handshakes are signed with the device key, not the root. The root PeerId is
stable across runs and recoverable from the mnemonic. The ticket is compact
(small enough for a QR code) and unsigned: it carries A's address plus A's root
and device PeerIds, and B checks A's hello and certificate chain against them.
It is still a bearer token for reachability. Both machines need outbound
internet to reach the n0 relays for discovery/holepunching.

Run `lattice-net whoami` to print your root and device ids, fingerprints and
certificate expiry. On every connection `lattice-net` prints a 60-digit **safety
number** of both root identities: compare it with your peer by voice or in
person, then run `lattice-net verify-peer` to mark their root as verified
(otherwise each connection says "UNVERIFIED peer"; nothing is verified
automatically). `lattice-net show-recovery-phrase --i-understand` prints your recovery
phrase for an offline backup — keep it secret.

Device management:

```bash
lattice-net renew-device                 # re-issue the device cert (needs the root)
lattice-net revoke-device <64-hex id>    # sign a revocation list (needs the root)
lattice-net forget-root --i-understand   # remove the root secret from this store
lattice-net import-root                  # restore the root; phrase read from stdin
lattice-net verify-peer <root peer id or fingerprint>  # mark a peer's root as verified
```

Certificates are renewed automatically while the root is in the store.
Revocation is lazy: peers learn a revoked device only when they next talk to a
non-revoked device of the same root. Tickets from older versions (v2) and peers
on the previous wire version fail with a clear version error.

**Reconnect & resume:** the session survives drops. If the connection breaks,
the listener returns to waiting and the dialer re-dials the same ticket with
exponential backoff (1→30s). If both sides still hold their session (a transient
network blip), they **resume the same ratchet with no re-handshake** (ADR-006);
if either restarted and lost its state, they fall back to a fresh handshake. The
persistent identity keeps each side's PeerId stable across reconnects. A kept
session is not resumed if the peer's certificate has expired or a cached
revocation list revokes its device. Press
Ctrl-D on either side to quit.

## Acknowledgements

Lattice stands on the shoulders of excellent open-source work — sincere thanks
to the people behind these projects:

- **[iroh](https://github.com/n0-computer/iroh)** (n0) — QUIC peer-to-peer transport, relays, and hole-punching.
- **[RustCrypto](https://github.com/RustCrypto)** — `ml-kem` &amp; `ml-dsa` (ML-KEM / ML-DSA), `sha2`, `hkdf`, `chacha20poly1305`, and `zeroize`.
- **[dalek-cryptography](https://github.com/dalek-cryptography)** — `ed25519-dalek` and `x25519-dalek`.
- **[BLAKE3](https://github.com/BLAKE3-team/BLAKE3)** — the hash behind the append-only log.
- **[age](https://github.com/str4d/rage)** (str4d; spec by @FiloSottile) — at-rest encryption of the identity mnemonic.
- **[keyring-rs](https://crates.io/crates/keyring)** — cross-platform OS keychain access.
- **[bip39](https://crates.io/crates/bip39)** — mnemonic identity recovery.
- **[Tokio](https://github.com/tokio-rs/tokio)** — the async runtime.

…and the wider Rust ecosystem (`serde`, `postcard`, `hex`, `rpassword`, and more). Any mistakes in how we use these are ours, not theirs.

## License

[MIT](./LICENSE) © 2026 Ian McMurray. The post-quantum guarantees, of course, are courtesy of mathematics, which is unlicensed.

