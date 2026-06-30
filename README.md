# Lattice (working name)

A security-forward, 100% Rust peer-to-peer application framework — the
Holepunch/Keet model redesigned with clean trait seams, post-quantum-hybrid
identity, and a swappable transport substrate.

> **Not a lattice-cryptography library.** "Lattice" refers to the peer-to-peer
> *mesh* topology — not the lattice-based PQ crypto it happens to use under the
> hood (ML-KEM / ML-DSA). (Name is a working codename; revisit before any public push.)

> **Status: working v0.1** (local git, no remote). The full stack is implemented
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
# 7b22616464...   <- copy this whole blob
```

**Device B** (dialer) — paste A's ticket:

```bash
./target/debug/lattice-net connect 7b22616464...
```

Once both show "secure session established", type a line on either side and it
appears, decrypted, on the other. Each device has a **persistent identity**: a
BIP39 mnemonic generated on first run and saved to `~/.lattice/identity`
(`0600`; override with `LATTICE_IDENTITY_FILE`), so its PeerId is stable across
runs and recoverable from the mnemonic. The ticket carries A's address + public
identity so B can authenticate the handshake (trust-on-first-use). Both machines
need outbound internet to reach the n0 relays for discovery/holepunching.

**Reconnect:** the session survives drops. If the connection breaks, the
listener returns to waiting and the dialer re-dials the same ticket with
exponential backoff (1→30s), then both re-handshake into a fresh session — no
restart needed (the persistent identity keeps each side's PeerId stable across
reconnects). Press Ctrl-D on either side to quit.

