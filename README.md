# Lattice (working name)

A security-forward, 100% Rust peer-to-peer application framework — the
Holepunch/Keet model redesigned with clean trait seams, post-quantum-hybrid
identity, and a swappable transport substrate.

> **Status: pre-alpha scaffold.** Trait shapes are settled; most layers are
> stubs (`todo!`). The append-only log (`lattice-log`) is the one primitive
> implemented end-to-end today, with tests.

See [`DESIGN.md`](./DESIGN.md) for the full architecture and threat model.

## Workspace

| Crate | Role |
|---|---|
| `lattice-core` | Shared types, error model, trait contracts (zero deps) |
| `lattice-identity` | PQ-hybrid keypair = identity |
| `lattice-transport` | `Transport` trait + iroh default impl (the swap seam) |
| `lattice-session` | Noise handshake + Double-Ratchet (forward secrecy) |
| `lattice-log` | Append-only signed log + CRDT merge (hand-built core primitive) |
| `lattice-caps` | Unforgeable, attenuable capability tokens |
| `lattice` | Umbrella API crate + `prelude` |
| `examples/chat` | North-star validating app (encrypted group chat) |

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

