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

## Build

```bash
cargo build --workspace
cargo test  --workspace
cargo run   -p lattice-chat-example
```
