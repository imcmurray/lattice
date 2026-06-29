# Lattice — Design & Threat Model

> **Working codename:** *Lattice* (a P2P mesh; placeholder, easy to rename).
> **One line:** A 100% Rust, security-forward peer-to-peer application framework — the Holepunch/Keet model, redesigned with clean trait boundaries, post-quantum-hybrid identity, and a transport substrate you can swap.
> **Status:** Design draft v0.1 — pre-scaffold. Nothing here is load-bearing yet; this doc is the contract we build to.

---

## 1. Purpose, scope, non-goals

### 1.1 Purpose
Lattice lets a developer build a **serverless, zero-infrastructure P2P application** — messaging, file sync, collaborative tooling, local-first apps — without standing up or trusting any central server. Data lives on user devices; peers discover each other and sync directly. The framework supplies the hard parts (identity, encrypted sessions, replicated state, connectivity) behind a small, ergonomic API so app authors think about *their app*, not about NAT traversal or ratchets.

It is explicitly a **framework for others to build on**, not a single app. The north-star validating app is a small encrypted group chat (a "ShadowWhisper, but in Rust and reusable").

### 1.2 In scope (v1)
- Keypair-as-identity with post-quantum **hybrid** key material.
- End-to-end encrypted, **forward-secret** sessions between peers.
- An **append-only, signed log** as the core state primitive (our hand-built Hypercore analog), with CRDT-style merge for multi-writer convergence.
- **Capability-based** access to logs/rooms (unforgeable tokens, not server-checked ACLs).
- A **`Transport` trait** with a default impl over a hardened Rust QUIC/holepunch crate (iroh), and a relay fallback for unreachable peers.
- Offline-first / eventual consistency semantics.
- Supply-chain and memory-safety rigor as a first-class requirement, not an afterthought.

### 1.3 Non-goals (v1 — may revisit)
- **Full metadata privacy** (hiding *who talks to whom* / traffic-analysis resistance). We design the `Transport` trait so a Tor/mix-relay impl can drop in later, but v1 protects *content*, not the *social graph*. This is called out loudly because it is the single most common over-promise in P2P.
- **Global consensus / ledger / token.** Lattice is point-to-point replication, not a blockchain. No global agreed-upon state.
- **Central moderation, server-side search, or server-side analytics.** There is no server to host them.
- **Reimplementing the DHT / QUIC / holepunching ourselves.** Delegated to a vetted Rust crate behind our trait. (See ADR-001.)
- **Account/data custody, audit trails, retention guarantees.** Lattice is unsuitable as-is for records-custody-regulated workloads (e.g. court systems); that's a deliberate boundary, not an oversight.

---

## 2. Design principles

1. **All Rust, memory-safe core.** `#![forbid(unsafe_code)]` in every crate we author. `unsafe` is permitted only inside vetted upstream deps.
2. **Trait boundaries everywhere the design might change.** `Identity`, `Log`, `Transport`, `Session` are traits first, impls second. The "redesign" cleanliness *is* these seams.
3. **Stand on the substrate, own the semantics.** We do not rewrite TCP to build a web framework. We delegate NAT traversal/QUIC; we author identity, log, caps, session crypto.
4. **Build the one primitive worth understanding.** The append-only signed log is hand-written — it's the conceptual heart of the model and only a few hundred lines.
5. **Secure by construction, not by configuration.** Encryption, signing, and forward secrecy are on by default and hard to turn off. There is no "insecure mode" footgun.
6. **No ambient authority.** Access is by capability (holding a key/token), never by "the server said you're allowed."
7. **Fail closed.** Unverified data is dropped, not quarantined-and-maybe-used. Unknown peers get no trust.
8. **Post-quantum from day one.** Hybrid classical+PQ so we're not retrofitting later; classical security holds even if a PQ primitive is broken, and vice versa.

---

## 3. Layered architecture

```
┌───────────────────────────────────────────────────────────┐
│  App API / DX  (lattice / lattice-app)                      │  app authors live here
│  Room, Document, Peer, events — the ergonomic surface       │
├───────────────────────────────────────────────────────────┤
│  Capabilities (lattice-caps)                                │
│  unforgeable read/write/admin tokens over logs & rooms      │
├───────────────────────────────────────────────────────────┤
│  State (lattice-log)                                        │
│  append-only signed log + CRDT merge → replicated state     │  ← we hand-build
├───────────────────────────────────────────────────────────┤
│  Session crypto (lattice-session)                           │
│  Noise handshake + Double-Ratchet (forward secrecy)         │
├───────────────────────────────────────────────────────────┤
│  Identity (lattice-identity)                                │
│  PQ-hybrid keypair = identity; rotation, multi-device       │
├───────────────────────────────────────────────────────────┤
│  Transport TRAIT (lattice-transport)                        │  ← the swap seam
│    default impl: iroh  (QUIC, holepunch, relay fallback)    │
│    future impls: libp2p, tor/mix-relay (metadata privacy)   │
├───────────────────────────────────────────────────────────┤
│  Core (lattice-core)                                        │
│  shared types, error model, traits, crypto-suite selection  │
└───────────────────────────────────────────────────────────┘
```

Dependencies point downward only. No layer reaches around another. The `Transport` trait is the only place the network substrate is named, so swapping iroh → libp2p → tor-relay is a contained change.

### 3.1 Layer responsibilities (brief)
- **core** — error type, ID/hash types, the trait definitions, crypto-suite enum (`Classical`, `Hybrid`), feature flags.
- **transport** — `connect(peer) → Stream`, `accept() → Stream`, peer discovery by topic, relay fallback. Hides NAT traversal entirely.
- **identity** — generate/load a hybrid keypair; derive a stable `PeerId`; sign/verify; key rotation + multi-device linkage.
- **session** — turn a raw transport stream into an authenticated, encrypted, forward-secret channel between two identities.
- **log** — the append-only signed log: append, verify, replicate, and a merge strategy for concurrent writers (CRDT). The state engine.
- **caps** — mint/verify/attenuate/revoke capability tokens that gate who may read or append to a given log/room.
- **app API** — `Room`/`Document` abstractions, subscription/event stream, the thing example apps and third parties import.

---

## 4. Core traits (sketch — final form lands in code)

```rust
// lattice-core — illustrative, not final
pub trait Identity {
    fn peer_id(&self) -> PeerId;                       // stable, derived from public keys
    fn sign(&self, msg: &[u8]) -> Signature;           // hybrid: Ed25519 + ML-DSA
    fn verify(id: &PeerId, msg: &[u8], sig: &Signature) -> bool;
}

pub trait Transport {
    type Stream: AsyncRead + AsyncWrite + Send + Unpin;
    async fn connect(&self, peer: &PeerId) -> Result<Self::Stream>;
    async fn accept(&self) -> Result<(PeerId, Self::Stream)>;
    async fn announce(&self, topic: &Topic) -> Result<()>;     // discoverability
    async fn lookup(&self, topic: &Topic) -> Result<Vec<PeerId>>;
}

pub trait Session {                                   // wraps a Transport::Stream
    async fn establish(stream: impl Stream, me: &impl Identity, them: &PeerId)
        -> Result<Self>;                              // Noise handshake + verify identity
    async fn send(&mut self, plaintext: &[u8]) -> Result<()>;  // ratchet forward
    async fn recv(&mut self) -> Result<Vec<u8>>;
}

pub trait Log {                                       // append-only, signed
    fn append(&mut self, payload: &[u8], by: &impl Identity) -> Result<Seq>;
    fn verify(&self) -> Result<()>;                   // full-chain signature check
    fn get(&self, seq: Seq) -> Result<Option<Entry>>;
    fn head(&self) -> Seq;
    async fn replicate(&mut self, peer: &mut impl Session) -> Result<()>;
}
```

CRDT merge for multi-writer state lives above `Log` (each writer owns a single-writer log; rooms are *sets* of logs merged deterministically). This mirrors how Keet models a group chat as many single-writer feeds, not one shared mutable table.

---

## 5. Cryptographic choices

| Function | Classical | PQ (hybrid partner) | Notes |
|---|---|---|---|
| Identity signatures | Ed25519 | ML-DSA (Dilithium) | hybrid sig = both must verify |
| Key agreement | X25519 | ML-KEM (Kyber) | hybrid KEM, combined into one shared secret |
| Session handshake | Noise (XX/IK pattern) | — over hybrid KEM | mutual auth, identity-hiding from passive observers |
| Forward secrecy | Double-Ratchet (Signal-style) | — | per-message key evolution |
| Hashing / IDs | BLAKE3 | — | log entry hashes, content addressing |
| AEAD | ChaCha20-Poly1305 | — | record encryption |

Hybrid construction rule: **a hybrid primitive is secure if *either* component is secure.** We never ship PQ-only (immature) or classical-only (harvest-now-decrypt-later risk). This reuses the Kyber+Ed25519 pattern already proven in ShadowWhisper, now using NIST-standardized ML-KEM/ML-DSA names.

Crate status: **pinned & wired** in `lattice-identity` — `ed25519-dalek` 2, `x25519-dalek` 2, `ml-dsa` 0.1 (FIPS 204), `ml-kem` 0.3 (FIPS 203), `bip39` 2, `hkdf`/`sha2`, `blake3`, `zeroize`. **Still to pin** for `lattice-session`: `snow` (Noise) and `chacha20poly1305` (AEAD). All RustCrypto-family where possible for audit-surface consistency.

### 5.1 Post-quantum posture

**Threat being defended:** *harvest-now-decrypt-later* (HNDL) — an adversary records ciphertext today and decrypts it once a cryptographically-relevant quantum computer (CRQC) exists. This reframes priorities: PQ **confidentiality** (key agreement) is time-urgent because recorded traffic is decrypted *retroactively*; PQ **authenticity** (signatures) matters mainly once a CRQC actually exists, since a forged signature does damage only in the present. We address both, but the urgency ordering is confidentiality-first.

**Design rules (binding):**
- **Hybrid, never PQ-only or classical-only.** Every primitive pairs a vetted classical scheme with a NIST-standardized PQ scheme. Security holds if *either* component holds — hedging both PQ immaturity and quantum risk.
- **KDF combiner, never XOR.** A hybrid shared secret is combined as `HKDF(ss_classical ‖ ss_pq ‖ transcript)`. Hybrid signatures require **every** component to verify (AND, not OR).
- **Standardized algorithms only:** ML-KEM (FIPS 203), ML-DSA (FIPS 204), via audited RustCrypto crates. No bespoke or pre-standard schemes; we do not roll our own.
- **Crypto-agility is mandatory.** The `CryptoSuite` tag is bound into the `PeerId`; signatures are length-prefixed; HKDF is domain-separated. A new suite (e.g. ML-KEM-1024, or a replacement if ML-DSA is weakened) must be introduceable via negotiation without breaking existing identities.

**Status by layer:**

| Layer | PQ posture | State |
|---|---|---|
| Identity signatures | Ed25519 + ML-DSA-65 hybrid (AND-verify) | **Done** |
| Identity key material | carries X25519 + ML-KEM-768 public keys | **Done** (keys derived & published) |
| Session confidentiality | hybrid KEM handshake (X25519 + ML-KEM-768) → HKDF → ratchet | **Pending** — `lattice-session` stub; **the urgent HNDL gap** |
| Transport (iroh/QUIC-TLS) | independent; app-layer session crypto is the real protection | out of our hands; do not rely on it for E2E |
| Capabilities | signed with the hybrid identity | inherited once caps sign via `Identity` |

**Caveats recorded honestly:**
- **PQ ≠ forward secrecy** — orthogonal. v1 stance is a PQ-hybrid *initial* handshake + classical Double-Ratchet for FS (fully-PQ ratcheting is open research; revisit).
- **Size/bandwidth cost is real** — ML-DSA-65 signatures ≈ 3.3 KB and ML-KEM-768 keys ≈ 1.2 KB, vs. 64 B for Ed25519. In a system that gossips keys and signs every log entry this is a genuine budget; measure early and consider signing batch roots rather than every entry.
- **Until the session KEM lands, message confidentiality is classical-only and therefore HNDL-exposed.** This is the next PQ priority.

---

## 6. Threat model

### 6.1 Assets to protect
- **A1 — Message/content confidentiality.** Plaintext of what users say/share.
- **A2 — Content integrity & authenticity.** Nobody can forge or tamper with a peer's entries.
- **A3 — Identity key material.** Private keys never leave the device unencrypted.
- **A4 — Forward/backward secrecy.** A key compromise must not retroactively (or indefinitely forward) expose other sessions.
- **A5 — Access control integrity.** Only capability holders can read/write a given room/log.
- **A6 — Availability of own data.** A user can always reach data they hold locally; reasonable sync availability when peers are reachable.
- **A7 (v2) — Relationship/metadata privacy.** Who-talks-to-whom, topic membership. *Out of scope v1 — see §1.3.*

### 6.2 Trust boundaries
1. **Device boundary** — local OS, keystore, app process. Private keys live here. Compromise of the device is largely out of scope (we mitigate at-rest, not a rooted attacker).
2. **Transport boundary** — the network between peers, plus any relay. **Fully untrusted.** Relays are honest-but-curious at best, malicious at worst.
3. **Peer boundary** — the remote identity we talk to. Authenticated but not trusted beyond its capabilities; a peer may be malicious within the rooms it's in.
4. **Discovery boundary** — the DHT/topic announce layer. Untrusted; assume adversary can observe announces and inject fake peers.

### 6.3 Adversary classes
- **N — Network adversary (passive).** Observes all traffic (ISP, Wi-Fi, backbone). Goal: read content, learn who talks to whom.
- **N+ — Network adversary (active).** Also injects, drops, replays, reorders, MITMs.
- **R — Malicious relay.** A relay node we route through when direct holepunch fails. Sees ciphertext + routing endpoints.
- **P — Malicious peer.** A legitimately-joined participant who tries to forge others' messages, escalate caps, corrupt shared state, or spam.
- **S — Sybil / eclipse adversary.** Floods discovery with fake identities to surround/isolate a victim or censor a topic.
- **D — Device-local malware (partial).** Non-root process snooping; we raise the bar but a rooted device is out of scope.

### 6.4 STRIDE per boundary (condensed)

| Threat | Where | Vector | Mitigation |
|---|---|---|---|
| **S**poofing identity | Peer/Discovery | Claim to be another `PeerId` | Identity = public key; every entry signed (hybrid); session handshake binds stream to verified identity |
| **T**ampering content | Transport/Peer | Alter messages/log entries in flight or at rest | AEAD per record; append-only log is a signed hash chain — any edit breaks verification, `verify()` fails closed |
| **R**epudiation | Peer | "I never wrote that" | Per-entry hybrid signatures are non-repudiable within a room |
| **I**nfo disclosure | Transport/Relay | Read plaintext | E2E AEAD; relay sees only ciphertext + endpoints; Noise hides peer identities from passive `N` |
| **I**nfo disclosure (metadata) | Discovery/Relay | Learn who talks to whom | **v1: accepted risk (A7 deferred).** v2: tor/mix `Transport` impl |
| **D**enial of service | Transport/Discovery | Drop/flood/eclipse | Relay fallback for reachability; cap-gated writes limit spam; Sybil-resistance hooks (see §6.6) |
| **E**levation of privilege | Caps | Forge/replay a capability to gain write/admin | Caps are signed, attenuable, audience- and action-scoped; revocation via epoch bump; verified locally, no server to trick |

### 6.5 Key compromise handling
- **Session key leak** → Double-Ratchet limits blast radius to a window of messages, not the whole history (forward secrecy + post-compromise recovery as the ratchet heals).
- **Identity key leak** → rotation: publish a signed rotation entry from the old key naming the new key; peers update binding. Multi-device uses per-device subkeys linked under the identity so losing one device ≠ losing the identity.
- **Recovery** → social/multi-device recovery (no server to reset against). **Open question (§8):** exact recovery UX. This is the sharpest tradeoff in keypair-as-identity systems and we will not hand-wave it.

### 6.6 Sybil / eclipse posture (v1 best-effort)
No server means no central rate-limiter. v1 mitigations: capability-gated writes (uninvited peers can't append), proof-of-membership before relay assistance, and pluggable peer-scoring hooks. Strong Sybil resistance is acknowledged as **hard and partial** in v1 — documented, not pretended away.

### 6.7 Explicitly out of scope (v1)
Rooted/compromised device; nation-state traffic-analysis of the social graph (A7); global consensus/double-spend concerns (no ledger); legal compulsion of a participant to hand over their own keys; denial-of-availability when *all* holders of a dataset are offline (inherent to P2P — mitigated by optional always-on "pinning" peers, not solved).

### 6.8 Security non-negotiables (acceptance gates)
- No code path sends A1 content unencrypted. (test-enforced)
- `Log::verify()` rejects any tampered chain. (test-enforced)
- No `unsafe` in authored crates. (`#![forbid(unsafe_code)]` + CI)
- `cargo-deny`, `cargo-audit` green in CI; deps pinned; `cargo-vet` for review provenance.
- Reproducible, signed release artifacts.

---

## 7. Proposed crate layout

```
P2P/                      (cargo workspace root)
├─ Cargo.toml             workspace, shared lints (forbid unsafe), pinned versions
├─ DESIGN.md              (this file)
├─ deny.toml              cargo-deny policy
├─ crates/
│  ├─ lattice-core/       types, errors, traits, crypto-suite selection
│  ├─ lattice-identity/   PQ-hybrid keypair, PeerId, sign/verify, rotation
│  ├─ lattice-transport/  Transport trait + iroh default impl + relay
│  ├─ lattice-session/    Noise handshake + Double-Ratchet
│  ├─ lattice-log/        append-only signed log + CRDT merge   (hand-built)
│  ├─ lattice-caps/       capability tokens
│  └─ lattice/            umbrella API crate (Room/Document/Peer) re-exporting the above
└─ examples/
   └─ chat/               north-star validating app (encrypted group chat)
```

---

## 8. Open questions / ADR backlog

- **ADR-001 (decided):** Delegate transport/NAT/holepunch to **iroh** behind a `Transport` trait, rather than reimplementing a DHT + QUIC + holepunching. Rationale: that layer is where subtle security/reliability bugs concentrate; n0 has years invested; the trait keeps us free to swap. *Cost accepted: a large dependency we don't control.*
- **ADR-002 (open):** CRDT choice for multi-writer room state — bespoke set-of-logs merge vs. adopting `automerge`/`yrs`. Tradeoff: control & footprint vs. proven convergence.
- **ADR-003 (open):** Capability token format — macaroons-style attenuable tokens vs. UCAN-style. Both give offline-verifiable, attenuable caps; pick one.
- **ADR-004 (decided):** **Deterministic identity from a BIP39 mnemonic + root→device delegation.** Master seed (mnemonic) → HKDF-SHA256 with per-algorithm domain labels → Ed25519 / X25519 / ML-DSA / ML-KEM keypairs; `PeerId = BLAKE3(canonical public-key bundle)`, so the same mnemonic reproduces the same identity. *Recovery* = re-enter the mnemonic (offline, no guardians). *Multi-device* = each device holds a fresh signing key authorized by a root-signed `DeviceCert`; lose-a-device → revoke, lose-all → restore from mnemonic. *Rejected:* social/Shamir as the v1 default (online-guardian + UX cost) → deferred to an optional `lattice-recovery` module; device-linking-only (no seed) → no offline floor for total device loss. *Cost accepted:* the mnemonic is a long-lived root secret — mitigated by offline custody, day-to-day signing via device subkeys, and session-layer forward secrecy.
- **ADR-005 (open):** At-rest key storage — OS keychain per platform vs. an encrypted-file fallback. Affects the device-boundary threat posture.
- **Naming:** "Lattice" is a placeholder. Decide before first publish.

---

## 9. What this is *not* good for (honest boundary)

Lattice is a poor fit — and we should say so to anyone who picks it up — for: authoritative global state (marketplaces, ledgers, leaderboards), regulated records custody / chain-of-custody / retention (e.g. court systems), strong centralized moderation, server-side discovery across strangers, or heavy server-side compute. It shines for private direct communication and data-sharing between parties who already know each other, censorship-resistant distribution, and local-first collaboration.
