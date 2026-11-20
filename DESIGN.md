# Lattice — Design & Threat Model

> **Working codename:** *Lattice* (a P2P mesh; placeholder, easy to rename).
> **One line:** A 100% Rust, security-forward peer-to-peer application framework — the Holepunch/Keet model, redesigned with clean trait boundaries, post-quantum-hybrid identity, and a transport substrate you can swap.
> **Status:** v0.1 implemented (local git, no remote). This doc is both the design contract and a map of what's built — per-section notes and the §5.1 status table mark done vs pending. The stack (identity, signed log, hybrid-KEM + Double-Ratchet session, single-hop capabilities, in-memory + iroh transport) is implemented and tested; the `lattice-net` CLI does two-device chat. It is experimental and **not externally audited**; §5, §5.1, §6.4, §6.5 and SECURITY.md list the known limitations.

---

## 1. Purpose, scope, non-goals

### 1.1 Purpose
Lattice lets a developer build a **serverless, zero-infrastructure P2P application** — messaging, file sync, collaborative tooling, local-first apps — without standing up or trusting any central server. Data lives on user devices; peers discover each other and sync directly. The framework supplies the hard parts (identity, encrypted sessions, replicated state, connectivity) behind a small, ergonomic API so app authors think about *their app*, not about NAT traversal or ratchets.

It is explicitly a **framework for others to build on**, not a single app. The north-star validating app is a small encrypted group chat (a "ShadowWhisper, but in Rust and reusable").

### 1.2 In scope (v1)
- Keypair-as-identity with post-quantum **hybrid** key material.
- End-to-end encrypted, **forward-secret** sessions between peers.
- An **append-only, signed log** as the core state primitive (our hand-built Hypercore analog), with CRDT-style merge for multi-writer convergence (**planned, not implemented**: ADR-002 is open; today each log is single-writer).
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
5. **Secure by construction, not by configuration.** Encryption, signing, and forward secrecy are on by default and hard to turn off. There is no "insecure mode" footgun; the one weaker option, the `Classical` suite (classical-only security, §5.1), is an explicit opt-in and never the default.
6. **No ambient authority.** Access is by capability (holding a key/token), never by "the server said you're allowed."
7. **Fail closed.** Unverified data is dropped, not quarantined-and-maybe-used. Unknown peers get no trust.
8. **Post-quantum from day one.** Hybrid classical+PQ so we're not retrofitting later; classical security holds even if a PQ primitive is broken, and vice versa.

---

## 3. Layered architecture

```
┌───────────────────────────────────────────────────────────┐
│  App API / DX  (lattice / lattice-app)                      │  app authors live here
│  re-exports + prelude; Room/Document/events: planned        │
├───────────────────────────────────────────────────────────┤
│  Capabilities (lattice-caps)                                │
│  unforgeable read/write/admin tokens over logs & rooms      │
├───────────────────────────────────────────────────────────┤
│  State (lattice-log)                                        │
│  append-only signed log (CRDT merge: planned) → state       │  ← we hand-build
├───────────────────────────────────────────────────────────┤
│  Session crypto (lattice-session)                           │
│  signed hybrid handshake + Double Ratchet (FS + PCS)        │
├───────────────────────────────────────────────────────────┤
│  Identity (lattice-identity)                                │
│  PQ-hybrid keypair = identity; device certs (multi-device)  │
├───────────────────────────────────────────────────────────┤
│  Transport TRAIT (lattice-transport)                        │  ← the swap seam
│    impls: in-memory + iroh QUIC (relay, holepunch)          │
│    future impls: libp2p, tor/mix-relay (metadata privacy)   │
├───────────────────────────────────────────────────────────┤
│  Core (lattice-core)                                        │
│  shared types, error model, traits, crypto-suite selection  │
└───────────────────────────────────────────────────────────┘
```

Dependencies point downward only. No layer reaches around another. The `Transport` trait is the only place the network substrate is named, so swapping iroh → libp2p → tor-relay is a contained change.

### 3.1 Layer responsibilities (brief)
- **core** — error type, ID/hash types, the trait definitions, crypto-suite enum (`Classical`, `Hybrid`), feature flags.
- **transport** — `connect(addr) → Conn`, `accept() → (addr, Conn)`, relay fallback via iroh relays. Peer discovery by topic is **not implemented**: `IrohTransport::announce` is a no-op and `lookup` returns an empty list. Hides NAT traversal entirely. Addresses are transport-specific and are not identities.
- **identity** — generate/load a hybrid keypair; derive a stable `PeerId`; sign/verify; root→device certificates (multi-device linkage). Key rotation is planned, not implemented.
- **session** — turn a raw transport stream into an authenticated, encrypted, forward-secret channel between two identities.
- **log** — the append-only signed log: append and verify, single-writer. Replication and a merge strategy for concurrent writers (CRDT) are planned and not implemented (ADR-002 is open). The state engine.
- **caps** — mint/verify single-hop signed capability tokens that gate who may read or append to a given log/room. Attenuation chains, expiry and revocation are not implemented.
- **app API** — the `lattice` crate is re-exports plus a `prelude`; that is what example apps and third parties import. `Room`/`Document` abstractions and a subscription/event stream are planned and not implemented.

---

## 4. Core traits (as implemented)

These are the actual `lattice-core` contracts; concrete impls live in sibling crates.

```rust
pub trait Identity {                 // signing half — holds secret keys
    fn peer_id(&self) -> PeerId;
    fn sign(&self, msg: &[u8]) -> Signature;                  // hybrid: Ed25519 + ML-DSA
}
pub trait Verify {                   // verifying half — a published public identity, no secrets
    fn peer_id(&self) -> PeerId;
    fn verify(&self, msg: &[u8], sig: &Signature) -> bool;    // every component must verify
}

pub trait Connection: Send {         // an established channel carrying framed messages
    async fn send(&mut self, msg: &[u8]) -> Result<()>;
    async fn recv(&mut self) -> Result<Vec<u8>>;
}
pub trait Transport {                // the swap seam — MemoryTransport today, IrohTransport (feature)
    type Addr;                       // transport address; NOT an identity (ADR-011)
    type Conn: Connection;
    async fn connect(&self, addr: &Self::Addr) -> Result<Self::Conn>;
    async fn accept(&self) -> Result<(Self::Addr, Self::Conn)>;
    async fn announce(&self, topic: &Topic) -> Result<()>;
    async fn lookup(&self, topic: &Topic) -> Result<Vec<Self::Addr>>;
}

pub trait Session {                  // an encrypted channel (ConnectedSession impls it)
    async fn send(&mut self, plaintext: &[u8]) -> Result<()>;
    async fn recv(&mut self) -> Result<Vec<u8>>;
}

pub trait Log {                      // append-only, BLAKE3 hash chain, single-writer
    fn append(&mut self, payload: &[u8], by: &dyn Identity) -> Result<Seq>;
    fn verify(&self) -> Result<()>;  // full hash + signature chain check; fails closed
    fn get(&self, seq: Seq) -> Result<Option<Entry>>;
    fn head(&self) -> Seq;
}
```

Why `Identity`/`Verify` are split: a signature can't be checked against a `PeerId` (it's only a hash of the public keys), so verification lives on the public-identity side, which holds the actual key bundle.

*Planned (ADR-002):* CRDT merge for multi-writer state above `Log` — each writer owns a single-writer log; rooms are *sets* of logs merged deterministically, mirroring how Keet models a group chat as many single-writer feeds, not one shared mutable table.

---

## 5. Cryptographic choices

| Function | Classical | PQ (hybrid partner) | Notes |
|---|---|---|---|
| Identity signatures | Ed25519 | ML-DSA (Dilithium) | hybrid sig = both must verify |
| Key agreement | X25519 | ML-KEM (Kyber) | hybrid KEM, combined into one shared secret |
| Session handshake | X25519 (two DHs) + HKDF-SHA256 | ML-KEM-768 (two encapsulations) | `lattice-session-hs-v3`: Lattice's own two-message handshake, signed by both sides with the hybrid identity signatures. No identity hiding |
| Forward secrecy / PCS | Double Ratchet: X25519 DH ratchet, HKDF-SHA256 root/chain KDFs | — | per-message key evolution; the healing leg is classical |
| Record encryption | ChaCha20-Poly1305 | — | per-message key; the ratchet header is the AAD |
| Resume proofs | HMAC-SHA256 | — | `lattice-resume-v2`, keyed from the session root |
| Signature domain | — | — | `lattice-sig-v2`: signatures bind the signer's suite and PeerId |
| Tickets | hybrid signature | — | `lattice-ticket-v2`: signs the iroh endpoint id, the full address (relay URLs and direct addresses) and the identity |
| Hashing / IDs | BLAKE3 | — | log entry hashes, PeerId, content addressing |

Hybrid construction rule: **a hybrid primitive is secure if *either* component is secure.** Hybrid is the default suite (`CryptoSuite::default()`) and is what `lattice-net` uses. `CryptoSuite::Classical` exists for constrained / no-`pq` builds and gives **classical-only security** (exposed to harvest-now-decrypt-later). Lattice never ships a PQ-only suite (immature). This reuses the Kyber+Ed25519 pattern already proven in ShadowWhisper, now using NIST-standardized ML-KEM/ML-DSA names.

**The v3 handshake (`lattice-session-hs-v3`).** Two messages:
- msg1 (initiator → responder) = `eph_i, ratchet_pub_i, kem_ct_s, kem_ek_i, sig_i`.
- msg2 (responder → initiator) = `eph_r, kem_ct_e, sig_r`.

Four secrets are mixed: `ss1` = X25519(eph_i, responder static key); `ss2` = ML-KEM encapsulation to the responder's static key; `ss3` = X25519(eph_i, eph_r); `ss4` = ML-KEM encapsulation to the initiator's ephemeral `kem_ek_i`. `ss2` and `ss4` exist only when the responder is Hybrid (§5.1). The transcript is:
- `T1 = "lattice-session-hs-v3" ‖ lp(binding) ‖ lp(initiator) ‖ lp(responder) ‖ eph_i ‖ ratchet_pub_i ‖ lp(kem_ct_s) ‖ lp(kem_ek_i)`
- `T2 = T1 ‖ lp(sig_i) ‖ eph_r ‖ lp(kem_ct_e)`
- `T = T2 ‖ lp(sig_r)`

where `lp(x) = u32le(len(x)) ‖ x`. The KEM fields are empty (length 0) when the PQ legs are off. The root key is `HKDF(salt = T, ikm = ss1 ‖ ss2 ‖ ss3 ‖ ss4)`. Both sides sign: the initiator signs `T1`, the responder signs `T2`. When signatures are checked: `respond` verifies `sig_i` before any DH or decapsulation; `PendingInitiator::finish` verifies `sig_r` before the `ss3` DH and the `ss4` decapsulation; `initiate` computes `ss1`/`ss2` against the caller-supplied responder static identity before any message is received, and that input is not attacker-controlled. The `nonzero` check rejects all-zero X25519 outputs, including on every ratchet DH step. Ephemeral secrets are erased after the handshake (the ephemeral ML-KEM key is zeroized on drop).

The `binding` is supplied by the caller. `lattice-net` uses `lattice-net-cb-v1` ‖ dialer endpoint id ‖ listener endpoint id, so a handshake or resume proof cannot be replayed onto another QUIC connection.

**Double Ratchet.** The root key seeds a Double Ratchet. Out-of-order and dropped frames use a skipped-key cache bounded by `MAX_SKIP` (1000 per step) and `MAX_SKIPPED_KEYS` (2048 total, FIFO-evicted). `open` skips and ratchets on a scratch copy of the state and commits only after the AEAD verifies, so a forged frame cannot advance or desync the ratchet.

**Resume proofs.** A reconnecting `lattice-net` dialer can resume a kept session only after both sides exchange an HMAC-SHA256 proof (`lattice-resume-v2`). The proof key is derived from the session root. The MAC covers both nonces, both identities, the role and the endpoint binding. Resume does not change the ratchet.

**Identity-bound signatures and tickets.** Signatures (`lattice-sig-v2`) cover the signer's crypto suite and PeerId, so a signature cannot move between the Classical and Hybrid identities derived from one mnemonic. A `lattice-net` ticket (`lattice-ticket-v2`) is signed by the listener's identity over its iroh endpoint id **and its full address (relay URLs and direct addresses)** plus its identity (`ticket_message` in `quic.rs`); the dialer verifies it before dialing and checks that it reached that endpoint.

**Parsing and limits.** Public identities and signatures are parsed canonically and strictly (trailing bytes, wrong lengths, invalid keys and small-order Ed25519 keys are rejected). Frames and handshake data are capped at 64 KiB: `MAX_FRAME_LEN` in the iroh framing, and `MAX_HANDSHAKE_LEN` per handshake message and per field. The identity store fails closed: a keyring error other than "no entry" is fatal, and nothing is generated or written.

Crate status: `lattice-identity` uses `ed25519-dalek` 2, `x25519-dalek` 2, `ml-dsa` 0.1 (FIPS 204), `ml-kem` 0.3 (FIPS 203), `bip39` 2, `hkdf`/`sha2`, `blake3` and `zeroize`. `lattice-session` uses `x25519-dalek` 2, `chacha20poly1305` 0.10, `hkdf`, `hmac`, `sha2` and `zeroize`. RustCrypto-family crates throughout, for audit-surface consistency.

Note on duplicate versions: `ed25519-dalek 3.0.0-rc.0` appears in `Cargo.lock` because iroh 1.0.1 uses it for its transport keys. Lattice identities use `ed25519-dalek` 2.x. The duplicate goes away with an iroh upgrade.

### 5.1 Post-quantum posture

**Threat being defended:** *harvest-now-decrypt-later* (HNDL) — an adversary records ciphertext today and decrypts it once a cryptographically-relevant quantum computer (CRQC) exists. This reframes priorities: PQ **confidentiality** (key agreement) is time-urgent because recorded traffic is decrypted *retroactively*; PQ **authenticity** (signatures) matters mainly once a CRQC actually exists, since a forged signature does damage only in the present. We address both, but the urgency ordering is confidentiality-first.

**Design rules (binding):**
- **Hybrid by default; never PQ-only.** The default suite (`CryptoSuite::default()`, used by `lattice-net`) is Hybrid: it pairs a vetted classical scheme with a NIST-standardized PQ scheme, and security holds if *either* component holds — hedging both PQ immaturity and quantum risk. `CryptoSuite::Classical` exists for constrained / no-`pq` builds and gives **classical-only security**. A session gets the ML-KEM legs if and only if the responder is Hybrid (and the `pq` feature is compiled in).
- **KDF combiner, never XOR.** The session root is `HKDF(salt = transcript, ikm = ss1 ‖ ss2 ‖ ss3 ‖ ss4)` (see §5). Hybrid signatures require **every** component to verify (AND, not OR).
- **Standardized algorithms only:** ML-KEM (FIPS 203), ML-DSA (FIPS 204), via audited RustCrypto crates. No bespoke or pre-standard schemes; we do not roll our own.
- **Crypto-agility is mandatory.** The `CryptoSuite` tag is bound into the `PeerId`; signatures are length-prefixed; HKDF is domain-separated. A new suite (e.g. ML-KEM-1024, or a replacement if ML-DSA is weakened) must be introduceable via negotiation without breaking existing identities. There is no suite negotiation today.

**Suites in the session.** The `Classical` suite exists (Ed25519 + X25519 only). The session's PQ legs (`ss2`, `ss4`) are on if and only if the **responder** is Hybrid. A Classical initiator talking to a Hybrid responder still gets both PQ legs; a Classical responder gets none, whatever the initiator is. The ratchet's healing leg is classical X25519.

**Status by layer:**

| Layer | PQ posture | State |
|---|---|---|
| Identity signatures | Ed25519 + ML-DSA-65 hybrid (AND-verify) | **Done** |
| Identity key material | carries X25519 + ML-KEM-768 public keys | **Done** (keys derived & published) |
| Session | v3 handshake: both sides sign the transcript; X25519 + ML-KEM-768 (when the responder is Hybrid) → HKDF(salt = transcript) → Double Ratchet → ChaCha20-Poly1305 | **Done** — `lattice-session-hs-v3` + Double Ratchet (forward secrecy + post-compromise security) + bounded skipped-key cache + resume proofs |
| Access control | UCAN-style signed capabilities (offline-verifiable) | **Done** — single-hop grants; no attenuation chain, expiry or revocation |
| Transport (iroh/QUIC-TLS) | independent; app-layer session crypto is the real protection | out of our hands; do not rely on it for E2E |
| Capabilities | signed via the `Identity` trait, so hybrid when the issuer is Hybrid | **Done** |

**Caveats recorded honestly:**
- **PQ ≠ forward secrecy** — orthogonal, and the session has both axes: the PQ-hybrid handshake protects the *initial* secret; the Double Ratchet provides per-message *forward secrecy* (symmetric chain) and *post-compromise security* (DH ratchet re-keys the root each direction flip). Out-of-order / dropped frames are handled by a bounded skipped-key cache (`MAX_SKIP` per step, FIFO-evicted total), and `open` skips/ratchets on a scratch copy committed only on AEAD success — so a forged header can't advance the ratchet. Note the DH ratchet's healing leg is classical X25519 — fully-PQ ratcheting remains open research.
- **Size/bandwidth cost is real** — ML-DSA-65 signatures ≈ 3.3 KB and ML-KEM-768 keys ≈ 1.2 KB, vs. 64 B for Ed25519. In a system that gossips keys and signs every log entry this is a genuine budget; measure early and consider signing batch roots rather than every entry.
- **The ratchet's healing leg is classical.** After the handshake, post-compromise recovery relies on X25519 only; an adversary with a CRQC who recorded the traffic and later compromises a session state could follow the ratchet. A PQ ratchet is not implemented.

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
| **S**poofing identity | Peer/Discovery | Claim to be another `PeerId` | Identity = public key; every entry signed (hybrid); the v3 handshake has mutual transcript signatures and a caller-supplied channel binding; `lattice-net` tickets are signed; first contact is TOFU with a manual fingerprint comparison |
| **T**ampering content | Transport/Peer | Alter messages/log entries in flight or at rest | AEAD per record; append-only log is a signed hash chain — any edit breaks verification, `verify()` fails closed |
| **R**epudiation | Peer | "I never wrote that" | Per-entry hybrid signatures are non-repudiable within a room |
| **I**nfo disclosure | Transport/Relay | Read plaintext | E2E AEAD; relay sees only ciphertext + endpoints. Identities are **not** hidden: they are sent in the clear (the `lattice-net` preamble carries the dialer's identity bundle, the ticket carries the listener's), so a passive observer of the handshake can learn them |
| **I**nfo disclosure (metadata) | Discovery/Relay | Learn who talks to whom | **v1: accepted risk (A7 deferred).** Metadata is not hidden. v2: tor/mix `Transport` impl |
| **D**enial of service | Transport/Discovery | Drop/flood/eclipse | iroh relay fallback for reachability; 64 KiB caps on frames and handshake fields; `MAX_SKIP`/`MAX_SKIPPED_KEYS` bound ratchet work; `lattice-net`'s 15 s `NEGOTIATION_TIMEOUT` on each pre-chat step and on finishing an inbound QUIC connection; a one-byte busy reply to a connection that arrives during a chat; at most `MAX_PENDING_ACCEPTS` (8) concurrent pending accepts and `MAX_BUSY_REPLIES` (8) concurrent busy replies, with extra connections dropped immediately. `IrohTransport::accept_conn` itself is unbounded, and `lattice-net` no longer uses it. Residuals: a flood can still fill the 8+8 slots and delay legitimate peers for up to the timeout; there is no per-peer rate limiting; there is no Sybil resistance (§6.6) |
| **E**levation of privilege | Caps | Forge/replay a capability to gain write/admin | Caps are signed and audience- and action-scoped, and verified locally (no server to trick). They are single-hop: no attenuation chain, no expiry and no revocation |

### 6.5 Key compromise handling
- **Session key leak** → Double-Ratchet limits blast radius to a window of messages, not the whole history (forward secrecy + post-compromise recovery as the ratchet heals).
- **Identity key leak** → forward secrecy protects recorded sessions, but the attacker can impersonate the owner in new sessions. No rotation or revocation mechanism is implemented. Device certificates (`lattice-device-cert-v2`) bind the full device identity and carry a mandatory `not_after`; they have no revocation, so a leaked device key stays valid until `not_after`. `lattice-net` uses the root identity directly as its everyday key.
- **Resume** → anyone holding the session state (for example a compromised device) can resume that session; resuming requires the mutual proof, which is derived from that state.
- **Recovery** → the BIP39 mnemonic (ADR-004); there is no server to reset against and no guardian scheme. **Open question (§8):** exact recovery UX. This is the sharpest tradeoff in keypair-as-identity systems and we will not hand-wave it.

**Known limitations** (SECURITY.md lists the same items):
- (a) Device certs have no revocation: a leaked device key stays valid until its `not_after`.
- (b) `lattice-net` uses the root identity as its everyday key; device keys are not wired into it.
- (c) Tickets are reachability bearer tokens: anyone holding one can try to connect.
- (d) TOFU fingerprint comparison is manual; nothing enforces that the user does it.
- (e) Metadata (who talks to whom) is not hidden.
- (f) A compromised identity can impersonate its owner in new sessions.
- (g) Resume requires, and is available to anyone holding, the session state.
- (h) No identity hiding: identities are sent in the clear in the preamble and ticket.
- (i) Capabilities are single-hop, with no expiry or revocation.

### 6.6 Sybil / eclipse posture (v1)
No server means no central rate-limiter. v1 has no Sybil mitigations beyond single-writer logs. Discovery is not topic-based yet. Strong Sybil resistance is not implemented; it is acknowledged as **hard** — documented, not pretended away. See the §8 "Not implemented" list.

### 6.7 Explicitly out of scope (v1)
Rooted/compromised device; nation-state traffic-analysis of the social graph (A7); global consensus/double-spend concerns (no ledger); legal compulsion of a participant to hand over their own keys; denial-of-availability when *all* holders of a dataset are offline (inherent to P2P — could be mitigated by always-on "pinning" peers (not implemented)).

### 6.8 Security non-negotiables (acceptance gates)
Enforcement status of each gate today:
- No A1 content unencrypted: holds for the session API (`SecureSession` / `ConnectedSession` only send AEAD frames). Applications that use a `Connection` directly, as `lattice-net` does for its preamble and resume frames, send those bytes unencrypted; they carry identities and nonces, not chat content. Not enforced by a dedicated test.
- `Log::verify()` rejects tampered chains: test-enforced, including with real hybrid and classical signatures.
- No `unsafe` in authored crates: `forbid(unsafe_code)` is a workspace lint.
- fmt, clippy and tests run in CI, and so does `cargo-deny` (`.github/workflows/ci.yml`).
- `cargo-audit` and `cargo-vet`: not in CI.
- Reproducible, signed release artifacts: not done.

---

## 7. Crate layout

```
Lattice/                  (cargo workspace root)
├─ Cargo.toml             workspace, shared lints (forbid unsafe), pinned versions
├─ DESIGN.md  README.md   design + threat model, and overview / run guide
├─ deny.toml              cargo-deny policy
├─ crates/
│  ├─ lattice-core/       types, errors, traits (Identity/Verify/Connection/Transport/Session/Log)
│  ├─ lattice-identity/   PQ-hybrid keypair, PeerId, BIP39 recovery, device certs
│  ├─ lattice-log/        append-only BLAKE3 hash chain + per-entry hybrid-sig verify
│  ├─ lattice-session/    hybrid-KEM handshake + Double Ratchet + ConnectedSession
│  ├─ lattice-caps/       UCAN-style signed capability tokens (single-hop)
│  ├─ lattice-transport/  Transport/Connection traits; MemoryTransport; iroh QUIC (feature `iroh`, src/quic.rs)
│  └─ lattice/            umbrella API crate + prelude (feature `iroh` re-exports IrohTransport)
└─ examples/chat/         lattice-chat (local one-process demo) + lattice-net (two-device P2P chat CLI)
```

---

## 8. Open questions / ADR backlog

- **ADR-001 (decided):** Delegate transport/NAT/holepunch to **iroh** behind a `Transport` trait, rather than reimplementing a DHT + QUIC + holepunching. Rationale: that layer is where subtle security/reliability bugs concentrate; n0 has years invested; the trait keeps us free to swap. *Cost accepted: a large dependency we don't control.* **Status:** the `Transport`/`Connection`/`Session` async traits are real, with an in-memory loopback impl (`MemoryTransport`) and `ConnectedSession` running the full handshake + Double Ratchet over a `Connection` — tested end-to-end. The iroh QUIC backend (`IrohTransport`) now implements the same trait — framed bi-streams, n0 relays + discovery, ticket-based dialing — and ships with the `lattice-net` CLI for real two-device chat. (The build/dev sandbox can't reach iroh's relay network, so the networked path is verified by compilation + the in-memory end-to-end test here; the actual cross-machine run is exercised on real infrastructure.)
- **ADR-002 (open):** CRDT choice for multi-writer room state — bespoke set-of-logs merge vs. adopting `automerge`/`yrs`. Tradeoff: control & footprint vs. proven convergence.
- **ADR-003 (decided):** **UCAN-style** signed capabilities over macaroons. Each capability is signed by the issuer's identity key and verified offline against the issuer's public identity — reusing the hybrid signatures and needing no shared secret (macaroons' HMAC root secret doesn't fit a no-central-server P2P model). *v1:* single-hop signed grant binding issuer/audience/resource/action. *Pending:* multi-hop delegation with attenuation (the body layout and `Action` ordering are already shaped for it).
- **ADR-004 (decided):** **Deterministic identity from a BIP39 mnemonic + root→device delegation.** Master seed (mnemonic) → HKDF-SHA256 with per-algorithm domain labels → Ed25519 / X25519 / ML-DSA / ML-KEM keypairs; `PeerId = BLAKE3(canonical public-key bundle)`, so the same mnemonic reproduces the same identity. *Recovery* = re-enter the mnemonic (offline, no guardians). *Multi-device* = each device holds a fresh signing key authorized by a root-signed `DeviceCert`; lose-a-device → no revocation yet (the cert expires at `not_after`), lose-all → restore from mnemonic. *Rejected:* social/Shamir as the v1 default (online-guardian + UX cost) → deferred to an optional `lattice-recovery` module; device-linking-only (no seed) → no offline floor for total device loss. *Cost accepted:* the mnemonic is a long-lived root secret. Device certs exist (`lattice-device-cert-v2`: hybrid, mandatory `not_after`, no revocation), but the example app `lattice-net` does not use device subkeys yet, so there the root identity is the hot key. The remaining mitigations are offline custody of the mnemonic and session forward secrecy.
- **ADR-005 (decided):** At-rest key storage = **OS keychain primary, age-encrypted file fallback** (`lattice-identity`, `storage` feature). The keychain (Secret Service / Keychain / Credential Manager) gives a seamless no-passphrase experience on desktops; headless/server hosts fall back to an `age` scrypt/passphrase-encrypted file (`identity.age`, `0600`; passphrase via `LATTICE_PASSPHRASE` or prompt). Backend recorded in `config.toml`; legacy plaintext files are migrated (the legacy plaintext is re-encrypted and the plaintext file is deleted; no backup is kept). `LATTICE_STORAGE=age` forces the file backend. This removes the plaintext-mnemonic exposure from the device boundary (A3).
- **ADR-006 (decided):** Session resumption across transport drops. The ratchet is transport-independent, so the library primitive is `ConnectedSession::resume(conn, session)` — rebind an existing `SecureSession` to a fresh connection with **no re-handshake**; counters/chains carry over and the skipped-key cache absorbs frames lost in the gap (done + tested). Resume now requires a mutual proof of the session secret (ADR-009). *CLI negotiation (done):* on reconnect the dialer signals intent with a 1-byte mode prefix (`fresh` vs `resume`) + its `PeerId`; the listener keeps a `PeerId → SecureSession` map and resumes if it holds the session, else replies `fresh` and both run a handshake (e.g. when a peer restarted and lost its in-memory state). Implemented in `lattice-net`. *Out of scope:* reliable redelivery of in-flight messages (acks/resend) — a message dropped at the instant of disconnect is lost, not recovered.
- **ADR-007 (accepted):** v3 handshake (`lattice-session-hs-v3`): two messages, both sides sign the transcript, four mixed secrets (two X25519, two ML-KEM when the responder is Hybrid), caller-supplied channel binding, root = HKDF(salt = transcript).
- **ADR-008 (accepted):** Identity-bound signatures (`lattice-sig-v2`): every signature covers the signer's crypto suite and PeerId.
- **ADR-009 (accepted):** Resume proof (`lattice-resume-v2`): HMAC-SHA256 under a key derived from the session root, covering both nonces, both identities, the role and the endpoint binding; both sides must verify before a session is rebound.
- **ADR-010 (accepted):** Channel binding + signed ticket: `lattice-net-cb-v1` (dialer and listener iroh endpoint ids) is bound into the handshake and resume proofs; `lattice-ticket-v2` signs the listener's endpoint id, its full address (relay URLs and direct addresses) and its identity (v1, which signed only the endpoint id and identity, is superseded).
- **ADR-011 (accepted):** Transport addressing: `Transport::Addr` is transport-specific, and addresses are not identities.
- **ADR-012 (accepted):** Hybrid device certs v2 (`lattice-device-cert-v2`): bind the full device identity and carry a mandatory `not_after`; no revocation.
- **Not implemented (future):** proof-of-membership before relay assistance, peer-scoring hooks, capability-gated log writes (capabilities are not wired into logs; `MemLog` enforces only its single author), topic-based peer discovery, and always-on pinning peers.
- **Naming:** "Lattice" is a placeholder. Decide before first publish.

---

## 9. What this is *not* good for (honest boundary)

Lattice is a poor fit — and we should say so to anyone who picks it up — for: authoritative global state (marketplaces, ledgers, leaderboards), regulated records custody / chain-of-custody / retention (e.g. court systems), strong centralized moderation, server-side discovery across strangers, or heavy server-side compute. It shines for private direct communication and data-sharing between parties who already know each other, censorship-resistant distribution, and local-first collaboration.
