# Lattice — Design & Threat Model

> **Working codename:** *Lattice* (a P2P mesh; placeholder, easy to rename).
> **One line:** A 100% Rust, security-forward peer-to-peer application framework — the Holepunch/Keet model, redesigned with clean trait boundaries, post-quantum-hybrid identity, and a transport substrate you can swap.
> **Status:** v0.1 implemented (local git, no remote). This doc is both the design contract and a map of what's built — per-section notes and the §5.1 status table mark done vs pending. The stack (identity, signed log, hybrid-KEM + Double-Ratchet session, single-hop capabilities, in-memory + iroh transport) is implemented and tested; the `lattice-net` CLI does two-device chat. It is experimental and **not externally audited**; §5, §5.1, §6.4, §6.5 and SECURITY.md list the known limitations.

---

## 1. Purpose, scope, non-goals

### 1.1 Purpose
Lattice lets a developer build a **serverless, zero-infrastructure P2P application** — messaging, file sync, collaborative tooling, local-first apps — without standing up or trusting any central server. Data lives on user devices, and peers connect directly. The framework supplies the hard parts (identity, encrypted sessions, connectivity, and signed append-only logs) behind a small, ergonomic API so app authors think about *their app*, not about NAT traversal or ratchets. Peer discovery by topic and replicated (CRDT) state are goals, not implemented yet (see §8).

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
| Identity signatures | Ed25519 | ML-DSA (Dilithium) | hybrid sig = both must verify (Hybrid suite; a Classical identity signs with Ed25519 only) |
| Key agreement | X25519 | ML-KEM (Kyber) | hybrid KEM, combined into one shared secret |
| Session handshake | X25519 (two DHs) + HKDF-SHA256 | ML-KEM-768 (two encapsulations) | `lattice-session-hs-v3`: Lattice's own two-message handshake, signed by both sides with their identity signatures (hybrid for Hybrid identities). No identity hiding |
| Forward secrecy / PCS | Double Ratchet: X25519 DH ratchet, HKDF-SHA256 root/chain KDFs | — | per-message key evolution; the healing leg is classical |
| Record encryption | ChaCha20-Poly1305 | — | per-message key; the ratchet header is the AAD |
| Resume proofs | HMAC-SHA256 | — | `lattice-resume-v2`, keyed from the session root |
| Signature domain | — | — | `lattice-sig-v2`: signatures bind the signer's suite and PeerId |
| Tickets | — (unsigned) | — | v3: iroh address + root PeerId + device PeerId, a compact out-of-band bearer (ADR-013). The signed `lattice-ticket-v2` is historical and superseded |
| Revocation lists | hybrid signature | — | `lattice-revocation-v1`: root-signed, monotonic `seq`, sorted device PeerIds, at most `MAX_REVOKED` (1024); signed through `lattice-sig-v2` |
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

**Identity-bound signatures and tickets.** Signatures (`lattice-sig-v2`) cover the signer's crypto suite and PeerId, so a signature cannot move between the Classical and Hybrid identities derived from one mnemonic. A `lattice-net` ticket is no longer signed (v3, ADR-013; the signed `lattice-ticket-v2` is historical and superseded). It is a compact bearer of the listener's iroh address, root PeerId and device PeerId. The dialer checks the listener's hello (device and root PeerIds equal the ticket's, device → root certificate chain, expiry, revocation) and that the connection reached the ticket's endpoint, then the handshake and an encrypted auth bundle pin the device and root. Revocation lists (`lattice-revocation-v1`) are signed the same way, through `lattice-sig-v2`.

**Parsing and limits.** Public identities and signatures are parsed canonically and strictly (trailing bytes, wrong lengths, invalid keys, small-order Ed25519 keys, and low-order or non-canonical X25519 keys are rejected). Frames and handshake data are capped at 64 KiB: `MAX_FRAME_LEN` in the iroh framing, and `MAX_HANDSHAKE_LEN` per handshake message and per field. The identity store fails closed: a keyring error other than "no entry" is fatal, and nothing is generated or written.

Crate status: `lattice-identity` uses `ed25519-dalek` 2, `x25519-dalek` 2, `ml-dsa` 0.1 (FIPS 204), `ml-kem` 0.3 (FIPS 203), `bip39` 2, `hkdf`/`sha2`, `blake3` and `zeroize`. `lattice-session` uses `x25519-dalek` 2, `chacha20poly1305` 0.10, `hkdf`, `hmac`, `sha2` and `zeroize`. RustCrypto-family crates throughout, for audit-surface consistency.

Note on duplicate versions: iroh 1.5.0 uses the stable `ed25519-dalek 3.0.0` (and `curve25519-dalek 5.0.0`) for its transport keys. Lattice identities deliberately stay on `ed25519-dalek` 2.x. So two major versions of ed25519-dalek appear in `Cargo.lock`, but neither is a release candidate.

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

### 5.2 Safety numbers

Two users compare one symmetric 60-digit **safety number** of their two **root** identities instead of two hex fingerprints. It is display-only: no wire format changes, and nothing in the protocol depends on it. `lattice_identity::safety_number(a, b)` is computed exactly as follows:

1. Order the two identities by PeerId: `(x, y) = (a, b)` if `a.peer_id() <= b.peer_id()` (the raw 32 bytes compared lexicographically), else `(b, a)`. So `safety_number(a, b) == safety_number(b, a)`.
2. `h = BLAKE3()`; `h.update("lattice-safety-number-v1")`; then for each `p` in `[x, y]`, with `bytes = p.to_bytes()` (suite tag, Ed25519, X25519, ML-DSA and ML-KEM keys): `h.update(u32le(len(bytes)))` and `h.update(bytes)`.
3. Read the BLAKE3 XOF `h.finalize_xof()` three bytes at a time. For each draw, `v = u32le(b0, b1, b2, 0)`. If `v < 16_700_000` (167 × 100 000) the group value is `v mod 100 000`; otherwise the draw is rejected and the next three bytes are read. This is unbiased rejection sampling (about 0.46 % of draws are rejected). The hash is not iterated.
4. Take 12 groups, format each as five digits (`{:05}`), and join them with single spaces: 12 × 5 = 60 decimal digits.

The number covers ≈199.3 bits (60 decimal digits) of output, computed over both full root encodings. Finding a new key that matches a fixed number costs about 2^199 work. A man in the middle who controls both substituted keys (one towards each user) only needs two numbers to collide in the two directions, which is a cross-collision costing about 2^100 work. That is still out of reach for a one-time comparison by voice or in person, where the attacker must have the keys ready before the users compare and cannot retry.

Device keys are bound to the root through the verified `DeviceCert` chain, so a device renewal or a new device does not change the number. Comparing is manual: `lattice-net` prints the number after every successful authentication, followed by "verified peer" when the peer's root is in `known_peers` (or is our own root) and a prominent "UNVERIFIED peer" line otherwise, and `lattice-net verify-peer` records the peer's root in `<dir>/known_peers`. `lattice-net` never verifies a peer automatically. `seen_peers` (the last 64 roots that authenticated) only lets `verify-peer` resolve a 40-hex fingerprint; it never marks anyone verified.

`PublicIdentity::from_bytes` also validates the X25519 key: it rejects bit 255 set, values ≥ 2^255 − 19, and the low-order u-coordinates (0, 1, the two order-8 points, p − 1, p, p + 1).

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
| **S**poofing identity | Peer/Discovery | Claim to be another `PeerId` | Identity = public key; every entry signed (hybrid for Hybrid identities); the v3 handshake has mutual transcript signatures and a caller-supplied channel binding; `lattice-net` peers prove device → root → not-revoked on the wire and the dialer checks the listener's hello against the ticket's PeerIds; first contact is TOFU with a manual comparison of the 60-digit safety number of both **root** identities (§5.2); `lattice-net` labels every connection "verified peer" or "UNVERIFIED peer" and only `verify-peer` records a root in `known_peers` |
| **T**ampering content | Transport/Peer | Alter messages/log entries in flight or at rest | AEAD per record; append-only log is a signed hash chain — any edit breaks verification, `verify()` fails closed |
| **R**epudiation | Peer | "I never wrote that" | Per-entry signatures (hybrid for Hybrid identities) are non-repudiable within a room |
| **I**nfo disclosure | Transport/Relay | Read plaintext | E2E AEAD; relay sees only ciphertext + endpoints. Identities are **not** hidden: the `lattice-net` preamble carries the dialer's device identity and the listener's hello carries its device identity, root identity and certificate chain, all in the clear (only the auth bundles after the handshake are encrypted), so a passive observer can learn them |
| **I**nfo disclosure (metadata) | Discovery/Relay | Learn who talks to whom | **v1: accepted risk (A7 deferred).** Metadata is not hidden. v2: tor/mix `Transport` impl |
| **D**enial of service | Transport/Discovery | Drop/flood/eclipse | iroh relay fallback for reachability; 64 KiB caps on frames and handshake fields; `MAX_SKIP`/`MAX_SKIPPED_KEYS` bound ratchet work; `lattice-net`'s 15 s `NEGOTIATION_TIMEOUT` on each pre-chat step and on finishing an inbound QUIC connection; a one-byte busy reply to a connection that arrives during a chat; at most `MAX_PENDING_ACCEPTS` (8) concurrent pending accepts and `MAX_BUSY_REPLIES` (8) concurrent busy replies, with extra connections dropped immediately; the listener keeps at most `MAX_KEPT_SESSIONS` (64) sessions for resume and evicts the least recently used; outgoing QUIC connect and `open_bi` are each bounded by `CONNECT_TIMEOUT` (15 s). `IrohTransport::accept_conn` has no timeout and the `Transport::accept` trait method is limited to 15 s per inbound connection but still serial; `lattice-net` uses neither. Before any task is spawned the listener also applies per-source and per-endpoint-id token buckets, temporary bans after repeated failures, a global accept-rate cap and slots reserved for previously verified peers (§6.6). Residuals: a distributed flood (many source IPs, fresh endpoint ids) can still saturate the non-reserved slots and the global cap for as long as it lasts, and there is no Sybil resistance (§6.6) |
| **E**levation of privilege | Caps | Forge/replay a capability to gain write/admin | Caps are signed and audience- and action-scoped, and verified locally (no server to trick). They are single-hop: no attenuation chain, no expiry and no revocation |

### 6.5 Key compromise handling
- **Session key leak** → Double-Ratchet limits blast radius to a window of messages, not the whole history (forward secrecy + post-compromise recovery as the ratchet heals).
- **Device key leak** → forward secrecy protects recorded sessions, but the attacker can impersonate the device in new sessions until its certificate (`lattice-device-cert-v2`, mandatory `not_after`, 30 days in `lattice-net`) expires or the root revokes it with a signed `lattice-revocation-v1` list. Revocation propagation is lazy (below).
- **Root key leak** → total: the root issues every certificate and revocation list, and there is no root rotation. `lattice-net` keeps the root out of everyday use: handshakes use a device key, and the root can be removed from a store with `forget-root` and restored from its mnemonic with `import-root`.
- **Resume** → anyone holding the session state (for example a compromised device) can resume that session; resuming requires the mutual proof, which is derived from that state.
- **Recovery** → the BIP39 mnemonic (ADR-004); there is no server to reset against and no guardian scheme. **Open question (§8):** exact recovery UX. This is the sharpest tradeoff in keypair-as-identity systems and we will not hand-wave it.

**Known limitations** (SECURITY.md lists the same items):
- (a) Tickets (v3) are unsigned, compact reachability bearer tokens: anyone holding one can try to connect. Editing the address in one can only deny service; the PeerIds it names are verified (ADR-013).
- (b) Revocation propagation is lazy: peers learn a revocation only when they next talk to a non-revoked device of the same root (the list rides in its hello or auth bundle; tickets carry none). Until then a revoked device is accepted; the 30-day `DEVICE_CERT_LIFETIME` bounds the window. A higher-seq list from the root can un-revoke a device, by design. Root compromise is total; there is no root rotation.
- (c) TOFU comparison of the safety number of the two **root** identities (§5.2) is manual; nothing enforces that the user does it. `lattice-net` marks peers it has not been told are verified as UNVERIFIED on every connection and never verifies anyone itself.
- (d) Metadata (who talks to whom) is not hidden.
- (e) A compromised device key can impersonate its owner in new sessions until its certificate expires or the revocation is learned.
- (f) Resume requires, and is available to anyone holding, the session state.
- (g) No identity hiding: the dialer's device identity (preamble) and the listener's device identity, root identity and certificate chain (hello) are sent in the clear.
- (h) Capabilities are single-hop, with no expiry or revocation.

### 6.6 Sybil / eclipse posture (v1) and `lattice-net` flood limits
No server means no central rate-limiter. v1 has no Sybil mitigations beyond single-writer logs. Discovery is not topic-based yet. Strong Sybil resistance is not implemented; it is acknowledged as **hard** — documented, not pretended away. See the §8 "Not implemented" list.

The `lattice-net` listener does limit a connection flood before any expensive work. The limiter is the pure, std-only module `examples/chat/src/bin/lattice-net/flood.rs` (generic over a clock and a source key, unit-tested with a fake clock); the numbers below are named constants in `lattice-net.rs`.

**Per attempt, in the acceptor, before a task is spawned** (everything is synchronous; nothing awaits while the limiter's mutex is held):
1. The source is read from `IncomingConn::remote_source()` (no handshake). A direct IPv4 source is keyed by its /32, an IPv4-mapped IPv6 address by that IPv4, any other IPv6 address by its **/64**.
2. A source banned for repeated failures is refused (`MAX_FAILURES_BEFORE_BAN` = 8 failures within `FAILURE_WINDOW` = 60 s starts a ban of `BAN_DURATION` = 300 s).
3. A per-source token bucket (`SOURCE_BURST` 4, one token per `SOURCE_REFILL` 2 s).
4. A global accept-rate cap (`GLOBAL_ACCEPT_BURST` 32, one token per `GLOBAL_ACCEPT_REFILL` 50 ms, i.e. 20/s sustained). The order matters: a single-source flooder is refused at steps 2–3 before it can drain the global bucket.
5. A free pending-accept slot (`MAX_PENDING_ACCEPTS` = 8). With none free the attempt is dropped.

Refused attempts are dropped without spawning anything. **After the handshake** the endpoint id is known and a per-endpoint-id bucket and ban apply (`ENDPOINT_BURST` 4, `ENDPOINT_REFILL` 2 s, same ban rule). The per-source and per-endpoint tables are bounded (`MAX_TRACKED_SOURCES` and `MAX_TRACKED_ENDPOINTS`, 4096 each) and evict the least recently seen entry, so memory is O(cap). Failures of the handshake, accept or negotiation count against the source (the endpoint id is unknown for a failed handshake) and, after the handshake, the endpoint id. Busy replies and limiter drops are not failures, and a successful authentication clears both the source's and the endpoint's failures and bans.

**Relayed attempts.** In iroh 1.5, `Incoming::remote_addr()` is an `IncomingAddr`: `Ip(SocketAddr)` for a direct path, and a relay variant for a relayed one, which carries no client IP. `lattice-transport` maps these to `IncomingSource::Direct`, `Relayed` and (for any other kind, since the enum is `#[non_exhaustive]`, or an unspecified address) `Unknown`. iroh's internal "mapped" addresses are all in `fd15:70a:510b::/48` (iroh 1.5.0 `socket/mapped_addrs.rs`); iroh normally converts them to the relay/custom variants, but falls back to `Ip(addr)` when a lookup fails, so an `Ip` address inside that /48 is also treated as `Relayed`. Other unique-local IPv6 addresses are real LAN/VPN peers and are keyed as direct sources. Relayed and unknown attempts all share **one** source key and **one** bucket (`RELAYED_BURST` 16, `RELAYED_REFILL` 250 ms). That key is never failure-tracked or banned, because one bad relayed peer must not ban every relayed peer; for relayed peers only the endpoint-id limits apply.

**Slot accounting.** The endpoint id is only known after the handshake, so before it nothing distinguishes a verified peer from a stranger. An attempt takes a general slot if one of the `MAX_PENDING_ACCEPTS - RESERVED_VERIFIED_SLOTS` (6) is free. Otherwise it takes one of the `RESERVED_VERIFIED_SLOTS` (2) reserved slots *provisionally*: that slot is bounded by the shorter `PROVISIONAL_HANDSHAKE_TIMEOUT` (5 s, against 15 s `NEGOTIATION_TIMEOUT` for a general slot) and is kept past the handshake only if the remote endpoint id is a recorded verified endpoint; a stranger's reserved slot is released then. So a stranger holds a reserved slot for at most the provisional timeout and never through negotiation, while a verified peer can still get in when a flood has filled all the general slots. A verified peer that obtained a general slot keeps it. A verified endpoint is one that authenticated while its root was in `known_peers` (or was our own root). The table is in memory, bounded (`MAX_VERIFIED_ENDPOINTS` 256, `MAX_ENDPOINTS_PER_VERIFIED_ROOT` 4) and lives for one listener run. `lattice-net` generates a fresh iroh endpoint id per process, so a restarted dialer competes as a stranger on its first connection until it has authenticated once.

**Reporting.** Dropped attempts are counted per reason and printed as one summary warning per `DROP_WARN_INTERVAL` (10 s), not one line per attempt.

**Residual risk** (these limits reduce, not remove, flood exposure):
- A botnet with many source IPs and fresh endpoint ids can still saturate the non-reserved slots and the global cap, and so deny service to strangers for as long as it lasts.
- Source IPs are not authenticated before the handshake; a spoofing attacker can burn another address's bucket or failure budget. Endpoint ids are free to generate, so per-endpoint limits stop only single-key floods.
- Relayed peers share one address and bucket, so a relayed flood can rate-limit legitimate relayed strangers.
- Stalled handshakes can still churn the reserved slots, up to the provisional timeout each.
- An evicted table entry forgets its ban.
- The verified-endpoint table is in memory and per dialer process, so it gives no priority to a peer after either side restarts until it authenticates again.
- With an attacker on the same source, a legitimate peer behind that /32 or /64 shares its limits.

### 6.7 Explicitly out of scope (v1)
Rooted/compromised device; nation-state traffic-analysis of the social graph (A7); global consensus/double-spend concerns (no ledger); legal compulsion of a participant to hand over their own keys; denial-of-availability when *all* holders of a dataset are offline (inherent to P2P — could be mitigated by always-on "pinning" peers (not implemented)).

### 6.8 Security non-negotiables (acceptance gates)
Enforcement status of each gate today:
- No A1 content unencrypted: holds for the session API (`SecureSession` / `ConnectedSession` only send AEAD frames). Applications that use a `Connection` directly, as `lattice-net` does for its preamble, hello and resume frames, send those bytes unencrypted; they carry identities, certificates and nonces, not chat content. Not enforced by a dedicated test.
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
- **ADR-004 (decided):** **Deterministic identity from a BIP39 mnemonic + root→device delegation.** Master seed (mnemonic) → HKDF-SHA256 with per-algorithm domain labels → Ed25519 / X25519 / ML-DSA / ML-KEM keypairs; `PeerId = BLAKE3(canonical public-key bundle)`, so the same mnemonic reproduces the same identity. *Recovery* = re-enter the mnemonic (offline, no guardians). *Multi-device* = each device holds a fresh signing key authorized by a root-signed `DeviceCert`; lose-a-device → the root signs a `lattice-revocation-v1` list (lazy propagation) or the cert expires at `not_after`, lose-all → restore from mnemonic. *Rejected:* social/Shamir as the v1 default (online-guardian + UX cost) → deferred to an optional `lattice-recovery` module; device-linking-only (no seed) → no offline floor for total device loss. *Cost accepted:* the mnemonic is a long-lived root secret. Device certs exist (`lattice-device-cert-v2`: hybrid, mandatory `not_after`), and the example app `lattice-net` now uses device subkeys: a separate Hybrid device key signs its handshakes, and the root is only needed to issue, renew and revoke. The remaining mitigations are offline custody of the mnemonic and session forward secrecy.
- **ADR-005 (decided):** At-rest key storage = **OS keychain primary, age-encrypted file fallback** (`lattice-identity`, `storage` feature). The keychain (Secret Service / Keychain / Credential Manager) gives a seamless no-passphrase experience on desktops; headless/server hosts fall back to an `age` scrypt/passphrase-encrypted file (`identity.age`, `0600`; passphrase via `LATTICE_PASSPHRASE` or prompt). Backend recorded in `config.toml`; legacy plaintext files are migrated (the legacy plaintext is re-encrypted and the plaintext file is deleted; no backup is kept). `LATTICE_STORAGE=age` forces the file backend. This removes the plaintext-mnemonic exposure from the device boundary (A3).
- **ADR-006 (decided):** Session resumption across transport drops. The ratchet is transport-independent, so the library primitive is `ConnectedSession::resume(conn, session)` — rebind an existing `SecureSession` to a fresh connection with **no re-handshake**; counters/chains carry over and the skipped-key cache absorbs frames lost in the gap (done + tested). Resume now requires a mutual proof of the session secret (ADR-009). *CLI negotiation (done):* the dialer's first frame is `[WIRE_VERSION][mode][nonce 32][full device PublicIdentity]`, where `mode` is `fresh` or `resume` and the nonce is zero for fresh. The listener always sends its hello first (device identity, root identity, certificate, optional revocation list; ADR-013), then its decision. It keeps a map from device `PeerId` to `SecureSession` and resumes only when it holds the kept session for that device **and** `resume_allowed` holds (certificate unexpired and not revoked by a cached list), through the mutual `lattice-resume-v2` proof (ADR-009). Otherwise it replies `fresh` and both sides run a handshake plus auth exchange (e.g. when a peer restarted and lost its in-memory state). Implemented in `lattice-net`. *Out of scope:* reliable redelivery of in-flight messages (acks/resend) — a message dropped at the instant of disconnect is lost, not recovered.
- **ADR-007 (accepted):** v3 handshake (`lattice-session-hs-v3`): two messages, both sides sign the transcript, four mixed secrets (two X25519, two ML-KEM when the responder is Hybrid), caller-supplied channel binding, root = HKDF(salt = transcript).
- **ADR-008 (accepted):** Identity-bound signatures (`lattice-sig-v2`): every signature covers the signer's crypto suite and PeerId.
- **ADR-009 (accepted):** Resume proof (`lattice-resume-v2`): HMAC-SHA256 under a key derived from the session root, covering both nonces, both identities, the role and the endpoint binding; both sides must verify before a session is rebound.
- **ADR-010 (accepted; superseded for tickets by ADR-013):** Channel binding + signed ticket: `lattice-net-cb-v1` (dialer and listener iroh endpoint ids) is bound into the handshake and resume proofs, and that part stands. `lattice-ticket-v2` signed the listener's endpoint id, its full address (relay URLs and direct addresses) and its identity (v1, which signed only the endpoint id and identity, was superseded by it); the signed ticket is itself now historical, replaced by the unsigned v3 ticket.
- **ADR-011 (accepted):** Transport addressing: `Transport::Addr` is transport-specific, and addresses are not identities.
- **ADR-012 (accepted):** Hybrid device certs v2 (`lattice-device-cert-v2`): bind the full device identity and carry a mandatory `not_after`. The cert itself has no revocation field; revocation is a separate root-signed list (ADR-013).
- **ADR-013 (accepted):** Device keys in `lattice-net`, revocation lists, compact v3 tickets and the listener hello.
  - *Device keys.* A store holds a root secret and a separate Hybrid device keypair with a root-signed `DeviceCert` (`device.age` or keyring account `device-mnemonic`, `device.cert`, `root.pub`). Handshakes are signed with the device key. Certificates last 30 days (`DEVICE_CERT_LIFETIME`) and are renewed automatically within 7 days of expiry while the root is in the store; otherwise `lattice-net` warns, and refuses to start once expired. The root can be removed with `forget-root` and restored with `import-root` (phrase on stdin). `load_or_create` never regenerates a forgotten root. Peers prove device → root → not-revoked over the wire, and users compare the peer's **root** fingerprint out of band.
  - *Revocation.* `lattice-revocation-v1`: `root ‖ u64le(seq) ‖ u64le(issued_at) ‖ sorted device PeerIds`, at most `MAX_REVOKED` (1024) entries, signed via `lattice-sig-v2`. A higher `seq` from the same root supersedes a lower one; an equal `seq` never replaces the first seen. Peers cache the highest-seq verified list per root (bounded to 256 roots) and check it on every fresh handshake and on resume. Propagation is lazy: the list rides in the hello or auth bundle of a non-revoked device of that root, and v3 tickets carry none, so a revoked device is accepted until the peer learns the list or the certificate expires. A higher-seq list can un-revoke a device; the root is the authority. Root compromise is total and there is no root rotation.
  - *Ticket v3.* `version=3, addr (postcard EndpointAddr), root_id[32], device_id[32]`, hex-encoded, unsigned, well under `COMPACT_TICKET_MAX_LEN` (1024 hex chars) for a realistic address, so it fits a QR code. Version 2 gives an "old ticket version" error.
  - *Listener hello and wire version.* The dialer's preamble starts with a wire-version byte (`WIRE_VERSION` = 2, distinct from the old 0/1 mode byte); an older dialer gets `[DECISION_VERSION, WIRE_VERSION]` and a version error. The listener then always sends a hello (`device identity ‖ root identity ‖ certificate ‖ optional list`) before its decision. The dialer checks the hello against the ticket's PeerIds, the chain and the revocation state before the handshake. After a fresh handshake each side sends its auth bundle sealed through the session. Resume exchanges no bundle: the auth recorded for the kept session is re-checked against expiry and the cache. Every step is inside the 15 s `NEGOTIATION_TIMEOUT`.
  - *Why an unsigned compact ticket is no weaker.* The ticket is an out-of-band bearer of PeerIds. An attacker who can edit it in transit could equally replace the PeerIds (and, under v2, the identity and the signature along with them), so the signature never authenticated the listener to someone who received the ticket from the wrong source; what matters is that the dialer compares the root fingerprint out of band and verifies the listener's hello and handshake against the ticket's PeerIds. Substituting the relay URL or direct addresses can only deny service, because TLS pins the endpoint id and the hello, handshake and certificate chain pin the device and root. The ticket remains a reachability bearer token.
  - *Costs accepted.* Lazy revocation; no identity hiding (hello and preamble identities are in the clear); the auth exchange costs a larger first message; old tickets and old peers stop working (breaking wire change, pre-1.0).
- **Not implemented (future):** proof-of-membership before relay assistance, peer-scoring hooks, capability-gated log writes (capabilities are not wired into logs; `MemLog` enforces only its single author), topic-based peer discovery, and always-on pinning peers.
- **Naming:** "Lattice" is a placeholder. Decide before first publish.

---

## 9. What this is *not* good for (honest boundary)

Lattice is a poor fit — and we should say so to anyone who picks it up — for: authoritative global state (marketplaces, ledgers, leaderboards), regulated records custody / chain-of-custody / retention (e.g. court systems), strong centralized moderation, server-side discovery across strangers, or heavy server-side compute. It shines for private direct communication and data-sharing between parties who already know each other, censorship-resistant distribution, and local-first collaboration.
