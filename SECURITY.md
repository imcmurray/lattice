# Security Policy

> **Lattice is experimental and has not been security-audited.** It implements
> modern, standards-based cryptography — a post-quantum hybrid handshake
> (X25519 + ML-KEM-768) and signatures (Ed25519 + ML-DSA-65), a Double Ratchet,
> and BLAKE3-chained signed logs — but none of it has had external review. Do
> not use it to protect information whose disclosure would harm you.

## Known limitations

- Lattice is experimental, and this patch is not an external audit.
- Both sides sign the v3 handshake transcript (`lattice-session-hs-v3`) with
  their identity signatures: Ed25519 and ML-DSA for a Hybrid identity (the
  default, and what `lattice-net` uses), Ed25519 only for a Classical
  identity. The transcript includes
  caller-supplied channel-binding bytes. `lattice-net` passes the dialer's and
  listener's iroh endpoint ids as that binding (`lattice-net-cb-v1`), so the
  handshake is bound to the specific iroh channel.
- Sessions have forward secrecy against later identity compromise: the
  handshake mixes fresh X25519 ephemerals from both sides, which are erased
  after the handshake. It also mixes ML-KEM only when the responder is Hybrid
  (the default suite, and what `lattice-net` uses). With a Classical responder
  the session is classical-only (X25519), with no post-quantum protection. A
  compromised long-term identity can still impersonate its owner in NEW
  sessions.
- The `lattice-net` listener limits each pre-chat step and the finishing of an
  inbound QUIC connection to 15 s, and bounds pending accepts and busy replies
  (8 each), dropping the excess. This is not Sybil or flood resistance: a
  sustained flood can keep those slots full and lock legitimate peers out for
  as long as it lasts.
- The `lattice-net` listen ticket (v3) is a compact, **unsigned** bearer token:
  the listener's iroh address plus its root and device PeerIds, small enough for
  a QR code. It grants reachability: anyone holding it can try to connect. It
  is no weaker than the old signed ticket (`lattice-ticket-v2`, historical and
  superseded): the ticket travels out of band, and an attacker who can edit it
  could equally replace the PeerIds, so a signature added nothing. Substituting
  the relay URL or direct addresses can only deny service, because TLS pins the
  iroh endpoint id and the listener's hello, handshake and certificate chain pin
  the device and root. The dialer checks the listener's hello (device and root
  PeerIds equal the ticket's, valid unexpired cert, not revoked) before the
  handshake, and that it reached the ticket's endpoint. Both the handshake
  transcripts and the resume proofs are bound to both endpoint ids
  (`lattice-net-cb-v1`, `lattice-resume-v2`). A v2 ticket, or a peer on the
  previous wire version, fails with a clear version error.
- `lattice-net` signs handshakes with a separate Hybrid **device** key, not the
  root identity. The root (recoverable from its mnemonic) only issues and
  renews device certificates (30-day lifetime, auto-renewed within 7 days of
  expiry while the root is in the store) and signs revocation lists; it can be removed from a store with
  `forget-root`. The root's own secret is still a single point of total
  compromise: there is no root rotation.
- Revocation lists (`lattice-revocation-v1`) are signed by the root, monotonic by
  `seq`, and capped at 1024 entries. Peers cache the highest-seq verified list
  per root and enforce it on fresh handshakes and on resume. **Propagation is
  lazy**: a peer learns a revocation only when it next talks to a non-revoked
  device of the same root, which sends the list in its hello or auth bundle. v3
  tickets carry no list. Until then a revoked device is accepted; the 30-day
  certificate lifetime bounds that window. A higher-seq list from the root can
  un-revoke a device; the root is the authority.
- Resuming a kept session in `lattice-net` requires a mutual HMAC proof bound to
  that session's secret and the channel binding (`lattice-resume-v2`). Anyone
  holding the current session state (for example a compromised device) can still
  resume.
- On first contact, compare the 60-digit **safety number** of the two root
  identities (printed on every connection; `lattice-net whoami` shows the root
  fingerprint) with your peer by voice or in person (trust on first use): the
  ticket itself is not authenticated. After comparing, run `lattice-net
  verify-peer` to record the peer's root in `known_peers`; later connections
  then say "verified peer", and every other one says "UNVERIFIED peer". The
  comparison is still manual: nothing enforces it, and `lattice-net` never
  verifies a peer automatically.
- Metadata (who talks to whom) is not hidden.
- There is no identity hiding: the dialer's device identity (in the
  `lattice-net` preamble) and the listener's device identity, root identity and
  certificate chain (in its hello) are sent in the clear. Only the auth bundles
  exchanged after the handshake are encrypted. The first byte of the preamble is
  a wire-version byte.
- Capabilities are single-hop signed grants, with no attenuation chain, expiry
  or revocation.
- Signatures are bound to the signer's full identity (crypto suite and PeerId,
  `lattice-sig-v2`), so a signature cannot move between the Classical and Hybrid
  identities derived from one mnemonic. This changes every signature: logs,
  caps and device certs signed earlier no longer verify (pre-1.0, no migration).
- Device certificates (`lattice-device-cert-v2`) now bind a device's full
  (hybrid) identity and carry a mandatory expiry (`not_after`). A Hybrid root
  cannot delegate to a Classical device. v1 device certs no longer verify
  (pre-1.0, no migration).
- Other applications built on `lattice-identity` get no revocation checking
  unless they call `DeviceCert::verify_with_revocation` with a list they have
  obtained; only `lattice-net` distributes and enforces lists (lazily, see
  above).
- Public identity and signature encodings are parsed strictly and canonically:
  trailing bytes, wrong-length or invalid keys, small-order Ed25519 keys, and
  low-order or non-canonical X25519 keys are rejected at parse time.
- The `lattice-net` listener keeps at most 64 sessions for resume
  (`MAX_KEPT_SESSIONS`) and evicts the least recently used. Outgoing QUIC
  connect and `open_bi` are each bounded by a 15 s `CONNECT_TIMEOUT`.
- `lattice-net` must not be used for real secrets.

## Reporting a vulnerability

Please report security issues **privately** — don't open a public issue or PR.

Use GitHub's private vulnerability reporting: on this repository, go to the
**Security** tab → **Report a vulnerability**. That opens a private advisory
visible only to the maintainer.

This is a personal research project, so responses are best-effort with no
guaranteed timeline. A useful report includes what you found, how to reproduce
it, and the impact you believe it has.

## Scope

**In scope** — anything that breaks a security property claimed in
[`DESIGN.md`](./DESIGN.md): message confidentiality or integrity, the
post-quantum hybrid guarantees for `Hybrid` identities (secure if *either*
the classical or PQ half holds; the `Classical` suite is classical-only by
design), forward secrecy / post-compromise security, identity authenticity, the
capability model, or the memory-safety invariant (`#![forbid(unsafe_code)]` in
every crate we author).

**Known non-goals** (documented limitations, not vulnerabilities): metadata
privacy (who-talks-to-whom is not hidden), strong Sybil resistance, reliable
redelivery of an in-flight message lost at a disconnect, and anything marked
"not yet" in the README. See the threat model in [`DESIGN.md`](./DESIGN.md) §6.

## Supported versions

Pre-release: only the latest `main` is supported. There are no published
releases yet, and the wire format may change without notice before v1.0.
