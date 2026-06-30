# Security Policy

> **Lattice is experimental and has not been security-audited.** It implements
> modern, standards-based cryptography — a post-quantum hybrid handshake
> (X25519 + ML-KEM-768) and signatures (Ed25519 + ML-DSA-65), a Double Ratchet,
> and BLAKE3-chained signed logs — but none of it has had external review. Do
> not use it to protect information whose disclosure would harm you.

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
post-quantum hybrid guarantees (secure if *either* the classical or PQ half
holds), forward secrecy / post-compromise security, identity authenticity, the
capability model, or the memory-safety invariant (`#![forbid(unsafe_code)]` in
every crate we author).

**Known non-goals** (documented limitations, not vulnerabilities): metadata
privacy (who-talks-to-whom is not hidden), strong Sybil resistance, reliable
redelivery of an in-flight message lost at a disconnect, and anything marked
"not yet" in the README. See the threat model in [`DESIGN.md`](./DESIGN.md) §6.

## Supported versions

Pre-release: only the latest `main` is supported. There are no published
releases yet, and the wire format may change without notice before v1.0.
