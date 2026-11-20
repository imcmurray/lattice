//! `lattice-net` — a real two-device P2P chat over Lattice.
//!
//! On device A:  `lattice-net listen`            → prints a TICKET
//! On device B:  `lattice-net connect <ticket>`  → dials A
//! Either side:  `lattice-net whoami`            → root + device ids, fingerprints, cert expiry
//!               `lattice-net show-recovery-phrase --i-understand`
//!               `lattice-net renew-device` / `revoke-device <id>`
//!               `lattice-net forget-root --i-understand` / `import-root`
//!               `lattice-net verify-peer <root peer id | root fingerprint>`
//!
//! **Safety numbers.** After every successful authentication (fresh or
//! resumed, on both sides) lattice-net prints one symmetric 60-digit safety
//! number derived from both *root* identities (`lattice_identity::safety_number`,
//! DESIGN.md §5.2) and says either "verified peer" or a prominent "UNVERIFIED
//! peer" line. Compare the number with your peer by voice or in person, then
//! run `verify-peer` to record that root in `<dir>/known_peers`. Verification
//! is never automatic: only `verify-peer` writes `known_peers`. Recently seen
//! roots are cached in `seen_peers` so a 40-hex fingerprint can be resolved.
//! A peer with our own root counts as verified. If `known_peers` is corrupt,
//! every peer is shown as unverified and the file is left alone.
//!
//! The listener keeps at most `MAX_KEPT_SESSIONS` (64) sessions for resume,
//! evicting the least recently used. Outgoing QUIC connect and open_bi are
//! bounded by `CONNECT_TIMEOUT` (15 s) in the transport; a timeout goes
//! through the normal retry/backoff path.
//!
//! **Device keys (ADR-013).** The root identity (recoverable from its mnemonic)
//! is *not* the everyday key. Each store holds a separate Hybrid **device**
//! keypair and a root-signed `DeviceCert` (30-day lifetime, auto-renewed within
//! 7 days of expiry while the root is in the store). Handshakes are signed with
//! the device key. The root is only needed to issue/renew certs and revocation
//! lists, and can be removed from the store with `forget-root` (restore it with
//! `import-root`, which reads the phrase from stdin). Peers prove
//! device → root → (not revoked) on the wire, and users compare the peer's
//! **root** fingerprint out of band.
//!
//! **Revocation.** The root signs `lattice-revocation-v1` lists
//! (`revoke-device`), monotonic by `seq`. Peers cache the highest-seq verified
//! list per root and enforce it on fresh handshakes *and on resume*. Propagation
//! is lazy: a peer learns a list only when it next talks to a non-revoked
//! device of that root (which sends it in its auth bundle / listener hello).
//!
//! **Ticket v3** is compact and unsigned: the iroh address plus the listener's
//! root and device PeerIds (small enough for a QR code). It is an out-of-band
//! bearer of those ids; its security comes from the listener's *hello*
//! (device identity + cert chain, sent before the handshake) being verified
//! against the ticket's ids, then the handshake and an auth-bundle exchange.
//! Both the handshake transcript and the resume proofs are bound to the
//! dialer's and listener's iroh endpoint ids (`lattice-net-cb-v1`). The ticket
//! still grants reachability. A v2 ticket, or a peer on the previous wire
//! version, fails with a clear version error (the dialer's first byte is the
//! wire version).
//!
//! Reconnects use **session resumption** (ADR-006): on a drop, each side keeps
//! its `SecureSession` and the verified peer auth; the dialer's reconnect
//! preamble signals `resume`, and if the listener still holds that peer's
//! session — and the peer's cert is unexpired and not revoked by a cached list —
//! both sides exchange HMAC proofs keyed by the session's secret and the
//! channel binding (`lattice-resume-v2`) and rebind with no re-handshake.
//! Otherwise they fall back to a fresh handshake plus auth exchange.
//!
//! Every pre-chat step (preamble, hello, resume challenge/response, handshake,
//! auth exchange) is limited to 15 s on both sides, so one slow or silent peer
//! cannot stall the listener. Finishing an inbound QUIC connection (handshake
//! plus the first stream) is limited to 15 s too. A separate acceptor task only
//! takes incoming connections and keeps accepting while a chat runs; each one
//! finishes in its own task, with at most 8 pending accepts at a time. Any
//! connection that arrives while a chat (or negotiation) is in progress gets a
//! one-byte "busy" reply and is dropped, with at most 8 busy replies at a
//! time. Excess connections beyond either limit are dropped immediately. A
//! dialer treats a busy reply as a failed attempt and retries with backoff.
//! Identity hiding is absent: the listener's identities and the dialer's device
//! identity are sent in the clear (the auth bundles are encrypted).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lattice::identity::safety_number;
use lattice::identity::storage::{IdentityStore, StorageBackend};
use lattice::prelude::*;
use lattice::session::{resume_nonce, ResumeRole};
use lattice::transport::{
    encode_ticket, parse_ticket, read_frame, write_frame, IrohConn, IrohTransport,
};
use tokio::io::{AsyncBufReadExt, BufReader, Lines, Stdin};
use tokio::sync::{Mutex, Notify};

/// First byte of the dialer's preamble. Must differ from the old preamble's
/// first byte (`MODE_FRESH`/`MODE_RESUME`, 0/1) so an old dialer is recognised.
const WIRE_VERSION: u8 = 2;
// Connection preamble: the dialer's first frame is
// [WIRE_VERSION] ++ [mode] ++ dialer_nonce[32] ++ its device identity
// (nonce is zero for fresh).
const MODE_FRESH: u8 = 0;
const MODE_RESUME: u8 = 1;
// The listener replies with a hello frame (LISTENER_HELLO), then a decision:
// fresh handshake, or a resume challenge
// [DECISION_CHALLENGE] ++ listener_nonce[32] ++ listener_tag[32]; the dialer then
// answers with its own 32-byte tag (see `ResumeRole`). Resuming needs both proofs.
const DECISION_FRESH: u8 = 0;
// Legacy unauthenticated resume: no longer sent; a dialer receiving it errors.
const DECISION_RESUMED: u8 = 1;
const DECISION_CHALLENGE: u8 = 2;
/// Listener reply to a connection that arrives while a chat is in progress.
const DECISION_BUSY: u8 = 3;
/// Listener reply `[DECISION_VERSION, WIRE_VERSION]` to an old/unknown preamble.
const DECISION_VERSION: u8 = 4;
/// Tag byte of the listener hello frame.
const LISTENER_HELLO: u8 = 5;
/// How long a freshly issued device certificate is valid.
const DEVICE_CERT_LIFETIME: Duration = Duration::from_secs(30 * 24 * 3600);
/// Renew (or warn) when the certificate has at most this long left.
const DEVICE_RENEW_WINDOW: Duration = Duration::from_secs(7 * 24 * 3600);
/// Max accepted dialer preamble (bytes); checked before parsing.
const MAX_PREAMBLE_LEN: usize = 8 * 1024;
/// Max accepted listener hello (bytes); checked before parsing.
const MAX_LISTENER_HELLO_LEN: usize = 60 * 1024;
/// Max accepted auth bundle (bytes); checked before parsing.
const MAX_AUTH_BUNDLE_LEN: usize = 60 * 1024;
/// Bound on the in-memory revocation cache (== `storage::MAX_PEER_REVOCATIONS`).
const MAX_CACHED_ROOTS: usize = 256;
/// Marker in wire-version errors; the dialer does not retry these.
const VERSION_ERR_MARK: &str = "wire version";
/// Upper bound on every pre-chat step (preamble, hello, resume
/// challenge/response, handshake, auth exchange) on both the listener and the dialer.
const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(15);
/// Max concurrent busy-reply tasks; over the limit a connection is dropped without spawning.
const MAX_BUSY_REPLIES: usize = 8;
/// Max concurrent pending accepts (QUIC handshake + accept_bi); over the limit an incoming is dropped.
const MAX_PENDING_ACCEPTS: usize = 8;
const NONCE_LEN: usize = 32;
const TAG_LEN: usize = 32;
/// Domain separator of the channel binding passed to the handshake and resume.
const CB_DOMAIN: &[u8] = b"lattice-net-cb-v1";

const USAGE: &str = "usage:
  lattice-net listen
  lattice-net connect <ticket>
  lattice-net whoami
  lattice-net show-recovery-phrase --i-understand
  lattice-net renew-device
  lattice-net revoke-device <64-hex device peer id>
  lattice-net forget-root --i-understand
  lattice-net import-root        (the recovery phrase is read from stdin)
  lattice-net verify-peer <64-hex root peer id | 40-hex root fingerprint>";

const RECOVERY_REFUSAL: &str = "the recovery phrase is the root secret of your identity:
anyone who has it can impersonate you. If you really want it printed, rerun with
`lattice-net show-recovery-phrase --i-understand`";

const RECOVERY_WARNING: &str = "[lattice-net] ⚠ this recovery phrase controls your identity.
Keep it secret and store it offline: anyone who has it can impersonate you.";

const FORGET_REFUSAL: &str = "forget-root removes the root secret from this store; make sure you
have the recovery phrase backed up first. Rerun with `lattice-net forget-root --i-understand`";

const NO_ROOT_HELP: &str =
    "the root is not in this store; restore it with `lattice-net import-root` \
     (the recovery phrase is read from stdin)";

type StdinLines = Lines<BufReader<Stdin>>;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("[lattice-net] error: {e}");
        std::process::exit(1);
    }
}

/// What ended a chat session — tells the reconnect loop what to do next.
enum Outcome {
    /// The peer's connection dropped — reconnect.
    PeerDisconnected,
    /// Local stdin closed (EOF / Ctrl-D) — exit.
    LocalClosed,
}

/// A parsed command line.
#[derive(Debug, PartialEq)]
enum Command {
    Listen,
    Connect(String),
    Whoami,
    ShowRecoveryPhrase,
    RenewDevice,
    RevokeDevice(PeerId),
    ForgetRoot,
    ImportRoot,
    VerifyPeer(VerifyTarget),
    Usage,
}

/// What `verify-peer` was given.
#[derive(Debug, PartialEq)]
enum VerifyTarget {
    /// A full 64-hex root peer id.
    Full(PeerId),
    /// A 40-hex root fingerprint (first 20 bytes of the root peer id).
    Fingerprint([u8; 20]),
}

/// Decode hex of either case; `None` on odd length or a non-hex character.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    b.chunks(2)
        .map(|p| {
            let hi = (p[0] as char).to_digit(16)?;
            let lo = (p[1] as char).to_digit(16)?;
            Some((hi * 16 + lo) as u8)
        })
        .collect()
}

/// Concatenate `parts` (so an unquoted, space-separated fingerprint works),
/// remove ASCII spaces, then: 64 hex chars → `Full`, 40 hex chars →
/// `Fingerprint`, anything else (empty, other lengths, non-hex) → `Err`.
fn parse_verify_target(parts: &[String]) -> Result<VerifyTarget> {
    let joined: String = parts.concat().chars().filter(|c| *c != ' ').collect();
    let bad = || {
        Error::Other(
            "usage: lattice-net verify-peer <64-hex root peer id | 40-hex root fingerprint>".into(),
        )
    };
    let bytes = decode_hex(&joined).ok_or_else(bad)?;
    match bytes.len() {
        32 => {
            let mut id = [0u8; 32];
            id.copy_from_slice(&bytes);
            Ok(VerifyTarget::Full(PeerId(id)))
        }
        20 => {
            let mut fp = [0u8; 20];
            fp.copy_from_slice(&bytes);
            Ok(VerifyTarget::Fingerprint(fp))
        }
        _ => Err(bad()),
    }
}

/// Resolve against candidate roots (`seen_peers`): exactly one whose first 20
/// bytes match → `Ok(id)`; none or several → `Err`. `Full(id)` → `Ok(id)`
/// without consulting the candidates.
fn resolve_verify_target(t: &VerifyTarget, candidates: &[PeerId]) -> Result<PeerId> {
    match t {
        VerifyTarget::Full(id) => Ok(id.clone()),
        VerifyTarget::Fingerprint(fp) => {
            let mut hits = candidates.iter().filter(|c| c.0[..20] == fp[..]);
            match (hits.next(), hits.next()) {
                (Some(id), None) => Ok(id.clone()),
                (None, _) => Err(Error::Other(
                    "no recently seen peer has that fingerprint: connect to the peer first, or \
                     pass the full 64-hex root peer id (the peer's `whoami` shows it)"
                        .into(),
                )),
                (Some(_), Some(_)) => Err(Error::Other(
                    "that fingerprint is ambiguous among recently seen peers: pass the full \
                     64-hex root peer id"
                        .into(),
                )),
            }
        }
    }
}

/// Pure: the lines printed after a successful auth (fresh or resumed).
fn trust_lines(
    own_root: &PublicIdentity,
    peer_root: &PublicIdentity,
    verified: bool,
) -> Vec<String> {
    let sn = safety_number(own_root, peer_root);
    let peer_id = peer_root.peer_id();
    let mut out = vec![
        format!(
            "[lattice-net] safety number: {sn} — compare this number with your peer by voice or in person"
        ),
        format!(
            "[lattice-net] safety number (single line): {}",
            sn.replace(' ', "")
        ),
    ];
    if verified {
        out.push(format!(
            "[lattice-net] verified peer (root {})",
            peer_id.fingerprint()
        ));
    } else {
        out.push(format!(
            "[lattice-net] ⚠ UNVERIFIED peer — compare the safety number, then run: lattice-net verify-peer {peer_id}"
        ));
    }
    out
}

/// Load known_peers (on Err: warn and treat as unverified), compute
/// verified = known.contains(peer) || peer == own root, record the peer as
/// seen (warn on Err), and print `trust_lines` to stderr. Never verifies anyone.
fn report_peer_trust(store: &IdentityStore, own_root: &PublicIdentity, peer_root: &PublicIdentity) {
    let peer_id = peer_root.peer_id();
    let known = match store.load_known_peers() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[lattice-net] warning: cannot read known_peers ({e}) — treating peers as unverified");
            Vec::new()
        }
    };
    let verified = known.contains(&peer_id) || peer_id == own_root.peer_id();
    if let Err(e) = store.note_seen_peer(&peer_id) {
        eprintln!("[lattice-net] warning: cannot record seen peer: {e}");
    }
    for line in trust_lines(own_root, peer_root, verified) {
        eprintln!("{line}");
    }
}

/// `verify-peer`: mark a root as verified. Touches only `known_peers` (and
/// reads `seen_peers` for the fingerprint form); loads no identity.
fn verify_peer_cmd(target: &VerifyTarget) -> Result<()> {
    let store = IdentityStore::open_default();
    let candidates = match target {
        VerifyTarget::Fingerprint(_) => store.load_seen_peers()?,
        VerifyTarget::Full(_) => Vec::new(),
    };
    let id = resolve_verify_target(target, &candidates)?;
    let added = store.add_known_peer(&id)?;
    println!(
        "{}",
        if added {
            format!("marked root {} ({id}) as verified", id.fingerprint())
        } else {
            format!("root {} ({id}) was already verified", id.fingerprint())
        }
    );
    Ok(())
}

/// Max sessions the listener keeps for resume; least recently used are evicted.
const MAX_KEPT_SESSIONS: usize = 64;

/// Bounded map PeerId -> V with least-recently-used eviction. "Use" = insert
/// (a resumed or fresh session is removed and re-inserted after its chat).
struct KeptSessions<V = KeptPeer> {
    map: HashMap<PeerId, (u64, V)>,
    tick: u64,
    cap: usize,
}

#[cfg_attr(not(test), allow(dead_code))]
impl<V> KeptSessions<V> {
    fn new() -> Self {
        Self::with_cap(MAX_KEPT_SESSIONS)
    }

    fn with_cap(cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            tick: 0,
            cap: cap.max(1),
        }
    }

    /// Does not refresh the tick: resume removes the entry anyway.
    fn get(&self, id: &PeerId) -> Option<&V> {
        self.map.get(id).map(|(_, v)| v)
    }

    fn remove(&mut self, id: &PeerId) -> Option<V> {
        self.map.remove(id).map(|(_, v)| v)
    }

    fn contains_key(&self, id: &PeerId) -> bool {
        self.map.contains_key(id)
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Insert/replace with a fresh tick; then evict the min-tick entry while
    /// len > cap. Returns the evicted ids (never `id` itself).
    fn insert(&mut self, id: PeerId, v: V) -> Vec<PeerId> {
        self.tick += 1;
        self.map.insert(id.clone(), (self.tick, v));
        let mut evicted = Vec::new();
        while self.map.len() > self.cap {
            let oldest = self
                .map
                .iter()
                .filter(|(k, _)| **k != id)
                .min_by_key(|(_, (t, _))| *t)
                .map(|(k, _)| k.clone());
            match oldest {
                Some(k) => {
                    self.map.remove(&k);
                    evicted.push(k);
                }
                None => break,
            }
        }
        evicted
    }
}

impl<V, const N: usize> From<[(PeerId, V); N]> for KeptSessions<V> {
    /// Inserts in array order.
    fn from(items: [(PeerId, V); N]) -> Self {
        let mut s = Self::new();
        for (id, v) in items {
            s.insert(id, v);
        }
        s
    }
}

/// Parse 64 hex characters (either case) into a PeerId.
fn parse_peer_hex(s: &str) -> Result<PeerId> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return Err(Error::Other("a device peer id is 64 hex characters".into()));
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        let hi = (b[2 * i] as char).to_digit(16);
        let lo = (b[2 * i + 1] as char).to_digit(16);
        match (hi, lo) {
            (Some(h), Some(l)) => *o = (h * 16 + l) as u8,
            _ => return Err(Error::Other("a device peer id is hex only".into())),
        }
    }
    Ok(PeerId(out))
}

/// Parse the full argv (`args[0]` is the program name). Runs before any
/// identity is loaded.
fn parse_command(args: &[String]) -> Result<Command> {
    match args.get(1).map(String::as_str) {
        Some("listen") => Ok(Command::Listen),
        Some("connect") => {
            let ticket = args
                .get(2)
                .ok_or_else(|| Error::Other("usage: lattice-net connect <ticket>".into()))?;
            Ok(Command::Connect(ticket.clone()))
        }
        Some("whoami") => Ok(Command::Whoami),
        Some("show-recovery-phrase") => {
            if args.len() == 3 && args[2] == "--i-understand" {
                Ok(Command::ShowRecoveryPhrase)
            } else {
                Err(Error::Other(RECOVERY_REFUSAL.into()))
            }
        }
        Some("renew-device") => {
            if args.len() == 2 {
                Ok(Command::RenewDevice)
            } else {
                Err(Error::Other("usage: lattice-net renew-device".into()))
            }
        }
        Some("revoke-device") => {
            if args.len() != 3 {
                return Err(Error::Other(
                    "usage: lattice-net revoke-device <64-hex device peer id>".into(),
                ));
            }
            Ok(Command::RevokeDevice(parse_peer_hex(&args[2])?))
        }
        Some("forget-root") => {
            if args.len() == 3 && args[2] == "--i-understand" {
                Ok(Command::ForgetRoot)
            } else {
                Err(Error::Other(FORGET_REFUSAL.into()))
            }
        }
        Some("import-root") => {
            if args.len() == 2 {
                Ok(Command::ImportRoot)
            } else {
                Err(Error::Other(
                    "the phrase is read from stdin, never from the command line".into(),
                ))
            }
        }
        Some("verify-peer") => Ok(Command::VerifyPeer(parse_verify_target(&args[2..])?)),
        _ => Ok(Command::Usage),
    }
}

// ---------------------------------------------------------------------------
// Time helpers.
// ---------------------------------------------------------------------------

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Pure: `YYYY-MM-DD` (UTC) for Unix seconds. No dependencies.
fn format_date(secs: u64) -> String {
    let z = secs / 86_400 + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum CertStatus {
    /// More than the renew window left.
    Valid,
    /// Still valid, but within the renew window.
    RenewSoon,
    /// `now > not_after`.
    Expired,
}

/// Pure expiry policy. `now == not_after` is still valid (`RenewSoon`).
fn cert_status(now: u64, not_after: u64, window: u64) -> CertStatus {
    if now > not_after {
        CertStatus::Expired
    } else if not_after - now <= window {
        CertStatus::RenewSoon
    } else {
        CertStatus::Valid
    }
}

// ---------------------------------------------------------------------------
// Credentials, revocation cache, auth bundle.
// ---------------------------------------------------------------------------

/// Our credentials for this run.
struct DeviceCreds {
    device: Keypair,
    root: PublicIdentity,
    cert: DeviceCert,
    /// Our own root's highest-seq list, if any.
    revocation: Option<RevocationList>,
}

/// Parsed peer auth bundle (nothing verified yet).
struct AuthBundle {
    root: PublicIdentity,
    cert: DeviceCert,
    revocation: Option<RevocationList>,
}

/// What we verified about a peer.
#[derive(Clone, Debug)]
struct PeerAuth {
    root: PublicIdentity,
    device: PublicIdentity,
    cert_not_after: u64,
}

/// A kept session for resume (listener: map value keyed by device PeerId;
/// dialer: `Option`).
struct KeptPeer {
    session: SecureSession,
    auth: PeerAuth,
}

/// Bounded per-root cache of the highest-seq verified revocation list.
struct RevocationCache {
    lists: HashMap<PeerId, RevocationList>,
    /// Roots whose entry changed since the last `take_dirty` (to persist).
    dirty: Vec<PeerId>,
}

impl RevocationCache {
    fn new() -> Self {
        Self {
            lists: HashMap::new(),
            dirty: Vec::new(),
        }
    }

    fn get(&self, root: &PeerId) -> Option<&RevocationList> {
        self.lists.get(root)
    }

    /// Store if no list for that root yet (and below `MAX_CACHED_ROOTS`) or if
    /// `list` supersedes the cached one. Returns true iff stored. The caller
    /// must only pass lists already verified under their root.
    fn observe(&mut self, list: RevocationList) -> bool {
        let root = list.root().clone();
        let store = match self.lists.get(&root) {
            Some(cached) => list.supersedes(cached),
            None => self.lists.len() < MAX_CACHED_ROOTS,
        };
        if store {
            self.lists.insert(root.clone(), list);
            if !self.dirty.contains(&root) {
                self.dirty.push(root);
            }
        }
        store
    }

    fn revokes(&self, root: &PeerId, device: &PeerId) -> bool {
        self.lists.get(root).is_some_and(|l| l.is_revoked(device))
    }

    fn take_dirty(&mut self) -> Vec<PeerId> {
        std::mem::take(&mut self.dirty)
    }
}

fn push_lp32(v: &mut Vec<u8>, x: &[u8]) {
    v.extend_from_slice(&(x.len() as u32).to_le_bytes());
    v.extend_from_slice(x);
}

/// Split one `u32le`-length-prefixed field off `rest`, bounds-checked.
fn take_lp32<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8]> {
    let all: &'a [u8] = rest;
    if all.len() < 4 {
        return Err(Error::Verify("truncated length prefix".into()));
    }
    let n = u32::from_le_bytes([all[0], all[1], all[2], all[3]]) as usize;
    let body = &all[4..];
    if n > body.len() {
        return Err(Error::Verify("length prefix exceeds input".into()));
    }
    let (head, tail) = body.split_at(n);
    *rest = tail;
    Ok(head)
}

fn vctx(what: &'static str) -> impl Fn(Error) -> Error {
    move |e| Error::Verify(format!("{what}: {e}"))
}

/// bundle = lp32(root identity) ‖ lp32(cert) ‖ lp32(revocation list | empty)
fn encode_auth_bundle(me: &DeviceCreds) -> Vec<u8> {
    let mut v = Vec::new();
    push_lp32(&mut v, &me.root.to_bytes());
    push_lp32(&mut v, &me.cert.to_bytes());
    match &me.revocation {
        Some(l) => push_lp32(&mut v, &l.to_bytes()),
        None => push_lp32(&mut v, &[]),
    }
    v
}

/// Length cap first, strict, no trailing bytes.
fn decode_auth_bundle(b: &[u8]) -> Result<AuthBundle> {
    if b.len() > MAX_AUTH_BUNDLE_LEN {
        return Err(Error::Verify(format!(
            "auth bundle too large: {} > {MAX_AUTH_BUNDLE_LEN}",
            b.len()
        )));
    }
    let mut rest = b;
    let root = PublicIdentity::from_bytes(take_lp32(&mut rest)?).map_err(vctx("bundle root"))?;
    let cert = DeviceCert::from_bytes(take_lp32(&mut rest)?).map_err(vctx("bundle cert"))?;
    let rev = take_lp32(&mut rest)?;
    let revocation = if rev.is_empty() {
        None
    } else {
        Some(RevocationList::from_bytes(rev).map_err(vctx("bundle revocation list"))?)
    };
    if !rest.is_empty() {
        return Err(Error::Verify("trailing bytes after auth bundle".into()));
    }
    Ok(AuthBundle {
        root,
        cert,
        revocation,
    })
}

/// Verify a peer's device → root → (not revoked) chain. On success the sent
/// list is observed into `cache`.
fn verify_peer_chain(
    b: &AuthBundle,
    peer_device: &PublicIdentity,
    now: u64,
    cache: &mut RevocationCache,
) -> Result<PeerAuth> {
    let device_id = peer_device.peer_id();
    let root_id = b.root.peer_id();
    if b.cert.device().peer_id() != device_id {
        return Err(Error::Verify(
            "peer chain: certificate is for a different device than the session peer".into(),
        ));
    }
    if !b.cert.verify(&b.root, now) {
        return Err(Error::Verify(
            "peer chain: certificate is invalid, expired, or not issued by the stated root".into(),
        ));
    }
    if let Some(l) = &b.revocation {
        if *l.root() != root_id {
            return Err(Error::Verify(
                "peer chain: revocation list is for a different root".into(),
            ));
        }
        if !l.verify(&b.root) {
            return Err(Error::Verify(
                "peer chain: revocation list signature is invalid".into(),
            ));
        }
        if l.is_revoked(&device_id) {
            return Err(Error::Verify(
                "peer chain: device is revoked by the root's list".into(),
            ));
        }
    }
    if cache.revokes(&root_id, &device_id) {
        return Err(Error::Verify(
            "peer chain: device is revoked by a cached list for its root".into(),
        ));
    }
    if let Some(l) = &b.revocation {
        cache.observe(l.clone());
    }
    Ok(PeerAuth {
        root: b.root.clone(),
        device: peer_device.clone(),
        cert_not_after: b.cert.not_after(),
    })
}

/// hello = [LISTENER_HELLO] ‖ lp32(device identity) ‖ auth bundle
fn encode_listener_hello(me: &DeviceCreds) -> Vec<u8> {
    let mut v = vec![LISTENER_HELLO];
    push_lp32(&mut v, &me.device.public().to_bytes());
    v.extend_from_slice(&encode_auth_bundle(me));
    v
}

/// Parse a listener hello, check its device/root PeerIds against the ticket,
/// then verify the chain.
fn verify_listener_hello(
    frame: &[u8],
    ticket_root: &[u8; 32],
    ticket_device: &[u8; 32],
    now: u64,
    cache: &mut RevocationCache,
) -> Result<PeerAuth> {
    if frame.len() > MAX_LISTENER_HELLO_LEN {
        return Err(Error::Verify(format!(
            "listener hello too large: {} > {MAX_LISTENER_HELLO_LEN}",
            frame.len()
        )));
    }
    if frame.first() != Some(&LISTENER_HELLO) {
        return Err(Error::Verify("not a listener hello".into()));
    }
    let mut rest = &frame[1..];
    let device = PublicIdentity::from_bytes(take_lp32(&mut rest)?).map_err(vctx("hello device"))?;
    let bundle = decode_auth_bundle(rest)?;
    if device.peer_id().0 != *ticket_device {
        return Err(Error::Verify(
            "listener's device is not the one named by the ticket".into(),
        ));
    }
    if bundle.root.peer_id().0 != *ticket_root {
        return Err(Error::Verify(
            "listener's root is not the one named by the ticket".into(),
        ));
    }
    verify_peer_chain(&bundle, &device, now, cache)
}

/// True iff the peer's cert is unexpired and the cache does not revoke it.
fn resume_allowed(auth: &PeerAuth, now: u64, cache: &RevocationCache) -> bool {
    now <= auth.cert_not_after && !cache.revokes(&auth.root.peer_id(), &auth.device.peer_id())
}

/// `CB_DOMAIN ‖ dialer_endpoint_id ‖ listener_endpoint_id` (81 bytes): binds a
/// session to the exact iroh endpoints of the connection that carries it.
fn channel_binding(dialer_ep: &[u8; 32], listener_ep: &[u8; 32]) -> Vec<u8> {
    let mut b = Vec::with_capacity(CB_DOMAIN.len() + 64);
    b.extend_from_slice(CB_DOMAIN);
    b.extend_from_slice(dialer_ep);
    b.extend_from_slice(listener_ep);
    b
}

/// Fail unless the connection reached the endpoint we expected.
fn check_endpoint(expected: &[u8; 32], remote: &[u8; 32]) -> Result<()> {
    if expected != remote {
        return Err(Error::Verify("endpoint id mismatch".into()));
    }
    Ok(())
}

/// Print the peer's root fingerprint (the out-of-band comparison value), then
/// its device fingerprint and certificate expiry.
fn announce_peer(peer: &PeerAuth, what: &str) {
    eprintln!("[lattice-net] {what} — type messages:");
    eprintln!(
        "[lattice-net] peer root fingerprint: {} — compare this with your peer out of band",
        peer.root.peer_id().fingerprint()
    );
    eprintln!(
        "[lattice-net] peer device {}, certificate valid until {}",
        peer.device.peer_id().fingerprint(),
        format_date(peer.cert_not_after)
    );
}

// ---------------------------------------------------------------------------
// Startup: device provisioning, renewal, revocation cache.
// ---------------------------------------------------------------------------

/// Load (or provision) our device credentials and the revocation cache.
fn startup(
    store: &IdentityStore,
    now: u64,
) -> Result<(DeviceCreds, RevocationCache, StorageBackend)> {
    let loaded = match store.load_device(CryptoSuite::Hybrid)? {
        Some(d) => d,
        None => {
            let root_pub = store.root_public()?;
            if root_pub.is_some() && !store.has_root()? {
                return Err(Error::Other(format!(
                    "no device key in this store and {NO_ROOT_HELP}"
                )));
            }
            let root = store.load_or_create(CryptoSuite::Hybrid)?;
            if root.created {
                eprintln!("[lattice-net] new root identity created");
            }
            if root.migrated {
                eprintln!(
                    "[lattice-net] ⚠ migrated your legacy plaintext identity into secure storage ({:?}); \
                     the legacy plaintext file was removed.",
                    root.backend
                );
            }
            let not_after = now + DEVICE_CERT_LIFETIME.as_secs();
            let d = store.provision_device(&root.keypair, CryptoSuite::Hybrid, not_after)?;
            eprintln!(
                "[lattice-net] device key created; certificate valid until {}",
                format_date(not_after)
            );
            d
        }
    };

    let root_id = loaded.root.peer_id();
    let mut cache = RevocationCache::new();
    if let Some(own) = store.load_revocation()? {
        if own.verify(&loaded.root) {
            cache.observe(own);
        } else {
            eprintln!(
                "[lattice-net] warning: ignoring revocation.bin (does not verify under this root)"
            );
        }
    }
    for l in store.load_peer_revocations()? {
        cache.observe(l);
    }
    let _ = cache.take_dirty(); // everything observed here came from disk
    let revocation = cache.get(&root_id).cloned();
    let creds = DeviceCreds {
        device: loaded.keypair,
        root: loaded.root,
        cert: loaded.cert,
        revocation,
    };
    Ok((creds, cache, loaded.backend))
}

/// Re-issue the cert for the same device key, valid for `DEVICE_CERT_LIFETIME`.
fn renew_cert(
    store: &IdentityStore,
    device: &Keypair,
    root: &Keypair,
    now: u64,
) -> Result<DeviceCert> {
    let cert = root.authorize_device(device.public(), now + DEVICE_CERT_LIFETIME.as_secs())?;
    store.store_device(device, &cert, root.public())?;
    Ok(cert)
}

/// Expiry policy for `listen`/`connect`: renew automatically while the root is
/// in the store; otherwise warn (renew soon) or refuse (expired).
fn maintain_cert(store: &IdentityStore, creds: &mut DeviceCreds, now: u64) -> Result<()> {
    let not_after = creds.cert.not_after();
    let status = cert_status(now, not_after, DEVICE_RENEW_WINDOW.as_secs());
    if status == CertStatus::Valid {
        return Ok(());
    }
    if store.has_root()? {
        let root = store
            .load_root(CryptoSuite::Hybrid)?
            .ok_or_else(|| Error::Other(NO_ROOT_HELP.into()))?;
        creds.cert = renew_cert(store, &creds.device, &root.keypair, now)?;
        eprintln!(
            "[lattice-net] device certificate renewed until {}",
            format_date(creds.cert.not_after())
        );
        return Ok(());
    }
    let date = format_date(not_after);
    match status {
        CertStatus::Expired => Err(Error::Other(format!(
            "the device certificate expired on {date} and the root is not in this store: \
             run `lattice-net import-root`, then `lattice-net renew-device`"
        ))),
        _ => {
            eprintln!(
                "[lattice-net] ⚠ the device certificate expires on {date}; to renew it run \
                 `lattice-net import-root`, then `lattice-net renew-device`"
            );
            Ok(())
        }
    }
}

/// Write cache entries that changed during negotiation. Failures are warnings.
fn persist_cache(store: &IdentityStore, cache: &mut RevocationCache) {
    for root in cache.take_dirty() {
        if let Some(l) = cache.get(&root) {
            if let Err(e) = store.store_peer_revocation(l) {
                eprintln!("[lattice-net] warning: could not persist a revocation list: {e}");
            }
        }
    }
}

async fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    // Parse first: bad usage must not touch (or create) any identity.
    let cmd = parse_command(&args)?;
    let now = now_secs();
    match cmd {
        Command::Usage => {
            eprintln!("{USAGE}");
            return Ok(());
        }
        Command::ImportRoot => return import_root_cmd(now),
        Command::VerifyPeer(target) => return verify_peer_cmd(&target),
        _ => {}
    }

    let store = IdentityStore::open_default();
    let (mut creds, cache, backend) = startup(&store, now)?;

    match cmd {
        Command::Whoami => {
            let in_store = store.has_root()?;
            println!("root peer id: {}", creds.root.peer_id());
            println!("root fingerprint: {}", creds.root.peer_id().fingerprint());
            println!("device peer id: {}", creds.device.peer_id());
            println!(
                "device fingerprint: {}",
                creds.device.peer_id().fingerprint()
            );
            println!(
                "device cert expires: {}",
                format_date(creds.cert.not_after())
            );
            println!(
                "root in this store: {}",
                if in_store { "yes" } else { "no" }
            );
            Ok(())
        }
        Command::ShowRecoveryPhrase => {
            let root = store
                .load_root(CryptoSuite::Hybrid)?
                .ok_or_else(|| Error::Other(NO_ROOT_HELP.into()))?;
            eprintln!("{RECOVERY_WARNING}");
            println!("{}", root.keypair.mnemonic());
            Ok(())
        }
        Command::RenewDevice => {
            let root = store
                .load_root(CryptoSuite::Hybrid)?
                .ok_or_else(|| Error::Other(NO_ROOT_HELP.into()))?;
            creds.cert = renew_cert(&store, &creds.device, &root.keypair, now)?;
            println!(
                "device certificate renewed until {}",
                format_date(creds.cert.not_after())
            );
            Ok(())
        }
        Command::RevokeDevice(id) => {
            let root = store
                .load_root(CryptoSuite::Hybrid)?
                .ok_or_else(|| Error::Other(NO_ROOT_HELP.into()))?;
            if id == creds.device.peer_id() {
                return Err(Error::Other(
                    "refusing to revoke this store's own current device".into(),
                ));
            }
            let root_id = root.keypair.peer_id();
            // Build on the highest-seq list known for this root (our own file or one
            // learned from a peer, possibly issued by another device of this root),
            // so the new seq supersedes it and no earlier revocation is dropped.
            let old = creds
                .revocation
                .clone()
                .filter(|l| *l.root() == root_id && l.verify(root.keypair.public()));
            let mut set: Vec<PeerId> = old
                .as_ref()
                .map(|l| l.revoked().to_vec())
                .unwrap_or_default();
            set.push(id);
            let seq = old.as_ref().map_or(1, |l| l.seq() + 1);
            let list = root.keypair.revoke_devices(seq, now, &set)?;
            store.store_revocation(&list)?;
            println!(
                "revocation list seq {seq} written ({} device(s) revoked). Peers learn it only \
                 when they next talk to a non-revoked device of this root.",
                list.revoked().len()
            );
            Ok(())
        }
        Command::ForgetRoot => {
            eprintln!("{RECOVERY_WARNING}");
            store.forget_root()?;
            println!(
                "root removed from this store; the device key remains. Restore the root with \
                 `lattice-net import-root`."
            );
            Ok(())
        }
        Command::Listen | Command::Connect(_) => {
            maintain_cert(&store, &mut creds, now)?;
            eprintln!(
                "[lattice-net] your root fingerprint: {} — device {}, certificate valid until {} [stored via {backend:?}]",
                creds.root.peer_id().fingerprint(),
                creds.device.peer_id().fingerprint(),
                format_date(creds.cert.not_after()),
            );
            // Read stdin once and reuse it across reconnects (typed input isn't lost).
            let lines = BufReader::new(tokio::io::stdin()).lines();
            match cmd {
                Command::Listen => listen(creds, cache, store, lines).await,
                Command::Connect(ticket) => connect(creds, cache, store, ticket, lines).await,
                _ => Ok(()),
            }
        }
        Command::ImportRoot | Command::VerifyPeer(_) | Command::Usage => Ok(()),
    }
}

/// `import-root`: read the phrase from stdin (never echoed or logged), restore
/// the root, and provision a device if the store has none.
fn import_root_cmd(now: u64) -> Result<()> {
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| Error::Other(format!("read stdin: {e}")))?;
    let store = IdentityStore::open_default();
    let loaded = store.import_root(CryptoSuite::Hybrid, line.trim())?;
    if store.load_device(CryptoSuite::Hybrid)?.is_none() {
        let not_after = now + DEVICE_CERT_LIFETIME.as_secs();
        store.provision_device(&loaded.keypair, CryptoSuite::Hybrid, not_after)?;
        eprintln!(
            "[lattice-net] device key created; certificate valid until {}",
            format_date(not_after)
        );
    }
    println!(
        "root imported; root fingerprint: {}",
        loaded.keypair.peer_id().fingerprint()
    );
    Ok(())
}

/// Listener loop: accept connections, negotiate resume-vs-fresh, chat, and keep
/// each peer's `SecureSession` so a reconnect can resume without re-handshaking.
async fn listen(
    me: DeviceCreds,
    mut cache: RevocationCache,
    store: IdentityStore,
    mut lines: StdinLines,
) -> Result<()> {
    let t = IrohTransport::bind().await?;
    eprintln!("[lattice-net] coming online (contacting relay)...");
    // The v3 ticket is compact and unsigned: our iroh address plus our root
    // and device PeerIds. The dialer checks our hello against those ids.
    let addr = t.ticket_addr().await?;
    let ticket = encode_ticket(&addr, &me.root.peer_id().0, &me.device.peer_id().0)?;
    println!("\n=== TICKET (copy to the other device) ===\n{ticket}\n=========================================\n");
    eprintln!(
        "[lattice-net] your root fingerprint (your peer compares this out of band): {}",
        me.root.peer_id().fingerprint()
    );

    // Acceptor task: only takes `Incoming`s, so one slow peer cannot stall it.
    // Each incoming finishes (QUIC handshake + first stream, limited to
    // NEGOTIATION_TIMEOUT) in its own task under the `pending` semaphore. A free
    // gate hands the connection to this loop; a taken gate gets a one-byte
    // "busy" reply under the `busy` semaphore. Excess connections are dropped.
    let t = Arc::new(t);
    let gate = Arc::new(ChatGate::new());
    let busy = Arc::new(tokio::sync::Semaphore::new(MAX_BUSY_REPLIES));
    let pending = Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_ACCEPTS));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<IrohConn>(1);
    let acceptor = {
        let t = t.clone();
        let gate = gate.clone();
        tokio::spawn(async move {
            loop {
                let incoming = match t.accept_incoming().await {
                    Ok(i) => i,
                    Err(e) => {
                        eprintln!("[lattice-net] accept failed: {e} — no longer accepting");
                        break;
                    }
                };
                let (gate, tx_task, busy) = (gate.clone(), tx.clone(), busy.clone());
                let task = async move {
                    let conn = match accept_within(NEGOTIATION_TIMEOUT, incoming.finish()).await {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("[lattice-net] inbound connection failed: {e}");
                            return;
                        }
                    };
                    // Not under the timeout: a timeout between claiming the gate
                    // and sending would leave the gate claimed forever.
                    let _ = dispatch(conn, &gate, &tx_task, &busy, |c| async move {
                        let _ = tokio::time::timeout(NEGOTIATION_TIMEOUT, reply_busy(c)).await;
                    })
                    .await;
                };
                if spawn_bounded(&pending, task).is_none() {
                    eprintln!("[lattice-net] too many pending accepts — dropped a connection");
                }
                if tx.is_closed() {
                    break;
                }
            }
        })
    };

    let mut sessions: KeptSessions = KeptSessions::new();
    loop {
        eprintln!("[lattice-net] waiting for a peer to connect...");
        let Some(conn) = rx.recv().await else {
            break; // acceptor ended
        };
        let binding = channel_binding(&conn.remote_endpoint_id(), &t.endpoint_id_bytes());
        let limit = NEGOTIATION_TIMEOUT;
        let accepted = negotiate_accept(
            conn,
            &me,
            &mut sessions,
            &binding,
            now_secs(),
            &mut cache,
            limit,
        )
        .await;
        persist_cache(&store, &mut cache);
        let (auth, sess) = match accepted {
            Ok(x) => x,
            Err(e) => {
                eprintln!("[lattice-net] negotiation failed: {e} — still listening");
                gate.release();
                continue;
            }
        };
        report_peer_trust(&store, &me.root, &auth.root);
        match chat(sess, &mut lines).await {
            Ok((Outcome::LocalClosed, _)) => {
                eprintln!("[lattice-net] input closed — exiting");
                break;
            }
            Ok((Outcome::PeerDisconnected, recovered)) => {
                if let Some(session) = recovered {
                    // keep for a future resume (least recently used are evicted)
                    let evicted =
                        sessions.insert(auth.device.peer_id(), KeptPeer { session, auth });
                    if !evicted.is_empty() {
                        eprintln!(
                            "[lattice-net] kept-session limit reached — dropped the least recently used session"
                        );
                    }
                }
                eprintln!("[lattice-net] peer disconnected — back to listening (session kept)");
            }
            Err(e) => eprintln!("[lattice-net] session error: {e} — back to listening"),
        }
        gate.release();
    }
    acceptor.abort();
    Ok(())
}

/// Spawn `fut` iff `sem` has a free permit (never waits). The permit moves into
/// the task and is released when the task ends (completion or abort). With no
/// permit, `fut` is dropped unpolled (dropping whatever it owns) and `None` is
/// returned.
fn spawn_bounded<F>(
    sem: &Arc<tokio::sync::Semaphore>,
    fut: F,
) -> Option<tokio::task::JoinHandle<F::Output>>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    let permit = sem.clone().try_acquire_owned().ok()?;
    Some(tokio::spawn(async move {
        let _permit = permit;
        fut.await
    }))
}

/// `fut` bounded by `limit`; on timeout returns a transport error and drops it.
async fn accept_within<F, T>(limit: Duration, fut: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    match tokio::time::timeout(limit, fut).await {
        Ok(r) => r,
        Err(_) => Err(Error::Transport(format!(
            "accept timed out after {limit:?}"
        ))),
    }
}

/// What happened to a finished inbound connection.
#[derive(Debug, PartialEq, Eq)]
enum Dispatched {
    /// Gate claimed and the connection was sent to the chat loop.
    Forwarded,
    /// Gate taken; a bounded busy-reply task was spawned.
    Busy,
    /// Gate taken and the busy semaphore was full; the connection was dropped.
    Dropped,
    /// Gate claimed but the chat loop's receiver is gone; gate released, connection dropped.
    Closed,
}

/// Route one established connection: claim the gate and forward it, else reply
/// busy under `busy` (via `spawn_bounded`), else drop it. `busy_reply` builds
/// the (already time-bounded) busy-reply future; it is only invoked inside the
/// spawned task, so it never runs when the busy semaphore is full.
async fn dispatch<C, B, Fut>(
    conn: C,
    gate: &ChatGate,
    tx: &tokio::sync::mpsc::Sender<C>,
    busy: &Arc<tokio::sync::Semaphore>,
    busy_reply: B,
) -> Dispatched
where
    C: Send + 'static,
    B: FnOnce(C) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    if gate.try_claim() {
        match tx.send(conn).await {
            Ok(()) => Dispatched::Forwarded,
            Err(_) => {
                gate.release();
                Dispatched::Closed
            }
        }
    } else if spawn_bounded(busy, async move { busy_reply(conn).await }).is_some() {
        Dispatched::Busy
    } else {
        Dispatched::Dropped
    }
}

/// Single-chat gate shared by the acceptor task and the listen loop.
struct ChatGate(AtomicBool);

impl ChatGate {
    fn new() -> Self {
        ChatGate(AtomicBool::new(false))
    }

    /// Atomically claim the gate; true iff it was free.
    fn try_claim(&self) -> bool {
        !self.0.swap(true, Ordering::AcqRel)
    }

    /// Free the gate.
    fn release(&self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Send exactly one frame `[DECISION_BUSY]` without reading anything from
/// `conn`, then drop it. Never touches identities or the session map.
async fn reply_busy<C: Connection>(mut conn: C) -> Result<()> {
    conn.send(&[DECISION_BUSY]).await?;
    // Best effort: give the transport a moment to flush before the drop.
    tokio::time::sleep(Duration::from_millis(250)).await;
    Ok(())
}

/// `accept_or_resume` bounded by `limit` (preamble, hello, decision,
/// handshake and auth exchange all included). A timed-out future is dropped
/// mid-await; `accept_or_resume` only mutates `sessions` after its last
/// `.await`, so a timeout leaves the map unchanged (keep it that way). The
/// revocation cache only ever gains verified, higher-seq lists.
async fn negotiate_accept<C: Connection>(
    conn: C,
    me: &DeviceCreds,
    sessions: &mut KeptSessions,
    binding: &[u8],
    now: u64,
    cache: &mut RevocationCache,
    limit: Duration,
) -> Result<(PeerAuth, ConnectedSession<C>)> {
    match tokio::time::timeout(
        limit,
        accept_or_resume(conn, me, sessions, binding, now, cache),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => Err(Error::Transport(format!(
            "negotiation timed out after {limit:?}"
        ))),
    }
}

/// `negotiate_dial` bounded by `limit`.
#[allow(clippy::too_many_arguments)]
async fn negotiate_dial_within<C: Connection>(
    conn: C,
    me: &DeviceCreds,
    ticket_root: &[u8; 32],
    ticket_device: &[u8; 32],
    kept: &mut Option<KeptPeer>,
    binding: &[u8],
    now: u64,
    cache: &mut RevocationCache,
    limit: Duration,
) -> Result<(PeerAuth, ConnectedSession<C>)> {
    match tokio::time::timeout(
        limit,
        negotiate_dial(
            conn,
            me,
            ticket_root,
            ticket_device,
            kept,
            binding,
            now,
            cache,
        ),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => Err(Error::Transport(format!(
            "negotiation timed out after {limit:?}"
        ))),
    }
}

/// Read the dialer's preamble and answer with our hello; resume a kept session
/// if asked, available, unexpired and not revoked, otherwise run a fresh
/// handshake plus the auth exchange. Returns the verified peer and the live
/// session. `binding` is the channel binding of this connection.
async fn accept_or_resume<C: Connection>(
    mut conn: C,
    me: &DeviceCreds,
    sessions: &mut KeptSessions,
    binding: &[u8],
    now: u64,
    cache: &mut RevocationCache,
) -> Result<(PeerAuth, ConnectedSession<C>)> {
    let preamble = conn.recv().await?;
    if preamble.len() > MAX_PREAMBLE_LEN {
        return Err(Error::Verify(format!(
            "preamble too long: {} > {MAX_PREAMBLE_LEN}",
            preamble.len()
        )));
    }
    if preamble.len() < 2 + NONCE_LEN {
        return Err(Error::Verify("short preamble".into()));
    }
    if preamble[0] != WIRE_VERSION {
        let _ = conn.send(&[DECISION_VERSION, WIRE_VERSION]).await;
        return Err(Error::Verify(format!(
            "peer uses an older lattice-net {VERSION_ERR_MARK}; both sides must upgrade"
        )));
    }
    let mode = preamble[1];
    let mut dialer_nonce = [0u8; NONCE_LEN];
    dialer_nonce.copy_from_slice(&preamble[2..2 + NONCE_LEN]);
    let peer = PublicIdentity::from_bytes(&preamble[2 + NONCE_LEN..])?;
    let peer_id = peer.peer_id();

    // Always send our hello first so the dialer can check us against its ticket.
    conn.send(&encode_listener_hello(me)).await?;

    if mode == MODE_RESUME {
        if let Some(kept) = sessions.get(&peer_id) {
            if resume_allowed(&kept.auth, now, cache) {
                // Prove we hold the session, then require the dialer's proof
                // *before* the session is removed from the map or used.
                let listener_nonce = resume_nonce()?;
                let listener_tag = kept.session.resume_tag(
                    ResumeRole::Listener,
                    &peer,
                    me.device.public(),
                    &dialer_nonce,
                    &listener_nonce,
                    binding,
                );
                let mut challenge = Vec::with_capacity(1 + NONCE_LEN + TAG_LEN);
                challenge.push(DECISION_CHALLENGE);
                challenge.extend_from_slice(&listener_nonce);
                challenge.extend_from_slice(&listener_tag);
                conn.send(&challenge).await?;
                let tag = conn.recv().await?;
                kept.session.verify_resume_tag(
                    ResumeRole::Dialer,
                    &peer,
                    me.device.public(),
                    &dialer_nonce,
                    &listener_nonce,
                    binding,
                    &tag,
                )?;
                let auth = kept.auth.clone();
                let kept = sessions
                    .remove(&peer_id)
                    .ok_or_else(|| Error::Verify("kept session vanished during resume".into()))?;
                announce_peer(&auth, "peer resumed — no re-handshake");
                return Ok((auth, ConnectedSession::resume(conn, kept.session)));
            }
            eprintln!(
                "[lattice-net] kept session for this peer is expired or revoked — requiring a fresh handshake"
            );
        }
    }
    // Fresh handshake (requested, resume with no usable kept session).
    conn.send(&[DECISION_FRESH]).await?;
    let mut cs = ConnectedSession::accept(conn, &me.device, &peer, binding).await?;
    // Auth exchange, sealed by the new session: dialer's bundle first.
    let bundle = decode_auth_bundle(&cs.recv().await?)?;
    let auth = verify_peer_chain(&bundle, &peer, now, cache)?;
    cs.send(&encode_auth_bundle(me)).await?;
    // Only a fully authenticated session replaces the stale one for this peer.
    sessions.remove(&peer_id);
    announce_peer(&auth, "peer connected (fresh session)");
    Ok((auth, cs))
}

/// Dialer loop: dial, negotiate resume-vs-fresh, chat; keep the `SecureSession`
/// across drops so the next dial can resume.
async fn connect(
    me: DeviceCreds,
    mut cache: RevocationCache,
    store: IdentityStore,
    ticket: String,
    mut lines: StdinLines,
) -> Result<()> {
    // Parse the ticket before binding or dialing; a bad ticket is fatal, not retried.
    let parsed = parse_ticket(&ticket)?;
    eprintln!(
        "[lattice-net] peer root fingerprint (from ticket): {} — compare this with your peer out of band",
        PeerId(parsed.root_id).fingerprint()
    );

    let t = IrohTransport::bind().await?;
    let mut kept: Option<KeptPeer> = None;
    let mut backoff = 1u64;
    loop {
        let r = dial_once(
            &t, &ticket, &parsed, &me, &mut kept, &mut cache, &store, &mut lines,
        )
        .await;
        persist_cache(&store, &mut cache);
        match r {
            Ok(Outcome::LocalClosed) => {
                eprintln!("[lattice-net] input closed — exiting");
                break;
            }
            Ok(Outcome::PeerDisconnected) => {
                backoff = 1;
                eprintln!("[lattice-net] peer disconnected — reconnecting...");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(e) if e.to_string().contains(VERSION_ERR_MARK) => return Err(e),
            Err(e) => {
                eprintln!("[lattice-net] connect/session failed: {e} — retrying in {backoff}s");
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(30);
            }
        }
    }
    Ok(())
}

/// Dialer-side negotiation after the transport connects: send the preamble,
/// verify the listener's hello against the ticket's ids, then either resume
/// the kept session (after a mutual proof) or run a fresh handshake plus the
/// auth exchange. A kept session that is expired/revoked (or for another peer)
/// is dropped *before* the preamble, so the dialer asks for a fresh session. On
/// `DECISION_FRESH`, `kept` is taken (cleared) before the fresh handshake runs,
/// so a failed fresh handshake leaves no kept session. On `DECISION_CHALLENGE`,
/// `kept` is taken only after the listener's proof verifies and the dialer's tag
/// is sent. Busy, version, bad-hello and unknown frames leave `kept` untouched.
/// `binding` is the channel binding of this connection.
#[allow(clippy::too_many_arguments)]
async fn negotiate_dial<C: Connection>(
    mut conn: C,
    me: &DeviceCreds,
    ticket_root: &[u8; 32],
    ticket_device: &[u8; 32],
    kept: &mut Option<KeptPeer>,
    binding: &[u8],
    now: u64,
    cache: &mut RevocationCache,
) -> Result<(PeerAuth, ConnectedSession<C>)> {
    if let Some(k) = kept.as_ref() {
        let other_peer =
            k.auth.device.peer_id().0 != *ticket_device || k.auth.root.peer_id().0 != *ticket_root;
        if other_peer || !resume_allowed(&k.auth, now, cache) {
            eprintln!(
                "[lattice-net] kept session is expired, revoked or for another peer — fresh handshake"
            );
            *kept = None;
        }
    }

    // Preamble: [WIRE_VERSION] ++ [mode] ++ dialer nonce ++ our device identity.
    let (mode, dialer_nonce) = if kept.is_some() {
        (MODE_RESUME, resume_nonce()?)
    } else {
        (MODE_FRESH, [0u8; NONCE_LEN])
    };
    let mut preamble = vec![WIRE_VERSION, mode];
    preamble.extend_from_slice(&dialer_nonce);
    preamble.extend_from_slice(&me.device.public().to_bytes());
    conn.send(&preamble).await?;

    // First frame: the listener's hello (or busy / a version complaint).
    let first = conn.recv().await?;
    let hello = match first.first().copied() {
        Some(DECISION_BUSY) => return Err(Error::Transport("listener is busy".into())),
        Some(DECISION_VERSION) => {
            let theirs = first.get(1).copied().unwrap_or(0);
            return Err(Error::Verify(format!(
                "listener speaks lattice-net {VERSION_ERR_MARK} {theirs}, we speak {WIRE_VERSION}; both sides must upgrade"
            )));
        }
        // A bare old-style decision as the first frame: an old listener.
        Some(DECISION_FRESH) | Some(DECISION_RESUMED) | Some(DECISION_CHALLENGE) => {
            return Err(Error::Verify(format!(
                "peer uses an older lattice-net {VERSION_ERR_MARK}; both sides must upgrade"
            )));
        }
        Some(LISTENER_HELLO) => {
            verify_listener_hello(&first, ticket_root, ticket_device, now, cache)?
        }
        _ => {
            return Err(Error::Verify(
                "unrecognised first frame from listener".into(),
            ))
        }
    };

    let decision = conn.recv().await?;
    match decision.first().copied() {
        Some(DECISION_FRESH) => {
            if kept.take().is_some() {
                eprintln!("[lattice-net] peer couldn't resume — fresh handshake");
            }
            let mut cs =
                ConnectedSession::initiate(conn, &me.device, &hello.device, binding).await?;
            // Auth exchange, sealed by the new session: ours first.
            cs.send(&encode_auth_bundle(me)).await?;
            let bundle = decode_auth_bundle(&cs.recv().await?)?;
            if bundle.root.peer_id() != hello.root.peer_id() {
                return Err(Error::Verify(
                    "auth bundle root differs from the root in the hello".into(),
                ));
            }
            let auth = verify_peer_chain(&bundle, &hello.device, now, cache)?;
            announce_peer(&auth, "connected (fresh session)");
            Ok((auth, cs))
        }
        Some(DECISION_CHALLENGE) => {
            let Some(k) = kept.as_ref() else {
                return Err(Error::Verify(
                    "peer sent a resume challenge but no session is kept".into(),
                ));
            };
            if k.auth.device.peer_id() != hello.device.peer_id()
                || k.auth.root.peer_id() != hello.root.peer_id()
                || !resume_allowed(&k.auth, now, cache)
            {
                return Err(Error::Verify(
                    "resume challenge from a peer that does not match the kept session".into(),
                ));
            }
            if decision.len() != 1 + NONCE_LEN + TAG_LEN {
                return Err(Error::Verify("malformed resume challenge".into()));
            }
            let mut listener_nonce = [0u8; NONCE_LEN];
            listener_nonce.copy_from_slice(&decision[1..1 + NONCE_LEN]);
            let listener_tag = &decision[1 + NONCE_LEN..];
            k.session.verify_resume_tag(
                ResumeRole::Listener,
                me.device.public(),
                &hello.device,
                &dialer_nonce,
                &listener_nonce,
                binding,
                listener_tag,
            )?;
            let dialer_tag = k.session.resume_tag(
                ResumeRole::Dialer,
                me.device.public(),
                &hello.device,
                &dialer_nonce,
                &listener_nonce,
                binding,
            );
            conn.send(&dialer_tag).await?;
            let k = kept
                .take()
                .ok_or_else(|| Error::Verify("kept session vanished during resume".into()))?;
            announce_peer(&k.auth, "resumed — no re-handshake");
            Ok((k.auth, ConnectedSession::resume(conn, k.session)))
        }
        Some(DECISION_BUSY) => Err(Error::Transport("listener is busy".into())),
        Some(DECISION_RESUMED) => Err(Error::Verify(
            "peer sent legacy unauthenticated resume decision".into(),
        )),
        _ => Err(Error::Verify("unrecognised resume decision".into())),
    }
}

#[allow(clippy::too_many_arguments)]
async fn dial_once(
    t: &IrohTransport,
    ticket: &str,
    parsed: &lattice::transport::ParsedTicket,
    me: &DeviceCreds,
    kept: &mut Option<KeptPeer>,
    cache: &mut RevocationCache,
    store: &IdentityStore,
    lines: &mut StdinLines,
) -> Result<Outcome> {
    eprintln!("[lattice-net] dialing peer...");
    let (dialed, conn) = t.connect_ticket(ticket).await?;
    // The ticket we dialed must be the one we parsed, and we must have
    // reached the endpoint it names.
    if dialed != *parsed {
        return Err(Error::Verify("ticket changed".into()));
    }
    check_endpoint(&parsed.endpoint_id, &conn.remote_endpoint_id())?;
    let binding = channel_binding(&t.endpoint_id_bytes(), &conn.remote_endpoint_id());

    let limit = NEGOTIATION_TIMEOUT;
    let (auth, cs) = negotiate_dial_within(
        conn,
        me,
        &parsed.root_id,
        &parsed.device_id,
        kept,
        &binding,
        now_secs(),
        cache,
        limit,
    )
    .await?;
    report_peer_trust(store, &me.root, &auth.root);

    match chat(cs, lines).await {
        Ok((Outcome::PeerDisconnected, recovered)) => {
            // keep for resume (None if unrecoverable)
            *kept = recovered.map(|session| KeptPeer { session, auth });
            Ok(Outcome::PeerDisconnected)
        }
        Ok((Outcome::LocalClosed, _)) => Ok(Outcome::LocalClosed),
        Err(e) => {
            *kept = None;
            Err(e)
        }
    }
}

/// Full-duplex chat over one session: a reader task decrypts incoming frames
/// while this task encrypts stdin lines. The ratchet is shared behind a mutex
/// (brief locks, no I/O held); the QUIC halves run concurrently. On a drop it
/// returns the recovered `SecureSession` so the caller can resume it.
async fn chat(
    sess: ConnectedSession<IrohConn>,
    lines: &mut StdinLines,
) -> Result<(Outcome, Option<SecureSession>)> {
    let (conn, secure) = sess.into_parts();
    let (mut send, mut recv) = conn.into_split();
    let secure = Arc::new(Mutex::new(secure));

    // Reader task: decrypt + print; signal `lost` when the peer drops.
    let lost = Arc::new(Notify::new());
    let secure_r = secure.clone();
    let lost_r = lost.clone();
    let reader = tokio::spawn(async move {
        while let Ok(frame) = read_frame(&mut recv).await {
            match secure_r.lock().await.open(&frame) {
                Ok(pt) => println!("peer> {}", String::from_utf8_lossy(&pt)),
                Err(e) => {
                    eprintln!("[lattice-net] decrypt error: {e}");
                    break;
                }
            }
        }
        lost_r.notify_one();
    });

    // Writer: stdin lines -> encrypt -> send, cancelled promptly if the peer drops.
    let outcome = loop {
        tokio::select! {
            maybe = lines.next_line() => {
                match maybe.map_err(|e| Error::Other(format!("stdin: {e}")))? {
                    Some(line) => {
                        let frame = { secure.lock().await.seal(line.as_bytes())? };
                        if write_frame(&mut send, &frame).await.is_err() {
                            break Outcome::PeerDisconnected;
                        }
                    }
                    None => break Outcome::LocalClosed,
                }
            }
            _ = lost.notified() => break Outcome::PeerDisconnected,
        }
    };

    // Recover the ratchet session for possible resumption: stop the reader so it
    // drops its handle, then reclaim sole ownership.
    reader.abort();
    let _ = reader.await;
    let recovered = Arc::try_unwrap(secure).ok().map(|m| m.into_inner());
    Ok((outcome, recovered))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice::identity::MAX_REVOKED;
    use lattice::transport::TicketAddr;

    /// Largest frame body the transport accepts (`lattice_transport::MAX_FRAME_LEN`).
    const FRAME_CAP: usize = 65_536;
    const NOW: u64 = 1_000;
    const FAR: u64 = 1_000_000;

    fn id() -> Keypair {
        Keypair::generate(CryptoSuite::Hybrid).unwrap()
    }

    /// Credentials for a fresh device under `root`, valid until `not_after`.
    fn creds_with(root: &Keypair, not_after: u64) -> DeviceCreds {
        let device = id();
        let cert = root.authorize_device(device.public(), not_after).unwrap();
        DeviceCreds {
            device,
            root: root.public().clone(),
            cert,
            revocation: None,
        }
    }

    /// Credentials under a brand-new root.
    fn creds() -> DeviceCreds {
        creds_with(&id(), FAR)
    }

    fn cache() -> RevocationCache {
        RevocationCache::new()
    }

    fn ids(c: &DeviceCreds) -> ([u8; 32], [u8; 32]) {
        (c.root.peer_id().0, c.device.peer_id().0)
    }

    fn auth_of(c: &DeviceCreds) -> PeerAuth {
        PeerAuth {
            root: c.root.clone(),
            device: c.device.public().clone(),
            cert_not_after: c.cert.not_after(),
        }
    }

    fn kept(session: SecureSession, peer: &DeviceCreds) -> KeptPeer {
        KeptPeer {
            session,
            auth: auth_of(peer),
        }
    }

    /// A fixed, valid channel binding for tests that don't care about its value.
    fn bnd() -> Vec<u8> {
        channel_binding(&[0xd1; 32], &[0x11; 32])
    }

    /// Connected in-memory pair: (dialer end, listener end).
    async fn pair() -> (MemoryConn, MemoryConn) {
        let net = MemoryNetwork::new();
        let (a, b) = (PeerId([1u8; 32]), PeerId([2u8; 32]));
        let ta = net.endpoint(a);
        let tb = net.endpoint(b.clone());
        let dial = ta.connect(&b).await.unwrap();
        let (_, listen) = tb.accept().await.unwrap();
        (dial, listen)
    }

    /// Alice (dialer) negotiates with `bob` (listener) using bob's ticket ids.
    async fn dial_to(
        conn: MemoryConn,
        alice: &DeviceCreds,
        bob: &DeviceCreds,
        kept: &mut Option<KeptPeer>,
        binding: &[u8],
        cache: &mut RevocationCache,
    ) -> Result<(PeerAuth, ConnectedSession<MemoryConn>)> {
        let (r, d) = ids(bob);
        negotiate_dial(conn, alice, &r, &d, kept, binding, NOW, cache).await
    }

    /// Listener map holding a kept session for alice's device (responder = bob).
    fn stale(alice: &DeviceCreds, bob: &DeviceCreds) -> KeptSessions {
        let (m1, pending) =
            SecureSession::initiate(&bob.device, alice.device.public(), b"").unwrap();
        let (m2, _) = SecureSession::respond(&alice.device, bob.device.public(), b"", &m1).unwrap();
        let s = pending.finish(&m2).unwrap();
        KeptSessions::from([(alice.device.peer_id(), kept(s, alice))])
    }

    async fn send_preamble(conn: &mut MemoryConn, mode: u8, nonce: [u8; NONCE_LEN], who: &Keypair) {
        let mut p = vec![WIRE_VERSION, mode];
        p.extend_from_slice(&nonce);
        p.extend_from_slice(&who.public().to_bytes());
        conn.send(&p).await.unwrap();
    }

    async fn preamble(conn: &mut MemoryConn, mode: u8, who: &Keypair) {
        send_preamble(conn, mode, [0u8; NONCE_LEN], who).await;
    }

    /// Genuine Alice–Bob pair: (alice, bob, alice's kept (of bob), bob's kept (of alice)).
    fn genuine() -> (DeviceCreds, DeviceCreds, KeptPeer, KeptPeer) {
        let (alice, bob) = (creds(), creds());
        let (m1, pending) =
            SecureSession::initiate(&alice.device, bob.device.public(), b"").unwrap();
        let (m2, b) = SecureSession::respond(&bob.device, alice.device.public(), b"", &m1).unwrap();
        let a = pending.finish(&m2).unwrap();
        let (ka, kb) = (kept(a, &bob), kept(b, &alice));
        (alice, bob, ka, kb)
    }

    // ---- fresh negotiation ----

    #[tokio::test]
    async fn fresh_dial_and_accept_two_roots() {
        let (alice, bob) = (creds(), creds());
        let mut sessions = KeptSessions::new();
        let (mut ca, mut cb) = (cache(), cache());
        let mut k = None;
        let (dial, listen) = pair().await;
        let bd = bnd();
        let (d, l) = tokio::join!(
            dial_to(dial, &alice, &bob, &mut k, &bd, &mut ca),
            accept_or_resume(listen, &bob, &mut sessions, &bd, NOW, &mut cb)
        );
        let ((da, mut ds), (la, mut ls)) = (d.unwrap(), l.unwrap());
        assert_eq!(da.root.peer_id(), bob.root.peer_id());
        assert_eq!(da.device.peer_id(), bob.device.peer_id());
        assert_eq!(la.root.peer_id(), alice.root.peer_id());
        assert_eq!(la.device.peer_id(), alice.device.peer_id());
        assert_eq!(la.cert_not_after, FAR);
        ds.send(b"hello").await.unwrap();
        assert_eq!(ls.recv().await.unwrap(), b"hello");
        ls.send(b"world").await.unwrap();
        assert_eq!(ds.recv().await.unwrap(), b"world");
    }

    #[tokio::test]
    async fn forged_initiator_keeps_stale_session() {
        let (alice, bob, eve) = (creds(), creds(), creds());
        let mut sessions = stale(&alice, &bob);
        let (mut dial, listen) = pair().await;
        preamble(&mut dial, MODE_FRESH, &alice.device).await;
        let b = bnd();
        // Eve's handshake, claimed to come from Alice's device.
        let dialer = async {
            // The listener's hello and decision come first, then the handshake.
            assert_eq!(dial.recv().await.unwrap()[0], LISTENER_HELLO);
            assert_eq!(dial.recv().await.unwrap(), [DECISION_FRESH]);
            ConnectedSession::initiate(dial, &eve.device, bob.device.public(), &b).await
        };
        let mut c = cache();
        let (d, r) = tokio::join!(
            dialer,
            accept_or_resume(listen, &bob, &mut sessions, &b, NOW, &mut c)
        );
        assert!(r.is_err());
        assert!(d.is_err());
        assert!(sessions.contains_key(&alice.device.peer_id()));
    }

    #[tokio::test]
    async fn genuine_fresh_handshake_replaces_stale_session() {
        let (alice, bob) = (creds(), creds());
        let mut sessions = stale(&alice, &bob);
        let (dial, listen) = pair().await;
        let b = bnd();
        let (mut ca, mut cb) = (cache(), cache());
        let mut k = None;
        let (d, r) = tokio::join!(
            dial_to(dial, &alice, &bob, &mut k, &b, &mut ca),
            accept_or_resume(listen, &bob, &mut sessions, &b, NOW, &mut cb)
        );
        assert!(d.is_ok());
        assert!(r.is_ok());
        assert!(!sessions.contains_key(&alice.device.peer_id()));
    }

    #[tokio::test]
    async fn fresh_handshake_with_mismatched_bindings_fails() {
        let (alice, bob) = (creds(), creds());
        let mut sessions = KeptSessions::new();
        let (dial, listen) = pair().await;
        let b_dial = channel_binding(&[1u8; 32], &[2u8; 32]);
        let b_listen = channel_binding(&[1u8; 32], &[3u8; 32]);
        let mut k = None;
        let (mut ca, mut cb) = (cache(), cache());
        let (d, r) = tokio::join!(
            dial_to(dial, &alice, &bob, &mut k, &b_dial, &mut ca),
            accept_or_resume(listen, &bob, &mut sessions, &b_listen, NOW, &mut cb)
        );
        assert!(matches!(r, Err(Error::Verify(_))));
        assert!(d.is_err());
        assert!(sessions.is_empty());
    }

    // ---- resume ----

    #[tokio::test]
    async fn genuine_resume_with_mutual_proof_succeeds() {
        let (alice, bob, a, b) = genuine();
        let mut sessions = KeptSessions::from([(alice.device.peer_id(), b)]);
        let mut k = Some(a);
        let (dial, listen) = pair().await;
        let bd = bnd();
        let (mut ca, mut cb) = (cache(), cache());
        let (d, l) = tokio::join!(
            dial_to(dial, &alice, &bob, &mut k, &bd, &mut ca),
            accept_or_resume(listen, &bob, &mut sessions, &bd, NOW, &mut cb)
        );
        let ((da, mut d), (la, mut l)) = (d.unwrap(), l.unwrap());
        assert_eq!(da.device.peer_id(), bob.device.peer_id());
        assert_eq!(la.device.peer_id(), alice.device.peer_id());
        assert!(k.is_none());
        assert!(!sessions.contains_key(&alice.device.peer_id()));
        d.send(b"hello").await.unwrap();
        assert_eq!(l.recv().await.unwrap(), b"hello");
        l.send(b"world").await.unwrap();
        assert_eq!(d.recv().await.unwrap(), b"world");
    }

    #[tokio::test]
    async fn resume_with_mismatched_bindings_fails_and_keeps_state() {
        let (alice, bob, a, b) = genuine();
        let mut sessions = KeptSessions::from([(alice.device.peer_id(), b)]);
        let mut k = Some(a);
        let (dial, listen) = pair().await;
        let b_dial = channel_binding(&[1u8; 32], &[2u8; 32]);
        let b_listen = channel_binding(&[1u8; 32], &[3u8; 32]);
        let (mut ca, mut cb) = (cache(), cache());
        let (d, l) = tokio::join!(
            dial_to(dial, &alice, &bob, &mut k, &b_dial, &mut ca),
            accept_or_resume(listen, &bob, &mut sessions, &b_listen, NOW, &mut cb)
        );
        assert!(d.is_err());
        assert!(l.is_err());
        assert!(k.is_some());
        assert!(sessions.contains_key(&alice.device.peer_id()));
    }

    fn resume_preamble(nonce: &[u8; NONCE_LEN], who: &Keypair) -> Vec<u8> {
        let mut p = vec![WIRE_VERSION, MODE_RESUME];
        p.extend_from_slice(nonce);
        p.extend_from_slice(&who.public().to_bytes());
        p
    }

    #[tokio::test]
    async fn impostor_with_bogus_tag_cannot_resume() {
        let (alice, bob, _a, b) = genuine();
        let mut sessions = KeptSessions::from([(alice.device.peer_id(), b)]);
        let (mut eve, listen) = pair().await;
        eve.send(&resume_preamble(&[7u8; NONCE_LEN], &alice.device))
            .await
            .unwrap();
        eve.send(&[0xAA; TAG_LEN]).await.unwrap();
        let mut c = cache();
        let r = accept_or_resume(listen, &bob, &mut sessions, &bnd(), NOW, &mut c).await;
        assert!(r.is_err());
        assert!(sessions.contains_key(&alice.device.peer_id()));
        assert_eq!(eve.recv().await.unwrap()[0], LISTENER_HELLO);
        let reply = eve.recv().await.unwrap();
        assert_eq!(reply.len(), 1 + NONCE_LEN + TAG_LEN);
        assert_eq!(reply[0], DECISION_CHALLENGE);
    }

    #[tokio::test]
    async fn impostor_hanging_up_cannot_resume() {
        let (alice, bob, _a, b) = genuine();
        let mut sessions = KeptSessions::from([(alice.device.peer_id(), b)]);
        let (mut eve, listen) = pair().await;
        eve.send(&resume_preamble(&[7u8; NONCE_LEN], &alice.device))
            .await
            .unwrap();
        drop(eve);
        let mut c = cache();
        let r = accept_or_resume(listen, &bob, &mut sessions, &bnd(), NOW, &mut c).await;
        assert!(r.is_err());
        assert!(sessions.contains_key(&alice.device.peer_id()));
    }

    #[test]
    fn resume_allowed_checks_expiry_and_cache() {
        let root = id();
        let c = creds_with(&root, 500);
        let auth = auth_of(&c);
        let mut cc = cache();
        assert!(resume_allowed(&auth, 500, &cc));
        assert!(!resume_allowed(&auth, 501, &cc));
        let list = root.revoke_devices(1, 0, &[c.device.peer_id()]).unwrap();
        assert!(cc.observe(list));
        assert!(!resume_allowed(&auth, 100, &cc));
    }

    #[tokio::test]
    async fn revoked_kept_session_is_not_resumed_listener_side() {
        let alice_root = id();
        let alice = creds_with(&alice_root, FAR);
        let bob = creds();
        let (m1, pending) =
            SecureSession::initiate(&alice.device, bob.device.public(), b"").unwrap();
        let (m2, b) = SecureSession::respond(&bob.device, alice.device.public(), b"", &m1).unwrap();
        let _a = pending.finish(&m2).unwrap();
        let mut sessions = KeptSessions::from([(alice.device.peer_id(), kept(b, &alice))]);
        // Bob learns that alice's root revoked alice's device.
        let mut cb = cache();
        let list = alice_root
            .revoke_devices(1, 0, &[alice.device.peer_id()])
            .unwrap();
        assert!(cb.observe(list));

        let (mut eve, listen) = pair().await;
        eve.send(&resume_preamble(&[7u8; NONCE_LEN], &alice.device))
            .await
            .unwrap();
        let binding = bnd();
        let r = accept_or_resume(listen, &bob, &mut sessions, &binding, NOW, &mut cb);
        let script = async {
            assert_eq!(eve.recv().await.unwrap()[0], LISTENER_HELLO);
            // No challenge: the listener demands a fresh handshake.
            assert_eq!(eve.recv().await.unwrap(), [DECISION_FRESH]);
            drop(eve);
        };
        let (r, ()) = tokio::join!(r, script);
        assert!(r.is_err());
        // The refused entry stays in the map and was never resumed.
        assert!(sessions.contains_key(&alice.device.peer_id()));
    }

    #[tokio::test]
    async fn dialer_drops_revoked_or_expired_kept_and_goes_fresh() {
        for expired in [false, true] {
            let bob_root = id();
            let (alice, bob) = (creds(), creds_with(&bob_root, 2_000));
            let (m1, pending) =
                SecureSession::initiate(&alice.device, bob.device.public(), b"").unwrap();
            let (m2, _b) =
                SecureSession::respond(&bob.device, alice.device.public(), b"", &m1).unwrap();
            let a = pending.finish(&m2).unwrap();
            let mut k = Some(kept(a, &bob));
            let mut ca = cache();
            let mut now = NOW;
            if expired {
                now = 2_001;
            } else {
                let list = bob_root
                    .revoke_devices(1, 0, &[bob.device.peer_id()])
                    .unwrap();
                assert!(ca.observe(list));
            }
            let (dial, mut listen) = pair().await;
            let script = async { listen.recv().await.unwrap() };
            let (r, d) = ids(&bob);
            let binding = bnd();
            let (res, p) = tokio::join!(
                negotiate_dial_within(dial, &alice, &r, &d, &mut k, &binding, now, &mut ca, SHORT),
                script
            );
            assert!(res.is_err());
            assert_eq!(p[0], WIRE_VERSION);
            assert_eq!(p[1], MODE_FRESH, "expired={expired}");
            assert!(k.is_none());
        }
    }

    #[tokio::test]
    async fn dialer_rejects_wrong_listener_tag_and_checks_preamble() {
        let (alice, bob, a, _b) = genuine();
        let mut k = Some(a);
        let (dial, mut listen) = pair().await;
        let hello = encode_listener_hello(&bob);
        let script = async {
            let p = listen.recv().await.unwrap();
            listen.send(&hello).await.unwrap();
            let mut reply = vec![DECISION_CHALLENGE];
            reply.extend_from_slice(&[3u8; NONCE_LEN]);
            reply.extend_from_slice(&[0xBB; TAG_LEN]);
            listen.send(&reply).await.unwrap();
            p
        };
        let bd = bnd();
        let mut c = cache();
        let (r, p) = tokio::join!(dial_to(dial, &alice, &bob, &mut k, &bd, &mut c), script);
        assert!(r.is_err());
        assert!(k.is_some());
        let ib = alice.device.public().to_bytes();
        assert_eq!(p[0], WIRE_VERSION);
        assert_eq!(p[1], MODE_RESUME);
        assert_eq!(p.len(), 2 + NONCE_LEN + ib.len());
        assert_eq!(&p[2 + NONCE_LEN..], &ib[..]);
    }

    #[tokio::test]
    async fn dialer_rejects_legacy_resumed_decision() {
        let (alice, bob, a, _b) = genuine();
        let mut k = Some(a);
        let (dial, mut listen) = pair().await;
        listen.send(&encode_listener_hello(&bob)).await.unwrap();
        listen.send(&[DECISION_RESUMED]).await.unwrap();
        let mut c = cache();
        let r = dial_to(dial, &alice, &bob, &mut k, &bnd(), &mut c).await;
        assert!(r.is_err());
        assert!(k.is_some());
    }

    #[tokio::test]
    async fn dialer_rejects_challenge_without_kept_session() {
        let (alice, bob) = (creds(), creds());
        let mut k = None;
        let (dial, mut listen) = pair().await;
        listen.send(&encode_listener_hello(&bob)).await.unwrap();
        let mut reply = vec![DECISION_CHALLENGE];
        reply.extend_from_slice(&[0u8; NONCE_LEN + TAG_LEN]);
        listen.send(&reply).await.unwrap();
        let mut c = cache();
        let r = dial_to(dial, &alice, &bob, &mut k, &bnd(), &mut c).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn short_and_long_preambles_are_rejected() {
        let (alice, bob) = (creds(), creds());
        for n in [0usize, 1, 2, 33, MAX_PREAMBLE_LEN + 1] {
            let mut sessions = stale(&alice, &bob);
            let (mut dial, listen) = pair().await;
            dial.send(&vec![WIRE_VERSION; n]).await.unwrap();
            let mut c = cache();
            let r = accept_or_resume(listen, &bob, &mut sessions, &bnd(), NOW, &mut c).await;
            assert!(matches!(r, Err(Error::Verify(_))), "len {n}");
            assert!(sessions.contains_key(&alice.device.peer_id()));
        }
    }

    #[tokio::test]
    async fn fresh_dial_preamble_has_version_mode_and_zero_nonce() {
        let (alice, bob) = (creds(), creds());
        let mut k = None;
        let (dial, mut listen) = pair().await;
        let script = async {
            let p = listen.recv().await.unwrap();
            listen.send(&[0xFF]).await.unwrap(); // unknown first frame → dialer errors
            p
        };
        let bd = bnd();
        let mut c = cache();
        let (r, p) = tokio::join!(dial_to(dial, &alice, &bob, &mut k, &bd, &mut c), script);
        assert!(r.is_err());
        assert_eq!(p[0], WIRE_VERSION);
        assert_eq!(p[1], MODE_FRESH);
        assert!(p[2..2 + NONCE_LEN].iter().all(|b| *b == 0));
    }

    // ---- wire version ----

    #[tokio::test]
    async fn old_preamble_gets_version_reply_and_error() {
        let (alice, bob) = (creds(), creds());
        for mode in [MODE_FRESH, MODE_RESUME] {
            let mut sessions = stale(&alice, &bob);
            let (mut dial, listen) = pair().await;
            let mut p = vec![mode];
            p.extend_from_slice(&[0u8; NONCE_LEN]);
            p.extend_from_slice(&alice.device.public().to_bytes());
            dial.send(&p).await.unwrap();
            let mut c = cache();
            let r = accept_or_resume(listen, &bob, &mut sessions, &bnd(), NOW, &mut c).await;
            match r {
                Err(e) => assert!(e.to_string().contains("version"), "{e}"),
                Ok(_) => panic!("old preamble accepted"),
            }
            assert_eq!(dial.recv().await.unwrap(), [DECISION_VERSION, WIRE_VERSION]);
            assert!(sessions.contains_key(&alice.device.peer_id()));
        }
        assert_ne!(WIRE_VERSION, MODE_FRESH);
        assert_ne!(WIRE_VERSION, MODE_RESUME);
    }

    #[tokio::test]
    async fn dialer_maps_version_and_old_decisions_to_version_error() {
        let (alice, bob, a, _b) = genuine();
        let mut k = Some(a);
        for first in [
            vec![DECISION_VERSION, 9],
            vec![DECISION_FRESH],
            vec![DECISION_RESUMED],
            vec![DECISION_CHALLENGE, 0, 0],
        ] {
            let (dial, mut listen) = pair().await;
            listen.send(&first).await.unwrap();
            let mut c = cache();
            let r = dial_to(dial, &alice, &bob, &mut k, &bnd(), &mut c).await;
            match r {
                Err(e) => assert!(e.to_string().contains("version"), "{e}"),
                Ok(_) => panic!("accepted"),
            }
            assert!(k.is_some());
        }
    }

    // ---- auth chain ----

    fn bundle_of(c: &DeviceCreds) -> AuthBundle {
        decode_auth_bundle(&encode_auth_bundle(c)).unwrap()
    }

    #[test]
    fn chain_accepts_genuine_and_observes_list() {
        let root = id();
        let mut c = creds_with(&root, FAR);
        c.revocation = Some(root.revoke_devices(4, 0, &[PeerId([9; 32])]).unwrap());
        let mut cc = cache();
        let auth = verify_peer_chain(&bundle_of(&c), c.device.public(), NOW, &mut cc).unwrap();
        assert_eq!(auth.root.peer_id(), root.peer_id());
        assert_eq!(cc.get(&root.peer_id()).unwrap().seq(), 4);
    }

    #[test]
    fn chain_rejects_cert_for_other_device() {
        let root = id();
        let (a, other) = (creds_with(&root, FAR), creds_with(&root, FAR));
        let mut cc = cache();
        let r = verify_peer_chain(&bundle_of(&other), a.device.public(), NOW, &mut cc);
        assert!(matches!(r, Err(Error::Verify(_))));
    }

    #[test]
    fn chain_rejects_expired_cert() {
        let c = creds_with(&id(), 500);
        let mut cc = cache();
        assert!(verify_peer_chain(&bundle_of(&c), c.device.public(), 500, &mut cc).is_ok());
        assert!(verify_peer_chain(&bundle_of(&c), c.device.public(), 501, &mut cc).is_err());
    }

    #[test]
    fn chain_rejects_device_revoked_by_sent_list() {
        let root = id();
        let mut c = creds_with(&root, FAR);
        c.revocation = Some(root.revoke_devices(1, 0, &[c.device.peer_id()]).unwrap());
        let mut cc = cache();
        assert!(verify_peer_chain(&bundle_of(&c), c.device.public(), NOW, &mut cc).is_err());
    }

    #[test]
    fn chain_rejects_device_revoked_by_cached_list_even_if_omitted() {
        let root = id();
        let c = creds_with(&root, FAR);
        let mut cc = cache();
        cc.observe(root.revoke_devices(2, 0, &[c.device.peer_id()]).unwrap());
        assert!(verify_peer_chain(&bundle_of(&c), c.device.public(), NOW, &mut cc).is_err());
    }

    #[test]
    fn chain_rejects_list_from_other_root_and_unrelated_bundles() {
        let root = id();
        let mut c = creds_with(&root, FAR);
        let other = id();
        c.revocation = Some(other.revoke_devices(1, 0, &[]).unwrap());
        let mut cc = cache();
        assert!(verify_peer_chain(&bundle_of(&c), c.device.public(), NOW, &mut cc).is_err());

        // Valid bundle for carol's own device, but the session peer is dave.
        let (carol, dave) = (creds(), creds());
        assert!(verify_peer_chain(&bundle_of(&carol), dave.device.public(), NOW, &mut cc).is_err());
    }

    #[test]
    fn chain_rejects_cert_signed_by_wrong_root() {
        let mut c = creds();
        c.root = id().public().clone(); // claims a root that did not sign the cert
        let mut cc = cache();
        assert!(verify_peer_chain(&bundle_of(&c), c.device.public(), NOW, &mut cc).is_err());
    }

    #[tokio::test]
    async fn bundle_for_wrong_device_rejected_and_sessions_unchanged() {
        let alice_root = id();
        let alice = creds_with(&alice_root, FAR);
        let other = creds_with(&alice_root, FAR);
        let bob = creds();
        let mut sessions = stale(&alice, &bob);
        let (mut dial, listen) = pair().await;
        preamble(&mut dial, MODE_FRESH, &alice.device).await;
        let bd = bnd();
        let script = async {
            assert_eq!(dial.recv().await.unwrap()[0], LISTENER_HELLO);
            assert_eq!(dial.recv().await.unwrap(), [DECISION_FRESH]);
            let mut cs = ConnectedSession::initiate(dial, &alice.device, bob.device.public(), &bd)
                .await
                .unwrap();
            // A genuine cert, but for a different device than the session peer.
            cs.send(&encode_auth_bundle(&other)).await.unwrap();
        };
        let mut c = cache();
        let (r, ()) = tokio::join!(
            accept_or_resume(listen, &bob, &mut sessions, &bd, NOW, &mut c),
            script
        );
        assert!(r.is_err());
        assert_eq!(sessions.len(), 1);
        assert!(sessions.contains_key(&alice.device.peer_id()));
    }

    #[test]
    fn bundle_size_caps() {
        // Oversized: rejected before parsing.
        assert!(decode_auth_bundle(&vec![0u8; MAX_AUTH_BUNDLE_LEN + 1]).is_err());
        // Trailing byte / truncation.
        let c = creds();
        let mut b = encode_auth_bundle(&c);
        assert!(decode_auth_bundle(&b).is_ok());
        assert!(decode_auth_bundle(&b[..b.len() - 1]).is_err());
        b.push(0);
        assert!(decode_auth_bundle(&b).is_err());
        // Length prefix larger than the input.
        assert!(decode_auth_bundle(&[0xff, 0xff, 0xff, 0x7f, 1, 2]).is_err());
    }

    #[test]
    fn maximal_bundle_and_hello_fit_caps_and_frames() {
        let root = id();
        let mut c = creds_with(&root, FAR);
        let many: Vec<PeerId> = (0..MAX_REVOKED)
            .map(|i| {
                let mut b = [0u8; 32];
                b[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
                PeerId(b)
            })
            .collect();
        c.revocation = Some(root.revoke_devices(1, 0, &many).unwrap());
        let bundle = encode_auth_bundle(&c);
        assert!(bundle.len() <= MAX_AUTH_BUNDLE_LEN, "{}", bundle.len());
        let parsed = decode_auth_bundle(&bundle).unwrap();
        assert_eq!(parsed.revocation.unwrap().revoked().len(), MAX_REVOKED);
        // Sealed by a session: must fit one transport frame.
        let peer = id();
        let (m1, pending) = SecureSession::initiate(&c.device, peer.public(), b"").unwrap();
        let (m2, _) = SecureSession::respond(&peer, c.device.public(), b"", &m1).unwrap();
        let mut s = pending.finish(&m2).unwrap();
        assert!(s.seal(&bundle).unwrap().len() <= FRAME_CAP);
        // The hello is a plain frame.
        let hello = encode_listener_hello(&c);
        assert!(hello.len() <= MAX_LISTENER_HELLO_LEN, "{}", hello.len());
        assert!(hello.len() <= FRAME_CAP);
        let (r, d) = ids(&c);
        let mut cc = cache();
        assert!(verify_listener_hello(&hello, &r, &d, NOW, &mut cc).is_ok());
    }

    // ---- listener hello ----

    #[test]
    fn hello_checks_against_ticket() {
        let root = id();
        let bob = creds_with(&root, FAR);
        let (r, d) = ids(&bob);
        let hello = encode_listener_hello(&bob);
        let mut cc = cache();
        let ok = verify_listener_hello(&hello, &r, &d, NOW, &mut cc).unwrap();
        assert_eq!(ok.device.peer_id(), bob.device.peer_id());

        let mut wrong_dev = d;
        wrong_dev[0] ^= 1;
        assert!(verify_listener_hello(&hello, &r, &wrong_dev, NOW, &mut cc).is_err());
        let mut wrong_root = r;
        wrong_root[0] ^= 1;
        assert!(verify_listener_hello(&hello, &wrong_root, &d, NOW, &mut cc).is_err());
        // Expired.
        assert!(verify_listener_hello(&hello, &r, &d, FAR + 1, &mut cc).is_err());
        // Cert not signed by the stated root.
        let mut forged = creds_with(&root, FAR);
        forged.root = id().public().clone();
        let (fr, fd) = ids(&forged);
        let fh = encode_listener_hello(&forged);
        assert!(verify_listener_hello(&fh, &fr, &fd, NOW, &mut cc).is_err());
        // Revoked by its own included list.
        let mut revoked = creds_with(&root, FAR);
        revoked.revocation = Some(
            root.revoke_devices(1, 0, &[revoked.device.peer_id()])
                .unwrap(),
        );
        let (rr, rd) = ids(&revoked);
        let rh = encode_listener_hello(&revoked);
        assert!(verify_listener_hello(&rh, &rr, &rd, NOW, &mut cc).is_err());
        // Oversized, wrong tag, trailing garbage.
        assert!(verify_listener_hello(
            &vec![LISTENER_HELLO; MAX_LISTENER_HELLO_LEN + 1],
            &r,
            &d,
            NOW,
            &mut cc
        )
        .is_err());
        let mut bad_tag = hello.clone();
        bad_tag[0] = 0;
        assert!(verify_listener_hello(&bad_tag, &r, &d, NOW, &mut cc).is_err());
        let mut trailing = hello.clone();
        trailing.push(0);
        assert!(verify_listener_hello(&trailing, &r, &d, NOW, &mut cc).is_err());
    }

    #[tokio::test]
    async fn bad_hello_leaves_kept_untouched() {
        let (alice, bob, a, _b) = genuine();
        let imposter = creds();
        let mut k = Some(a);
        // The listener answers with a hello for someone other than the ticket's peer.
        let (dial, mut listen) = pair().await;
        listen
            .send(&encode_listener_hello(&imposter))
            .await
            .unwrap();
        let mut c = cache();
        let r = dial_to(dial, &alice, &bob, &mut k, &bnd(), &mut c).await;
        assert!(matches!(r, Err(Error::Verify(_))));
        assert!(k.is_some());

        // Oversized hello.
        let (dial, mut listen) = pair().await;
        listen
            .send(&vec![LISTENER_HELLO; MAX_LISTENER_HELLO_LEN + 1])
            .await
            .unwrap();
        let r = dial_to(dial, &alice, &bob, &mut k, &bnd(), &mut c).await;
        assert!(matches!(r, Err(Error::Verify(_))));
        assert!(k.is_some());
    }

    // ---- negotiation timeouts, busy reply, gate ----

    const SHORT: Duration = Duration::from_millis(50);
    const MEDIUM: Duration = Duration::from_secs(5);

    #[test]
    fn negotiation_constants() {
        assert_eq!(NEGOTIATION_TIMEOUT, Duration::from_secs(15));
        assert_eq!(DECISION_BUSY, 3);
        assert_eq!(WIRE_VERSION, 2);
        assert_eq!(DECISION_VERSION, 4);
        assert_eq!(LISTENER_HELLO, 5);
        assert_eq!(MAX_CACHED_ROOTS, 256);
        assert_eq!(DEVICE_CERT_LIFETIME, Duration::from_secs(30 * 24 * 3600));
        assert_eq!(DEVICE_RENEW_WINDOW, Duration::from_secs(7 * 24 * 3600));
    }

    #[tokio::test]
    async fn silent_dialer_times_out_and_keeps_sessions() {
        let (alice, bob) = (creds(), creds());
        let mut sessions = stale(&alice, &bob);
        let (_dial, listen) = pair().await;
        let mut c = cache();
        let r = negotiate_accept(listen, &bob, &mut sessions, &bnd(), NOW, &mut c, SHORT).await;
        assert!(matches!(
            r,
            Err(Error::Transport(_)) | Err(Error::Verify(_))
        ));
        assert_eq!(sessions.len(), 1);
        assert!(sessions.contains_key(&alice.device.peer_id()));
    }

    #[tokio::test]
    async fn resume_without_tag_times_out_and_session_still_resumes() {
        let (alice, bob, a, b) = genuine();
        let mut sessions = KeptSessions::from([(alice.device.peer_id(), b)]);
        let (mut eve, listen) = pair().await;
        eve.send(&resume_preamble(&[7u8; NONCE_LEN], &alice.device))
            .await
            .unwrap();
        let mut c = cache();
        let r = negotiate_accept(listen, &bob, &mut sessions, &bnd(), NOW, &mut c, SHORT).await;
        assert!(r.is_err());
        assert!(sessions.contains_key(&alice.device.peer_id()));
        drop(eve);

        // A genuine resume on a new pair still works.
        let mut k = Some(a);
        let (dial, listen) = pair().await;
        let bd = bnd();
        let mut ca = cache();
        let (d, l) = tokio::join!(
            dial_to(dial, &alice, &bob, &mut k, &bd, &mut ca),
            accept_or_resume(listen, &bob, &mut sessions, &bd, NOW, &mut c)
        );
        assert!(d.is_ok());
        assert!(l.is_ok());
    }

    #[tokio::test]
    async fn fresh_without_msg1_times_out_and_keeps_sessions() {
        let (alice, bob) = (creds(), creds());
        let mut sessions = stale(&alice, &bob);
        let (mut dial, listen) = pair().await;
        preamble(&mut dial, MODE_FRESH, &alice.device).await;
        let mut c = cache();
        let r = negotiate_accept(listen, &bob, &mut sessions, &bnd(), NOW, &mut c, SHORT).await;
        assert!(r.is_err());
        assert_eq!(sessions.len(), 1);
        assert!(sessions.contains_key(&alice.device.peer_id()));
    }

    #[tokio::test]
    async fn handshake_without_auth_bundle_times_out_and_keeps_sessions() {
        let (alice, bob) = (creds(), creds());
        let mut sessions = stale(&alice, &bob);
        let (mut dial, listen) = pair().await;
        preamble(&mut dial, MODE_FRESH, &alice.device).await;
        let bd = bnd();
        let script = async {
            let _ = dial.recv().await.unwrap();
            let _ = dial.recv().await.unwrap();
            let _cs = ConnectedSession::initiate(dial, &alice.device, bob.device.public(), &bd)
                .await
                .unwrap();
            // Handshake done; never send the auth bundle.
            std::future::pending::<()>().await;
        };
        let mut c = cache();
        let r = tokio::select! {
            r = negotiate_accept(listen, &bob, &mut sessions, &bd, NOW, &mut c, MEDIUM) => r,
            _ = script => unreachable!(),
        };
        assert!(matches!(r, Err(Error::Transport(_))));
        assert_eq!(sessions.len(), 1);
        assert!(sessions.contains_key(&alice.device.peer_id()));
    }

    #[tokio::test]
    async fn silent_listener_times_out_and_keeps_kept() {
        let (alice, bob, a, _b) = genuine();
        let mut k = Some(a);
        let (dial, _listen) = pair().await;
        let (r, d) = ids(&bob);
        let mut c = cache();
        let res =
            negotiate_dial_within(dial, &alice, &r, &d, &mut k, &bnd(), NOW, &mut c, SHORT).await;
        assert!(matches!(res, Err(Error::Transport(_))));
        assert!(k.is_some());
    }

    #[tokio::test]
    async fn listener_silent_after_hello_times_out_and_keeps_kept() {
        let (alice, bob, a, _b) = genuine();
        let mut k = Some(a);
        let (dial, mut listen) = pair().await;
        listen.send(&encode_listener_hello(&bob)).await.unwrap();
        let (r, d) = ids(&bob);
        let mut c = cache();
        let res =
            negotiate_dial_within(dial, &alice, &r, &d, &mut k, &bnd(), NOW, &mut c, SHORT).await;
        assert!(matches!(res, Err(Error::Transport(_))));
        assert!(k.is_some());
    }

    #[tokio::test]
    async fn listener_silent_at_auth_bundle_times_out_dialer_side() {
        let (alice, bob) = (creds(), creds());
        let (dial, mut listen) = pair().await;
        let bd = bnd();
        let hello = encode_listener_hello(&bob);
        let script = async {
            let p = listen.recv().await.unwrap();
            let who = PublicIdentity::from_bytes(&p[2 + NONCE_LEN..]).unwrap();
            listen.send(&hello).await.unwrap();
            listen.send(&[DECISION_FRESH]).await.unwrap();
            let _cs = ConnectedSession::accept(listen, &bob.device, &who, &bd)
                .await
                .unwrap();
            // Handshake done; never send our bundle.
            std::future::pending::<()>().await;
        };
        let (r, d) = ids(&bob);
        let mut k = None;
        let mut c = cache();
        let res = tokio::select! {
            res = negotiate_dial_within(dial, &alice, &r, &d, &mut k, &bd, NOW, &mut c, MEDIUM) => res,
            _ = script => unreachable!(),
        };
        assert!(matches!(res, Err(Error::Transport(_))));
        assert!(k.is_none());
    }

    #[tokio::test]
    async fn busy_listener_is_an_error_and_keeps_kept() {
        let (alice, bob, a, _b) = genuine();
        let mut k = Some(a);
        let (dial, mut listen) = pair().await;
        listen.send(&[DECISION_BUSY]).await.unwrap();
        let mut c = cache();
        let r = dial_to(dial, &alice, &bob, &mut k, &bnd(), &mut c).await;
        assert!(matches!(r, Err(Error::Transport(_))));
        assert!(k.is_some());

        let (dial, mut listen) = pair().await;
        listen.send(&[DECISION_BUSY]).await.unwrap();
        let (r, d) = ids(&bob);
        let res =
            negotiate_dial_within(dial, &alice, &r, &d, &mut k, &bnd(), NOW, &mut c, SHORT).await;
        assert!(matches!(res, Err(Error::Transport(_))));
        assert!(k.is_some());

        let mut none = None;
        let (dial, mut listen) = pair().await;
        listen.send(&[DECISION_BUSY]).await.unwrap();
        let r = dial_to(dial, &alice, &bob, &mut none, &bnd(), &mut c).await;
        assert!(matches!(r, Err(Error::Transport(_))));
        assert!(none.is_none());
    }

    #[tokio::test]
    async fn reply_busy_sends_one_byte_and_closes() {
        let alice = creds();
        let (mut dial, listen) = pair().await;
        preamble(&mut dial, MODE_FRESH, &alice.device).await; // stays unread
        reply_busy(listen).await.unwrap();
        assert_eq!(dial.recv().await.unwrap(), [DECISION_BUSY]);
        assert!(dial.recv().await.is_err());
    }

    #[test]
    fn chat_gate_claims_once_until_released() {
        let g = ChatGate::new();
        assert!(g.try_claim());
        assert!(!g.try_claim());
        g.release();
        assert!(g.try_claim());
    }

    // ---- bounded accept path ----

    fn sem(n: usize) -> Arc<tokio::sync::Semaphore> {
        Arc::new(tokio::sync::Semaphore::new(n))
    }

    #[test]
    fn listener_limits_are_set() {
        assert_eq!(MAX_BUSY_REPLIES, 8);
        assert_eq!(MAX_PENDING_ACCEPTS, 8);
        assert_eq!(NEGOTIATION_TIMEOUT, Duration::from_secs(15));
    }

    #[tokio::test]
    async fn spawn_bounded_without_permit_never_polls() {
        let (mut dial, listen) = pair().await;
        let polled = Arc::new(AtomicBool::new(false));
        let flag = polled.clone();
        let s = sem(0);
        let h = spawn_bounded(&s, async move {
            flag.store(true, Ordering::SeqCst);
            let _own = listen;
        });
        assert!(h.is_none());
        assert!(!polled.load(Ordering::SeqCst));
        // The owned connection was dropped: the peer sees a closed channel.
        assert!(dial.recv().await.is_err());
    }

    #[tokio::test]
    async fn spawn_bounded_caps_tasks_and_releases_on_abort() {
        const N: usize = 3;
        let s = sem(N);
        let mut handles = Vec::new();
        for _ in 0..N {
            let h = spawn_bounded(&s, std::future::pending::<()>());
            handles.push(h.expect("permit available"));
        }
        assert!(spawn_bounded(&s, std::future::pending::<()>()).is_none());
        for h in &handles {
            h.abort();
        }
        for h in handles {
            let _ = h.await;
        }
        assert_eq!(s.available_permits(), N);
    }

    #[tokio::test]
    async fn spawn_bounded_releases_permit_on_completion() {
        let s = sem(2);
        let h = spawn_bounded(&s, async { 7 }).unwrap();
        assert_eq!(h.await.unwrap(), 7);
        assert_eq!(s.available_permits(), 2);
    }

    #[tokio::test]
    async fn accept_within_times_out() {
        let r = tokio::time::timeout(
            Duration::from_secs(5),
            accept_within(SHORT, std::future::pending::<Result<()>>()),
        )
        .await
        .expect("accept_within must not hang");
        assert!(matches!(r, Err(Error::Transport(_))));
    }

    #[tokio::test]
    async fn accept_within_passes_results_through() {
        assert_eq!(accept_within(SHORT, async { Ok(5) }).await.unwrap(), 5);
        let r = accept_within(SHORT, async { Err::<(), _>(Error::Verify("x".into())) }).await;
        assert!(matches!(r, Err(Error::Verify(_))));
    }

    #[tokio::test]
    async fn pending_accept_does_not_block_another() {
        let s = sem(2);
        let a = spawn_bounded(
            &s,
            accept_within(SHORT, std::future::pending::<Result<()>>()),
        )
        .unwrap();
        let b = spawn_bounded(&s, accept_within(SHORT, async { Ok(()) })).unwrap();
        // B finishes while A is still waiting for its timeout.
        assert!(b.await.unwrap().is_ok());
        assert!(!a.is_finished());
        assert!(matches!(a.await.unwrap(), Err(Error::Transport(_))));
        assert_eq!(s.available_permits(), 2);
    }

    async fn no_busy(_c: MemoryConn) {}

    #[tokio::test]
    async fn dispatch_forwards_when_gate_free() {
        let (_dial, listen) = pair().await;
        let gate = ChatGate::new();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<MemoryConn>(1);
        let r = dispatch(listen, &gate, &tx, &sem(1), no_busy).await;
        assert_eq!(r, Dispatched::Forwarded);
        assert!(rx.recv().await.is_some());
        assert!(!gate.try_claim());
    }

    #[tokio::test]
    async fn dispatch_closed_releases_gate() {
        let (_dial, listen) = pair().await;
        let gate = ChatGate::new();
        let (tx, rx) = tokio::sync::mpsc::channel::<MemoryConn>(1);
        drop(rx);
        let r = dispatch(listen, &gate, &tx, &sem(1), no_busy).await;
        assert_eq!(r, Dispatched::Closed);
        assert!(gate.try_claim());
    }

    #[tokio::test]
    async fn dispatch_busy_replies_and_frees_permit() {
        let (mut dial, listen) = pair().await;
        let gate = ChatGate::new();
        assert!(gate.try_claim());
        let (tx, _rx) = tokio::sync::mpsc::channel::<MemoryConn>(1);
        let busy = sem(2);
        let r = dispatch(listen, &gate, &tx, &busy, |c| async move {
            let _ = tokio::time::timeout(NEGOTIATION_TIMEOUT, reply_busy(c)).await;
        })
        .await;
        assert_eq!(r, Dispatched::Busy);
        assert_eq!(dial.recv().await.unwrap(), [DECISION_BUSY]);
        tokio::time::timeout(Duration::from_secs(5), async {
            while busy.available_permits() != 2 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("busy permit released");
    }

    #[tokio::test]
    async fn dispatch_drops_when_busy_semaphore_full() {
        let (mut dial, listen) = pair().await;
        let gate = ChatGate::new();
        assert!(gate.try_claim());
        let (tx, _rx) = tokio::sync::mpsc::channel::<MemoryConn>(1);
        let invoked = Arc::new(AtomicBool::new(false));
        let flag = invoked.clone();
        let r = dispatch(listen, &gate, &tx, &sem(0), move |c| async move {
            flag.store(true, Ordering::SeqCst);
            let _ = reply_busy(c).await;
        })
        .await;
        assert_eq!(r, Dispatched::Dropped);
        assert!(!invoked.load(Ordering::SeqCst));
        assert!(dial.recv().await.is_err());
    }

    // ---- channel binding ----

    #[test]
    fn channel_binding_layout_and_asymmetry() {
        let (d, l) = ([1u8; 32], [2u8; 32]);
        let b = channel_binding(&d, &l);
        assert!(b.starts_with(b"lattice-net-cb-v1"));
        assert_eq!(b.len(), 81);
        assert_eq!(&b[17..49], &d);
        assert_eq!(&b[49..], &l);
        // Dialer view (own, remote) == listener view (remote, own).
        assert_eq!(channel_binding(&d, &l), channel_binding(&d, &l));
        assert_ne!(channel_binding(&l, &d), b);
        let mut d2 = d;
        d2[0] ^= 1;
        let mut l2 = l;
        l2[31] ^= 1;
        assert_ne!(channel_binding(&d2, &l), b);
        assert_ne!(channel_binding(&d, &l2), b);
    }

    // ---- ticket v3 ----

    #[test]
    fn ticket_v3_carries_root_and_device_ids() {
        let ep = id().public().ed25519_bytes();
        let addr = TicketAddr::from_parts(
            &ep,
            &["https://relay.example.org./"],
            &["192.0.2.1:4433".parse().unwrap()],
        )
        .unwrap();
        let c = creds();
        let (r, d) = ids(&c);
        let t = parse_ticket(&encode_ticket(&addr, &r, &d).unwrap()).unwrap();
        assert_eq!((t.root_id, t.device_id), (r, d));
        assert_eq!(t.endpoint_id, ep);
        assert_eq!(t.addr_bytes, addr.as_bytes());
    }

    #[test]
    fn check_endpoint_matches_only_equal_ids() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert!(check_endpoint(&a, &a).is_ok());
        assert!(matches!(check_endpoint(&a, &b), Err(Error::Verify(_))));
    }

    // ---- revocation cache ----

    #[test]
    fn cache_observe_rules() {
        let root = id();
        let mut cc = cache();
        let l1 = root.revoke_devices(1, 0, &[PeerId([1; 32])]).unwrap();
        let l1b = root.revoke_devices(1, 5, &[PeerId([2; 32])]).unwrap();
        let l2 = root.revoke_devices(2, 0, &[PeerId([3; 32])]).unwrap();
        let l0 = root.revoke_devices(0, 0, &[]).unwrap();
        assert!(cc.observe(l1));
        assert!(!cc.observe(l1b), "equal seq: first one wins");
        assert!(!cc.observe(l0));
        assert!(cc.revokes(&root.peer_id(), &PeerId([1; 32])));
        assert!(cc.observe(l2));
        assert!(!cc.revokes(&root.peer_id(), &PeerId([1; 32])));
        assert!(cc.revokes(&root.peer_id(), &PeerId([3; 32])));
        assert_eq!(cc.take_dirty().len(), 1);
        assert!(cc.take_dirty().is_empty());
    }

    #[test]
    fn cache_is_bounded_but_accepts_newer_for_known_roots() {
        let mut cc = cache();
        let first = Keypair::generate(CryptoSuite::Classical).unwrap();
        assert!(cc.observe(first.revoke_devices(1, 0, &[]).unwrap()));
        for _ in 1..MAX_CACHED_ROOTS {
            let k = Keypair::generate(CryptoSuite::Classical).unwrap();
            assert!(cc.observe(k.revoke_devices(1, 0, &[]).unwrap()));
        }
        let extra = Keypair::generate(CryptoSuite::Classical).unwrap();
        assert!(!cc.observe(extra.revoke_devices(1, 0, &[]).unwrap()));
        assert!(cc.get(&extra.peer_id()).is_none());
        assert!(cc.observe(first.revoke_devices(2, 0, &[]).unwrap()));
        assert_eq!(cc.lists.len(), MAX_CACHED_ROOTS);
    }

    // ---- expiry policy and dates ----

    #[test]
    fn cert_status_boundaries() {
        let (na, w) = (10_000u64, 100u64);
        assert_eq!(cert_status(na, na, w), CertStatus::RenewSoon);
        assert_eq!(cert_status(na + 1, na, w), CertStatus::Expired);
        assert_eq!(cert_status(na - w, na, w), CertStatus::RenewSoon);
        assert_eq!(cert_status(na - w - 1, na, w), CertStatus::Valid);
    }

    #[test]
    fn format_date_known_values() {
        assert_eq!(format_date(0), "1970-01-01");
        assert_eq!(format_date(951_782_400), "2000-02-29");
        assert_eq!(format_date(951_782_399), "2000-02-28");
        assert_eq!(format_date(1_700_000_000), "2023-11-14");
    }

    // ---- command line ----

    /// `parse_command` over `["lattice-net", ..a]`.
    fn cmd(a: &[&str]) -> Result<Command> {
        let mut args = vec!["lattice-net".to_string()];
        args.extend(a.iter().map(|s| s.to_string()));
        parse_command(&args)
    }

    // ---- safety numbers, verify-peer, kept sessions ----

    #[test]
    fn trust_lines_unverified_and_verified() {
        let (a, b) = (id(), id());
        let sn = safety_number(a.public(), b.public());
        let peer_hex = b.public().peer_id().to_string();

        let un = trust_lines(a.public(), b.public(), false);
        assert!(un.iter().any(|l| l.contains(&sn)
            && l.contains("compare this number with your peer by voice or in person")));
        assert!(un.iter().any(|l| l.contains(&sn.replace(' ', ""))));
        assert!(un.iter().any(
            |l| l.contains("UNVERIFIED peer — compare the safety number")
                && l.contains(&format!("verify-peer {peer_hex}"))
        ));
        assert!(!un.iter().any(|l| l.contains("verified peer (")));

        let ok = trust_lines(a.public(), b.public(), true);
        assert!(ok.iter().any(|l| l.contains("verified peer")));
        assert!(!ok.iter().any(|l| l.contains("UNVERIFIED")));

        // Both sides print the same safety number.
        let ba = trust_lines(b.public(), a.public(), false);
        assert_eq!(un[0], ba[0]);
        assert_eq!(un[1], ba[1]);
    }

    #[test]
    fn parse_command_verify_peer() {
        let hex = "ab".repeat(32);
        let full = Command::VerifyPeer(VerifyTarget::Full(PeerId([0xab; 32])));
        assert_eq!(cmd(&["verify-peer", &hex]).unwrap(), full);
        assert_eq!(cmd(&["verify-peer", &hex.to_uppercase()]).unwrap(), full);

        let id32: Vec<u8> = (0u8..32).collect();
        let fp_hex: String = id32[..20].iter().map(|b| format!("{b:02x}")).collect();
        let mut fp = [0u8; 20];
        fp.copy_from_slice(&id32[..20]);
        let want = Command::VerifyPeer(VerifyTarget::Fingerprint(fp));
        let spaced = fp_hex
            .as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(cmd(&["verify-peer", &spaced.join(" ")]).unwrap(), want);
        let mut args = vec!["verify-peer"];
        args.extend(spaced.iter().copied());
        assert_eq!(args.len(), 11);
        assert_eq!(cmd(&args).unwrap(), want);

        assert!(cmd(&["verify-peer"]).is_err());
        assert!(cmd(&["verify-peer", &"a".repeat(63)]).is_err());
        assert!(cmd(&["verify-peer", &"a".repeat(65)]).is_err());
        assert!(cmd(&["verify-peer", &"a".repeat(39)]).is_err());
        assert!(cmd(&["verify-peer", &"g".repeat(64)]).is_err());
        assert!(cmd(&["verify-peer", &"z".repeat(40)]).is_err());
    }

    #[test]
    fn resolve_verify_target_cases() {
        let a = PeerId([1; 32]);
        let mut b_bytes = [2u8; 32];
        b_bytes[25] = 9;
        let b = PeerId(b_bytes);
        assert_eq!(
            resolve_verify_target(&VerifyTarget::Full(a.clone()), &[]).unwrap(),
            a
        );
        let mut fp = [0u8; 20];
        fp.copy_from_slice(&b.0[..20]);
        let t = VerifyTarget::Fingerprint(fp);
        assert_eq!(
            resolve_verify_target(&t, &[a.clone(), b.clone()]).unwrap(),
            b
        );
        assert!(resolve_verify_target(&t, std::slice::from_ref(&a)).is_err());
        assert!(resolve_verify_target(&t, &[]).is_err());
        // Two candidates sharing the first 20 bytes are ambiguous.
        let mut b2_bytes = b.0;
        b2_bytes[31] ^= 1;
        let b2 = PeerId(b2_bytes);
        assert!(resolve_verify_target(&t, &[b, b2]).is_err());
    }

    #[tokio::test]
    async fn dialer_sends_nothing_before_the_hello_check_passes() {
        let (alice, bob) = (creds(), creds());
        // (a) same root, different device than the ticket names.
        let root = id();
        let named = creds_with(&root, FAR);
        let other_device = creds_with(&root, FAR);
        let (tr, td) = ids(&named);
        let hello_a = encode_listener_hello(&other_device);
        // (b) the right device, but the ticket names a different root.
        let (_, bd) = ids(&bob);
        let wrong_root = id().peer_id().0;
        let hello_b = encode_listener_hello(&bob);

        for (hello, ticket_root, ticket_device) in [(hello_a, tr, td), (hello_b, wrong_root, bd)] {
            let (dial, mut listen) = pair().await;
            listen.send(&hello).await.unwrap();
            listen.send(&[DECISION_FRESH]).await.unwrap();
            let mut k = None;
            let mut c = cache();
            let r = negotiate_dial(
                dial,
                &alice,
                &ticket_root,
                &ticket_device,
                &mut k,
                &bnd(),
                NOW,
                &mut c,
            )
            .await;
            assert!(r.is_err());
            // The dialer end is dropped now: exactly the preamble was sent.
            let first = tokio::time::timeout(MEDIUM, listen.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(first[0], WIRE_VERSION);
            let next = tokio::time::timeout(MEDIUM, listen.recv()).await.unwrap();
            assert!(next.is_err());
        }
    }

    fn pidn(n: u8) -> PeerId {
        PeerId([n; 32])
    }

    #[test]
    fn kept_sessions_evict_least_recently_used() {
        let mut s: KeptSessions<u8> = KeptSessions::with_cap(4);
        let mut evicted = Vec::new();
        for n in 1..=6u8 {
            evicted.extend(s.insert(pidn(n), n));
        }
        assert_eq!(s.len(), 4);
        assert_eq!(evicted, vec![pidn(1), pidn(2)]);
        assert!(!s.contains_key(&pidn(1)) && !s.contains_key(&pidn(2)));
        assert!((3..=6).all(|n| s.contains_key(&pidn(n))));
        // Re-inserting 3 refreshes it; inserting 7 then evicts 4, not 3.
        assert!(s.insert(pidn(3), 33).is_empty());
        assert_eq!(s.get(&pidn(3)), Some(&33));
        assert_eq!(s.insert(pidn(7), 7), vec![pidn(4)]);
        assert!(s.contains_key(&pidn(3)));
        assert_eq!(s.remove(&pidn(3)), Some(33));
        assert!(!s.is_empty());
    }

    #[test]
    fn kept_sessions_production_cap() {
        assert_eq!(MAX_KEPT_SESSIONS, 64);
        let mut s = KeptSessions::<u8>::new();
        assert_eq!(s.cap, 64);
        for n in 0..(MAX_KEPT_SESSIONS + 10) as u8 {
            s.insert(pidn(n), n);
        }
        assert_eq!(s.len(), MAX_KEPT_SESSIONS);
        for n in 0..(MAX_KEPT_SESSIONS + 10) as u8 {
            assert_eq!(s.contains_key(&pidn(n)), n >= 10, "{n}");
        }
    }

    #[test]
    fn parse_command_subcommands() {
        assert_eq!(cmd(&[]).unwrap(), Command::Usage);
        assert_eq!(cmd(&["bogus"]).unwrap(), Command::Usage);
        assert_eq!(cmd(&["listen"]).unwrap(), Command::Listen);
        assert_eq!(cmd(&["whoami"]).unwrap(), Command::Whoami);
        assert_eq!(
            cmd(&["connect", "abc"]).unwrap(),
            Command::Connect("abc".into())
        );
        assert!(cmd(&["connect"]).is_err());
    }

    #[test]
    fn parse_command_recovery_phrase_requires_flag() {
        assert_eq!(
            cmd(&["show-recovery-phrase", "--i-understand"]).unwrap(),
            Command::ShowRecoveryPhrase
        );
        match cmd(&["show-recovery-phrase"]) {
            Err(Error::Other(m)) => assert!(m.contains("--i-understand")),
            other => panic!("unexpected: {other:?}"),
        }
        assert!(cmd(&["show-recovery-phrase", "--yes"]).is_err());
        assert!(cmd(&["show-recovery-phrase", "--i-understand", "x"]).is_err());
    }

    #[test]
    fn parse_command_new_commands() {
        assert_eq!(cmd(&["renew-device"]).unwrap(), Command::RenewDevice);
        assert!(cmd(&["renew-device", "x"]).is_err());

        let hex = "ab".repeat(32);
        assert_eq!(
            cmd(&["revoke-device", &hex]).unwrap(),
            Command::RevokeDevice(PeerId([0xab; 32]))
        );
        assert_eq!(
            cmd(&["revoke-device", &hex.to_uppercase()]).unwrap(),
            Command::RevokeDevice(PeerId([0xab; 32]))
        );
        assert!(cmd(&["revoke-device"]).is_err());
        assert!(cmd(&["revoke-device", "abcd"]).is_err());
        assert!(cmd(&["revoke-device", &"zz".repeat(32)]).is_err());
        assert!(cmd(&["revoke-device", &hex, "extra"]).is_err());

        assert_eq!(
            cmd(&["forget-root", "--i-understand"]).unwrap(),
            Command::ForgetRoot
        );
        for bad in [&["forget-root"][..], &["forget-root", "--yes"][..]] {
            match cmd(bad) {
                Err(Error::Other(m)) => assert!(m.contains("--i-understand")),
                other => panic!("unexpected: {other:?}"),
            }
        }

        assert_eq!(cmd(&["import-root"]).unwrap(), Command::ImportRoot);
        match cmd(&["import-root", "abandon", "abandon"]) {
            Err(Error::Other(m)) => assert!(m.contains("stdin")),
            other => panic!("unexpected: {other:?}"),
        }
    }
}
