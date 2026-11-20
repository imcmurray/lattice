//! `lattice-net` — a real two-device P2P chat over Lattice.
//!
//! On device A:  `lattice-net listen`            → prints a TICKET
//! On device B:  `lattice-net connect <ticket>`  → dials A
//! Either side:  `lattice-net whoami`            → prints your peer id + fingerprint
//!               `lattice-net show-recovery-phrase --i-understand`
//!
//! Each side loads a persistent PQ-hybrid identity via [`IdentityStore`] (OS
//! keychain, else an age-encrypted file), then runs the hybrid-KEM +
//! Double-Ratchet handshake over an iroh QUIC connection and relays stdin lines
//! as end-to-end-encrypted messages.
//!
//! The TICKET is signed by the listener's Lattice identity and names its iroh
//! endpoint. The dialer verifies that signature *before dialing*, then checks
//! that it actually reached the endpoint the ticket names. Both the handshake
//! transcript and the resume proofs are bound to the dialer's and listener's
//! iroh endpoint ids (`lattice-net-cb-v1`), so a session cannot be replayed onto
//! a different QUIC connection. The ticket still grants reachability, and a
//! first contact is trust-on-first-use: compare the printed fingerprints
//! (`lattice-net whoami`) with your peer out of band.
//!
//! Reconnects use **session resumption** (ADR-006): on a drop, each side keeps
//! its `SecureSession`; the dialer's reconnect preamble signals `resume`, and if
//! the listener still holds that peer's session both sides exchange HMAC proofs
//! keyed by the session's secret and the channel binding (`lattice-resume-v2`);
//! only when both verify do they rebind to the new connection with no
//! re-handshake. If either side lost its state (e.g. a restart), they fall back
//! to a fresh handshake.
//!
//! Every pre-chat step (preamble, resume challenge/response, handshake) is
//! limited to 15 s on both sides, so one slow or silent peer cannot stall the
//! listener. A separate acceptor task keeps accepting while a chat runs; any
//! connection that arrives while a chat (or negotiation) is in progress gets a
//! one-byte "busy" reply and is dropped, and a dialer treats that as a failed
//! attempt and retries with backoff.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use lattice::identity::storage::IdentityStore;
use lattice::prelude::*;
use lattice::session::{resume_nonce, ResumeRole};
use lattice::transport::{
    parse_ticket, read_frame, ticket_message, write_frame, IrohConn, IrohTransport,
};
use tokio::io::{AsyncBufReadExt, BufReader, Lines, Stdin};
use tokio::sync::{Mutex, Notify};

// Connection preamble: the dialer's first frame is
// [mode] ++ dialer_nonce[32] ++ its identity bundle (nonce is zero for fresh).
const MODE_FRESH: u8 = 0;
const MODE_RESUME: u8 = 1;
// The listener's reply: fresh handshake, or a resume challenge
// [DECISION_CHALLENGE] ++ listener_nonce[32] ++ listener_tag[32]; the dialer then
// answers with its own 32-byte tag (see `ResumeRole`). Resuming needs both proofs.
const DECISION_FRESH: u8 = 0;
// Legacy unauthenticated resume: no longer sent; a dialer receiving it errors.
const DECISION_RESUMED: u8 = 1;
const DECISION_CHALLENGE: u8 = 2;
/// Listener reply to a connection that arrives while a chat is in progress.
const DECISION_BUSY: u8 = 3;
/// Upper bound on every pre-chat step (preamble, resume challenge/response,
/// v3 handshake) on both the listener and the dialer.
const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(15);
const NONCE_LEN: usize = 32;
const TAG_LEN: usize = 32;
/// Domain separator of the channel binding passed to the handshake and resume.
const CB_DOMAIN: &[u8] = b"lattice-net-cb-v1";

const USAGE: &str = "usage:
  lattice-net listen
  lattice-net connect <ticket>
  lattice-net whoami
  lattice-net show-recovery-phrase --i-understand";

const RECOVERY_REFUSAL: &str = "the recovery phrase is the root secret of your identity:
anyone who has it can impersonate you. If you really want it printed, rerun with
`lattice-net show-recovery-phrase --i-understand`";

const RECOVERY_WARNING: &str = "[lattice-net] ⚠ this recovery phrase controls your identity.
Keep it secret and store it offline: anyone who has it can impersonate you.";

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
    Usage,
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
        _ => Ok(Command::Usage),
    }
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

/// Verify a ticket's signature under the identity it carries (pure; no network).
fn verify_ticket(
    app_identity: &[u8],
    app_sig: &[u8],
    endpoint_id: &[u8; 32],
) -> Result<PublicIdentity> {
    let id = PublicIdentity::from_bytes(app_identity)?;
    let msg = ticket_message(endpoint_id, app_identity);
    if app_sig.is_empty() || !id.verify(&msg, &Signature(app_sig.to_vec())) {
        return Err(Error::Verify("ticket signature invalid".into()));
    }
    Ok(id)
}

/// Fail unless the connection reached the endpoint we expected.
fn check_endpoint(expected: &[u8; 32], remote: &[u8; 32]) -> Result<()> {
    if expected != remote {
        return Err(Error::Verify("endpoint id mismatch".into()));
    }
    Ok(())
}

/// Print the peer's fingerprint for out-of-band comparison.
fn announce_peer(peer: &PeerId, what: &str) {
    eprintln!("[lattice-net] {what} — type messages:");
    eprintln!(
        "[lattice-net] peer fingerprint: {} — compare this with your peer out of band",
        peer.fingerprint()
    );
}

async fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    // Parse first: bad usage must not touch (or create) any identity.
    let cmd = parse_command(&args)?;
    if cmd == Command::Usage {
        eprintln!("{USAGE}");
        return Ok(());
    }

    // Persistent identity: OS keychain if available, else an age-encrypted file.
    let loaded = IdentityStore::open_default().load_or_create(CryptoSuite::Hybrid)?;
    let me = loaded.keypair;
    let note = if loaded.created {
        " (new identity created)"
    } else {
        ""
    };
    if loaded.migrated {
        eprintln!(
            "[lattice-net] ⚠ migrated your legacy plaintext identity into secure storage ({:?}); \
             the legacy plaintext file was removed.",
            loaded.backend
        );
    }

    match cmd {
        Command::Whoami => {
            println!("peer id: {}", me.peer_id());
            println!("fingerprint: {}", me.peer_id().fingerprint());
            return Ok(());
        }
        Command::ShowRecoveryPhrase => {
            eprintln!("{RECOVERY_WARNING}");
            println!("{}", me.mnemonic());
            return Ok(());
        }
        _ => {}
    }

    eprintln!(
        "[lattice-net] your fingerprint: {} [stored via {:?}]{note}",
        me.peer_id().fingerprint(),
        loaded.backend
    );

    // Read stdin once and reuse it across reconnects (typed input isn't lost).
    let lines = BufReader::new(tokio::io::stdin()).lines();

    match cmd {
        Command::Listen => listen(me, lines).await,
        Command::Connect(ticket) => connect(me, ticket, lines).await,
        _ => Ok(()),
    }
}

/// Listener loop: accept connections, negotiate resume-vs-fresh, chat, and keep
/// each peer's `SecureSession` so a reconnect can resume without re-handshaking.
async fn listen(me: Keypair, mut lines: StdinLines) -> Result<()> {
    let t = IrohTransport::bind().await?;
    eprintln!("[lattice-net] coming online (contacting relay)...");
    // The ticket is signed by our Lattice identity and names our iroh endpoint.
    let app_identity = me.public().to_bytes();
    let msg = ticket_message(&t.endpoint_id_bytes(), &app_identity);
    let app_sig = me.sign(&msg).0;
    let ticket = t.ticket(&app_identity, &app_sig).await?;
    println!("\n=== TICKET (copy to the other device) ===\n{ticket}\n=========================================\n");

    // Acceptor task: keeps accepting while a chat runs. A free gate hands the
    // connection to this loop; a taken gate gets a one-byte "busy" reply.
    let t = Arc::new(t);
    let gate = Arc::new(ChatGate::new());
    let (tx, mut rx) = tokio::sync::mpsc::channel::<IrohConn>(1);
    let acceptor = {
        let t = t.clone();
        let gate = gate.clone();
        tokio::spawn(async move {
            loop {
                let conn = match t.accept_conn().await {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("[lattice-net] accept failed: {e} — still listening");
                        continue;
                    }
                };
                if gate.try_claim() {
                    if tx.send(conn).await.is_err() {
                        break;
                    }
                } else {
                    tokio::spawn(async move {
                        let _ = tokio::time::timeout(NEGOTIATION_TIMEOUT, reply_busy(conn)).await;
                    });
                }
            }
        })
    };

    let mut sessions: HashMap<PeerId, SecureSession> = HashMap::new();
    loop {
        eprintln!("[lattice-net] waiting for a peer to connect...");
        let Some(conn) = rx.recv().await else {
            break; // acceptor ended
        };
        let binding = channel_binding(&conn.remote_endpoint_id(), &t.endpoint_id_bytes());
        let limit = NEGOTIATION_TIMEOUT;
        let accepted = negotiate_accept(conn, &me, &mut sessions, &binding, limit).await;
        let (peer_id, sess) = match accepted {
            Ok(x) => x,
            Err(e) => {
                eprintln!("[lattice-net] negotiation failed: {e} — still listening");
                gate.release();
                continue;
            }
        };
        match chat(sess, &mut lines).await {
            Ok((Outcome::LocalClosed, _)) => {
                eprintln!("[lattice-net] input closed — exiting");
                break;
            }
            Ok((Outcome::PeerDisconnected, recovered)) => {
                if let Some(s) = recovered {
                    sessions.insert(peer_id, s); // keep for a future resume
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

/// `accept_or_resume` bounded by `limit`. A timed-out future is dropped
/// mid-await; `accept_or_resume` only mutates `sessions` after its last
/// `.await`, so a timeout leaves the map unchanged (keep it that way).
async fn negotiate_accept<C: Connection>(
    conn: C,
    me: &Keypair,
    sessions: &mut HashMap<PeerId, SecureSession>,
    binding: &[u8],
    limit: Duration,
) -> Result<(PeerId, ConnectedSession<C>)> {
    match tokio::time::timeout(limit, accept_or_resume(conn, me, sessions, binding)).await {
        Ok(r) => r,
        Err(_) => Err(Error::Transport(format!(
            "negotiation timed out after {limit:?}"
        ))),
    }
}

/// `negotiate_dial` bounded by `limit`.
async fn negotiate_dial_within<C: Connection>(
    conn: C,
    me: &Keypair,
    peer: &PublicIdentity,
    kept: &mut Option<SecureSession>,
    binding: &[u8],
    limit: Duration,
) -> Result<ConnectedSession<C>> {
    match tokio::time::timeout(limit, negotiate_dial(conn, me, peer, kept, binding)).await {
        Ok(r) => r,
        Err(_) => Err(Error::Transport(format!(
            "negotiation timed out after {limit:?}"
        ))),
    }
}

/// Read the dialer's preamble; resume a kept session if asked and available,
/// otherwise run a fresh handshake. Returns the peer id and the live session.
/// `binding` is the channel binding of this connection.
async fn accept_or_resume<C: Connection>(
    mut conn: C,
    me: &Keypair,
    sessions: &mut HashMap<PeerId, SecureSession>,
    binding: &[u8],
) -> Result<(PeerId, ConnectedSession<C>)> {
    let preamble = conn.recv().await?;
    if preamble.len() < 1 + NONCE_LEN {
        return Err(Error::Verify("short preamble".into()));
    }
    let mode = preamble[0];
    let mut dialer_nonce = [0u8; NONCE_LEN];
    dialer_nonce.copy_from_slice(&preamble[1..1 + NONCE_LEN]);
    let peer = PublicIdentity::from_bytes(&preamble[1 + NONCE_LEN..])?;
    let peer_id = peer.peer_id();

    if mode == MODE_RESUME {
        if let Some(kept) = sessions.get(&peer_id) {
            // Prove we hold the session, then require the dialer's proof
            // *before* the session is removed from the map or used.
            let listener_nonce = resume_nonce()?;
            let listener_tag = kept.resume_tag(
                ResumeRole::Listener,
                &peer,
                me.public(),
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
            kept.verify_resume_tag(
                ResumeRole::Dialer,
                &peer,
                me.public(),
                &dialer_nonce,
                &listener_nonce,
                binding,
                &tag,
            )?;
            let sess = sessions
                .remove(&peer_id)
                .ok_or_else(|| Error::Verify("kept session vanished during resume".into()))?;
            announce_peer(&peer_id, "peer resumed — no re-handshake");
            return Ok((peer_id, ConnectedSession::resume(conn, sess)));
        }
    }
    // Fresh handshake (requested, or resume with no kept session).
    conn.send(&[DECISION_FRESH]).await?;
    let cs = ConnectedSession::accept(conn, me, &peer, binding).await?;
    // Only a successful handshake replaces the stale session for this peer.
    sessions.remove(&peer_id);
    announce_peer(&peer_id, "peer connected (fresh session)");
    Ok((peer_id, cs))
}

/// What the dialer learned from (and verified about) the ticket, before dialing.
struct VerifiedTicket {
    /// The listener's identity, as proven by the ticket signature.
    identity: PublicIdentity,
    /// The identity bytes exactly as carried by the ticket.
    identity_bytes: Vec<u8>,
    /// The iroh endpoint id the ticket names (covered by the signature).
    endpoint_id: [u8; 32],
}

/// Dialer loop: dial, negotiate resume-vs-fresh, chat; keep the `SecureSession`
/// across drops so the next dial can resume.
async fn connect(me: Keypair, ticket: String, mut lines: StdinLines) -> Result<()> {
    // Verify the ticket before binding or dialing; a bad ticket is fatal, not retried.
    let (identity_bytes, sig, endpoint_id) = parse_ticket(&ticket)?;
    let identity = verify_ticket(&identity_bytes, &sig, &endpoint_id)?;
    eprintln!(
        "[lattice-net] peer fingerprint (from ticket): {} — compare this with your peer out of band",
        identity.peer_id().fingerprint()
    );
    let verified = VerifiedTicket {
        identity,
        identity_bytes,
        endpoint_id,
    };

    let t = IrohTransport::bind().await?;
    let mut kept: Option<SecureSession> = None;
    let mut backoff = 1u64;
    loop {
        match dial_once(&t, &ticket, &verified, &me, &mut kept, &mut lines).await {
            Ok(Outcome::LocalClosed) => {
                eprintln!("[lattice-net] input closed — exiting");
                break;
            }
            Ok(Outcome::PeerDisconnected) => {
                backoff = 1;
                eprintln!("[lattice-net] peer disconnected — reconnecting...");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
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
/// then either resume the kept session (after a mutual proof) or run a fresh
/// handshake. `kept` is only taken once the outcome is certain. `binding` is
/// the channel binding of this connection.
async fn negotiate_dial<C: Connection>(
    mut conn: C,
    me: &Keypair,
    peer: &PublicIdentity,
    kept: &mut Option<SecureSession>,
    binding: &[u8],
) -> Result<ConnectedSession<C>> {
    // Preamble: [mode] ++ dialer nonce ++ our identity bundle.
    let (mode, dialer_nonce) = if kept.is_some() {
        (MODE_RESUME, resume_nonce()?)
    } else {
        (MODE_FRESH, [0u8; NONCE_LEN])
    };
    let mut preamble = vec![mode];
    preamble.extend_from_slice(&dialer_nonce);
    preamble.extend_from_slice(&me.public().to_bytes());
    conn.send(&preamble).await?;

    let decision = conn.recv().await?;
    match decision.first().copied() {
        Some(DECISION_FRESH) => {
            if kept.take().is_some() {
                eprintln!("[lattice-net] peer couldn't resume — fresh handshake");
            }
            let cs = ConnectedSession::initiate(conn, me, peer, binding).await?;
            announce_peer(&peer.peer_id(), "connected (fresh session)");
            Ok(cs)
        }
        Some(DECISION_CHALLENGE) => {
            let Some(sess) = kept.as_ref() else {
                return Err(Error::Verify(
                    "peer sent a resume challenge but no session is kept".into(),
                ));
            };
            if decision.len() != 1 + NONCE_LEN + TAG_LEN {
                return Err(Error::Verify("malformed resume challenge".into()));
            }
            let mut listener_nonce = [0u8; NONCE_LEN];
            listener_nonce.copy_from_slice(&decision[1..1 + NONCE_LEN]);
            let listener_tag = &decision[1 + NONCE_LEN..];
            sess.verify_resume_tag(
                ResumeRole::Listener,
                me.public(),
                peer,
                &dialer_nonce,
                &listener_nonce,
                binding,
                listener_tag,
            )?;
            let dialer_tag = sess.resume_tag(
                ResumeRole::Dialer,
                me.public(),
                peer,
                &dialer_nonce,
                &listener_nonce,
                binding,
            );
            conn.send(&dialer_tag).await?;
            let sess = kept
                .take()
                .ok_or_else(|| Error::Verify("kept session vanished during resume".into()))?;
            announce_peer(&peer.peer_id(), "resumed — no re-handshake");
            Ok(ConnectedSession::resume(conn, sess))
        }
        Some(DECISION_BUSY) => Err(Error::Transport("listener is busy".into())),
        Some(DECISION_RESUMED) => Err(Error::Verify(
            "peer sent legacy unauthenticated resume decision".into(),
        )),
        _ => Err(Error::Verify("unrecognised resume decision".into())),
    }
}

async fn dial_once(
    t: &IrohTransport,
    ticket: &str,
    verified: &VerifiedTicket,
    me: &Keypair,
    kept: &mut Option<SecureSession>,
    lines: &mut StdinLines,
) -> Result<Outcome> {
    eprintln!("[lattice-net] dialing peer...");
    let (peer_bytes, _sig, ticket_ep, conn) = t.connect_ticket(ticket).await?;
    // The ticket we dialed must be the one we verified, and we must have
    // reached the endpoint it names.
    check_endpoint(&verified.endpoint_id, &ticket_ep)?;
    check_endpoint(&ticket_ep, &conn.remote_endpoint_id())?;
    if peer_bytes != verified.identity_bytes {
        return Err(Error::Verify("ticket identity changed".into()));
    }
    let binding = channel_binding(&t.endpoint_id_bytes(), &conn.remote_endpoint_id());

    let limit = NEGOTIATION_TIMEOUT;
    let cs = negotiate_dial_within(conn, me, &verified.identity, kept, &binding, limit).await?;

    match chat(cs, lines).await {
        Ok((Outcome::PeerDisconnected, recovered)) => {
            *kept = recovered; // keep for resume (None if unrecoverable)
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

    fn id() -> Keypair {
        Keypair::generate(CryptoSuite::Hybrid).unwrap()
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

    fn stale(alice: &Keypair, bob: &Keypair) -> HashMap<PeerId, SecureSession> {
        let (m1, pending) = SecureSession::initiate(bob, alice.public(), b"").unwrap();
        let (m2, _) = SecureSession::respond(alice, bob.public(), b"", &m1).unwrap();
        let s = pending.finish(&m2).unwrap();
        HashMap::from([(alice.peer_id(), s)])
    }

    async fn preamble(conn: &mut MemoryConn, mode: u8, who: &Keypair) {
        let mut p = vec![mode];
        p.extend_from_slice(&[0u8; NONCE_LEN]);
        p.extend_from_slice(&who.public().to_bytes());
        conn.send(&p).await.unwrap();
    }

    #[tokio::test]
    async fn forged_initiator_keeps_stale_session() {
        let (alice, bob, eve) = (id(), id(), id());
        let mut sessions = stale(&alice, &bob);
        let (mut dial, listen) = pair().await;
        preamble(&mut dial, MODE_FRESH, &alice).await;
        let b = bnd();
        // Eve's handshake, claimed to come from Alice.
        let dialer = async {
            // The listener's decision byte comes first, then the handshake.
            assert_eq!(dial.recv().await.unwrap(), [DECISION_FRESH]);
            ConnectedSession::initiate(dial, &eve, bob.public(), &b).await
        };
        let (d, r) = tokio::join!(dialer, accept_or_resume(listen, &bob, &mut sessions, &b));
        assert!(r.is_err());
        assert!(d.is_err());
        assert!(sessions.contains_key(&alice.peer_id()));
    }

    #[tokio::test]
    async fn genuine_fresh_handshake_replaces_stale_session() {
        let (alice, bob) = (id(), id());
        let mut sessions = stale(&alice, &bob);
        let (mut dial, listen) = pair().await;
        preamble(&mut dial, MODE_FRESH, &alice).await;
        let b = bnd();
        let dialer = async {
            assert_eq!(dial.recv().await.unwrap(), [DECISION_FRESH]);
            ConnectedSession::initiate(dial, &alice, bob.public(), &b).await
        };
        let (d, r) = tokio::join!(dialer, accept_or_resume(listen, &bob, &mut sessions, &b));
        assert!(d.is_ok());
        assert!(r.is_ok());
        assert!(!sessions.contains_key(&alice.peer_id()));
    }

    #[tokio::test]
    async fn fresh_handshake_with_mismatched_bindings_fails() {
        let (alice, bob) = (id(), id());
        let mut sessions = HashMap::new();
        let (dial, listen) = pair().await;
        let b_dial = channel_binding(&[1u8; 32], &[2u8; 32]);
        let b_listen = channel_binding(&[1u8; 32], &[3u8; 32]);
        let mut kept = None;
        let (d, r) = tokio::join!(
            negotiate_dial(dial, &alice, bob.public(), &mut kept, &b_dial),
            accept_or_resume(listen, &bob, &mut sessions, &b_listen)
        );
        assert!(matches!(r, Err(Error::Verify(_))));
        assert!(d.is_err());
        assert!(sessions.is_empty());
    }

    #[tokio::test]
    async fn genuine_resume_with_mutual_proof_succeeds() {
        let (alice, bob, a, b) = genuine();
        let mut sessions = HashMap::from([(alice.peer_id(), b)]);
        let mut kept = Some(a);
        let (dial, listen) = pair().await;
        let bd = bnd();
        let (d, l) = tokio::join!(
            negotiate_dial(dial, &alice, bob.public(), &mut kept, &bd),
            accept_or_resume(listen, &bob, &mut sessions, &bd)
        );
        let (mut d, (_, mut l)) = (d.unwrap(), l.unwrap());
        assert!(kept.is_none());
        assert!(!sessions.contains_key(&alice.peer_id()));
        d.send(b"hello").await.unwrap();
        assert_eq!(l.recv().await.unwrap(), b"hello");
        l.send(b"world").await.unwrap();
        assert_eq!(d.recv().await.unwrap(), b"world");
    }

    #[tokio::test]
    async fn resume_with_mismatched_bindings_fails_and_keeps_state() {
        let (alice, bob, a, b) = genuine();
        let mut sessions = HashMap::from([(alice.peer_id(), b)]);
        let mut kept = Some(a);
        let (dial, listen) = pair().await;
        let b_dial = channel_binding(&[1u8; 32], &[2u8; 32]);
        let b_listen = channel_binding(&[1u8; 32], &[3u8; 32]);
        let (d, l) = tokio::join!(
            negotiate_dial(dial, &alice, bob.public(), &mut kept, &b_dial),
            accept_or_resume(listen, &bob, &mut sessions, &b_listen)
        );
        assert!(d.is_err());
        assert!(l.is_err());
        assert!(kept.is_some());
        assert!(sessions.contains_key(&alice.peer_id()));
    }

    #[tokio::test]
    async fn impostor_with_legacy_preamble_cannot_resume() {
        let (alice, bob) = (id(), id());
        let mut sessions = stale(&alice, &bob);
        let (mut dial, listen) = pair().await;
        let mut p = vec![MODE_RESUME];
        p.extend_from_slice(&alice.public().to_bytes());
        dial.send(&p).await.unwrap();
        let r = accept_or_resume(listen, &bob, &mut sessions, &bnd()).await;
        assert!(r.is_err());
        assert!(sessions.contains_key(&alice.peer_id()));
    }

    /// Genuine Alice–Bob pair: (alice, bob, alice's session, bob's session).
    fn genuine() -> (Keypair, Keypair, SecureSession, SecureSession) {
        let (alice, bob) = (id(), id());
        let (m1, pending) = SecureSession::initiate(&alice, bob.public(), b"").unwrap();
        let (m2, b) = SecureSession::respond(&bob, alice.public(), b"", &m1).unwrap();
        let a = pending.finish(&m2).unwrap();
        (alice, bob, a, b)
    }

    fn resume_preamble(nonce: &[u8; NONCE_LEN], who: &Keypair) -> Vec<u8> {
        let mut p = vec![MODE_RESUME];
        p.extend_from_slice(nonce);
        p.extend_from_slice(&who.public().to_bytes());
        p
    }

    #[tokio::test]
    async fn impostor_with_bogus_tag_cannot_resume() {
        let (alice, bob, _a, b) = genuine();
        let mut sessions = HashMap::from([(alice.peer_id(), b)]);
        let (mut eve, listen) = pair().await;
        eve.send(&resume_preamble(&[7u8; NONCE_LEN], &alice))
            .await
            .unwrap();
        eve.send(&[0xAA; TAG_LEN]).await.unwrap();
        let r = accept_or_resume(listen, &bob, &mut sessions, &bnd()).await;
        assert!(r.is_err());
        assert!(sessions.contains_key(&alice.peer_id()));
        let reply = eve.recv().await.unwrap();
        assert_eq!(reply.len(), 1 + NONCE_LEN + TAG_LEN);
        assert_eq!(reply[0], DECISION_CHALLENGE);
    }

    #[tokio::test]
    async fn impostor_hanging_up_cannot_resume() {
        let (alice, bob, _a, b) = genuine();
        let mut sessions = HashMap::from([(alice.peer_id(), b)]);
        let (mut eve, listen) = pair().await;
        eve.send(&resume_preamble(&[7u8; NONCE_LEN], &alice))
            .await
            .unwrap();
        drop(eve);
        let r = accept_or_resume(listen, &bob, &mut sessions, &bnd()).await;
        assert!(r.is_err());
        assert!(sessions.contains_key(&alice.peer_id()));
    }

    #[tokio::test]
    async fn dialer_rejects_wrong_listener_tag_and_checks_preamble() {
        let (alice, bob, a, _b) = genuine();
        let mut kept = Some(a);
        let (dial, mut listen) = pair().await;
        let script = async {
            let p = listen.recv().await.unwrap();
            let mut reply = vec![DECISION_CHALLENGE];
            reply.extend_from_slice(&[3u8; NONCE_LEN]);
            reply.extend_from_slice(&[0xBB; TAG_LEN]);
            listen.send(&reply).await.unwrap();
            p
        };
        let bd = bnd();
        let (r, p) = tokio::join!(
            negotiate_dial(dial, &alice, bob.public(), &mut kept, &bd),
            script
        );
        assert!(r.is_err());
        assert!(kept.is_some());
        let ib = alice.public().to_bytes();
        assert_eq!(p[0], MODE_RESUME);
        assert_eq!(p.len(), 1 + NONCE_LEN + ib.len());
        assert_eq!(&p[1 + NONCE_LEN..], &ib[..]);
    }

    #[tokio::test]
    async fn dialer_rejects_legacy_resumed_decision() {
        let (alice, bob, a, _b) = genuine();
        let mut kept = Some(a);
        let (dial, mut listen) = pair().await;
        listen.send(&[DECISION_RESUMED]).await.unwrap();
        let r = negotiate_dial(dial, &alice, bob.public(), &mut kept, &bnd()).await;
        assert!(r.is_err());
        assert!(kept.is_some());
    }

    #[tokio::test]
    async fn dialer_rejects_challenge_without_kept_session() {
        let (alice, bob) = (id(), id());
        let mut kept = None;
        let (dial, mut listen) = pair().await;
        let mut reply = vec![DECISION_CHALLENGE];
        reply.extend_from_slice(&[0u8; NONCE_LEN + TAG_LEN]);
        listen.send(&reply).await.unwrap();
        let r = negotiate_dial(dial, &alice, bob.public(), &mut kept, &bnd()).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn short_preambles_are_rejected() {
        let (alice, bob) = (id(), id());
        for n in [0usize, 1, 32] {
            let mut sessions = stale(&alice, &bob);
            let (mut dial, listen) = pair().await;
            dial.send(&vec![MODE_RESUME; n]).await.unwrap();
            let r = accept_or_resume(listen, &bob, &mut sessions, &bnd()).await;
            assert!(r.is_err(), "len {n}");
            assert!(sessions.contains_key(&alice.peer_id()));
        }
    }

    #[tokio::test]
    async fn fresh_dial_preamble_has_zero_nonce() {
        let (alice, bob) = (id(), id());
        let mut kept = None;
        let (dial, mut listen) = pair().await;
        let script = async {
            let p = listen.recv().await.unwrap();
            listen.send(&[0xFF]).await.unwrap(); // unknown decision → dialer errors
            p
        };
        let bd = bnd();
        let (r, p) = tokio::join!(
            negotiate_dial(dial, &alice, bob.public(), &mut kept, &bd),
            script
        );
        assert!(r.is_err());
        assert_eq!(p[0], MODE_FRESH);
        assert!(p[1..1 + NONCE_LEN].iter().all(|b| *b == 0));
    }

    // ---- negotiation timeouts, busy reply, gate ----

    const SHORT: Duration = Duration::from_millis(50);

    #[test]
    fn negotiation_constants() {
        assert_eq!(NEGOTIATION_TIMEOUT, Duration::from_secs(15));
        assert_eq!(DECISION_BUSY, 3);
    }

    #[tokio::test]
    async fn silent_dialer_times_out_and_keeps_sessions() {
        let (alice, bob) = (id(), id());
        let mut sessions = stale(&alice, &bob);
        let (_dial, listen) = pair().await;
        let r = negotiate_accept(listen, &bob, &mut sessions, &bnd(), SHORT).await;
        assert!(matches!(
            r,
            Err(Error::Transport(_)) | Err(Error::Verify(_))
        ));
        assert_eq!(sessions.len(), 1);
        assert!(sessions.contains_key(&alice.peer_id()));
    }

    #[tokio::test]
    async fn resume_without_tag_times_out_and_session_still_resumes() {
        let (alice, bob, a, b) = genuine();
        let mut sessions = HashMap::from([(alice.peer_id(), b)]);
        let (mut eve, listen) = pair().await;
        eve.send(&resume_preamble(&[7u8; NONCE_LEN], &alice))
            .await
            .unwrap();
        let r = negotiate_accept(listen, &bob, &mut sessions, &bnd(), SHORT).await;
        assert!(r.is_err());
        assert!(sessions.contains_key(&alice.peer_id()));
        drop(eve);

        // A genuine resume on a new pair still works.
        let mut kept = Some(a);
        let (dial, listen) = pair().await;
        let bd = bnd();
        let (d, l) = tokio::join!(
            negotiate_dial(dial, &alice, bob.public(), &mut kept, &bd),
            accept_or_resume(listen, &bob, &mut sessions, &bd)
        );
        assert!(d.is_ok());
        assert!(l.is_ok());
    }

    #[tokio::test]
    async fn fresh_without_msg1_times_out_and_keeps_sessions() {
        let (alice, bob) = (id(), id());
        let mut sessions = stale(&alice, &bob);
        let (mut dial, listen) = pair().await;
        preamble(&mut dial, MODE_FRESH, &alice).await;
        let r = negotiate_accept(listen, &bob, &mut sessions, &bnd(), SHORT).await;
        assert!(r.is_err());
        assert_eq!(sessions.len(), 1);
        assert!(sessions.contains_key(&alice.peer_id()));
    }

    #[tokio::test]
    async fn silent_listener_times_out_and_keeps_kept() {
        let (alice, bob, a, _b) = genuine();
        let mut kept = Some(a);
        let (dial, _listen) = pair().await;
        let r = negotiate_dial_within(dial, &alice, bob.public(), &mut kept, &bnd(), SHORT).await;
        assert!(matches!(r, Err(Error::Transport(_))));
        assert!(kept.is_some());
    }

    #[tokio::test]
    async fn busy_listener_is_an_error_and_keeps_kept() {
        let (alice, bob, a, _b) = genuine();
        let mut kept = Some(a);
        let (dial, mut listen) = pair().await;
        listen.send(&[DECISION_BUSY]).await.unwrap();
        let r = negotiate_dial(dial, &alice, bob.public(), &mut kept, &bnd()).await;
        assert!(matches!(r, Err(Error::Transport(_))));
        assert!(kept.is_some());

        let (dial, mut listen) = pair().await;
        listen.send(&[DECISION_BUSY]).await.unwrap();
        let r = negotiate_dial_within(dial, &alice, bob.public(), &mut kept, &bnd(), SHORT).await;
        assert!(matches!(r, Err(Error::Transport(_))));
        assert!(kept.is_some());

        let mut none = None;
        let (dial, mut listen) = pair().await;
        listen.send(&[DECISION_BUSY]).await.unwrap();
        let r = negotiate_dial(dial, &alice, bob.public(), &mut none, &bnd()).await;
        assert!(matches!(r, Err(Error::Transport(_))));
        assert!(none.is_none());
    }

    #[tokio::test]
    async fn reply_busy_sends_one_byte_and_closes() {
        let alice = id();
        let (mut dial, listen) = pair().await;
        preamble(&mut dial, MODE_FRESH, &alice).await; // stays unread
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

    // ---- ticket verification ----

    fn signed_ticket(k: &Keypair, ep: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let ident = k.public().to_bytes();
        let sig = k.sign(&ticket_message(ep, &ident)).0;
        (ident, sig)
    }

    #[test]
    fn verify_ticket_accepts_genuine() {
        let k = id();
        let ep = [5u8; 32];
        let (ident, sig) = signed_ticket(&k, &ep);
        let got = verify_ticket(&ident, &sig, &ep).unwrap();
        assert_eq!(got.peer_id(), k.peer_id());
    }

    #[test]
    fn verify_ticket_rejects_tampering() {
        let (k, other) = (id(), id());
        let ep = [5u8; 32];
        let (ident, sig) = signed_ticket(&k, &ep);

        // Changed endpoint id.
        let mut ep2 = ep;
        ep2[0] ^= 1;
        let r = verify_ticket(&ident, &sig, &ep2);
        assert!(matches!(r, Err(Error::Verify(_))));
        // Signature from a different keypair.
        let (_, other_sig) = signed_ticket(&other, &ep);
        let r = verify_ticket(&ident, &other_sig, &ep);
        assert!(matches!(r, Err(Error::Verify(_))));
        // Empty signature.
        let r = verify_ticket(&ident, &[], &ep);
        assert!(matches!(r, Err(Error::Verify(_))));
        // Swapped identity (valid identity, signature not made by it).
        let other_ident = other.public().to_bytes();
        let r = verify_ticket(&other_ident, &sig, &ep);
        assert!(r.is_err());
        // Tampered identity bytes.
        let mut bad = ident.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 1;
        let r = verify_ticket(&bad, &sig, &ep);
        assert!(r.is_err());
        // Truncated identity bytes.
        let r = verify_ticket(&ident[..ident.len() / 2], &sig, &ep);
        assert!(r.is_err());
    }

    #[test]
    fn check_endpoint_matches_only_equal_ids() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert!(check_endpoint(&a, &a).is_ok());
        assert!(matches!(check_endpoint(&a, &b), Err(Error::Verify(_))));
    }

    // ---- command line ----

    /// `parse_command` over `["lattice-net", ..a]`.
    fn cmd(a: &[&str]) -> Result<Command> {
        let mut args = vec!["lattice-net".to_string()];
        args.extend(a.iter().map(|s| s.to_string()));
        parse_command(&args)
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
}
