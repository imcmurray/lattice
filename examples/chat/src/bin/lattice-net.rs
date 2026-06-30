//! `lattice-net` — a real two-device P2P chat over Lattice.
//!
//! On device A:  `lattice-net listen`            → prints a TICKET
//! On device B:  `lattice-net connect <ticket>`  → dials A
//!
//! Each side loads a persistent PQ-hybrid identity via [`IdentityStore`] (OS
//! keychain, else an age-encrypted file), then runs the hybrid-KEM +
//! Double-Ratchet handshake over an iroh QUIC connection and relays stdin lines
//! as end-to-end-encrypted messages.
//!
//! Reconnects use **session resumption** (ADR-006): on a drop, each side keeps
//! its `SecureSession`; the dialer's reconnect preamble signals `resume`, and if
//! the listener still holds that peer's session both rebind to the new
//! connection with no re-handshake. If either side lost its state (e.g. a
//! restart), they fall back to a fresh handshake.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use lattice::identity::storage::IdentityStore;
use lattice::prelude::*;
use lattice::transport::{read_frame, write_frame, IrohConn, IrohTransport};
use tokio::io::{AsyncBufReadExt, BufReader, Lines, Stdin};
use tokio::sync::{Mutex, Notify};

// Connection preamble: the dialer's first frame is [mode] ++ its identity bundle.
const MODE_FRESH: u8 = 0;
const MODE_RESUME: u8 = 1;
// The listener's reply byte: did it resume an existing session?
const DECISION_FRESH: u8 = 0;
const DECISION_RESUMED: u8 = 1;

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

async fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // Persistent identity: OS keychain if available, else an age-encrypted file.
    let loaded = IdentityStore::open_default().load_or_create(CryptoSuite::Hybrid)?;
    let me = loaded.keypair;
    let note = if loaded.created {
        " (new identity created)"
    } else {
        ""
    };
    eprintln!(
        "[lattice-net] identity {:?} [stored via {:?}]{note}",
        me.peer_id(),
        loaded.backend
    );
    if loaded.migrated {
        eprintln!(
            "[lattice-net] ⚠ migrated your legacy plaintext identity into secure storage ({:?}). \
             The old file is backed up at <dir>/identity.legacy.bak — delete it once you've confirmed things work.",
            loaded.backend
        );
    }

    // Read stdin once and reuse it across reconnects (typed input isn't lost).
    let lines = BufReader::new(tokio::io::stdin()).lines();

    match args.get(1).map(String::as_str) {
        Some("listen") => listen(me, lines).await,
        Some("connect") => {
            let ticket = args
                .get(2)
                .ok_or_else(|| Error::Other("usage: lattice-net connect <ticket>".into()))?
                .clone();
            connect(me, ticket, lines).await
        }
        _ => {
            eprintln!("usage:\n  lattice-net listen\n  lattice-net connect <ticket>");
            Ok(())
        }
    }
}

/// Listener loop: accept connections, negotiate resume-vs-fresh, chat, and keep
/// each peer's `SecureSession` so a reconnect can resume without re-handshaking.
async fn listen(me: Keypair, mut lines: StdinLines) -> Result<()> {
    let t = IrohTransport::bind().await?;
    eprintln!("[lattice-net] coming online (contacting relay)...");
    let ticket = t.ticket(&me.public().to_bytes()).await?;
    println!("\n=== TICKET (copy to the other device) ===\n{ticket}\n=========================================\n");

    let mut sessions: HashMap<PeerId, SecureSession> = HashMap::new();
    loop {
        eprintln!("[lattice-net] waiting for a peer to connect...");
        let conn = match t.accept_conn().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[lattice-net] accept failed: {e} — still listening");
                continue;
            }
        };
        let (peer_id, sess) = match accept_or_resume(conn, &me, &mut sessions).await {
            Ok(x) => x,
            Err(e) => {
                eprintln!("[lattice-net] negotiation failed: {e} — still listening");
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
    }
    Ok(())
}

/// Read the dialer's preamble; resume a kept session if asked and available,
/// otherwise run a fresh handshake. Returns the peer id and the live session.
async fn accept_or_resume(
    mut conn: IrohConn,
    me: &Keypair,
    sessions: &mut HashMap<PeerId, SecureSession>,
) -> Result<(PeerId, ConnectedSession<IrohConn>)> {
    let preamble = conn.recv().await?;
    let mode = *preamble
        .first()
        .ok_or_else(|| Error::Verify("empty preamble".into()))?;
    let peer = PublicIdentity::from_bytes(&preamble[1..])?;
    let peer_id = peer.peer_id();

    if mode == MODE_RESUME {
        if let Some(sess) = sessions.remove(&peer_id) {
            conn.send(&[DECISION_RESUMED]).await?;
            eprintln!(
                "[lattice-net] {:?} resumed — no re-handshake — type messages:",
                peer_id
            );
            return Ok((peer_id, ConnectedSession::resume(conn, sess)));
        }
    }
    // Fresh handshake (requested, or resume with no kept session).
    sessions.remove(&peer_id); // drop any stale session for this peer
    conn.send(&[DECISION_FRESH]).await?;
    let cs = ConnectedSession::accept(conn, me, &peer).await?;
    eprintln!(
        "[lattice-net] {:?} connected (fresh session) — type messages:",
        peer_id
    );
    Ok((peer_id, cs))
}

/// Dialer loop: dial, negotiate resume-vs-fresh, chat; keep the `SecureSession`
/// across drops so the next dial can resume.
async fn connect(me: Keypair, ticket: String, mut lines: StdinLines) -> Result<()> {
    let t = IrohTransport::bind().await?;
    let mut kept: Option<SecureSession> = None;
    let mut backoff = 1u64;
    loop {
        match dial_once(&t, &ticket, &me, &mut kept, &mut lines).await {
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

async fn dial_once(
    t: &IrohTransport,
    ticket: &str,
    me: &Keypair,
    kept: &mut Option<SecureSession>,
    lines: &mut StdinLines,
) -> Result<Outcome> {
    eprintln!("[lattice-net] dialing peer...");
    let (peer_bytes, mut conn) = t.connect_ticket(ticket).await?;
    let peer = PublicIdentity::from_bytes(&peer_bytes)?;

    // Preamble: [mode] ++ our identity bundle. Resume if we kept a session.
    let mode = if kept.is_some() {
        MODE_RESUME
    } else {
        MODE_FRESH
    };
    let mut preamble = vec![mode];
    preamble.extend_from_slice(&me.public().to_bytes());
    conn.send(&preamble).await?;

    let decision = conn.recv().await?;
    let resumed = decision.first() == Some(&DECISION_RESUMED);

    let cs = if resumed {
        let sess = kept.take().expect("resume decision implies a kept session");
        eprintln!(
            "[lattice-net] resumed with {:?} — no re-handshake — type messages:",
            peer.peer_id()
        );
        ConnectedSession::resume(conn, sess)
    } else {
        if kept.take().is_some() {
            eprintln!("[lattice-net] peer couldn't resume — fresh handshake");
        }
        let cs = ConnectedSession::initiate(conn, me, &peer).await?;
        eprintln!(
            "[lattice-net] connected to {:?} (fresh session) — type messages:",
            peer.peer_id()
        );
        cs
    };

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
