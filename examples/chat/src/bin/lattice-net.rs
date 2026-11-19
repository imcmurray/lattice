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
//! the listener still holds that peer's session both sides exchange HMAC proofs
//! keyed by the session's secret (`lattice-resume-v1`); only when both verify do
//! they rebind to the new connection with no re-handshake. If either side lost
//! its state (e.g. a restart), they fall back to a fresh handshake.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use lattice::identity::storage::IdentityStore;
use lattice::prelude::*;
use lattice::session::{resume_nonce, ResumeRole};
use lattice::transport::{read_frame, write_frame, IrohConn, IrohTransport};
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
const NONCE_LEN: usize = 32;
const TAG_LEN: usize = 32;

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
            "[lattice-net] ⚠ migrated your legacy plaintext identity into secure storage ({:?}); \
             the legacy plaintext file was removed.",
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
async fn accept_or_resume<C: Connection>(
    mut conn: C,
    me: &Keypair,
    sessions: &mut HashMap<PeerId, SecureSession>,
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
                &tag,
            )?;
            let sess = sessions
                .remove(&peer_id)
                .ok_or_else(|| Error::Verify("kept session vanished during resume".into()))?;
            eprintln!(
                "[lattice-net] {:?} resumed — no re-handshake — type messages:",
                peer_id
            );
            return Ok((peer_id, ConnectedSession::resume(conn, sess)));
        }
    }
    // Fresh handshake (requested, or resume with no kept session).
    conn.send(&[DECISION_FRESH]).await?;
    let cs = ConnectedSession::accept(conn, me, &peer).await?;
    // Only a successful handshake replaces the stale session for this peer.
    sessions.remove(&peer_id);
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

/// Dialer-side negotiation after the transport connects: send the preamble,
/// then either resume the kept session (after a mutual proof) or run a fresh
/// handshake. `kept` is only taken once the outcome is certain.
async fn negotiate_dial<C: Connection>(
    mut conn: C,
    me: &Keypair,
    peer: &PublicIdentity,
    kept: &mut Option<SecureSession>,
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
            let cs = ConnectedSession::initiate(conn, me, peer).await?;
            eprintln!(
                "[lattice-net] connected to {:?} (fresh session) — type messages:",
                peer.peer_id()
            );
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
                listener_tag,
            )?;
            let dialer_tag = sess.resume_tag(
                ResumeRole::Dialer,
                me.public(),
                peer,
                &dialer_nonce,
                &listener_nonce,
            );
            conn.send(&dialer_tag).await?;
            let sess = kept
                .take()
                .ok_or_else(|| Error::Verify("kept session vanished during resume".into()))?;
            eprintln!(
                "[lattice-net] resumed with {:?} — no re-handshake — type messages:",
                peer.peer_id()
            );
            Ok(ConnectedSession::resume(conn, sess))
        }
        Some(DECISION_RESUMED) => Err(Error::Verify(
            "peer sent legacy unauthenticated resume decision".into(),
        )),
        _ => Err(Error::Verify("unrecognised resume decision".into())),
    }
}

async fn dial_once(
    t: &IrohTransport,
    ticket: &str,
    me: &Keypair,
    kept: &mut Option<SecureSession>,
    lines: &mut StdinLines,
) -> Result<Outcome> {
    eprintln!("[lattice-net] dialing peer...");
    let (peer_bytes, conn) = t.connect_ticket(ticket).await?;
    let peer = PublicIdentity::from_bytes(&peer_bytes)?;

    let cs = negotiate_dial(conn, me, &peer, kept).await?;

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
        let (_, s) = SecureSession::initiate(bob, alice.public()).unwrap();
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
        // Eve's handshake, claimed to come from Alice.
        let _dialer = ConnectedSession::initiate(dial, &eve, bob.public())
            .await
            .unwrap();
        let r = accept_or_resume(listen, &bob, &mut sessions).await;
        assert!(r.is_err());
        assert!(sessions.contains_key(&alice.peer_id()));
    }

    #[tokio::test]
    async fn genuine_fresh_handshake_replaces_stale_session() {
        let (alice, bob) = (id(), id());
        let mut sessions = stale(&alice, &bob);
        let (mut dial, listen) = pair().await;
        preamble(&mut dial, MODE_FRESH, &alice).await;
        // Keep the dialer end alive so the listener's decision byte can be sent.
        let _dialer = ConnectedSession::initiate(dial, &alice, bob.public())
            .await
            .unwrap();
        let r = accept_or_resume(listen, &bob, &mut sessions).await;
        assert!(r.is_ok());
        assert!(!sessions.contains_key(&alice.peer_id()));
    }

    #[tokio::test]
    async fn genuine_resume_with_mutual_proof_succeeds() {
        let (alice, bob) = (id(), id());
        let (hs, a) = SecureSession::initiate(&alice, bob.public()).unwrap();
        let b = SecureSession::accept(&bob, alice.public(), &hs).unwrap();
        let mut sessions = HashMap::from([(alice.peer_id(), b)]);
        let mut kept = Some(a);
        let (dial, listen) = pair().await;
        let (d, l) = tokio::join!(
            negotiate_dial(dial, &alice, bob.public(), &mut kept),
            accept_or_resume(listen, &bob, &mut sessions)
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
    async fn impostor_with_legacy_preamble_cannot_resume() {
        let (alice, bob) = (id(), id());
        let mut sessions = stale(&alice, &bob);
        let (mut dial, listen) = pair().await;
        let mut p = vec![MODE_RESUME];
        p.extend_from_slice(&alice.public().to_bytes());
        dial.send(&p).await.unwrap();
        let r = accept_or_resume(listen, &bob, &mut sessions).await;
        assert!(r.is_err());
        assert!(sessions.contains_key(&alice.peer_id()));
    }

    /// Genuine Alice–Bob pair: (alice, bob, alice's session, bob's session).
    fn genuine() -> (Keypair, Keypair, SecureSession, SecureSession) {
        let (alice, bob) = (id(), id());
        let (hs, a) = SecureSession::initiate(&alice, bob.public()).unwrap();
        let b = SecureSession::accept(&bob, alice.public(), &hs).unwrap();
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
        let r = accept_or_resume(listen, &bob, &mut sessions).await;
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
        let r = accept_or_resume(listen, &bob, &mut sessions).await;
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
        let (r, p) = tokio::join!(
            negotiate_dial(dial, &alice, bob.public(), &mut kept),
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
        let r = negotiate_dial(dial, &alice, bob.public(), &mut kept).await;
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
        let r = negotiate_dial(dial, &alice, bob.public(), &mut kept).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn short_preambles_are_rejected() {
        let (alice, bob) = (id(), id());
        for n in [0usize, 1, 32] {
            let mut sessions = stale(&alice, &bob);
            let (mut dial, listen) = pair().await;
            dial.send(&vec![MODE_RESUME; n]).await.unwrap();
            let r = accept_or_resume(listen, &bob, &mut sessions).await;
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
        let (r, p) = tokio::join!(
            negotiate_dial(dial, &alice, bob.public(), &mut kept),
            script
        );
        assert!(r.is_err());
        assert_eq!(p[0], MODE_FRESH);
        assert!(p[1..1 + NONCE_LEN].iter().all(|b| *b == 0));
    }
}
