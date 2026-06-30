//! `lattice-net` — a real two-device P2P chat over Lattice.
//!
//! On device A:  `lattice-net listen`            → prints a TICKET
//! On device B:  `lattice-net connect <ticket>`  → dials A
//!
//! Each side loads a persistent PQ-hybrid identity (from a saved BIP39 mnemonic,
//! generated on first run), exchanges public identities, runs the hybrid-KEM +
//! Double-Ratchet handshake over an iroh QUIC connection (relay + holepunch),
//! then relays stdin lines as end-to-end-encrypted messages. Because the
//! identity persists, this device keeps a stable PeerId across runs.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use lattice::prelude::*;
use lattice::transport::{read_frame, write_frame, IrohConn, IrohTransport};
use tokio::io::{AsyncBufReadExt, BufReader, Lines, Stdin};
use tokio::sync::{Mutex, Notify};

/// Where the persistent mnemonic lives. Override with `LATTICE_IDENTITY_FILE`.
fn identity_path() -> PathBuf {
    if let Ok(p) = std::env::var("LATTICE_IDENTITY_FILE") {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".lattice").join("identity")
}

/// Load the identity from its saved BIP39 mnemonic, or generate one and persist
/// it on first run — so this device keeps a stable PeerId across runs (ADR-004).
fn load_or_create_identity() -> Result<Keypair> {
    let path = identity_path();
    if path.exists() {
        let phrase = std::fs::read_to_string(&path)
            .map_err(|e| Error::Other(format!("read identity {}: {e}", path.display())))?;
        let kp = Keypair::from_mnemonic(CryptoSuite::Hybrid, phrase.trim())?;
        eprintln!("[lattice-net] loaded identity from {}", path.display());
        Ok(kp)
    } else {
        let kp = Keypair::generate(CryptoSuite::Hybrid)?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| Error::Other(format!("mkdir {}: {e}", dir.display())))?;
        }
        write_secret(&path, kp.mnemonic())?;
        eprintln!(
            "[lattice-net] new identity saved to {} — this mnemonic is your recovery secret, keep it safe",
            path.display()
        );
        Ok(kp)
    }
}

/// Write the mnemonic owner-readable only (0600 on Unix, created atomically).
fn write_secret(path: &PathBuf, mnemonic: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| Error::Other(format!("create {}: {e}", path.display())))?;
        f.write_all(mnemonic.as_bytes())
            .map_err(|e| Error::Other(format!("write {}: {e}", path.display())))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, mnemonic)
            .map_err(|e| Error::Other(format!("write {}: {e}", path.display())))?;
    }
    Ok(())
}

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
    let me = load_or_create_identity()?;
    eprintln!("[lattice-net] your identity: {:?}", me.peer_id());

    // Read stdin once and reuse it across reconnects (typed input isn't lost).
    let mut lines = BufReader::new(tokio::io::stdin()).lines();

    match args.get(1).map(String::as_str) {
        Some("listen") => {
            let t = IrohTransport::bind().await?;
            eprintln!("[lattice-net] coming online (contacting relay)...");
            let ticket = t.ticket(&me.public().to_bytes()).await?;
            println!("\n=== TICKET (copy to the other device) ===\n{ticket}\n=========================================\n");

            loop {
                eprintln!("[lattice-net] waiting for a peer to connect...");
                let conn = match t.accept_conn().await {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("[lattice-net] accept failed: {e} — still listening");
                        continue;
                    }
                };
                match responder_session(conn, &me, &mut lines).await {
                    Ok(Outcome::LocalClosed) => {
                        eprintln!("[lattice-net] input closed — exiting");
                        break;
                    }
                    Ok(Outcome::PeerDisconnected) => {
                        eprintln!("[lattice-net] peer disconnected — back to listening");
                    }
                    Err(e) => eprintln!("[lattice-net] session error: {e} — back to listening"),
                }
            }
            Ok(())
        }
        Some("connect") => {
            let ticket = args
                .get(2)
                .ok_or_else(|| Error::Other("usage: lattice-net connect <ticket>".into()))?
                .clone();
            let t = IrohTransport::bind().await?;
            let mut backoff = 1u64;

            loop {
                match dialer_session(&t, &ticket, &me, &mut lines).await {
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
                        eprintln!(
                            "[lattice-net] connect/session failed: {e} — retrying in {backoff}s"
                        );
                        tokio::time::sleep(Duration::from_secs(backoff)).await;
                        backoff = (backoff * 2).min(30);
                    }
                }
            }
            Ok(())
        }
        _ => {
            eprintln!("usage:\n  lattice-net listen\n  lattice-net connect <ticket>");
            Ok(())
        }
    }
}

/// Responder: receive the dialer's identity, run the handshake, then chat.
async fn responder_session(
    mut conn: IrohConn,
    me: &Keypair,
    lines: &mut Lines<BufReader<Stdin>>,
) -> Result<Outcome> {
    let peer = PublicIdentity::from_bytes(&conn.recv().await?)?;
    eprintln!("[lattice-net] peer connected: {:?}", peer.peer_id());
    let sess = ConnectedSession::accept(conn, me, &peer).await?;
    eprintln!("[lattice-net] secure session established — type messages:");
    chat(sess, lines).await
}

/// Dialer: connect the ticket, send our identity, run the handshake, then chat.
async fn dialer_session(
    t: &IrohTransport,
    ticket: &str,
    me: &Keypair,
    lines: &mut Lines<BufReader<Stdin>>,
) -> Result<Outcome> {
    eprintln!("[lattice-net] dialing peer...");
    let (peer_bytes, mut conn) = t.connect_ticket(ticket).await?;
    let peer = PublicIdentity::from_bytes(&peer_bytes)?;
    conn.send(&me.public().to_bytes()).await?;
    eprintln!("[lattice-net] connected to: {:?}", peer.peer_id());
    let sess = ConnectedSession::initiate(conn, me, &peer).await?;
    eprintln!("[lattice-net] secure session established — type messages:");
    chat(sess, lines).await
}

/// Full-duplex chat over one session: a reader task decrypts incoming frames
/// while this task encrypts stdin lines. The ratchet is shared behind a mutex
/// (brief locks, no I/O held); the QUIC halves run concurrently. Returns when
/// the peer drops or local input closes — the caller decides reconnect vs exit.
async fn chat(
    sess: ConnectedSession<IrohConn>,
    lines: &mut Lines<BufReader<Stdin>>,
) -> Result<Outcome> {
    let (conn, secure) = sess.into_parts();
    let (mut send, mut recv) = conn.into_split();
    let secure = Arc::new(Mutex::new(secure));

    // Reader task: decrypt + print; signal `lost` when the peer drops.
    let lost = Arc::new(Notify::new());
    let secure_r = secure.clone();
    let lost_r = lost.clone();
    let reader = tokio::spawn(async move {
        // Loop ends when the peer drops (read_frame errors) or a frame fails to
        // decrypt.
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

    reader.abort();
    Ok(outcome)
}
