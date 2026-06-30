//! `lattice-net` — a real two-device P2P chat over Lattice.
//!
//! On device A:  `lattice-net listen`            → prints a TICKET
//! On device B:  `lattice-net connect <ticket>`  → dials A
//!
//! Each side generates a fresh PQ-hybrid identity, exchanges public identities,
//! runs the hybrid-KEM + Double-Ratchet handshake over an iroh QUIC connection
//! (relay + holepunch), then relays stdin lines as end-to-end-encrypted messages.

use std::sync::Arc;

use lattice::prelude::*;
use lattice::transport::{read_frame, write_frame, IrohConn, IrohTransport};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("[lattice-net] error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let me = Keypair::generate(CryptoSuite::Hybrid)?;
    eprintln!("[lattice-net] your identity: {:?}", me.peer_id());

    match args.get(1).map(String::as_str) {
        Some("listen") => {
            let t = IrohTransport::bind().await?;
            eprintln!("[lattice-net] coming online (contacting relay)...");
            let ticket = t.ticket(&me.public().to_bytes()).await?;
            println!("\n=== TICKET (copy to the other device) ===\n{ticket}\n=========================================\n");
            eprintln!("[lattice-net] waiting for a peer to connect...");

            let mut conn = t.accept_conn().await?;
            let peer = PublicIdentity::from_bytes(&conn.recv().await?)?;
            eprintln!("[lattice-net] peer connected: {:?}", peer.peer_id());

            let sess = ConnectedSession::accept(conn, &me, &peer).await?;
            eprintln!("[lattice-net] secure session established — type messages:");
            chat(sess).await
        }
        Some("connect") => {
            let ticket = args
                .get(2)
                .ok_or_else(|| Error::Other("usage: lattice-net connect <ticket>".into()))?;
            let t = IrohTransport::bind().await?;
            eprintln!("[lattice-net] dialing peer...");

            let (peer_bytes, mut conn) = t.connect_ticket(ticket).await?;
            let peer = PublicIdentity::from_bytes(&peer_bytes)?;
            conn.send(&me.public().to_bytes()).await?;
            eprintln!("[lattice-net] connected to: {:?}", peer.peer_id());

            let sess = ConnectedSession::initiate(conn, &me, &peer).await?;
            eprintln!("[lattice-net] secure session established — type messages:");
            chat(sess).await
        }
        _ => {
            eprintln!("usage:\n  lattice-net listen\n  lattice-net connect <ticket>");
            Ok(())
        }
    }
}

/// Full-duplex chat: a reader task decrypts incoming frames while the main task
/// encrypts stdin lines. The ratchet state is shared behind a mutex (locks are
/// brief, no I/O held); the QUIC send/recv halves run concurrently.
async fn chat(sess: ConnectedSession<IrohConn>) -> Result<()> {
    let (conn, secure) = sess.into_parts();
    let (mut send, mut recv) = conn.into_split();
    let secure = Arc::new(Mutex::new(secure));

    let secure_r = secure.clone();
    let reader = tokio::spawn(async move {
        loop {
            match read_frame(&mut recv).await {
                Ok(frame) => {
                    let opened = secure_r.lock().await.open(&frame);
                    match opened {
                        Ok(pt) => println!("peer> {}", String::from_utf8_lossy(&pt)),
                        Err(e) => {
                            eprintln!("[lattice-net] decrypt error: {e}");
                            break;
                        }
                    }
                }
                Err(_) => {
                    eprintln!("[lattice-net] peer disconnected");
                    break;
                }
            }
        }
    });

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines
        .next_line()
        .await
        .map_err(|e| Error::Other(format!("stdin: {e}")))?
    {
        let frame = {
            let mut s = secure.lock().await;
            s.seal(line.as_bytes())?
        };
        if write_frame(&mut send, &frame).await.is_err() {
            break;
        }
    }

    reader.abort();
    Ok(())
}
