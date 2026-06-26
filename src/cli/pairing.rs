//! `pair-send` / `pair-receive` — move a secret between devices with the
//! post-quantum pairing handshake (`network::transfer`).
//!
//! Carry the (~1.5 KB) pairing code and bundle by **LAN** (`--listen` →
//! `ip:port` embedded in the code; `pair-send` connects and pushes), by **file**
//! (`--code-out`/`--to-file`/`--bundle-out`/`--bundle-in`), or by **stdin/stdout**.
//! The bundle is PQC-sealed, so the plaintext-TCP hop adds no exposure.
//!
//! MitM defense: both ends derive a **verification code (SAS)** from the
//! transcript; the receiver prompts the user to confirm it matches the sender's
//! *before* storing. Automatic networked transport over Tor/I2P is deferred
//! (`TODOs.md`).

use crate::cli::client;
use crate::network::pairing::PairingSession;
use crate::network::transfer::{self, Opened};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

/// Per-read socket timeout, and the max bytes accepted from a single peer.
const SOCKET_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_LAN_READ: u64 = 256 * 1024;
/// Absolute wall-clock budget for receiving one bundle (defeats a slowloris peer
/// that dribbles bytes to keep the per-read timeout from ever firing).
const RECEIVE_DEADLINE: Duration = Duration::from_secs(60);
/// How many junk/early connections to tolerate before giving up.
const MAX_ACCEPT_ATTEMPTS: usize = 20;

/// `pair-send NAME (--to CODE | --to-file FILE) [--bundle-out FILE]`.
pub(crate) fn pair_send(
    name: &str,
    to: Option<&str>,
    to_file: Option<&str>,
    bundle_out: Option<&str>,
    assume_yes: bool,
) -> Result<(), String> {
    let paircode = match (to, to_file) {
        (Some(_), Some(_)) => return Err("use only one of --to / --to-file".to_string()),
        (Some(code), None) => code.to_string(),
        (None, Some(path)) => {
            std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?
        }
        (None, None) => return Err("provide the peer's code via --to or --to-file".to_string()),
    };
    let paircode = paircode.trim();

    // Verify the receiver's key fingerprint BEFORE the secret is sealed/sent —
    // both sides know it from the code, so a swapped key is caught up front.
    let fp = transfer::code_fingerprint(paircode)?;
    let confirmed = if assume_yes {
        eprintln!("verification code: {fp} (auto-accepted via --yes — MitM check skipped)");
        true
    } else {
        confirm_code(&fp)?
    };
    if !confirmed {
        return Err("aborted: verification code was not confirmed".to_string());
    }

    let mut secret = client::fetch_secret(name)?;
    let sealed = transfer::seal_for(paircode, name, &secret);
    secret.zeroize();
    let sealed = sealed?;

    let address = transfer::code_address(paircode);
    match (bundle_out, address) {
        (Some(path), _) => {
            write_private(path, &sealed.bundle)?;
            eprintln!("wrote transfer bundle to {path} — send it to the receiver");
        }
        (None, Some(addr)) => {
            let ack = send_over_tcp(&addr, &sealed.bundle)?;
            eprintln!("sent '{name}' to {addr} ({ack})");
        }
        (None, None) => println!("{}", sealed.bundle),
    }
    Ok(())
}

/// `pair-receive [--into NAME] [--listen] [--port N] [--code-out FILE] [--qr]
/// [--bundle-in FILE]`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn pair_receive(
    into: Option<&str>,
    code_out: Option<&str>,
    qr: bool,
    bundle_in: Option<&str>,
    listen: bool,
    port: u16,
    assume_yes: bool,
) -> Result<(), String> {
    let (session, code) = transfer::new_pairing()?;

    // Bind first (when listening) so the real address goes into the code. Bind to
    // the specific LAN interface, not 0.0.0.0, to narrow the exposure.
    let bound = if listen {
        let ip = local_lan_ip();
        if ip == "127.0.0.1" {
            eprintln!("warning: could not determine a LAN IP — only local connections will work");
        }
        let listener =
            TcpListener::bind((ip.as_str(), port)).map_err(|e| format!("cannot listen: {e}"))?;
        let real_port = listener.local_addr().map_err(|e| format!("{e}"))?.port();
        Some((listener, fmt_addr(&ip, real_port)))
    } else {
        None
    };
    let code = match &bound {
        Some((_, addr)) => format!("{code}@{addr}"),
        None => code,
    };

    emit_code(&code, code_out, qr)?;

    // Obtain a validated, opened bundle (over TCP, from a file, or from stdin).
    let (opened, mut stream) = match (&bound, bundle_in) {
        (Some((listener, addr)), _) => {
            eprintln!("listening on {addr} — waiting for the sender…");
            let (stream, opened) = accept_until_valid(listener, &session)?;
            (opened, Some(stream))
        }
        (None, Some(path)) => {
            let line = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
            (transfer::open_bundle(&session, &line)?, None)
        }
        (None, None) => {
            eprintln!("On the sender run:  simple-secrets pair-send <name> --to-file <code-file>");
            eprintln!("then paste the bundle here and press Enter:");
            let mut line = String::new();
            std::io::stdin()
                .lock()
                .read_line(&mut line)
                .map_err(|e| format!("read bundle failed: {e}"))?;
            (transfer::open_bundle(&session, &line)?, None)
        }
    };

    // Anti-MitM: verify the key fingerprint out-of-band BEFORE storing. The
    // receiver computes it from its own code — equal to the sender's iff no MitM.
    let name = opened.name.clone();
    let sas = transfer::code_fingerprint(&code)?;
    let confirmed = if assume_yes {
        eprintln!("VERIFICATION CODE: {sas} (auto-accepted via --yes — MitM check skipped)");
        true
    } else {
        confirm_code(&sas)?
    };
    if !confirmed {
        let mut o = opened;
        o.secret.zeroize();
        if let Some(s) = stream.as_mut() {
            let _ = writeln!(s, "ERR verification rejected by receiver");
        }
        return Err("aborted: verification code was not confirmed".to_string());
    }

    let stored = store_received(opened, into);
    if let Some(s) = stream.as_mut() {
        let ack = match &stored {
            Ok(target) => format!("OK stored '{target}'"),
            Err(e) => format!("ERR {e}"),
        };
        let _ = writeln!(s, "{ack}");
    }
    let target = stored?;
    eprintln!("received '{name}' — stored as '{target}' (code {sas} confirmed).");
    Ok(())
}

/// Refuses to overwrite, then stores. Zeroizes the plaintext on every path.
fn store_received(mut opened: Opened, into: Option<&str>) -> Result<String, String> {
    let target = into.unwrap_or(&opened.name).to_string();
    // Best-effort overwrite guard (TOCTOU: the agent's Put is last-writer-wins).
    let exists = match client::list_names() {
        Ok(names) => names.iter().any(|n| n == &target),
        Err(e) => {
            opened.secret.zeroize();
            return Err(e);
        }
    };
    if exists {
        opened.secret.zeroize();
        return Err(format!(
            "'{target}' already exists in this vault; receive with --into <new-name>"
        ));
    }
    let stored = client::store_secret(&target, &opened.secret);
    opened.secret.zeroize();
    stored?;
    Ok(target)
}

/// Prompts the user (on the controlling terminal) to confirm the SAS matches the
/// sender's. Fails **closed** if there is no terminal (the out-of-band compare
/// can't be done) — use `--yes` to bypass verification in scripts.
fn confirm_code(sas: &str) -> Result<bool, String> {
    eprintln!("\nVERIFICATION CODE: {sas}");
    let tty = match File::open("/dev/tty") {
        Ok(f) => f,
        Err(_) => {
            // Fail closed: with no terminal we cannot do the out-of-band compare.
            eprintln!(
                "(no terminal to confirm on — re-run with --yes to accept without verifying)"
            );
            return Ok(false);
        }
    };
    eprint!("Does this EXACTLY match the code on the sending device? [y/N]: ");
    std::io::stderr().flush().ok();
    let mut answer = String::new();
    BufReader::new(tty)
        .read_line(&mut answer)
        .map_err(|e| format!("read terminal: {e}"))?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES"))
}

/// Emits the pairing code to a file (0600, if `code_out`) or stdout, plus an
/// optional QR on stderr.
fn emit_code(code: &str, code_out: Option<&str>, qr: bool) -> Result<(), String> {
    match code_out {
        Some(path) => {
            write_private(path, code)?;
            eprintln!("wrote pairing code to {path} — share it with the sender");
        }
        None => println!("{code}"),
    }
    if qr {
        eprintln!("\n{}", transfer::qr_code(code)?);
        eprintln!("(scan the code above with the sending device)");
    }
    Ok(())
}

// ── LAN transport ─────────────────────────────────────────────────────────

/// Best-effort local LAN IP: ask the OS which source address it would use to
/// reach an off-link destination (no packet is actually sent).
fn local_lan_ip() -> String {
    // Prefer IPv4; fall back to IPv6 for v6-only networks. Loopback is the last
    // resort (only local connections will work — the caller warns on it).
    probe_src("0.0.0.0:0", "8.8.8.8:80")
        .or_else(|| probe_src("[::]:0", "[2001:4860:4860::8888]:80"))
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

/// The OS-chosen source address for reaching `dest` (no packet is sent).
fn probe_src(bind: &str, dest: &str) -> Option<String> {
    let sock = UdpSocket::bind(bind).ok()?;
    sock.connect(dest).ok()?;
    Some(sock.local_addr().ok()?.ip().to_string())
}

/// Formats a socket address, bracketing IPv6 literals.
fn fmt_addr(ip: &str, port: u16) -> String {
    if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

/// Connects to `addr`, sends one bundle line, and returns the ack line.
fn send_over_tcp(addr: &str, bundle: &str) -> Result<String, String> {
    let sock = addr
        .to_socket_addrs()
        .map_err(|e| format!("bad address {addr}: {e}"))?
        .next()
        .ok_or_else(|| format!("could not resolve {addr}"))?;
    let mut stream = TcpStream::connect_timeout(&sock, Duration::from_secs(10))
        .map_err(|e| format!("connect to {addr} failed: {e}"))?;
    stream.set_write_timeout(Some(SOCKET_TIMEOUT)).ok();
    stream.set_read_timeout(Some(SOCKET_TIMEOUT)).ok();
    writeln!(stream, "{}", bundle.trim()).map_err(|e| format!("send failed: {e}"))?;
    stream.flush().ok();

    let mut ack = String::new();
    BufReader::new(stream)
        .read_line(&mut ack)
        .map_err(|e| format!("no acknowledgement: {e}"))?;
    Ok(ack.trim().to_string())
}

/// Accepts connections until one delivers a bundle that opens for `session`.
/// A junk/early peer gets an `ERR` ack and the listener keeps waiting, so a
/// stray connection cannot pre-empt the real sender (bounded by an attempt cap).
fn accept_until_valid(
    listener: &TcpListener,
    session: &PairingSession,
) -> Result<(TcpStream, Opened), String> {
    for _ in 0..MAX_ACCEPT_ATTEMPTS {
        let (mut stream, _peer) = listener
            .accept()
            .map_err(|e| format!("accept failed: {e}"))?;
        stream.set_read_timeout(Some(SOCKET_TIMEOUT)).ok();
        stream.set_write_timeout(Some(SOCKET_TIMEOUT)).ok();
        let line = match read_line_bounded(&stream) {
            Ok(l) => l,
            Err(_) => continue,
        };
        match transfer::open_bundle(session, &line) {
            Ok(opened) => return Ok((stream, opened)),
            Err(e) => {
                let _ = writeln!(stream, "ERR {e}");
            }
        }
    }
    Err("too many invalid connection attempts; giving up".to_string())
}

/// Reads one newline-terminated line, capped at [`MAX_LAN_READ`] bytes.
fn read_line_bounded(stream: &TcpStream) -> Result<String, String> {
    let mut clone = stream
        .try_clone()
        .map_err(|e| format!("socket clone: {e}"))?;
    // Short per-read timeout so we re-check the absolute deadline frequently.
    clone.set_read_timeout(Some(Duration::from_secs(1))).ok();
    let deadline = Instant::now() + RECEIVE_DEADLINE;
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if Instant::now() >= deadline {
            return Err("receive timed out".to_string());
        }
        if buf.len() as u64 >= MAX_LAN_READ {
            return Err("bundle exceeded the size limit".to_string());
        }
        match clone.read(&mut byte) {
            Ok(0) => break, // peer closed
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => buf.push(byte[0]),
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // No data this window — loop to re-check the deadline.
            }
            Err(e) => return Err(format!("read failed: {e}")),
        }
    }
    String::from_utf8(buf).map_err(|_| "bundle is not valid UTF-8".to_string())
}

/// Writes `content` to `path` with owner-only (0600) permissions.
fn write_private(path: &str, content: &str) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("write {path}: {e}"))?;
    f.write_all(content.as_bytes())
        .map_err(|e| format!("write {path}: {e}"))
}
