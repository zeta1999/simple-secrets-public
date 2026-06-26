//! Client-side commands: the short-lived processes the user actually runs.
//!
//! Most verbs simply connect to the running agent over its Unix socket and
//! exchange one framed message. `init` creates the persistent vault, and
//! `signin` spawns a detached agent and prints the `export` line for `eval`.

use crate::cli::paths;
use crate::cli::protocol::{read_msg, write_msg, Request, Response, TOKEN_B64};
use crate::core::entropy::DefaultEntropySource;
use crate::core::manager::SecretManager;
use crate::crypto::vdf_kdf::Argon2Params;
use base64::Engine;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::sync::Arc;
use zeroize::Zeroize;

/// Connects to the agent socket, mapping a connection failure to the standard
/// "no agent" guidance.
fn connect() -> Result<UnixStream, String> {
    let sock = paths::socket_path()?;
    UnixStream::connect(&sock)
        .map_err(|_| "no running agent — run: eval $(simple-secrets signin)".to_string())
}

/// Reads and decodes the session token from `$SIMPLE_SECRETS_SESSION`.
fn session_token() -> Result<Vec<u8>, String> {
    let raw = std::env::var("SIMPLE_SECRETS_SESSION")
        .map_err(|_| "no session — run: eval $(simple-secrets signin)".to_string())?;
    TOKEN_B64
        .decode(raw.trim())
        .map_err(|e| format!("invalid session token: {e}"))
}

/// Sends one request and reads one response.
fn request(req: &Request) -> Result<Response, String> {
    let mut stream = connect()?;
    write_msg(&mut stream, req)?;
    read_msg(&mut stream)
}

/// Fetches and decrypts a stored secret via the agent (errors if absent).
pub(crate) fn fetch_secret(name: &str) -> Result<Vec<u8>, String> {
    let token = session_token()?;
    match request(&Request::Get {
        token,
        name: name.to_string(),
    })? {
        Response::Secret(Some(value)) => Ok(value),
        Response::Secret(None) => Err(format!("no such secret: {name}")),
        Response::Err(e) => Err(e),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

/// Stores a secret via the agent.
pub(crate) fn store_secret(name: &str, value: &[u8]) -> Result<(), String> {
    let token = session_token()?;
    match request(&Request::Put {
        token,
        name: name.to_string(),
        value: value.to_vec(),
    })? {
        Response::Ok => Ok(()),
        Response::Err(e) => Err(e),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

/// `get NAME` — print the decrypted secret (with a trailing newline) to stdout.
pub(crate) fn get(name: &str) -> Result<(), String> {
    let mut value = fetch_secret(name)?;
    let mut out = std::io::stdout();
    let res = out
        .write_all(&value)
        .and_then(|()| out.write_all(b"\n"))
        .map_err(|e| format!("write failed: {e}"));
    value.zeroize();
    res
}

/// `put NAME [VALUE]` — store a secret. With `VALUE` omitted (or `-`) the value
/// is read from stdin (a single trailing newline is stripped, so
/// `echo s | put k` stores `s`). Prefer stdin: a value passed as an argument is
/// visible in `ps` output and shell history.
pub(crate) fn put(name: &str, value: Option<&str>) -> Result<(), String> {
    let mut bytes = match value {
        None | Some("-") => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| format!("read stdin failed: {e}"))?;
            if buf.last() == Some(&b'\n') {
                buf.pop();
                if buf.last() == Some(&b'\r') {
                    buf.pop();
                }
            }
            buf
        }
        Some(v) => v.as_bytes().to_vec(),
    };
    let result = store_secret(name, &bytes);
    bytes.zeroize();
    result
}

/// `otp-add NAME [--generate]` — store a TOTP entry as a canonical otpauth:// URI.
/// Without `--generate` it reads an existing URI/base32 seed from stdin; with it,
/// a fresh random seed is minted and the URI + a QR are printed so you can
/// register the *same* secret on the verifying side.
pub(crate) fn otp_add(name: &str, generate: bool) -> Result<(), String> {
    use crate::core::totp::{self, TotpAlg, TotpConfig};
    let cfg = if generate {
        let mgr = SecretManager::new(Arc::new(DefaultEntropySource));
        TotpConfig {
            secret: mgr.random_bytes(20)?, // 160-bit SHA-1 key (the common size)
            digits: 6,
            period: 30,
            algorithm: TotpAlg::Sha1,
        }
    } else {
        let mut input = String::new();
        std::io::stdin()
            .read_to_string(&mut input)
            .map_err(|e| format!("read stdin failed: {e}"))?;
        let parsed = totp::parse(input.trim())
            .ok_or("not a valid otpauth:// URI or base32 seed".to_string());
        input.zeroize();
        parsed?
    };

    let uri = totp::to_uri(&cfg, name);
    store_secret(name, uri.as_bytes())?;
    if generate {
        println!("{uri}");
        if let Ok(qr) = crate::network::transfer::qr_code(&uri) {
            eprintln!("\n{qr}");
        }
        eprintln!("generated TOTP '{name}' — register the URI/QR above on the verifying device");
    } else {
        eprintln!("stored TOTP '{name}' — view the code with: simple-secrets otp {name}");
    }
    Ok(())
}

/// `otp NAME` — print the live TOTP code for a stored otpauth:// / base32 secret.
/// The code goes to stdout (scriptable); the countdown goes to stderr.
pub(crate) fn otp(name: &str) -> Result<(), String> {
    use crate::core::totp;
    let mut bytes = fetch_secret(name)?;
    let value = String::from_utf8_lossy(&bytes).into_owned();
    bytes.zeroize();
    let cfg = totp::parse(&value).ok_or_else(|| format!("'{name}' is not a TOTP secret"))?;
    let now = totp::unix_now();
    println!("{}", totp::code_at(&cfg, now));
    eprintln!("valid for {}s", totp::seconds_remaining(&cfg, now));
    Ok(())
}

/// Returns the names of all stored secrets (via the agent).
pub(crate) fn list_names() -> Result<Vec<String>, String> {
    let token = session_token()?;
    match request(&Request::List { token })? {
        Response::Names(names) => Ok(names),
        Response::Err(e) => Err(e),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

/// `list` — print one secret name per line.
pub(crate) fn list() -> Result<(), String> {
    for name in list_names()? {
        println!("{name}");
    }
    Ok(())
}

/// `status` — report whether the agent is running and the vault unlocked.
pub(crate) fn status() -> Result<(), String> {
    let token = match session_token() {
        Ok(t) => t,
        Err(_) => {
            // No session env at all: still useful to say whether a socket answers.
            if connect().is_ok() {
                println!("agent:   running (no session token in this shell)");
            } else {
                println!("agent:   not running");
            }
            return Ok(());
        }
    };
    match request(&Request::Status { token }) {
        Ok(Response::Status {
            unlocked,
            vault_path,
            idle_secs_remaining,
        }) => {
            println!("agent:   running");
            println!("vault:   {vault_path}");
            println!("unlocked:{unlocked}");
            println!("idle in: {idle_secs_remaining}s");
            Ok(())
        }
        Ok(Response::Err(e)) => Err(e),
        Ok(other) => Err(format!("unexpected response: {other:?}")),
        Err(_) => {
            println!("agent:   not running");
            Ok(())
        }
    }
}

/// `signout` — lock the vault and stop the agent.
pub(crate) fn signout() -> Result<(), String> {
    let token = session_token()?;
    match request(&Request::Signout { token })? {
        Response::Ok => {
            println!("# signed out; run: unset SIMPLE_SECRETS_SESSION");
            Ok(())
        }
        Response::Err(e) => Err(e),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

/// `init` — create the persistent vault, prompting for a passphrase twice.
pub(crate) fn init() -> Result<(), String> {
    let vault = paths::vault_path()?;
    if vault.exists() {
        return Err(format!(
            "vault already exists at {}; refusing to overwrite",
            vault.display()
        ));
    }
    if let Some(parent) = vault.parent() {
        paths::ensure_private_dir(parent)?;
    }

    let mut pass = rpassword::prompt_password("New passphrase: ")
        .map_err(|e| format!("cannot read passphrase: {e}"))?;
    let mut confirm = rpassword::prompt_password("Confirm passphrase: ")
        .map_err(|e| format!("cannot read passphrase: {e}"))?;
    if pass.is_empty() {
        pass.zeroize();
        confirm.zeroize();
        return Err("passphrase must not be empty".to_string());
    }
    if pass != confirm {
        pass.zeroize();
        confirm.zeroize();
        return Err("passphrases do not match".to_string());
    }
    confirm.zeroize();

    let mut manager = SecretManager::new(Arc::new(DefaultEntropySource));
    let result = manager.create_vault(&vault, pass.as_bytes(), &Argon2Params::default(), 0, None);
    pass.zeroize();
    result?;
    // manager drops here, locking the vault (master key zeroized on drop).

    println!("created vault at {}", vault.display());
    println!("next: eval $(simple-secrets signin)");
    Ok(())
}

/// `signin` — prompt for the passphrase, spawn a detached agent that unlocks the
/// vault, and print the `export SIMPLE_SECRETS_SESSION=...` line for `eval`.
pub(crate) fn signin() -> Result<(), String> {
    let vault = paths::vault_path()?;
    if !vault.exists() {
        return Err(format!(
            "no vault at {}; run: simple-secrets init",
            vault.display()
        ));
    }
    if connect().is_ok() {
        return Err("an agent is already running; run `simple-secrets signout` first".to_string());
    }

    let mut pass = rpassword::prompt_password("Unlock passphrase: ")
        .map_err(|e| format!("cannot read passphrase: {e}"))?;

    let exe = std::env::current_exe().map_err(|e| format!("cannot locate binary: {e}"))?;
    let mut cmd = Command::new(exe);
    cmd.arg("__agent")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // SAFETY: the pre_exec closure runs in the forked child before execve. It
    // calls only setsid(), which is async-signal-safe; it does not allocate or
    // touch locks. setsid detaches the agent from the controlling terminal so
    // it survives the parent (and the shell) exiting.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("cannot spawn agent: {e}"))?;

    // Write the handshake, then drop stdin (EOF) BEFORE reading stdout, or the
    // child (waiting on stdin EOF) and we (waiting on its stdout) would deadlock.
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "agent stdin unavailable".to_string())?;
        let handshake = format!("{}\n{}\n", vault.display(), pass);
        let write_res = stdin
            .write_all(handshake.as_bytes())
            .map_err(|e| format!("handshake write failed: {e}"));
        // `handshake` and `pass` both hold the passphrase; wipe our copies.
        let mut handshake = handshake;
        handshake.zeroize();
        pass.zeroize();
        write_res?;
        // stdin drops here -> EOF for the child.
    }

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "agent stdout unavailable".to_string())?;
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .map_err(|e| format!("agent handshake read failed: {e}"))?;
    let line = line.trim_end();

    if let Some(token) = line.strip_prefix("READY ") {
        println!("export SIMPLE_SECRETS_SESSION={token}");
        Ok(())
    } else if let Some(msg) = line.strip_prefix("ERR ") {
        Err(msg.to_string())
    } else {
        Err(format!("agent handshake failed: {line:?}"))
    }
}
