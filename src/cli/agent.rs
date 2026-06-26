//! The background session agent.
//!
//! [`run_agent`] is the hidden `__agent` entrypoint: it reads the vault path and
//! passphrase from its stdin (written by the `signin` parent), opens the vault,
//! mints a session token, binds a per-user Unix socket, hands the token back to
//! the parent over stdout, detaches its standard streams, and then serves
//! requests via [`Agent::serve`].
//!
//! [`Agent::serve`] is split out as the testable core: it owns the unlocked
//! [`SecretManager`] on a single thread (so the `Send`-but-not-`Sync`
//! [`crate::storage::local_store::LocalStore`] never needs a lock) and handles
//! one request per accepted connection.

use crate::cli::paths;
use crate::cli::protocol::{read_msg, write_msg, Request, Response, TOKEN_B64};
use crate::core::entropy::DefaultEntropySource;
use crate::core::manager::SecretManager;
use base64::Engine;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Default idle lifetime before the agent locks itself and exits (mirrors `op`).
pub(crate) const DEFAULT_IDLE: Duration = Duration::from_secs(30 * 60);

/// Tracks time since start and the last request, so a watchdog can detect idle
/// expiry without touching the (non-`Sync`) manager.
pub(crate) struct ActivityClock {
    start: Instant,
    last_ms: AtomicU64,
}

impl ActivityClock {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last_ms: AtomicU64::new(0),
        }
    }

    fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    fn touch(&self) {
        self.last_ms.store(self.elapsed_ms(), Ordering::SeqCst);
    }

    fn idle(&self) -> Duration {
        Duration::from_millis(
            self.elapsed_ms()
                .saturating_sub(self.last_ms.load(Ordering::SeqCst)),
        )
    }
}

/// An unlocked agent ready to serve requests.
pub(crate) struct Agent {
    manager: SecretManager,
    token: Vec<u8>,
    vault_path: String,
    idle: Duration,
    clock: Arc<ActivityClock>,
}

impl Agent {
    pub(crate) fn new(
        manager: SecretManager,
        token: Vec<u8>,
        vault_path: String,
        idle: Duration,
    ) -> Self {
        let clock = Arc::new(ActivityClock::new());
        clock.touch();
        Self {
            manager,
            token,
            vault_path,
            idle,
            clock,
        }
    }

    pub(crate) fn clock(&self) -> Arc<ActivityClock> {
        Arc::clone(&self.clock)
    }

    /// Serves one request per accepted connection until a valid `Signout`
    /// arrives (or the listener errors). On signout the vault is locked (its
    /// master key zeroized on drop) before returning.
    pub(crate) fn serve(mut self, listener: UnixListener) -> Result<(), String> {
        for conn in listener.incoming() {
            let mut stream = match conn {
                Ok(s) => s,
                Err(_) => continue, // transient accept error; keep serving
            };
            self.clock.touch();
            let req: Request = match read_msg(&mut stream) {
                Ok(r) => r,
                Err(_) => continue, // malformed frame; drop this connection
            };
            let (resp, signout) = self.handle(req);
            let _ = write_msg(&mut stream, &resp);
            if signout {
                self.manager.lock();
                return Ok(());
            }
        }
        Ok(())
    }

    fn handle(&mut self, req: Request) -> (Response, bool) {
        if !token_eq(&self.token, req.token()) {
            return (Response::Err("invalid session token".to_string()), false);
        }
        match req {
            Request::Get { name, .. } => match self.manager.get_secret(&name) {
                Ok(v) => (Response::Secret(v), false),
                Err(e) => (Response::Err(e), false),
            },
            Request::Put {
                name, mut value, ..
            } => {
                let out = match self.manager.put_secret(&name, &value) {
                    Ok(()) => Response::Ok,
                    Err(e) => Response::Err(e),
                };
                value.zeroize(); // best-effort wipe of the plaintext we received
                (out, false)
            }
            Request::List { .. } => match self.manager.secret_names() {
                Ok(names) => (Response::Names(names), false),
                Err(e) => (Response::Err(e), false),
            },
            Request::Status { .. } => {
                let remaining = self.idle.saturating_sub(self.clock.idle());
                (
                    Response::Status {
                        unlocked: self.manager.is_unlocked(),
                        vault_path: self.vault_path.clone(),
                        idle_secs_remaining: remaining.as_secs(),
                    },
                    false,
                )
            }
            Request::Signout { .. } => (Response::Ok, true),
        }
    }
}

/// Constant-time comparison of two byte strings (length-checked first).
fn token_eq(expected: &[u8], presented: &[u8]) -> bool {
    if expected.len() != presented.len() {
        return false;
    }
    expected.ct_eq(presented).into()
}

/// Hidden `__agent` entrypoint. Reads `vault_path\npassphrase\n` from stdin,
/// opens the vault, and starts serving. Communicates success/failure back to
/// the `signin` parent over stdout (`READY <token>` / `ERR <message>`).
pub(crate) fn run_agent() -> i32 {
    // Read the whole handshake (parent closes stdin to signal EOF).
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        return fail_handshake(&format!("cannot read handshake: {e}"));
    }
    let mut lines = input.lines();
    let vault_path = lines.next().unwrap_or("").to_string();
    let passphrase = lines.next().unwrap_or("").to_string();
    if vault_path.is_empty() {
        input.zeroize();
        return fail_handshake("missing vault path in handshake");
    }

    let mut manager = SecretManager::new(Arc::new(DefaultEntropySource));
    if let Err(e) = manager.open_vault(Path::new(&vault_path), passphrase.as_bytes(), None) {
        input.zeroize();
        return fail_handshake(&format!("cannot open vault: {e}"));
    }
    input.zeroize(); // wipe the passphrase from our address space

    let token = match manager.random_bytes(32) {
        Ok(t) => t,
        Err(e) => return fail_handshake(&format!("cannot mint token: {e}")),
    };
    let token_b64 = TOKEN_B64.encode(&token);

    let sock = match bind_socket() {
        Ok(s) => s,
        Err(e) => return fail_handshake(&e),
    };

    // Hand the token to the parent, then detach so its `read_line` returns.
    println!("READY {token_b64}");
    let _ = std::io::stdout().flush();
    detach_stdio();

    let listener = open_listener(&sock);
    let agent = Agent::new(manager, token, vault_path, DEFAULT_IDLE);
    spawn_watchdog(agent.clock(), DEFAULT_IDLE, sock.clone());
    let result = agent.serve(listener);
    let _ = std::fs::remove_file(&sock);
    match result {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// Reports a pre-detach failure to the parent over stdout and returns exit 1.
fn fail_handshake(msg: &str) -> i32 {
    println!("ERR {msg}");
    let _ = std::io::stdout().flush();
    1
}

/// Resolves the socket path, refuses to start if a live agent already answers,
/// clears a stale socket node, prepares the 0700 parent directory, and returns
/// the path (the actual bind happens in [`open_listener`]).
fn bind_socket() -> Result<PathBuf, String> {
    let sock = paths::socket_path()?;
    if let Some(parent) = sock.parent() {
        paths::ensure_private_dir(parent)?;
    }
    if UnixStream::connect(&sock).is_ok() {
        return Err("an agent is already running for this user".to_string());
    }
    // Either no socket node, or a stale one from a crashed agent.
    let _ = std::fs::remove_file(&sock);
    Ok(sock)
}

/// Binds the listener and tightens the socket node to owner-only (0600). Kept
/// separate so the path can be validated before we detach stdio.
fn open_listener(sock: &Path) -> UnixListener {
    use std::os::unix::fs::PermissionsExt;
    // bind() into the already-0700 parent dir; a panic here is unrecoverable
    // because we have already detached and told the parent we are READY.
    let listener = UnixListener::bind(sock).expect("bind agent socket");
    let _ = std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o600));
    listener
}

/// Redirects fd 0/1/2 onto `/dev/null`, severing the parent's pipes.
fn detach_stdio() {
    // SAFETY: opening /dev/null and dup2'ing it over the standard fds is the
    // standard daemonization step; the fds are valid for the process lifetime.
    unsafe {
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if devnull >= 0 {
            libc::dup2(devnull, 0);
            libc::dup2(devnull, 1);
            libc::dup2(devnull, 2);
            if devnull > 2 {
                libc::close(devnull);
            }
        }
    }
}

/// Spawns a watchdog that exits the process once the idle deadline passes.
///
/// It only reads the [`ActivityClock`] (never the manager), so it is safe
/// alongside the single-threaded serve loop. Exiting via `process::exit` skips
/// the manager's `Drop`, so the master key is not explicitly zeroized on this
/// path; it stays mlock'd (never swapped) and the kernel zeroes freed pages, so
/// it never reaches disk.
fn spawn_watchdog(clock: Arc<ActivityClock>, idle: Duration, sock: PathBuf) {
    std::thread::spawn(move || {
        let tick = Duration::from_secs(15).min(idle);
        loop {
            std::thread::sleep(tick);
            if clock.idle() >= idle {
                let _ = std::fs::remove_file(&sock);
                std::process::exit(0);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::vdf_kdf::Argon2Params;
    use std::sync::atomic::AtomicU32;

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn temp_dir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("ss-agent-test-{}-{}", std::process::id(), n))
    }

    fn fast_params() -> Argon2Params {
        Argon2Params {
            time: 1,
            memory: 8 * 1024,
            threads: 1,
        }
    }

    #[test]
    fn token_eq_is_correct() {
        assert!(token_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!token_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!token_eq(&[1, 2, 3], &[1, 2])); // length mismatch
    }

    #[test]
    fn agent_serves_then_signs_out() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let vault = dir.join("vault.bin");
        let sock = dir.join("agent.sock");

        let mut mgr = SecretManager::new(Arc::new(DefaultEntropySource));
        mgr.create_vault(&vault, b"correct horse", &fast_params(), 0, None)
            .unwrap();

        let token = vec![9u8; 32];
        let listener = UnixListener::bind(&sock).unwrap();
        let agent = Agent::new(
            mgr,
            token.clone(),
            vault.display().to_string(),
            Duration::from_secs(3600),
        );
        let handle = std::thread::spawn(move || agent.serve(listener));

        let send = |req: &Request| -> Response {
            let mut s = UnixStream::connect(&sock).unwrap();
            write_msg(&mut s, req).unwrap();
            read_msg(&mut s).unwrap()
        };

        assert_eq!(
            send(&Request::Put {
                token: token.clone(),
                name: "k".into(),
                value: b"v".to_vec()
            }),
            Response::Ok
        );
        assert_eq!(
            send(&Request::List {
                token: token.clone()
            }),
            Response::Names(vec!["k".into()])
        );
        assert_eq!(
            send(&Request::Get {
                token: token.clone(),
                name: "k".into()
            }),
            Response::Secret(Some(b"v".to_vec()))
        );
        assert_eq!(
            send(&Request::Get {
                token: token.clone(),
                name: "absent".into()
            }),
            Response::Secret(None)
        );
        // A wrong token must be rejected.
        match send(&Request::List {
            token: vec![0u8; 32],
        }) {
            Response::Err(_) => {}
            other => panic!("expected Err, got {other:?}"),
        }
        // Status reports the vault as unlocked.
        match send(&Request::Status {
            token: token.clone(),
        }) {
            Response::Status { unlocked, .. } => assert!(unlocked),
            other => panic!("expected Status, got {other:?}"),
        }

        assert_eq!(
            send(&Request::Signout {
                token: token.clone()
            }),
            Response::Ok
        );
        handle.join().unwrap().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
