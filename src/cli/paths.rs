//! Filesystem path resolution for the persistent vault and the agent socket.
//!
//! Resolution is factored through an injectable env lookup so the precedence
//! rules can be unit-tested without mutating the process-global environment.

use std::path::{Path, PathBuf};

/// Conservative cap on a Unix-domain socket path. `sockaddr_un.sun_path` is 108
/// bytes on Linux but only 104 on macOS; we hold to the smaller limit so a path
/// that binds on Linux also binds on macOS.
const MAX_SOCKET_PATH_LEN: usize = 104;

/// Looks up an environment variable, treating empty values as unset.
fn env_lookup(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// Resolves the persistent vault path, honoring (in order):
/// `SIMPLE_SECRETS_VAULT`, `XDG_DATA_HOME/simple-secrets/vault.bin`, then
/// `HOME/.local/share/simple-secrets/vault.bin`.
pub fn vault_path() -> Result<PathBuf, String> {
    resolve_vault_path(&env_lookup)
}

fn resolve_vault_path(env: &dyn Fn(&str) -> Option<String>) -> Result<PathBuf, String> {
    if let Some(explicit) = env("SIMPLE_SECRETS_VAULT") {
        return Ok(PathBuf::from(explicit));
    }
    if let Some(data_home) = env("XDG_DATA_HOME") {
        return Ok(PathBuf::from(data_home)
            .join("simple-secrets")
            .join("vault.bin"));
    }
    if let Some(home) = env("HOME") {
        return Ok(PathBuf::from(home)
            .join(".local/share/simple-secrets")
            .join("vault.bin"));
    }
    Err("cannot locate vault: set $SIMPLE_SECRETS_VAULT or $HOME".to_string())
}

/// Resolves the per-user agent socket path. Prefers `XDG_RUNTIME_DIR`
/// (`<dir>/simple-secrets/agent.sock`); otherwise falls back to a uid-scoped
/// directory under `TMPDIR` (or `/tmp`).
pub fn socket_path() -> Result<PathBuf, String> {
    // SAFETY: getuid() is always successful and has no preconditions.
    let uid = unsafe { libc::getuid() };
    resolve_socket_path(&env_lookup, uid)
}

fn resolve_socket_path(env: &dyn Fn(&str) -> Option<String>, uid: u32) -> Result<PathBuf, String> {
    let dir = if let Some(runtime) = env("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime).join("simple-secrets")
    } else {
        let tmp = env("TMPDIR").unwrap_or_else(|| "/tmp".to_string());
        PathBuf::from(tmp).join(format!("simple-secrets-{uid}"))
    };
    let sock = dir.join("agent.sock");
    let len = sock.as_os_str().len();
    if len >= MAX_SOCKET_PATH_LEN {
        return Err(format!(
            "agent socket path is too long ({len} bytes; limit {MAX_SOCKET_PATH_LEN}). \
             Set $XDG_RUNTIME_DIR to a shorter directory."
        ));
    }
    Ok(sock)
}

/// Creates `dir` (and parents) if absent and tightens it to owner-only (0700).
pub fn ensure_private_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("cannot chmod {}: {e}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn faker(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k: &str| map.get(k).cloned()
    }

    #[test]
    fn vault_path_prefers_explicit_override() {
        let env = faker(&[
            ("SIMPLE_SECRETS_VAULT", "/custom/v.bin"),
            ("XDG_DATA_HOME", "/xdg"),
            ("HOME", "/home/u"),
        ]);
        assert_eq!(
            resolve_vault_path(&env).unwrap(),
            PathBuf::from("/custom/v.bin")
        );
    }

    #[test]
    fn vault_path_falls_back_to_xdg_then_home() {
        let xdg = faker(&[("XDG_DATA_HOME", "/xdg"), ("HOME", "/home/u")]);
        assert_eq!(
            resolve_vault_path(&xdg).unwrap(),
            PathBuf::from("/xdg/simple-secrets/vault.bin")
        );
        let home = faker(&[("HOME", "/home/u")]);
        assert_eq!(
            resolve_vault_path(&home).unwrap(),
            PathBuf::from("/home/u/.local/share/simple-secrets/vault.bin")
        );
    }

    #[test]
    fn vault_path_errors_when_unresolvable() {
        let env = faker(&[]);
        assert!(resolve_vault_path(&env).is_err());
    }

    #[test]
    fn socket_path_prefers_runtime_dir() {
        let env = faker(&[("XDG_RUNTIME_DIR", "/run/user/1000")]);
        assert_eq!(
            resolve_socket_path(&env, 1000).unwrap(),
            PathBuf::from("/run/user/1000/simple-secrets/agent.sock")
        );
    }

    #[test]
    fn socket_path_falls_back_to_uid_scoped_tmp() {
        let env = faker(&[("TMPDIR", "/tmp")]);
        assert_eq!(
            resolve_socket_path(&env, 501).unwrap(),
            PathBuf::from("/tmp/simple-secrets-501/agent.sock")
        );
    }

    #[test]
    fn socket_path_rejects_overlong_base() {
        let long = format!("/{}", "x".repeat(120));
        let env = faker(&[("XDG_RUNTIME_DIR", long.as_str())]);
        assert!(resolve_socket_path(&env, 0).is_err());
    }
}
