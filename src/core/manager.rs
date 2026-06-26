use crate::core::entropy::EntropySource;
use crate::crypto::vdf_kdf::Argon2Params;
use crate::sharing::multisig::{self, SplitResult};
use crate::storage::local_store::LocalStore;
use crate::storage::ram_store::RamStore;
use secure_memory::LockedBuffer;
use std::path::Path;
use std::sync::Arc;

/// The central facade for the library: it owns the entropy source, an optional
/// open on-disk vault, and an in-RAM store, and ties the cryptographic
/// primitives together so embedders interact with a single type.
///
/// The vault is locked (closed) until [`create_vault`](Self::create_vault) or
/// [`open_vault`](Self::open_vault) is called; secret operations error while it
/// is locked.
pub struct SecretManager {
    entropy_source: Arc<dyn EntropySource + Send + Sync>,
    vault: Option<LocalStore>,
    ram: RamStore,
}

impl SecretManager {
    pub fn new(entropy_source: Arc<dyn EntropySource + Send + Sync>) -> Self {
        Self {
            entropy_source,
            vault: None,
            ram: RamStore::new(),
        }
    }

    /// Draws `len` bytes of randomness from the configured entropy source.
    ///
    /// This is the single funnel through which key material, salts, and nonces
    /// should be generated, so that callers embedding the library can swap in a
    /// hardware RNG or a deterministic test source.
    pub fn random_bytes(&self, len: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; len];
        self.entropy_source.fill_bytes(&mut buf)?;
        Ok(buf)
    }

    /// Generates a memorable `word_count`-word passphrase from the default
    /// 2048-word BIP-0039 list, drawing uniform randomness from the entropy
    /// source. At 11 bits/word a 20-word phrase carries 220 bits of entropy. See
    /// [`crate::core::passphrase`].
    pub fn generate_passphrase(&self, word_count: usize) -> Result<String, String> {
        use crate::core::passphrase;
        let wordlist = passphrase::default_wordlist();
        let need = passphrase::required_random_bytes(wordlist.len(), word_count);
        let random = self.random_bytes(need)?;
        let words = passphrase::select_words(&wordlist, word_count, &random)?;
        Ok(words.join(" "))
    }

    /// Generates a random `len`-character password drawn uniformly from `charset`
    /// (which must be non-empty ASCII). Uses rejection sampling so there is no
    /// modulo bias toward earlier characters.
    pub fn generate_password(&self, len: usize, charset: &[u8]) -> Result<String, String> {
        let n = charset.len();
        if n == 0 || n > 256 {
            return Err("charset must have 1..=256 characters".to_string());
        }
        // Largest multiple of n that fits in a byte; bytes at/above are rejected.
        let limit = (256 / n) * n;
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            for &b in &self.random_bytes(len)? {
                if (b as usize) < limit {
                    out.push(charset[b as usize % n]);
                    if out.len() == len {
                        break;
                    }
                }
            }
        }
        String::from_utf8(out).map_err(|_| "charset must be ASCII".to_string())
    }

    // ── Vault lifecycle ──────────────────────────────────────────

    /// Creates a new on-disk vault, generating a fresh random salt from the
    /// entropy source, and leaves it open on the manager. Fails if a file already
    /// exists at `path`.
    pub fn create_vault(
        &mut self,
        path: &Path,
        passphrase: &[u8],
        params: &Argon2Params,
        vdf_iterations: u64,
        hardware_key: Option<&[u8]>,
    ) -> Result<(), String> {
        let salt = self.random_bytes(32)?;
        let store = LocalStore::create(
            path,
            passphrase,
            &salt,
            params,
            vdf_iterations,
            hardware_key,
        )?;
        self.vault = Some(store);
        Ok(())
    }

    /// Opens an existing vault (its salt and KDF parameters come from the file
    /// header) and leaves it open on the manager.
    pub fn open_vault(
        &mut self,
        path: &Path,
        passphrase: &[u8],
        hardware_key: Option<&[u8]>,
    ) -> Result<(), String> {
        self.vault = Some(LocalStore::open(path, passphrase, hardware_key)?);
        Ok(())
    }

    /// Closes the open vault, dropping the master key (zeroized on drop).
    pub fn lock(&mut self) {
        self.vault = None;
    }

    /// Whether a vault is currently open.
    pub fn is_unlocked(&self) -> bool {
        self.vault.is_some()
    }

    fn vault_mut(&mut self) -> Result<&mut LocalStore, String> {
        self.vault
            .as_mut()
            .ok_or_else(|| "vault is locked".to_string())
    }

    fn vault_ref(&self) -> Result<&LocalStore, String> {
        self.vault
            .as_ref()
            .ok_or_else(|| "vault is locked".to_string())
    }

    // ── Secret storage (plaintext in, sealed on disk) ────────────

    /// Stores a plaintext secret, encrypting it per-entry before it is written.
    pub fn put_secret(&mut self, name: &str, plaintext: &[u8]) -> Result<(), String> {
        self.vault_mut()?.put_secret(name, plaintext)
    }

    /// Retrieves and decrypts a stored secret, or `None` if absent.
    pub fn get_secret(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
        self.vault_ref()?.get_secret(name)
    }

    /// Names of all stored secrets.
    pub fn secret_names(&self) -> Result<Vec<String>, String> {
        Ok(self
            .vault_ref()?
            .names()
            .iter()
            .map(|s| s.to_string())
            .collect())
    }

    /// Deletes a stored secret. `Ok(true)` if it existed, `Ok(false)` otherwise.
    pub fn delete_secret(&mut self, name: &str) -> Result<bool, String> {
        self.vault_mut()?.delete_secret(name)
    }

    // ── In-RAM, never-persisted secrets ──────────────────────────

    /// Loads a secret into the in-RAM store (e.g. for piping to a child process).
    /// These values are never written to disk and are wiped on drop / [`clear_ram`].
    pub fn put_ram(&mut self, name: &str, value: LockedBuffer) {
        self.ram.set(name, value);
    }

    pub fn get_ram(&self, name: &str) -> Option<&LockedBuffer> {
        self.ram.get(name)
    }

    pub fn clear_ram(&mut self) {
        self.ram.clear();
    }

    // ── k-in-n sharing ───────────────────────────────────────────

    /// Splits `secret` into `n` custodian-encrypted shares with threshold `m`,
    /// using the authenticated multisig scheme (sub-threshold reconstruction is
    /// rejected, not silently wrong).
    pub fn share_secret(
        &self,
        secret: &[u8],
        m: usize,
        n: usize,
        custodian_keys: &[&[u8]],
    ) -> Result<SplitResult, String> {
        multisig::split_secret(secret, m, n, custodian_keys)
    }

    /// Reconstructs a secret from custodian shares, verifying both per-share
    /// commitments and the embedded secret integrity tag.
    pub fn reconstruct_secret(
        &self,
        blobs: &[&[u8]],
        custodian_keys: &[&[u8]],
        commitments: &[Vec<u8>],
    ) -> Result<Vec<u8>, String> {
        multisig::reconstruct_secret(blobs, custodian_keys, commitments)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entropy::DefaultEntropySource;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);
    fn temp_path() -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("ss-mgr-test-{}-{}.bin", std::process::id(), n))
    }

    fn fast_params() -> Argon2Params {
        Argon2Params {
            time: 1,
            memory: 8 * 1024,
            threads: 1,
        }
    }

    fn manager() -> SecretManager {
        SecretManager::new(Arc::new(DefaultEntropySource))
    }

    #[test]
    fn vault_lifecycle_and_secret_round_trip() {
        let path = temp_path();
        let mut mgr = manager();
        assert!(!mgr.is_unlocked());
        assert!(
            mgr.put_secret("k", b"v").is_err(),
            "must error while locked"
        );

        mgr.create_vault(&path, b"pw", &fast_params(), 0, None)
            .unwrap();
        assert!(mgr.is_unlocked());
        mgr.put_secret("api-token", b"hunter2").unwrap();
        mgr.put_secret("ssh", b"key-bytes").unwrap();

        let mut names = mgr.secret_names().unwrap();
        names.sort();
        assert_eq!(names, vec!["api-token".to_string(), "ssh".to_string()]);

        mgr.lock();
        assert!(!mgr.is_unlocked());

        // Reopen from disk and read the secret back.
        mgr.open_vault(&path, b"pw", None).unwrap();
        assert_eq!(mgr.get_secret("api-token").unwrap().unwrap(), b"hunter2");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn delete_secret_removes_and_persists() {
        let path = temp_path();
        let mut mgr = manager();
        assert!(
            mgr.delete_secret("x").is_err(),
            "delete must error while locked"
        );

        mgr.create_vault(&path, b"pw", &fast_params(), 0, None)
            .unwrap();
        mgr.put_secret("keep", b"1").unwrap();
        mgr.put_secret("drop", b"2").unwrap();

        assert!(mgr.delete_secret("drop").unwrap(), "existing -> true");
        assert!(!mgr.delete_secret("drop").unwrap(), "absent -> false");

        // Removal is persisted: reopen from disk and confirm.
        mgr.lock();
        mgr.open_vault(&path, b"pw", None).unwrap();
        let names = mgr.secret_names().unwrap();
        assert_eq!(names, vec!["keep".to_string()]);
        assert!(mgr.get_secret("drop").unwrap().is_none());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn generates_passphrase_of_requested_length() {
        let mgr = manager();
        let phrase = mgr.generate_passphrase(20).unwrap();
        assert_eq!(phrase.split(' ').count(), 20);
        assert!(phrase.split(' ').all(|w| !w.is_empty()));
    }

    #[test]
    fn generates_password_of_requested_length_and_charset() {
        let mgr = manager();
        let charset = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        let pw = mgr.generate_password(40, charset).unwrap();
        assert_eq!(pw.len(), 40);
        assert!(pw.bytes().all(|b| charset.contains(&b)));
        assert!(mgr.generate_password(8, b"").is_err());
    }

    #[test]
    fn ram_secrets_are_isolated_from_vault() {
        let mut mgr = manager();
        let buf = LockedBuffer::from_bytes_move(&mut b"in-ram".to_vec()).unwrap();
        mgr.put_ram("session", buf);
        assert!(mgr.get_ram("session").is_some());
        mgr.clear_ram();
        assert!(mgr.get_ram("session").is_none());
    }

    #[test]
    fn share_and_reconstruct_through_manager() {
        let mgr = manager();
        let keys: Vec<[u8; 32]> = (0u8..3).map(|i| [i + 1; 32]).collect();
        let kr: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
        let split = mgr.share_secret(b"shared secret", 2, 3, &kr).unwrap();
        let blobs: Vec<&[u8]> = split.blobs.iter().map(|b| b.as_slice()).collect();
        let recovered = mgr
            .reconstruct_secret(&blobs, &kr, &split.commitments)
            .unwrap();
        assert_eq!(recovered, b"shared secret");
    }
}
