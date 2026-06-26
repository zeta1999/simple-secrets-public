use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::vdf_kdf::{derive_key, Argon2Params};
use hkdf::Hkdf;
use secure_memory::crypto::{decrypt_aad, encrypt_aad};
use secure_memory::LockedBuffer;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use zeroize::Zeroize;

/// On-disk vault layout: a fixed-size cleartext header followed by the AEAD
/// ciphertext of the serialized entries. The header is self-describing — it
/// carries the salt and KDF parameters so a vault can be reopened with only the
/// passphrase (and optional hardware key); it is bound into the ciphertext as
/// associated data so the parameters cannot be tampered with or downgraded.
const MAGIC: &[u8; 4] = b"SSV1";
const HEADER_VERSION: u8 = 1;
const SALT_LEN: usize = 32;
// magic(4) + version(1) + salt(32) + argon_time(4) + argon_memory(4)
// + argon_threads(4) + vdf_iterations(8)
const HEADER_LEN: usize = 4 + 1 + SALT_LEN + 4 + 4 + 4 + 8;

#[derive(Serialize, Deserialize)]
pub struct SecretEntry {
    pub name: String,
    pub encrypted_value: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct VaultPayload {
    entries: Vec<SecretEntry>,
}

struct VaultHeader {
    salt: [u8; SALT_LEN],
    params: Argon2Params,
    vdf_iterations: u64,
}

impl VaultHeader {
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN);
        out.extend_from_slice(MAGIC);
        out.push(HEADER_VERSION);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.params.time.to_le_bytes());
        out.extend_from_slice(&self.params.memory.to_le_bytes());
        out.extend_from_slice(&self.params.threads.to_le_bytes());
        out.extend_from_slice(&self.vdf_iterations.to_le_bytes());
        out
    }

    fn parse(data: &[u8]) -> Result<(Self, &[u8]), String> {
        if data.len() < HEADER_LEN {
            return Err("vault file too short for header".to_string());
        }
        let (header, ciphertext) = data.split_at(HEADER_LEN);
        if &header[0..4] != MAGIC {
            return Err("not a simple-secrets vault (bad magic)".to_string());
        }
        if header[4] != HEADER_VERSION {
            return Err(format!("unsupported vault version {}", header[4]));
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&header[5..5 + SALT_LEN]);
        let mut off = 5 + SALT_LEN;
        let time = u32::from_le_bytes(header[off..off + 4].try_into().unwrap());
        off += 4;
        let memory = u32::from_le_bytes(header[off..off + 4].try_into().unwrap());
        off += 4;
        let threads = u32::from_le_bytes(header[off..off + 4].try_into().unwrap());
        off += 4;
        let vdf_iterations = u64::from_le_bytes(header[off..off + 8].try_into().unwrap());
        Ok((
            Self {
                salt,
                params: Argon2Params {
                    time,
                    memory,
                    threads,
                },
                vdf_iterations,
            },
            ciphertext,
        ))
    }
}

pub struct LocalStore {
    path: PathBuf,
    master_key: LockedBuffer,
    header: VaultHeader,
    entries: HashMap<String, SecretEntry>,
}

impl LocalStore {
    /// Creates a new vault on disk. Fails (race-free, via `O_EXCL`) if `path`
    /// already exists, so an existing vault is never silently clobbered. The
    /// 32-byte `salt` should be freshly random (see `SecretManager::random_bytes`).
    pub fn create(
        path: &Path,
        passphrase: &[u8],
        salt: &[u8],
        params: &Argon2Params,
        vdf_iterations: u64,
        hardware_key: Option<&[u8]>,
    ) -> Result<Self, String> {
        if salt.len() != SALT_LEN {
            return Err(format!("salt must be {} bytes", SALT_LEN));
        }
        // Atomically reserve the path (O_EXCL): this fails if the file already
        // exists, with no check-then-write TOCTOU race against another process.
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| format!("cannot create vault at {}: {}", path.display(), e))?;
        let master_key = derive_key(passphrase, salt, params, vdf_iterations, hardware_key)?;
        let mut salt_arr = [0u8; SALT_LEN];
        salt_arr.copy_from_slice(salt);
        let store = Self {
            path: path.to_path_buf(),
            master_key,
            header: VaultHeader {
                salt: salt_arr,
                params: Argon2Params {
                    time: params.time,
                    memory: params.memory,
                    threads: params.threads,
                },
                vdf_iterations,
            },
            entries: HashMap::new(),
        };
        store.save()?;
        Ok(store)
    }

    /// Opens an existing vault. The salt and KDF parameters are read from the
    /// vault's own header, so only the passphrase (and the same optional
    /// `hardware_key` used at creation) are required.
    pub fn open(
        path: &Path,
        passphrase: &[u8],
        hardware_key: Option<&[u8]>,
    ) -> Result<Self, String> {
        let data = fs::read(path).map_err(|e| format!("Failed to read vault: {}", e))?;
        let (header, ciphertext) = VaultHeader::parse(&data)?;
        let header_bytes = header.to_bytes();

        let master_key = derive_key(
            passphrase,
            &header.salt,
            &header.params,
            header.vdf_iterations,
            hardware_key,
        )?;

        let mut payload_bytes =
            decrypt_aad(master_key.as_slice().unwrap(), ciphertext, &header_bytes)
                .map_err(|e| format!("Failed to decrypt vault: {:?}", e))?;

        let payload: VaultPayload = bincode::deserialize(&payload_bytes)
            .map_err(|e| format!("Failed to deserialize vault: {}", e))?;
        payload_bytes.zeroize();

        let mut entries = HashMap::new();
        for entry in payload.entries {
            entries.insert(entry.name.clone(), entry);
        }

        Ok(Self {
            path: path.to_path_buf(),
            master_key,
            header,
            entries,
        })
    }

    pub fn save(&self) -> Result<(), String> {
        let entries_vec: Vec<SecretEntry> = self
            .entries
            .values()
            .map(|e| SecretEntry {
                name: e.name.clone(),
                encrypted_value: e.encrypted_value.clone(),
            })
            .collect();

        let payload = VaultPayload {
            entries: entries_vec,
        };
        let mut payload_bytes = bincode::serialize(&payload)
            .map_err(|e| format!("Failed to serialize vault: {}", e))?;

        let header_bytes = self.header.to_bytes();
        let encrypted = encrypt_aad(
            self.master_key.as_slice().unwrap(),
            &payload_bytes,
            &header_bytes,
        )
        .map_err(|e| format!("Failed to encrypt vault: {:?}", e))?;
        payload_bytes.zeroize();

        let mut file_bytes = header_bytes;
        file_bytes.extend_from_slice(&encrypted);

        // Write to a sibling temp file and rename over the target, so a crash
        // mid-write leaves the previous vault intact instead of a truncated one.
        let mut tmp_os = self.path.as_os_str().to_owned();
        tmp_os.push(".tmp");
        let tmp = PathBuf::from(tmp_os);
        fs::write(&tmp, &file_bytes).map_err(|e| format!("Failed to write vault: {}", e))?;
        fs::rename(&tmp, &self.path).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            format!("Failed to finalize vault: {}", e)
        })?;

        Ok(())
    }

    /// Stores a raw, already-encrypted value verbatim and persists the vault.
    /// Crate-internal: external callers must go through
    /// [`put_secret`](Self::put_secret) so values are always sealed, never stored
    /// in the clear by mistake.
    pub(crate) fn set(&mut self, name: &str, encrypted_value: Vec<u8>) -> Result<(), String> {
        self.entries.insert(
            name.to_string(),
            SecretEntry {
                name: name.to_string(),
                encrypted_value,
            },
        );
        self.save()
    }

    /// Returns the raw stored (ciphertext) bytes for `name`. Crate-internal;
    /// external callers want [`get_secret`](Self::get_secret).
    pub(crate) fn get(&self, name: &str) -> Option<&Vec<u8>> {
        self.entries.get(name).map(|e| &e.encrypted_value)
    }

    /// The per-entry value-encryption key, derived from the vault master key via
    /// HKDF with a distinct label so it is cryptographically separated from the
    /// key used for the whole-file envelope.
    fn value_key(&self) -> [u8; 32] {
        let hk = Hkdf::<Sha512>::new(None, self.master_key.as_slice().unwrap());
        let mut k = [0u8; 32];
        hk.expand(b"simple-secrets/value-key/v1", &mut k)
            .expect("32 is a valid HKDF-SHA512 output length");
        k
    }

    /// Encrypts `plaintext` under a per-entry key (binding the entry name as
    /// associated data) and stores the ciphertext, giving defence-in-depth on top
    /// of the whole-vault envelope. The plaintext never touches disk in the clear.
    pub fn put_secret(&mut self, name: &str, plaintext: &[u8]) -> Result<(), String> {
        let mut vk = self.value_key();
        let ciphertext = encrypt_aad(&vk, plaintext, name.as_bytes())
            .map_err(|e| format!("Failed to seal secret: {:?}", e));
        vk.zeroize();
        self.set(name, ciphertext?)
    }

    /// Decrypts and returns the plaintext value previously stored with
    /// [`put_secret`](Self::put_secret), or `None` if `name` is absent.
    pub fn get_secret(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
        let ciphertext = match self.get(name) {
            None => return Ok(None),
            Some(ct) => ct,
        };
        let mut vk = self.value_key();
        let plaintext = decrypt_aad(&vk, ciphertext, name.as_bytes())
            .map_err(|e| format!("Failed to open secret: {:?}", e));
        vk.zeroize();
        Ok(Some(plaintext?))
    }

    /// Names of all stored entries.
    pub fn names(&self) -> Vec<&str> {
        self.entries.keys().map(|s| s.as_str()).collect()
    }

    /// Removes the entry `name` and persists the vault. Returns `Ok(true)` if an
    /// entry was removed, `Ok(false)` if `name` was absent (no rewrite then).
    pub fn delete_secret(&mut self, name: &str) -> Result<bool, String> {
        if self.entries.remove(name).is_some() {
            self.save()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    // Unique temp path per test invocation without relying on Date/random.
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    fn temp_path() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("ss-vault-test-{}-{}.bin", std::process::id(), n))
    }

    fn fast_params() -> Argon2Params {
        Argon2Params {
            time: 1,
            memory: 8 * 1024,
            threads: 1,
        }
    }

    #[test]
    fn create_persists_and_reopens_with_only_passphrase() {
        let path = temp_path();
        let salt = [3u8; SALT_LEN];
        let params = fast_params();
        {
            let mut store = LocalStore::create(&path, b"pw", &salt, &params, 4, None).unwrap();
            store.set("k", b"ciphertext".to_vec()).unwrap();
        }
        // Reopen needs no salt/params — they come from the header.
        let store = LocalStore::open(&path, b"pw", None).unwrap();
        assert_eq!(store.get("k").unwrap(), b"ciphertext");
        fs::remove_file(&path).ok();
    }

    #[test]
    fn create_refuses_to_clobber() {
        let path = temp_path();
        let salt = [3u8; SALT_LEN];
        let params = fast_params();
        LocalStore::create(&path, b"pw", &salt, &params, 0, None).unwrap();
        let again = LocalStore::create(&path, b"pw", &salt, &params, 0, None);
        assert!(again.is_err());
        fs::remove_file(&path).ok();
    }

    #[test]
    fn put_secret_seals_value_and_round_trips() {
        let path = temp_path();
        let salt = [3u8; SALT_LEN];
        let params = fast_params();
        {
            let mut store = LocalStore::create(&path, b"pw", &salt, &params, 0, None).unwrap();
            store.put_secret("api", b"super secret value").unwrap();
            // The raw stored bytes must not contain the plaintext.
            let raw = store.get("api").unwrap();
            assert!(raw
                .windows(b"super secret".len())
                .all(|w| w != b"super secret"));
        }
        let store = LocalStore::open(&path, b"pw", None).unwrap();
        assert_eq!(
            store.get_secret("api").unwrap().unwrap(),
            b"super secret value"
        );
        assert!(store.get_secret("missing").unwrap().is_none());
        fs::remove_file(&path).ok();
    }

    #[test]
    fn save_is_atomic_and_leaves_no_temp_file() {
        let path = temp_path();
        let salt = [3u8; SALT_LEN];
        let params = fast_params();
        let mut store = LocalStore::create(&path, b"pw", &salt, &params, 0, None).unwrap();
        store.put_secret("k", b"v1").unwrap();
        store.put_secret("k", b"v2").unwrap();

        // No leftover ".tmp" sibling after a successful save.
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        assert!(!std::path::Path::new(&tmp).exists());

        let reopened = LocalStore::open(&path, b"pw", None).unwrap();
        assert_eq!(reopened.get_secret("k").unwrap().unwrap(), b"v2");
        fs::remove_file(&path).ok();
    }

    #[test]
    fn wrong_passphrase_fails_to_open() {
        let path = temp_path();
        let salt = [3u8; SALT_LEN];
        let params = fast_params();
        LocalStore::create(&path, b"right", &salt, &params, 0, None).unwrap();
        assert!(LocalStore::open(&path, b"wrong", None).is_err());
        fs::remove_file(&path).ok();
    }
}
