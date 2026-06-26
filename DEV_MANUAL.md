# Simple Secrets - Developer Manual

Welcome to the internal integration documentation for the `simple-secrets` crate. This guide is for developers intending to utilize the core primitives, network handlers, or the FFI bindings for cross-platform integration.

## Implementation Status

This crate is under active development. The cryptographic and storage primitives
below are implemented and tested; the TUI (`ui`) and the FFI entrypoints (`ffi`)
are currently **scaffolding** — they compile and run but are not yet wired to the
core primitives (e.g. the TUI renders placeholder data, and `tor_i2p.rs` is a
stub). Treat anything in the "scaffolding" category as a UI/integration preview,
not a finished feature.

## Crate Architecture

The `simple-secrets` logic is composed of the following modules:
- **`core::entropy`** *(done)*: The `EntropySource` trait plus `DefaultEntropySource` (OS RNG). Pluggable so embedders can supply a hardware or deterministic-test RNG.
- **`core::manager`** *(facade)*: `SecretManager` is the primary entrypoint — it owns the `EntropySource`, the open vault, and the in-RAM store, and exposes vault lifecycle (`create_vault`/`open_vault`/`lock`), sealed secret storage (`put_secret`/`get_secret`/`secret_names`), `generate_passphrase`, RAM secrets, and k-in-n `share_secret`/`reconstruct_secret`.
- **`core::passphrase`** *(done)*: BIP-39-style memorable passphrase generation with entropy accounting.
- **`storage`** *(done)*: `LocalStore` (disk-based, Argon2id-derived-key AEAD vault) and `RamStore` (in-memory `LockedBuffer` map).
- **`crypto`** *(done)*: `pqc_auth.rs` wraps `secure-memory`'s ML-DSA-65 signatures (`Authenticator`) and ML-KEM-768 KEM (`Encryptor`); `vdf_kdf.rs` derives keys via Argon2id → sequential SHA-512 iteration → HKDF (a wall-clock cost knob, not a true VDF).
- **`sharing`** *(done)*: GF(2^8) *k-in-n* Shamir secret sharing (`shamir`) and per-share SHA-512 commitments + custodian-encrypted blobs (`multisig`).
- **`network`** *(partial)*: Base64 ASCII (de)serialization, AEAD blob (`prepare`/`extract`), and KEM-based `PairingSession`. The actual transport bridge to `simple-network` and Tor/I2P (`tor_i2p.rs`) is not yet implemented.
- **`ui`** *(scaffolding)*: `ratatui`/`crossterm` TUI with Vault/Network/Editor tabs rendering placeholder content.
- **`ffi`** *(scaffolding)*: Empty C (`simple_secrets_init`) and JNI (`Java_com_simplesecrets_Library_init`) entrypoints.

## Rust Integration Example

Drive everything through the `SecretManager` facade:

```rust
use std::path::Path;
use std::sync::Arc;
use simple_secrets::core::entropy::DefaultEntropySource;
use simple_secrets::core::manager::SecretManager;
use simple_secrets::crypto::vdf_kdf::Argon2Params;

fn run() -> Result<(), String> {
    // 1. A manager owns the entropy source, the vault, and the RAM store.
    let mut mgr = SecretManager::new(Arc::new(DefaultEntropySource));

    // 2. Propose a memorable 20-word passphrase (~140 bits) for the user.
    let passphrase = mgr.generate_passphrase(20)?;

    // 3. Create the vault on disk. The salt is generated from the entropy
    //    source and stored in the vault's authenticated header.
    mgr.create_vault(Path::new("vault.bin"), passphrase.as_bytes(), &Argon2Params::default(), 0, None)?;

    // 4. Store and read back a plaintext secret — it is sealed per-entry before
    //    it ever touches disk.
    mgr.put_secret("ssh-key", b"-----BEGIN OPENSSH PRIVATE KEY-----...")?;
    let _value = mgr.get_secret("ssh-key")?; // Some(plaintext)
    let _names = mgr.secret_names()?;

    // 5. Lock, then reopen later with only the passphrase.
    mgr.lock();
    mgr.open_vault(Path::new("vault.bin"), passphrase.as_bytes(), None)?;
    Ok(())
}
```

For low-level control, `storage::local_store::LocalStore` is available directly
via `put_secret`/`get_secret` (per-entry sealing). Raw verbatim blob storage is
crate-internal, so values always go through the per-entry seal.

> Notes:
> - The vault file is `header || AEAD(ciphertext)`; the header carries the magic,
>   version, salt, and Argon2/iteration parameters and is bound in as associated
>   data, so parameters cannot be downgraded or tampered with.
> - `create_vault` refuses to overwrite an existing file.
> - Per-entry values are sealed under an HKDF-separated key with the entry name
>   bound as associated data, so plaintext never reaches disk.

## Cross-Platform (FFI) Usage

The `Cargo.toml` is configured to output a `cdylib`, allowing shared objects (`.so`, `.dylib`) to be ingested by mobile platforms.

### Android (JNI)
Bindings are exposed in `src/ffi/android.rs`.
- Target: `aarch64-linux-android`
- Hook: `Java_com_simplesecrets_Library_init(JNIEnv, JClass)`

You can load the native library in your Kotlin/Java code via `System.loadLibrary("simple_secrets")`.

### iOS (C-API)
Bindings are exposed in `src/ffi/ios.rs`.
- Target: `aarch64-apple-ios`
- Hook: `void simple_secrets_init();`

To use this in Swift/Objective-C, compile a static or dynamic library via `cargo build --target aarch64-apple-ios`, link it against your Xcode project, and expose the C-API headers in your bridging header.
