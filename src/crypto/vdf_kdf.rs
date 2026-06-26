//! Passphrase-based key derivation.
//!
//! The pipeline is Argon2id (memory-hard) → a sequential SHA-512 iteration step
//! → HKDF-SHA-512 extraction. The middle step adds a tunable *sequential* delay
//! on top of Argon2's memory hardness; note that despite the historical
//! `vdf`/`vdf_iterations` naming this is **not** a Verifiable Delay Function (it
//! has no efficient public verification) — it is plain iterated hashing used as
//! a wall-clock cost knob. Raise `vdf_iterations` (see [`vdf_calibrate`]) to make
//! each guess slower for an offline attacker.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use secure_memory::LockedBuffer;
use sha2::{Digest, Sha512};
use std::time::{Duration, Instant};

pub struct Argon2Params {
    pub time: u32,
    pub memory: u32,
    pub threads: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            time: 1,
            memory: 256 * 1024,
            threads: 4,
        }
    }
}

pub fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    params: &Argon2Params,
    vdf_iterations: u64,
    hardware_key: Option<&[u8]>,
) -> Result<LockedBuffer, String> {
    if salt.len() != 32 {
        return Err(format!("salt must be 32 bytes, got {}", salt.len()));
    }

    // Step 1: Argon2id
    let argon2_params = Params::new(params.memory, params.time, params.threads, Some(32))
        .map_err(|e| format!("argon2 params: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut argon_key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut argon_key)
        .map_err(|e| format!("argon2 error: {}", e))?;

    // Step 2: sequential SHA-512 iteration (wall-clock hardening, not a true VDF)
    let mut vdf_output = Vec::new();
    if vdf_iterations > 0 {
        let mut hasher = Sha512::new();
        hasher.update(argon_key);
        hasher.update(salt);
        hasher.update(b"vdf-input");
        let mut h = hasher.finalize();

        for _ in 0..vdf_iterations {
            h = Sha512::digest(h);
        }
        vdf_output.extend_from_slice(&h);
    }

    // Step 3: Combine with HKDF
    let mut combined = Vec::new();
    combined.extend_from_slice(&argon_key);
    if vdf_iterations > 0 {
        combined.extend_from_slice(&vdf_output);
    }
    if let Some(hw_key) = hardware_key {
        combined.extend_from_slice(hw_key);
    }

    let hk = Hkdf::<Sha512>::new(Some(salt), &combined);
    let mut okm = [0u8; 32];
    hk.expand(b"vault-master", &mut okm)
        .map_err(|e| format!("HKDF expand: {}", e))?;

    // Zeroize every intermediate buffer before dropping so that no copy of the
    // master key or its inputs lingers on the stack/heap after we return. The
    // `okm` stack array in particular held the final master key and must be
    // wiped explicitly, since `to_vec()` only copies it.
    use zeroize::Zeroize;
    argon_key.zeroize();
    combined.zeroize();
    vdf_output.zeroize();

    let mut okm_vec = okm.to_vec();
    okm.zeroize();
    let result = LockedBuffer::from_bytes_move(&mut okm_vec)
        .map_err(|e| format!("LockedBuffer error: {}", e));
    okm_vec.zeroize();
    result
}

pub fn vdf_calibrate(target: Duration) -> u64 {
    const SAMPLE: u64 = 100_000;
    let mut h = Sha512::digest(b"calibrate");
    let start = Instant::now();
    for _ in 0..SAMPLE {
        h = Sha512::digest(h);
    }
    let elapsed = start.elapsed();
    let iter_per_sec = SAMPLE as f64 / elapsed.as_secs_f64();
    let t = (iter_per_sec * target.as_secs_f64()) as u64;
    std::cmp::max(t, 1)
}

pub fn vdf_eval(input: &[u8], iterations: u64) -> Vec<u8> {
    let mut h = Sha512::digest(input);
    for _ in 1..iterations {
        h = Sha512::digest(h);
    }
    h.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cheap params keep the test fast while still exercising the full pipeline.
    fn fast_params() -> Argon2Params {
        Argon2Params {
            time: 1,
            memory: 8 * 1024,
            threads: 1,
        }
    }

    #[test]
    fn derive_key_rejects_wrong_salt_length() {
        let p = fast_params();
        assert!(derive_key(b"pw", &[0u8; 16], &p, 0, None).is_err());
        assert!(derive_key(b"pw", &[0u8; 32], &p, 0, None).is_ok());
    }

    #[test]
    fn derive_key_is_deterministic() {
        let p = fast_params();
        let salt = [7u8; 32];
        let a = derive_key(b"passphrase", &salt, &p, 16, None).unwrap();
        let b = derive_key(b"passphrase", &salt, &p, 16, None).unwrap();
        assert_eq!(a.as_slice().unwrap(), b.as_slice().unwrap());
    }

    #[test]
    fn derive_key_diverges_on_inputs() {
        let p = fast_params();
        let salt = [7u8; 32];
        let base = derive_key(b"passphrase", &salt, &p, 16, None)
            .unwrap()
            .as_slice()
            .unwrap()
            .to_vec();

        // Different passphrase, salt, vdf count, and hardware key all change the
        // derived master key.
        let other_pw = derive_key(b"passphras3", &salt, &p, 16, None).unwrap();
        let other_salt = derive_key(b"passphrase", &[8u8; 32], &p, 16, None).unwrap();
        let other_vdf = derive_key(b"passphrase", &salt, &p, 17, None).unwrap();
        let with_hw = derive_key(b"passphrase", &salt, &p, 16, Some(b"hw")).unwrap();

        assert_ne!(base, other_pw.as_slice().unwrap());
        assert_ne!(base, other_salt.as_slice().unwrap());
        assert_ne!(base, other_vdf.as_slice().unwrap());
        assert_ne!(base, with_hw.as_slice().unwrap());
    }

    #[test]
    fn vdf_eval_is_iteration_sensitive() {
        assert_ne!(vdf_eval(b"seed", 1), vdf_eval(b"seed", 2));
    }
}
