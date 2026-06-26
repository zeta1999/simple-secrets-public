//! `share` / `reconstruct` — k-of-n threshold splitting of a stored secret.
//!
//! `share <name>` fetches a secret from the running agent, splits it into N
//! self-contained **share tokens** (one per custodian), and writes each to its
//! own file. Any `threshold` of those files reconstruct the secret;
//! `reconstruct` does so **offline** — it needs no vault and no agent (unless you
//! ask it to store the result back with `--into`).
//!
//! Each token bundles a freshly generated per-custodian key, that custodian's
//! encrypted Shamir share, and all N commitments (commitments are SHA-512
//! hashes, not secret). The token therefore self-describes a complete share:
//! **possessing any `threshold` tokens recovers the secret**, so treat the files
//! as sensitive. The underlying scheme is integrity-checked but not dealer-
//! authenticated (see `sharing::multisig`).

use crate::cli::client;
use crate::core::entropy::DefaultEntropySource;
use crate::core::manager::SecretManager;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use zeroize::Zeroize;

/// Human-recognizable, version-tagged prefix on every share file.
const SHARE_PREFIX: &str = "simple-secrets-share-v1:";

/// Base64 alphabet for the token body.
const SHARE_B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD_NO_PAD;

/// One custodian's complete, self-contained share.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct ShareFile {
    threshold: usize,
    total: usize,
    /// 1-based custodian position, for humans and duplicate detection.
    index: usize,
    /// Provenance label (the secret's name at split time).
    secret_name: String,
    /// This custodian's encrypted Shamir share.
    blob: Vec<u8>,
    /// This custodian's symmetric key (random, 32 bytes).
    key: Vec<u8>,
    /// All N commitments (needed to verify any reconstructing subset).
    commitments: Vec<Vec<u8>>,
}

fn encode_share(share: &ShareFile) -> Result<String, String> {
    let body = bincode::serialize(share).map_err(|e| format!("encode share: {e}"))?;
    Ok(format!("{SHARE_PREFIX}{}", SHARE_B64.encode(body)))
}

fn decode_share(text: &str) -> Result<ShareFile, String> {
    let body = text
        .trim()
        .strip_prefix(SHARE_PREFIX)
        .ok_or_else(|| "not a simple-secrets share file".to_string())?;
    let bytes = SHARE_B64
        .decode(body)
        .map_err(|e| format!("decode share: {e}"))?;
    bincode::deserialize(&bytes).map_err(|e| format!("parse share: {e}"))
}

/// Splits `secret` into `shares` tokens with the given `threshold`. Pure core
/// (no agent, no files) so it is directly testable.
fn split_into_tokens(
    secret: &[u8],
    threshold: usize,
    shares: usize,
    name: &str,
) -> Result<Vec<String>, String> {
    if shares < 2 {
        return Err("need at least 2 shares".to_string());
    }
    if shares > 255 {
        return Err("at most 255 shares are supported".to_string());
    }
    if threshold < 1 || threshold > shares {
        return Err(format!(
            "threshold must be between 1 and {shares}, got {threshold}"
        ));
    }

    let manager = SecretManager::new(Arc::new(DefaultEntropySource));
    let keys: Vec<Vec<u8>> = (0..shares)
        .map(|_| manager.random_bytes(32))
        .collect::<Result<_, _>>()?;
    let key_refs: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();

    let split = manager.share_secret(secret, threshold, shares, &key_refs)?;

    let tokens = (0..shares)
        .map(|i| {
            encode_share(&ShareFile {
                threshold: split.threshold,
                total: split.total,
                index: i + 1,
                secret_name: name.to_string(),
                blob: split.blobs[i].clone(),
                key: keys[i].clone(),
                commitments: split.commitments.clone(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(tokens)
}

/// Reconstructs the secret from a set of share tokens. Pure core (no files, no
/// agent) so it is directly testable.
fn reconstruct_from_tokens(tokens: &[String]) -> Result<Vec<u8>, String> {
    if tokens.is_empty() {
        return Err("no share files provided".to_string());
    }
    let parsed: Vec<ShareFile> = tokens
        .iter()
        .map(|t| decode_share(t))
        .collect::<Result<_, _>>()?;

    let threshold = parsed[0].threshold;
    let commitments = &parsed[0].commitments;
    let mut seen = std::collections::HashSet::new();
    for share in &parsed {
        if &share.commitments != commitments {
            return Err("share files are from different splits".to_string());
        }
        if !seen.insert(share.index) {
            return Err(format!("duplicate share #{} provided", share.index));
        }
    }
    if parsed.len() < threshold {
        return Err(format!(
            "need at least {threshold} shares to reconstruct, got {}",
            parsed.len()
        ));
    }

    let blobs: Vec<&[u8]> = parsed.iter().map(|s| s.blob.as_slice()).collect();
    let keys: Vec<&[u8]> = parsed.iter().map(|s| s.key.as_slice()).collect();

    let manager = SecretManager::new(Arc::new(DefaultEntropySource));
    manager.reconstruct_secret(&blobs, &keys, commitments)
}

/// Replaces path separators so a secret name like `ssh/id_ed25519` yields a safe
/// flat filename.
fn safe_stem(name: &str) -> String {
    name.chars()
        .map(|c| if c == '/' || c == '\\' { '_' } else { c })
        .collect()
}

/// `share NAME --threshold M --shares N [--out DIR]`.
pub(crate) fn share(name: &str, threshold: usize, shares: usize, out: &str) -> Result<(), String> {
    let mut secret = client::fetch_secret(name)?;
    let tokens = split_into_tokens(&secret, threshold, shares, name);
    secret.zeroize();
    let tokens = tokens?;

    let out_dir = std::path::Path::new(out);
    std::fs::create_dir_all(out_dir)
        .map_err(|e| format!("cannot create {}: {e}", out_dir.display()))?;

    let stem = safe_stem(name);
    let mut written = Vec::with_capacity(tokens.len());
    for (i, token) in tokens.iter().enumerate() {
        let path = out_dir.join(format!("{stem}.share{}.txt", i + 1));
        std::fs::write(&path, token).map_err(|e| format!("write {}: {e}", path.display()))?;
        // Share files are sensitive: any `threshold` of them recover the secret.
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        written.push(path);
    }

    println!(
        "split '{name}' into {shares} shares (threshold {threshold}); any {threshold} reconstruct it:"
    );
    for path in &written {
        println!("  {}", path.display());
    }
    println!("distribute one file per custodian; keep them secret.");
    Ok(())
}

/// `reconstruct FILE... [--into NAME]`.
pub(crate) fn reconstruct(files: &[String], into: Option<&str>) -> Result<(), String> {
    if files.is_empty() {
        return Err("provide the share files to reconstruct from".to_string());
    }
    let tokens = files
        .iter()
        .map(|p| std::fs::read_to_string(p).map_err(|e| format!("read {p}: {e}")))
        .collect::<Result<Vec<_>, _>>()?;

    let mut secret = reconstruct_from_tokens(&tokens)?;
    let result = match into {
        Some(name) => {
            let r = client::store_secret(name, &secret);
            if r.is_ok() {
                println!("reconstructed secret stored in the vault as '{name}'");
            }
            r
        }
        None => {
            let mut out = std::io::stdout();
            out.write_all(&secret)
                .and_then(|()| out.write_all(b"\n"))
                .map_err(|e| format!("write failed: {e}"))
        }
    };
    secret.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_encode_decode_round_trip() {
        let share = ShareFile {
            threshold: 2,
            total: 3,
            index: 1,
            secret_name: "db".into(),
            blob: vec![1, 2, 3],
            key: vec![9u8; 32],
            commitments: vec![vec![0u8; 64], vec![1u8; 64]],
        };
        let token = encode_share(&share).unwrap();
        assert!(token.starts_with(SHARE_PREFIX));
        assert_eq!(decode_share(&token).unwrap(), share);
    }

    #[test]
    fn decode_rejects_foreign_text() {
        assert!(decode_share("hello world").is_err());
    }

    #[test]
    fn split_then_reconstruct_with_threshold_subset() {
        let secret = b"correct horse battery staple";
        let tokens = split_into_tokens(secret, 3, 5, "phrase").unwrap();
        assert_eq!(tokens.len(), 5);

        // Any 3 of the 5 reconstruct (custodians 0, 2, 4).
        let subset = vec![tokens[0].clone(), tokens[2].clone(), tokens[4].clone()];
        let recovered = reconstruct_from_tokens(&subset).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn fewer_than_threshold_is_rejected() {
        let tokens = split_into_tokens(b"secret", 3, 5, "x").unwrap();
        let subset = vec![tokens[0].clone(), tokens[1].clone()];
        let err = reconstruct_from_tokens(&subset).unwrap_err();
        assert!(err.contains("need at least 3"));
    }

    #[test]
    fn duplicate_share_is_rejected() {
        let tokens = split_into_tokens(b"secret", 2, 3, "x").unwrap();
        let dupe = vec![tokens[0].clone(), tokens[0].clone()];
        assert!(reconstruct_from_tokens(&dupe)
            .unwrap_err()
            .contains("duplicate"));
    }

    #[test]
    fn mixing_two_splits_is_rejected() {
        let a = split_into_tokens(b"secret-a", 2, 3, "a").unwrap();
        let b = split_into_tokens(b"secret-b", 2, 3, "b").unwrap();
        let mixed = vec![a[0].clone(), b[1].clone()];
        assert!(reconstruct_from_tokens(&mixed)
            .unwrap_err()
            .contains("different splits"));
    }

    #[test]
    fn invalid_parameters_are_rejected() {
        assert!(split_into_tokens(b"s", 4, 3, "x").is_err()); // threshold > shares
        assert!(split_into_tokens(b"s", 1, 1, "x").is_err()); // shares < 2
    }
}
