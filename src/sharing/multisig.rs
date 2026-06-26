use crate::sharing::shamir::{self, Share};
use secure_memory::crypto::{decrypt, encrypt};
use secure_memory::error::Error;
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;

pub struct SplitResult {
    pub blobs: Vec<Vec<u8>>,
    pub commitments: Vec<Vec<u8>>,
    pub threshold: usize,
    pub total: usize,
}

/// Domain-separated length of the integrity tag appended to the secret before
/// sharing. The tag lets `reconstruct_secret` detect a reconstruction performed
/// with fewer than `threshold` shares (or with corrupted/inconsistent shares),
/// which Shamir interpolation alone cannot do — it would otherwise return wrong
/// bytes with no error. Holders of fewer than `threshold` shares learn nothing
/// about the tag (it is part of the shared payload), so they cannot fake a valid
/// reconstruction.
///
/// Scope: this is an *integrity* check against insufficient/corrupt shares, NOT a
/// MAC and NOT dealer authentication. An adversary who already holds at least
/// `threshold` shares can recover `secret || tag` and re-deal any chosen secret
/// with a matching (unkeyed) tag and commitments. Authenticating the dealer would
/// require a keyed construction, which this layer does not provide.
const SECRET_TAG_LEN: usize = 32;
const SECRET_TAG_DOMAIN: &[u8] = b"simple-secrets/multisig/secret-tag/v1";

/// Computes the integrity tag bound to a secret value.
fn secret_tag(secret: &[u8]) -> [u8; SECRET_TAG_LEN] {
    let mut h = Sha512::new();
    h.update(SECRET_TAG_DOMAIN);
    h.update((secret.len() as u64).to_le_bytes());
    h.update(secret);
    let digest = h.finalize();
    let mut tag = [0u8; SECRET_TAG_LEN];
    tag.copy_from_slice(&digest[..SECRET_TAG_LEN]);
    tag
}

pub fn commit(share: &Share) -> Vec<u8> {
    let mut h = Sha512::new();
    h.update([share.index]);
    h.update(&share.data);
    h.finalize().to_vec()
}

pub fn verify_commitment(share: &Share, commitment: &[u8]) -> bool {
    let expected = commit(share);
    expected.ct_eq(commitment).into()
}

pub fn commit_all(shares: &[Share]) -> Vec<Vec<u8>> {
    shares.iter().map(commit).collect()
}

pub fn create_blob(share: &Share, custodian_key: &[u8]) -> Result<Vec<u8>, Error> {
    let mut payload = vec![share.index];
    payload.extend_from_slice(&share.data);
    encrypt(custodian_key, &payload)
}

pub fn open_blob(blob: &[u8], custodian_key: &[u8]) -> Result<Share, Error> {
    let plain = decrypt(custodian_key, blob)?;
    if plain.is_empty() {
        return Err(Error::DecryptionFailed("empty blob".into()));
    }
    let index = plain[0];
    let data = plain[1..].to_vec();
    Ok(Share { index, data })
}

pub fn split_secret(
    secret: &[u8],
    m: usize,
    n: usize,
    custodian_keys: &[&[u8]],
) -> Result<SplitResult, String> {
    if custodian_keys.len() != n {
        return Err(format!(
            "need {} custodian keys, got {}",
            n,
            custodian_keys.len()
        ));
    }

    use zeroize::Zeroize;

    // Bind an integrity tag to the secret and share the (secret || tag) payload
    // so that reconstruction can be verified. See `SECRET_TAG_LEN`.
    let mut payload = Vec::with_capacity(secret.len() + SECRET_TAG_LEN);
    payload.extend_from_slice(secret);
    payload.extend_from_slice(&secret_tag(secret));

    let mut shares = shamir::split(&payload, m, n)?;
    payload.zeroize();
    let commitments = commit_all(&shares);

    let mut blobs = Vec::with_capacity(n);
    for (i, share) in shares.iter().enumerate() {
        let blob = create_blob(share, custodian_keys[i])
            .map_err(|e| format!("create blob {}: {:?}", i, e))?;
        blobs.push(blob);
    }

    for s in &mut shares {
        s.data.zeroize();
    }

    Ok(SplitResult {
        blobs,
        commitments,
        threshold: m,
        total: n,
    })
}

pub fn reconstruct_secret(
    blobs: &[&[u8]],
    custodian_keys: &[&[u8]],
    commitments: &[Vec<u8>],
) -> Result<Vec<u8>, String> {
    if blobs.len() != custodian_keys.len() {
        return Err(format!(
            "blobs/keys length mismatch: {} vs {}",
            blobs.len(),
            custodian_keys.len()
        ));
    }

    let mut shares = Vec::with_capacity(blobs.len());
    for (i, blob) in blobs.iter().enumerate() {
        let share =
            open_blob(blob, custodian_keys[i]).map_err(|e| format!("open blob {}: {:?}", i, e))?;
        shares.push(share);
    }

    for share in &shares {
        let idx = (share.index as usize).saturating_sub(1);
        if idx >= commitments.len() {
            return Err(format!(
                "share index {} out of commitment range",
                share.index
            ));
        }
        if !verify_commitment(share, &commitments[idx]) {
            return Err(format!(
                "commitment verification failed for share {}",
                share.index
            ));
        }
    }

    use zeroize::Zeroize;

    let mut payload = shamir::reconstruct(&shares)?;
    for s in &mut shares {
        s.data.zeroize();
    }

    // Verify the embedded integrity tag. A reconstruction with fewer than
    // `threshold` shares (or with mismatched shares that nonetheless passed their
    // individual commitments) yields a wrong payload whose tag will not match, so
    // we reject it instead of returning confidently-wrong bytes.
    if payload.len() < SECRET_TAG_LEN {
        payload.zeroize();
        return Err("reconstructed payload too short for integrity tag".to_string());
    }
    let split_at = payload.len() - SECRET_TAG_LEN;
    let expected = secret_tag(&payload[..split_at]);
    let tag_ok: bool = payload[split_at..].ct_eq(&expected).into();
    if !tag_ok {
        payload.zeroize();
        return Err(
            "secret integrity check failed (insufficient or inconsistent shares)".to_string(),
        );
    }

    let secret = payload[..split_at].to_vec();
    payload.zeroize();
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Four distinct 32-byte custodian keys.
    fn keys() -> Vec<[u8; 32]> {
        (0u8..5).map(|i| [i.wrapping_add(1); 32]).collect()
    }

    fn key_refs(keys: &[[u8; 32]]) -> Vec<&[u8]> {
        keys.iter().map(|k| k.as_slice()).collect()
    }

    #[test]
    fn round_trip_with_all_custodians() {
        let secret = b"multisig protected secret";
        let ks = keys();
        let kr = key_refs(&ks);
        let split = split_secret(secret, 3, 5, &kr).unwrap();

        let blobs: Vec<&[u8]> = split.blobs.iter().map(|b| b.as_slice()).collect();
        let recovered = reconstruct_secret(&blobs, &kr, &split.commitments).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn round_trip_with_exactly_threshold() {
        let secret = b"multisig protected secret";
        let ks = keys();
        let kr = key_refs(&ks);
        let split = split_secret(secret, 3, 5, &kr).unwrap();

        // Use custodians 0, 2, 4 (threshold == 3). Commitments are indexed by the
        // original share index, so the full commitment vector is passed through.
        let pick = [0usize, 2, 4];
        let blobs: Vec<&[u8]> = pick.iter().map(|&i| split.blobs[i].as_slice()).collect();
        let sub_keys: Vec<&[u8]> = pick.iter().map(|&i| ks[i].as_slice()).collect();
        let recovered = reconstruct_secret(&blobs, &sub_keys, &split.commitments).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn fewer_than_threshold_is_rejected_not_silently_wrong() {
        // Regression guard for the headline bug: with < threshold shares the old
        // code returned confidently-wrong bytes. The integrity tag must turn this
        // into an explicit error instead.
        let secret = b"multisig protected secret";
        let ks = keys();
        let kr = key_refs(&ks);
        let split = split_secret(secret, 3, 5, &kr).unwrap();

        let pick = [0usize, 1]; // only 2 of the required 3
        let blobs: Vec<&[u8]> = pick.iter().map(|&i| split.blobs[i].as_slice()).collect();
        let sub_keys: Vec<&[u8]> = pick.iter().map(|&i| ks[i].as_slice()).collect();
        let result = reconstruct_secret(&blobs, &sub_keys, &split.commitments);
        assert!(result.is_err(), "sub-threshold reconstruction must error");
        assert!(result.unwrap_err().contains("integrity"));
    }

    #[test]
    fn tampered_blob_is_rejected_by_commitment() {
        let secret = b"multisig protected secret";
        let ks = keys();
        let kr3 = key_refs(&ks[..3]);
        let split = split_secret(secret, 2, 3, &kr3).unwrap();

        // Re-encrypt a different share value under custodian 0's key: the blob
        // decrypts fine but no longer matches its commitment.
        let forged = create_blob(
            &Share {
                index: 1,
                data: vec![0xAA; split.blobs[0].len()],
            },
            &ks[0],
        )
        .unwrap();
        let blobs: Vec<&[u8]> = vec![forged.as_slice(), split.blobs[1].as_slice()];
        let sub_keys: Vec<&[u8]> = vec![ks[0].as_slice(), ks[1].as_slice()];
        let result = reconstruct_secret(&blobs, &sub_keys, &split.commitments);
        assert!(result.is_err());
    }
}
