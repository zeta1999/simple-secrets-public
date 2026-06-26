use rand::RngCore;
use std::collections::HashSet;

#[derive(Clone, Debug)]
pub struct Share {
    pub index: u8,
    pub data: Vec<u8>,
}

fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Branch-free GF(2^8) multiplication (AES polynomial 0x11B).
///
/// The loop runs a fixed 8 iterations and uses bit masks instead of branches on
/// secret-derived values, which matters because shares carry secret bytes through
/// this routine. Note this is constant-time *by construction at the source level*
/// only — it is not a compiler-/hardware-verified guarantee, so do not rely on it
/// as a hard defence against a local timing adversary.
fn gf_mul(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut p: u8 = 0;
    for _ in 0..8 {
        // mask = 0xFF when the low bit of b is set, else 0x00.
        let mask = (b & 1).wrapping_neg();
        p ^= a & mask;
        // reduce_mask = 0xFF when the high bit of a is set (carry out on <<1).
        let reduce_mask = (a >> 7).wrapping_neg();
        a = (a << 1) ^ (0x1B & reduce_mask);
        b >>= 1;
    }
    p
}

/// Constant-time multiplicative inverse in GF(2^8) via `a^254`.
///
/// `a == 0` has no inverse; this returns 0 for it (the same convention as
/// before) without a value-dependent branch — `0^254` is `0`.
fn gf_inv(a: u8) -> u8 {
    let mut result = a;
    for _ in 0..6 {
        result = gf_mul(result, result);
        result = gf_mul(result, a);
    }
    gf_mul(result, result)
}

fn eval_poly(coeffs: &[u8], x: u8) -> u8 {
    let mut result = *coeffs.last().unwrap();
    for i in (0..coeffs.len() - 1).rev() {
        result = gf_add(gf_mul(result, x), coeffs[i]);
    }
    result
}

pub fn split(secret: &[u8], m: usize, n: usize) -> Result<Vec<Share>, String> {
    if !(2..=255).contains(&m) {
        return Err(format!("threshold M must be 2..255, got {}", m));
    }
    if n < m || n > 255 {
        return Err(format!("N must be M..255, got {}", n));
    }
    if secret.is_empty() {
        return Err("secret must not be empty".to_string());
    }

    let mut shares: Vec<Share> = (0..n)
        .map(|i| Share {
            index: (i + 1) as u8,
            data: vec![0; secret.len()],
        })
        .collect();

    let mut coeffs = vec![0u8; m];
    let mut rng = rand::thread_rng();

    for (byte_idx, &byte) in secret.iter().enumerate() {
        coeffs[0] = byte;
        rng.fill_bytes(&mut coeffs[1..]);

        for share in shares.iter_mut() {
            share.data[byte_idx] = eval_poly(&coeffs, share.index);
        }
    }

    Ok(shares)
}

pub fn reconstruct(shares: &[Share]) -> Result<Vec<u8>, String> {
    if shares.len() < 2 {
        return Err("need at least 2 shares".to_string());
    }

    let data_len = shares[0].data.len();
    for s in &shares[1..] {
        if s.data.len() != data_len {
            return Err(format!(
                "share length mismatch: {} vs {}",
                s.data.len(),
                data_len
            ));
        }
    }

    let mut seen = HashSet::new();
    for s in shares {
        if s.index == 0 {
            return Err("share index must be > 0".to_string());
        }
        if !seen.insert(s.index) {
            return Err(format!("duplicate share index {}", s.index));
        }
    }

    let mut secret = Vec::with_capacity(data_len);

    for byte_idx in 0..data_len {
        let mut value = 0u8;
        for (i, si) in shares.iter().enumerate() {
            let xi = si.index;
            let yi = si.data[byte_idx];

            let mut num = 1u8;
            let mut den = 1u8;

            for (j, sj) in shares.iter().enumerate() {
                if i == j {
                    continue;
                }
                let xj = sj.index;
                num = gf_mul(num, xj);
                den = gf_mul(den, gf_add(xi, xj));
            }

            let li = gf_mul(num, gf_inv(den));
            value = gf_add(value, gf_mul(yi, li));
        }
        secret.push(value);
    }

    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf_inverse_is_consistent() {
        // a * a^-1 == 1 for every non-zero element of GF(2^8).
        for a in 1u8..=255 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "inverse failed for {}", a);
        }
        // 0 has no inverse; our convention returns 0.
        assert_eq!(gf_inv(0), 0);
    }

    #[test]
    fn round_trip_with_all_shares() {
        let secret = b"correct horse battery staple";
        let shares = split(secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);
        let recovered = reconstruct(&shares).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn round_trip_with_exactly_threshold_shares() {
        let secret = b"\x00\x01\xff\x80 a secret with binary bytes";
        let shares = split(secret, 3, 5).unwrap();
        // Any subset of size == threshold reconstructs the secret.
        for combo in [[0, 1, 2], [1, 3, 4], [0, 2, 4]] {
            let subset: Vec<Share> = combo.iter().map(|&i| shares[i].clone()).collect();
            assert_eq!(reconstruct(&subset).unwrap(), secret);
        }
    }

    #[test]
    fn fewer_than_threshold_does_not_recover_secret() {
        // With < threshold shares the interpolation yields a value that is not
        // the secret (perfect-secrecy property at the math level).
        let secret = b"top secret payload";
        let shares = split(secret, 4, 6).unwrap();
        let subset: Vec<Share> = shares[..3].to_vec();
        let guess = reconstruct(&subset).unwrap();
        assert_ne!(guess, secret);
    }

    #[test]
    fn rejects_bad_parameters() {
        assert!(split(b"x", 1, 5).is_err()); // threshold too small
        assert!(split(b"x", 6, 5).is_err()); // threshold > n
        assert!(split(b"", 3, 5).is_err()); // empty secret
    }

    #[test]
    fn rejects_duplicate_share_indices() {
        let shares = split(b"abcdef", 2, 4).unwrap();
        let dup = vec![shares[0].clone(), shares[0].clone()];
        assert!(reconstruct(&dup).is_err());
    }
}
