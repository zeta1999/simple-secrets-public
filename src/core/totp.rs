//! Time-based one-time passwords (RFC 6238 over RFC 4226 / HOTP).
//!
//! A TOTP entry is stored like any other secret — its plaintext is either an
//! `otpauth://totp/…` URI (what authenticator apps export) or a bare base32
//! seed. [`parse`] turns such a value into a [`TotpConfig`]; [`code_at`] then
//! derives the rotating code. The code functions are pure (the timestamp is a
//! parameter) so they are deterministically testable against the RFC vectors;
//! only [`unix_now`] reads the clock.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

/// HMAC hash used by the TOTP entry. Authenticator apps default to SHA-1.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TotpAlg {
    Sha1,
    Sha256,
    Sha512,
}

/// A parsed TOTP configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TotpConfig {
    /// The decoded shared secret (HMAC key).
    pub secret: Vec<u8>,
    /// Number of digits in the generated code (6–8 typical).
    pub digits: u32,
    /// Time step in seconds (default 30).
    pub period: u64,
    pub algorithm: TotpAlg,
}

/// Current wall-clock time as seconds since the Unix epoch (0 if the clock is
/// somehow before the epoch — impossible in practice, and never panics).
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parses an `otpauth://totp/…` URI or a bare base32 seed into a [`TotpConfig`].
/// Returns `None` if the value is not a recognizable TOTP, so callers can treat
/// it as an ordinary secret.
pub fn parse(value: &str) -> Option<TotpConfig> {
    let trimmed = value.trim();
    if let Some(cfg) = parse_otpauth(trimmed) {
        return Some(cfg);
    }
    // Bare base32 seed. Require a reasonable length so an arbitrary secret that
    // merely happens to be valid base32 is not misdetected as a TOTP.
    if trimmed.len() >= 16 {
        if let Some(secret) = decode_base32(trimmed) {
            return Some(TotpConfig {
                secret,
                digits: 6,
                period: 30,
                algorithm: TotpAlg::Sha1,
            });
        }
    }
    None
}

fn parse_otpauth(value: &str) -> Option<TotpConfig> {
    let rest = value.strip_prefix("otpauth://totp/")?;
    let query = rest.split_once('?').map(|(_, q)| q).unwrap_or("");

    let mut secret = None;
    let mut digits = 6u32;
    let mut period = 30u64;
    let mut algorithm = TotpAlg::Sha1;

    for pair in query.split('&') {
        let Some((key, val)) = pair.split_once('=') else {
            continue;
        };
        match key.to_ascii_lowercase().as_str() {
            "secret" => secret = decode_base32(val),
            "digits" => {
                if let Ok(d) = val.parse::<u32>() {
                    if (1..=9).contains(&d) {
                        digits = d;
                    }
                }
            }
            "period" => {
                if let Ok(p) = val.parse::<u64>() {
                    if p > 0 {
                        period = p;
                    }
                }
            }
            "algorithm" => {
                algorithm = match val.to_ascii_uppercase().as_str() {
                    "SHA1" => TotpAlg::Sha1,
                    "SHA256" => TotpAlg::Sha256,
                    "SHA512" => TotpAlg::Sha512,
                    _ => return None, // unknown algorithm: we cannot compute it
                };
            }
            _ => {}
        }
    }

    Some(TotpConfig {
        secret: secret?,
        digits,
        period,
        algorithm,
    })
}

/// Decodes an RFC 4648 base32 string (case-insensitive; `=` padding, spaces, and
/// `-` separators are ignored). Returns `None` on an invalid character or empty
/// result.
fn decode_base32(s: &str) -> Option<Vec<u8>> {
    let mut acc = 0u32;
    let mut nbits = 0u32;
    let mut out = Vec::new();
    for ch in s.chars() {
        let c = ch.to_ascii_uppercase();
        if c == '=' || c == ' ' || c == '-' {
            continue;
        }
        let val = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => return None,
        };
        acc = (acc << 5) | val;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Builds a canonical `otpauth://totp/LABEL?...` URI for `cfg`. Storing this form
/// makes a TOTP entry explicit and unambiguous (no base32 guessing).
pub fn to_uri(cfg: &TotpConfig, label: &str) -> String {
    let alg = match cfg.algorithm {
        TotpAlg::Sha1 => "SHA1",
        TotpAlg::Sha256 => "SHA256",
        TotpAlg::Sha512 => "SHA512",
    };
    format!(
        "otpauth://totp/{}?secret={}&digits={}&period={}&algorithm={}",
        encode_label(label),
        encode_base32(&cfg.secret),
        cfg.digits,
        cfg.period,
        alg
    )
}

/// Encodes bytes as RFC 4648 base32 (uppercase, no padding).
fn encode_base32(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// Percent-encodes a URI path label, leaving unreserved characters intact.
fn encode_label(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' | b':' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The TOTP code for `cfg` at `unix_secs`, zero-padded to `cfg.digits`.
pub fn code_at(cfg: &TotpConfig, unix_secs: u64) -> String {
    let counter = unix_secs / cfg.period.max(1);
    hotp(&cfg.secret, counter, cfg.digits, cfg.algorithm)
}

/// Seconds until the current code rolls over to the next one.
pub fn seconds_remaining(cfg: &TotpConfig, unix_secs: u64) -> u64 {
    let period = cfg.period.max(1);
    period - (unix_secs % period)
}

/// RFC 4226 HOTP: HMAC(secret, counter) with dynamic truncation to `digits`.
fn hotp(secret: &[u8], counter: u64, digits: u32, alg: TotpAlg) -> String {
    let msg = counter.to_be_bytes();
    let hash = match alg {
        TotpAlg::Sha1 => {
            let mut m = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts any key length");
            m.update(&msg);
            m.finalize().into_bytes().to_vec()
        }
        TotpAlg::Sha256 => {
            let mut m =
                Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
            m.update(&msg);
            m.finalize().into_bytes().to_vec()
        }
        TotpAlg::Sha512 => {
            let mut m =
                Hmac::<Sha512>::new_from_slice(secret).expect("HMAC accepts any key length");
            m.update(&msg);
            m.finalize().into_bytes().to_vec()
        }
    };

    // Dynamic truncation (RFC 4226 §5.3). `offset + 3` is always in range: the
    // smallest HMAC output here is 20 bytes and `offset` is at most 15.
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let bin = ((u32::from(hash[offset]) & 0x7f) << 24)
        | (u32::from(hash[offset + 1]) << 16)
        | (u32::from(hash[offset + 2]) << 8)
        | u32::from(hash[offset + 3]);

    let modulo = 10u32.pow(digits);
    format!("{:0width$}", bin % modulo, width = digits as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test seeds (raw ASCII bytes, used directly as the key).
    fn seed_sha1() -> Vec<u8> {
        b"12345678901234567890".to_vec()
    }
    fn seed_sha256() -> Vec<u8> {
        b"12345678901234567890123456789012".to_vec()
    }
    fn seed_sha512() -> Vec<u8> {
        b"1234567890123456789012345678901234567890123456789012345678901234".to_vec()
    }

    fn cfg(secret: Vec<u8>, alg: TotpAlg) -> TotpConfig {
        TotpConfig {
            secret,
            digits: 8,
            period: 30,
            algorithm: alg,
        }
    }

    #[test]
    fn rfc6238_vectors() {
        // (time, sha1, sha256, sha512)
        let cases = [
            (59u64, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (t, s1, s256, s512) in cases {
            assert_eq!(
                code_at(&cfg(seed_sha1(), TotpAlg::Sha1), t),
                s1,
                "sha1 @ {t}"
            );
            assert_eq!(
                code_at(&cfg(seed_sha256(), TotpAlg::Sha256), t),
                s256,
                "sha256 @ {t}"
            );
            assert_eq!(
                code_at(&cfg(seed_sha512(), TotpAlg::Sha512), t),
                s512,
                "sha512 @ {t}"
            );
        }
    }

    #[test]
    fn base32_round_trips_known_vector() {
        // "Hello!\xde\xad\xbe\xef" -> JBSWY3DPEHPK3PXP (RFC 4648 example).
        assert_eq!(
            decode_base32("JBSWY3DPEHPK3PXP").unwrap(),
            b"Hello!\xde\xad\xbe\xef"
        );
        // Lowercase, spaces, and padding are tolerated.
        assert_eq!(
            decode_base32("jbsw y3dp ehpk 3pxp").unwrap(),
            b"Hello!\xde\xad\xbe\xef"
        );
        assert!(decode_base32("0189").is_none()); // invalid base32 chars
    }

    #[test]
    fn base32_encode_decode_round_trip() {
        for v in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            assert_eq!(decode_base32(&encode_base32(v)).unwrap_or_default(), v);
        }
    }

    #[test]
    fn to_uri_round_trips_through_parse() {
        let cfg = TotpConfig {
            secret: b"Hello!\xde\xad\xbe\xef".to_vec(),
            digits: 6,
            period: 30,
            algorithm: TotpAlg::Sha1,
        };
        let uri = to_uri(&cfg, "ACME:me@host");
        assert!(uri.starts_with("otpauth://totp/"));
        let back = parse(&uri).unwrap();
        assert_eq!(back, cfg); // secret/digits/period/algorithm all preserved
    }

    #[test]
    fn parse_otpauth_uri() {
        let uri = "otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&issuer=ACME&digits=6&period=30&algorithm=SHA1";
        let cfg = parse(uri).unwrap();
        assert_eq!(cfg.digits, 6);
        assert_eq!(cfg.period, 30);
        assert_eq!(cfg.algorithm, TotpAlg::Sha1);
        assert_eq!(cfg.secret, b"Hello!\xde\xad\xbe\xef");
    }

    #[test]
    fn parse_bare_base32_and_rejects_non_totp() {
        assert!(parse("JBSWY3DPEHPK3PXP").is_some()); // 16 chars, valid base32
        assert!(parse("not a secret!").is_none()); // contains invalid chars
        assert!(parse("short").is_none()); // below the length heuristic
        assert!(parse("otpauth://totp/x?issuer=ACME").is_none()); // no secret
        assert!(parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5").is_none());
    }

    #[test]
    fn seconds_remaining_boundaries() {
        let c = cfg(seed_sha1(), TotpAlg::Sha1);
        assert_eq!(seconds_remaining(&c, 0), 30);
        assert_eq!(seconds_remaining(&c, 29), 1);
        assert_eq!(seconds_remaining(&c, 30), 30);
    }
}
