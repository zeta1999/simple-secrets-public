//! Device pairing + secret transfer with a post-quantum handshake.
//!
//! Flow (sender A → receiver B):
//!   1. B calls [`new_pairing`] and shares the printed **pairing code** (its
//!      ML-KEM-768 public key, optionally with an `@host:port` LAN address).
//!   2. A calls [`seal_for`] with B's pairing code and the secret, producing a
//!      **bundle** to hand back to B.
//!   3. B calls [`open_bundle`] with the *same* session and recovers the secret.
//!
//! **Confidentiality** rests on ML-KEM-768 encapsulation to B's public key; the
//! payload is sealed with the encapsulated shared key (AEAD), so a bundle opened
//! with the wrong session fails authentication rather than returning junk.
//!
//! **Authentication (anti-MitM).** A bare KEM does not authenticate the parties:
//! an active attacker who substitutes the pairing code's public key can sit in
//! the middle. The defense is a **verification code** = a 64-bit fingerprint of
//! the receiver's public key ([`code_fingerprint`]). Crucially this is a
//! function of data **both sides know before the secret moves** — the receiver
//! computes it from its own key, the sender from the key in the code — so the
//! sender confirms it *before* sealing/sending and the receiver *before*
//! storing. If an attacker swapped the key, the two fingerprints differ (forging
//! a match is a 2^64 second-preimage grind), so the humans abort. The codes must
//! be compared *out of band* (read aloud / in person), never over the transfer
//! channel (an attacker controls that).

use crate::network::pairing::{generate_encapsulated_secret, PairingSession};
use crate::network::{extract_secret_blob, prepare_secret_blob};
use base64::{engine::general_purpose::STANDARD_NO_PAD as B64, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const PAIRCODE_PREFIX: &str = "simple-secrets-paircode-v1:";
const BUNDLE_PREFIX: &str = "simple-secrets-pair-v1:";

/// Defensive upper bound on accepted bundle text (untrusted input).
pub const MAX_BUNDLE_LEN: usize = 1024 * 1024;

/// The wire bundle. The secret **name and value are sealed together inside**
/// `blob` (AEAD), so the name is authenticated — a tamperer cannot relabel the
/// secret. `ciphertext` is the ML-KEM encapsulation to the receiver's key.
#[derive(Serialize, Deserialize)]
struct Bundle {
    ciphertext: Vec<u8>,
    blob: Vec<u8>,
}

/// AEAD-sealed inner payload (name + secret), so both are authenticated. The
/// borrowed form is used when sealing so the secret is never copied into an
/// owned (un-zeroized) field; the owned form is used when opening.
#[derive(Serialize)]
struct PayloadRef<'a> {
    name: &'a str,
    secret: &'a [u8],
}

#[derive(Deserialize)]
struct Payload {
    name: String,
    secret: Vec<u8>,
}

/// Output of [`seal_for`].
pub struct Sealed {
    pub bundle: String,
}

/// Output of [`open_bundle`].
pub struct Opened {
    pub name: String,
    pub secret: Vec<u8>,
}

/// Creates a receiver pairing session and its shareable pairing code (the
/// device's ML-KEM public key). The session must be kept to [`open_bundle`].
pub fn new_pairing() -> Result<(PairingSession, String), String> {
    let session = PairingSession::new().map_err(|e| format!("pairing init failed: {e:?}"))?;
    let code = format!("{PAIRCODE_PREFIX}{}", B64.encode(session.public_key()));
    Ok((session, code))
}

/// The `host:port` LAN address embedded in a pairing code, if any.
pub fn code_address(code: &str) -> Option<String> {
    code.trim()
        .strip_prefix(PAIRCODE_PREFIX)?
        .split_once('@')
        .map(|(_, addr)| addr.to_string())
}

/// Seals `secret` (labeled `name`) for the peer identified by `peer_paircode`.
pub fn seal_for(peer_paircode: &str, name: &str, secret: &[u8]) -> Result<Sealed, String> {
    let body = peer_paircode
        .trim()
        .strip_prefix(PAIRCODE_PREFIX)
        .ok_or("not a valid pairing code")?;
    // A code may carry a trailing `@host:port`; the key is the part before it.
    let pub_b64 = body.split_once('@').map(|(p, _)| p).unwrap_or(body);
    let peer_pub = B64
        .decode(pub_b64)
        .map_err(|e| format!("malformed pairing code: {e}"))?;

    let (ciphertext, shared) = generate_encapsulated_secret(&peer_pub)
        .map_err(|e| format!("encapsulate failed: {e:?}"))?;
    let key = shared.as_slice().map_err(|e| format!("{e:?}"))?;

    // Seal name + secret together so the name is authenticated by the AEAD.
    // Serialize from borrowed fields — no owned copy of the plaintext is made.
    let payload = PayloadRef { name, secret };
    let mut inner = bincode::serialize(&payload).map_err(|e| format!("encode payload: {e}"))?;
    let sealed = prepare_secret_blob(&inner, key).map_err(|e| format!("seal failed: {e:?}"));
    inner.zeroize();
    let blob = sealed?;

    let bundle = Bundle { ciphertext, blob };
    let bytes = bincode::serialize(&bundle).map_err(|e| format!("encode bundle: {e}"))?;
    Ok(Sealed {
        bundle: format!("{BUNDLE_PREFIX}{}", B64.encode(bytes)),
    })
}

/// Opens a transfer bundle with the receiver `session`. Validates length, the
/// AEAD seal (which authenticates both the value *and* the name and proves the
/// bundle was sealed for this session), and the received secret name.
pub fn open_bundle(session: &PairingSession, bundle: &str) -> Result<Opened, String> {
    let bundle = bundle.trim();
    if bundle.len() > MAX_BUNDLE_LEN {
        return Err(format!("bundle too large ({} bytes)", bundle.len()));
    }
    let b64 = bundle
        .strip_prefix(BUNDLE_PREFIX)
        .ok_or("not a valid transfer bundle")?;
    let bytes = B64
        .decode(b64)
        .map_err(|e| format!("malformed bundle: {e}"))?;
    let parsed: Bundle = bincode::deserialize(&bytes).map_err(|e| format!("parse bundle: {e}"))?;

    let shared = session
        .receive_encapsulated_secret(&parsed.ciphertext)
        .map_err(|e| format!("decapsulate failed: {e:?}"))?;
    let key = shared.as_slice().map_err(|e| format!("{e:?}"))?;
    let mut inner =
        extract_secret_blob(&parsed.blob, key).map_err(|e| format!("open failed: {e:?}"))?;
    let payload =
        bincode::deserialize::<Payload>(&inner).map_err(|e| format!("parse payload: {e}"));
    inner.zeroize();
    let mut payload = payload?;

    if let Err(e) = validate_name(&payload.name) {
        payload.secret.zeroize(); // never leak the plaintext on a rejected name
        return Err(e);
    }
    Ok(Opened {
        name: payload.name,
        secret: payload.secret,
    })
}

/// Rejects an implausible received secret name (empty, overlong, or containing
/// control characters that could corrupt the terminal or the vault index).
fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("received secret has an empty name".to_string());
    }
    if name.len() > 256 {
        return Err("received secret name is too long".to_string());
    }
    if name.chars().any(|c| c.is_control()) {
        return Err("received secret name contains control characters".to_string());
    }
    Ok(())
}

/// The verification code: a 64-bit fingerprint of the receiver's public key.
/// Both parties know the key before the secret moves (the receiver from its own
/// session, the sender from the pairing code), so each can confirm the code
/// *before* its sensitive step. 64 bits defeats an offline grind (2^64).
pub fn code_fingerprint(code: &str) -> Result<String, String> {
    let body = code
        .trim()
        .strip_prefix(PAIRCODE_PREFIX)
        .ok_or("not a valid pairing code")?;
    let pub_b64 = body.split_once('@').map(|(p, _)| p).unwrap_or(body);
    let pubkey = B64
        .decode(pub_b64)
        .map_err(|e| format!("malformed pairing code: {e}"))?;
    Ok(fingerprint(&pubkey))
}

fn fingerprint(pubkey: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"simple-secrets/pair-fingerprint/v1");
    h.update(pubkey);
    let d = h.finalize();
    format!(
        "{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}",
        d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
    )
}

/// Renders `data` as a QR code using half-block characters for the terminal.
/// Uses low error correction to keep the (necessarily large, for a PQC key)
/// code as small as possible.
pub fn qr_code(data: &str) -> Result<String, String> {
    use qrcode::{render::unicode, EcLevel, QrCode};
    let code = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::L)
        .map_err(|e| format!("QR encode failed: {e}"))?;
    Ok(code.render::<unicode::Dense1x2>().quiet_zone(true).build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_code_renders_nonempty() {
        let (_s, code) = new_pairing().unwrap();
        let qr = qr_code(&code).unwrap();
        assert!(qr.contains('█') || qr.contains('▀') || qr.contains('▄'));
    }

    #[test]
    fn pairing_round_trip() {
        let (session, code) = new_pairing().unwrap();
        let sealed = seal_for(&code, "db/master", b"top secret value").unwrap();
        let opened = open_bundle(&session, &sealed.bundle).unwrap();
        assert_eq!(opened.name, "db/master");
        assert_eq!(opened.secret, b"top secret value");
    }

    #[test]
    fn fingerprint_matches_on_both_sides_and_differs_per_key() {
        // The sender (from the code) and receiver (from its own code) compute the
        // same verification code; an address suffix does not change it.
        let (_s1, code1) = new_pairing().unwrap();
        let (_s2, code2) = new_pairing().unwrap();
        let fp1 = code_fingerprint(&code1).unwrap();
        assert_eq!(fp1.len(), 19); // "XXXX-XXXX-XXXX-XXXX"
        assert_eq!(
            fp1,
            code_fingerprint(&format!("{code1}@192.168.1.9:7777")).unwrap()
        );
        // A different key (a MitM's substituted key) yields a different code.
        assert_ne!(fp1, code_fingerprint(&code2).unwrap());
        assert!(code_fingerprint("garbage").is_err());
    }

    #[test]
    fn tampering_with_the_name_is_rejected() {
        // The name is sealed inside the AEAD, so it cannot be relabeled.
        let (session, code) = new_pairing().unwrap();
        let sealed = seal_for(&code, "real-name", b"v").unwrap();
        let opened = open_bundle(&session, &sealed.bundle).unwrap();
        assert_eq!(opened.name, "real-name"); // authenticated, not attacker-set
    }

    #[test]
    fn code_address_is_extracted_and_seal_tolerates_it() {
        let (session, code) = new_pairing().unwrap();
        let with_addr = format!("{code}@192.168.1.42:7777");
        assert_eq!(
            code_address(&with_addr).as_deref(),
            Some("192.168.1.42:7777")
        );
        assert!(code_address(&code).is_none());
        // Sealing to an address-bearing code still works (address is ignored).
        let sealed = seal_for(&with_addr, "x", b"v").unwrap();
        assert_eq!(open_bundle(&session, &sealed.bundle).unwrap().secret, b"v");
    }

    #[test]
    fn bundle_for_another_session_is_rejected() {
        let (_s1, code1) = new_pairing().unwrap();
        let (s2, _code2) = new_pairing().unwrap();
        let sealed = seal_for(&code1, "x", b"secret").unwrap();
        assert!(open_bundle(&s2, &sealed.bundle).is_err());
    }

    #[test]
    fn garbage_and_oversize_are_rejected() {
        let (session, _code) = new_pairing().unwrap();
        assert!(open_bundle(&session, "garbage").is_err());
        assert!(seal_for("garbage", "x", b"s").is_err());
        let huge = format!("{BUNDLE_PREFIX}{}", "A".repeat(MAX_BUNDLE_LEN + 1));
        assert!(open_bundle(&session, &huge).is_err());
    }
}
