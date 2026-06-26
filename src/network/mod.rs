pub mod pairing;
pub mod transfer;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use secure_memory::crypto::{decrypt_aad, encrypt_aad};
use secure_memory::error::Error;

pub fn serialize_to_ascii(blob: &[u8]) -> String {
    BASE64.encode(blob)
}

pub fn deserialize_from_ascii(ascii: &str) -> Result<Vec<u8>, base64::DecodeError> {
    BASE64.decode(ascii)
}

pub fn prepare_secret_blob(secret: &[u8], shared_key: &[u8]) -> Result<Vec<u8>, Error> {
    encrypt_aad(shared_key, secret, b"simple-secrets-exchange")
}

pub fn extract_secret_blob(blob: &[u8], shared_key: &[u8]) -> Result<Vec<u8>, Error> {
    decrypt_aad(shared_key, blob, b"simple-secrets-exchange")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_round_trip() {
        let blob = vec![0u8, 1, 2, 250, 255, 42, 7];
        let encoded = serialize_to_ascii(&blob);
        assert!(encoded.is_ascii());
        assert_eq!(deserialize_from_ascii(&encoded).unwrap(), blob);
    }

    #[test]
    fn deserialize_rejects_invalid_ascii() {
        assert!(deserialize_from_ascii("not valid base64 !!!").is_err());
    }
}
