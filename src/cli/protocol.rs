//! Wire protocol between the CLI client and the background session agent.
//!
//! Each message is a `u32` little-endian length prefix followed by a bincode
//! body. The length is bound-checked against [`MAX_FRAME`] *before* any buffer
//! is allocated, so a confused or hostile peer cannot induce a huge allocation.
//!
//! Every request carries the raw 32-byte session token; the agent verifies it
//! in constant time (see [`crate::cli::agent`]) before acting.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

/// Upper bound on a single framed message body (16 MiB). Secrets are small;
/// this is purely a denial-of-service guard on the length prefix.
pub const MAX_FRAME: u32 = 16 * 1024 * 1024;

/// Base64 alphabet used to encode the session token (no padding, so it is clean
/// in a shell `export` and in the `SIMPLE_SECRETS_SESSION` environment value).
pub(crate) const TOKEN_B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD_NO_PAD;

/// A request from the client to the agent. The `token` is the raw 32 bytes of
/// the session token (not its base64 form), so the agent's constant-time check
/// operates on a fixed-length value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// Fetch and decrypt a secret by name.
    Get { token: Vec<u8>, name: String },
    /// Store (encrypt + persist) a secret.
    Put {
        token: Vec<u8>,
        name: String,
        value: Vec<u8>,
    },
    /// List the names of all stored secrets.
    List { token: Vec<u8> },
    /// Report whether the vault is unlocked and how long until idle expiry.
    Status { token: Vec<u8> },
    /// Lock the vault and shut the agent down.
    Signout { token: Vec<u8> },
}

impl Request {
    /// The session token carried by every request variant.
    pub fn token(&self) -> &[u8] {
        match self {
            Request::Get { token, .. }
            | Request::Put { token, .. }
            | Request::List { token }
            | Request::Status { token }
            | Request::Signout { token } => token,
        }
    }
}

/// A response from the agent to the client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    /// Result of `Get`: `None` means no such secret.
    Secret(Option<Vec<u8>>),
    /// Result of `List`.
    Names(Vec<String>),
    /// Result of `Status`.
    Status {
        unlocked: bool,
        vault_path: String,
        idle_secs_remaining: u64,
    },
    /// Acknowledgement for `Put` / `Signout`.
    Ok,
    /// A handled error (bad token, locked vault, I/O failure, …).
    Err(String),
}

/// Serializes `msg` and writes it as a length-prefixed frame.
pub fn write_msg<W: Write, T: Serialize>(w: &mut W, msg: &T) -> Result<(), String> {
    let body = bincode::serialize(msg).map_err(|e| format!("serialize failed: {e}"))?;
    if body.len() > MAX_FRAME as usize {
        return Err(format!("message too large: {} bytes", body.len()));
    }
    let len = (body.len() as u32).to_le_bytes();
    w.write_all(&len)
        .map_err(|e| format!("write failed: {e}"))?;
    w.write_all(&body)
        .map_err(|e| format!("write failed: {e}"))?;
    w.flush().map_err(|e| format!("flush failed: {e}"))?;
    Ok(())
}

/// Reads a single length-prefixed frame and deserializes it.
///
/// The length prefix is validated against [`MAX_FRAME`] before the body buffer
/// is allocated.
pub fn read_msg<R: Read, T: DeserializeOwned>(r: &mut R) -> Result<T, String> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)
        .map_err(|e| format!("read failed: {e}"))?;
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(format!("frame length {len} exceeds maximum {MAX_FRAME}"));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)
        .map_err(|e| format!("read failed: {e}"))?;
    bincode::deserialize(&body).map_err(|e| format!("deserialize failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn roundtrip_request(msg: &Request) {
        let mut buf = Vec::new();
        write_msg(&mut buf, msg).expect("write");
        let mut cur = Cursor::new(buf);
        let back: Request = read_msg(&mut cur).expect("read");
        assert_eq!(&back, msg);
    }

    fn roundtrip_response(msg: &Response) {
        let mut buf = Vec::new();
        write_msg(&mut buf, msg).expect("write");
        let mut cur = Cursor::new(buf);
        let back: Response = read_msg(&mut cur).expect("read");
        assert_eq!(&back, msg);
    }

    #[test]
    fn requests_round_trip() {
        let tok = vec![7u8; 32];
        roundtrip_request(&Request::Get {
            token: tok.clone(),
            name: "github".into(),
        });
        roundtrip_request(&Request::Put {
            token: tok.clone(),
            name: "api".into(),
            value: b"s3cr3t".to_vec(),
        });
        roundtrip_request(&Request::List { token: tok.clone() });
        roundtrip_request(&Request::Status { token: tok.clone() });
        roundtrip_request(&Request::Signout { token: tok });
    }

    #[test]
    fn responses_round_trip() {
        roundtrip_response(&Response::Secret(Some(b"value".to_vec())));
        roundtrip_response(&Response::Secret(None));
        roundtrip_response(&Response::Names(vec!["a".into(), "b".into()]));
        roundtrip_response(&Response::Status {
            unlocked: true,
            vault_path: "/tmp/v.bin".into(),
            idle_secs_remaining: 1800,
        });
        roundtrip_response(&Response::Ok);
        roundtrip_response(&Response::Err("nope".into()));
    }

    #[test]
    fn oversize_prefix_is_rejected_without_allocating() {
        // A length prefix above MAX_FRAME must error on the prefix alone,
        // before any body is read or a huge buffer is allocated.
        let mut framed = (MAX_FRAME + 1).to_le_bytes().to_vec();
        framed.extend_from_slice(b"not really this long");
        let mut cur = Cursor::new(framed);
        let res: Result<Request, String> = read_msg(&mut cur);
        assert!(res.is_err(), "oversize frame should be rejected");
    }

    #[test]
    fn truncated_body_errors() {
        let mut buf = Vec::new();
        write_msg(
            &mut buf,
            &Request::Get {
                token: vec![1u8; 32],
                name: "x".into(),
            },
        )
        .unwrap();
        buf.truncate(buf.len() - 1); // chop the last body byte
        let mut cur = Cursor::new(buf);
        let res: Result<Request, String> = read_msg(&mut cur);
        assert!(res.is_err(), "truncated body should error");
    }
}
