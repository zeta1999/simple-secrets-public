//! Shared rules for secret names stored in the vault index.

/// Maximum UTF-8 length of a secret name.
pub const MAX_NAME_LEN: usize = 256;

/// Rejects an empty, overlong, or control-character name so a hostile label
/// cannot corrupt the terminal or the vault index.
pub fn validate_secret_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("secret name is empty".to_string());
    }
    if name.len() > MAX_NAME_LEN {
        return Err("secret name is too long".to_string());
    }
    if name.chars().any(|c| c.is_control()) {
        return Err("secret name contains control characters".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_names() {
        validate_secret_name("api").unwrap();
        validate_secret_name("ssh/id_ed25519").unwrap();
    }

    #[test]
    fn rejects_empty_overlong_and_controls() {
        assert!(validate_secret_name("").is_err());
        assert!(validate_secret_name(&"a".repeat(MAX_NAME_LEN + 1)).is_err());
        assert!(validate_secret_name("bad\nname").is_err());
    }
}
