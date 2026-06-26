//! A minimal secret-value editor backed by secure memory.
//!
//! Unlike a general text widget that keeps content in ordinary heap `String`s,
//! `SecureEditor` stores the editing buffer in a [`LockedBuffer`] — mlock'd (so
//! it is never swapped to disk) and zeroized on drop. Editing happens in place
//! in a fixed-capacity buffer, so growing the text never reallocates and leaves
//! un-wiped copies behind.
//!
//! The model is intentionally simple (append/backspace at the end, newlines
//! allowed) — enough to type or paste a secret value and correct it. The only
//! transient plaintext copy is the one produced for on-screen rendering
//! ([`display`]), which is the same exposure as viewing a decrypted value.

use secure_memory::LockedBuffer;

/// Maximum editable value size. Comfortably covers keys, certs, and recovery
/// phrases; larger values are truncated on load rather than reallocating.
const CAPACITY: usize = 64 * 1024;

pub(crate) struct SecureEditor {
    buf: LockedBuffer,
    len: usize,
}

impl SecureEditor {
    pub(crate) fn new() -> Self {
        Self::from_bytes(&[])
    }

    /// Builds an editor seeded with `init` (truncated to capacity).
    pub(crate) fn from_bytes(init: &[u8]) -> Self {
        let mut buf = LockedBuffer::new(CAPACITY).expect("allocate secure editor buffer");
        let n = init.len().min(CAPACITY);
        if n > 0 {
            if let Ok(slice) = buf.as_mut_slice() {
                slice[..n].copy_from_slice(&init[..n]);
            }
        }
        Self { buf, len: n }
    }

    /// The current contents (a borrow into the locked buffer; no copy).
    pub(crate) fn as_bytes(&self) -> &[u8] {
        match self.buf.as_slice() {
            Ok(slice) => &slice[..self.len],
            Err(_) => &[],
        }
    }

    /// Appends a character at the end (ignored if it would exceed capacity).
    pub(crate) fn push_char(&mut self, c: char) {
        let mut tmp = [0u8; 4];
        let bytes = c.encode_utf8(&mut tmp).as_bytes();
        if self.len + bytes.len() > CAPACITY {
            return;
        }
        let end = self.len + bytes.len();
        if let Ok(slice) = self.buf.as_mut_slice() {
            slice[self.len..end].copy_from_slice(bytes);
            self.len = end;
        }
    }

    /// Removes the last character, wiping the freed bytes.
    pub(crate) fn backspace(&mut self) {
        if self.len == 0 {
            return;
        }
        // Step back over a UTF-8 character (skip 0b10xx_xxxx continuation bytes).
        let new_len = match self.buf.as_slice() {
            Ok(slice) => {
                let mut i = self.len - 1;
                while i > 0 && (slice[i] & 0xC0) == 0x80 {
                    i -= 1;
                }
                i
            }
            Err(_) => self.len - 1,
        };
        if let Ok(slice) = self.buf.as_mut_slice() {
            for b in slice[new_len..self.len].iter_mut() {
                *b = 0;
            }
        }
        self.len = new_len;
    }

    /// A `String` copy of the contents for rendering. This is a transient
    /// plaintext copy on the heap (dropped right after the frame is drawn) — the
    /// same exposure as showing a decrypted value in the details pane.
    pub(crate) fn display(&self) -> String {
        String::from_utf8_lossy(self.as_bytes()).into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typing_and_backspace_round_trip() {
        let mut e = SecureEditor::new();
        for c in "héllo".chars() {
            e.push_char(c);
        }
        assert_eq!(e.as_bytes(), "héllo".as_bytes());
        e.backspace(); // removes 'o'
        assert_eq!(e.as_bytes(), "héll".as_bytes());
        e.backspace(); // removes 'l'
        e.backspace(); // removes 'l'
        e.backspace(); // removes 'é' (two bytes) — must not split UTF-8
        assert_eq!(e.as_bytes(), "h".as_bytes());
    }

    #[test]
    fn seeds_from_bytes_and_appends_newline() {
        let mut e = SecureEditor::from_bytes(b"line1");
        e.push_char('\n');
        e.push_char('x');
        assert_eq!(e.display(), "line1\nx");
    }

    #[test]
    fn backspace_on_empty_is_noop() {
        let mut e = SecureEditor::new();
        e.backspace();
        assert_eq!(e.as_bytes(), b"");
    }
}
