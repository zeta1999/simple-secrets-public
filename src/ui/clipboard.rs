//! Best-effort clipboard copy with auto-clear, by shelling out to the platform's
//! clipboard tool (no dependency, and nothing links an X11/Wayland library).
//!
//! The clipboard is a real leak vector — any process on the session can read it —
//! so this is opt-in (`c` in the TUI) and the entry is wiped after a short delay.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

/// How long a copied secret lingers before the clipboard is cleared.
const CLEAR_AFTER: Duration = Duration::from_secs(15);

/// Clipboard writers to try, in order, until one is present.
const CANDIDATES: &[&[&str]] = &[
    &["pbcopy"],                           // macOS
    &["wl-copy"],                          // Wayland
    &["xclip", "-selection", "clipboard"], // X11
    &["xsel", "-b", "-i"],                 // X11 (alt)
];

/// Copies `data` to the clipboard and spawns a thread to clear it after a delay.
pub(crate) fn copy_with_autoclear(data: &[u8]) -> Result<(), String> {
    let cmd = write_clipboard(data)?;
    std::thread::spawn(move || {
        std::thread::sleep(CLEAR_AFTER);
        let _ = spawn_write(cmd, b"");
    });
    Ok(())
}

/// Tries each candidate until one writes successfully; returns the one that worked.
fn write_clipboard(data: &[u8]) -> Result<&'static [&'static str], String> {
    for &cmd in CANDIDATES {
        if spawn_write(cmd, data).is_ok() {
            return Ok(cmd);
        }
    }
    Err("no clipboard tool found (install pbcopy / wl-copy / xclip)".to_string())
}

fn spawn_write(cmd: &[&str], data: &[u8]) -> Result<(), String> {
    let mut child = Command::new(cmd[0])
        .args(&cmd[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    child
        .stdin
        .take()
        .ok_or("clipboard tool has no stdin")?
        .write_all(data)
        .map_err(|e| e.to_string())?;
    child.wait().map_err(|e| e.to_string())?;
    Ok(())
}
