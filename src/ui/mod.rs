//! Interactive terminal UI: a real, full-CRUD front-end over the persistent
//! vault (the same vault the `op`-style CLI uses).
//!
//! On launch it resolves the persistent vault path and either prompts to create
//! the vault (first run) or to unlock it. Once unlocked, the Vault tab lists the
//! real stored secrets and supports add / edit / delete / generate, and renders a
//! live TOTP code when a secret is an `otpauth://` / base32 seed. The TUI opens
//! the vault directly in its own session (independent of the background agent);
//! the on-disk vault is written atomically, so concurrent edits are last-writer-
//! wins rather than corrupting.

use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
        KeyModifiers,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, Clear, Paragraph, Tabs, Wrap},
    Terminal,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{error::Error, io};
use zeroize::{Zeroize, Zeroizing};

use crate::cli::paths;
use crate::core::entropy::DefaultEntropySource;
use crate::core::manager::SecretManager;
use crate::crypto::vdf_kdf::Argon2Params;
use crate::network::pairing::PairingSession;
use crate::network::transfer;
use crate::ui::editor::SecureEditor;

mod clipboard;
pub mod editor;
pub mod network;
pub mod vault;

/// Character set for generated random passwords (printable ASCII, ~90 symbols).
const PASSWORD_CHARSET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{};:,.?";

/// The interaction state of the app. Each variant owns its own input buffers, so
/// transitions are explicit and key handling never has to guess the context.
pub(crate) enum Mode {
    /// First run: no vault file yet. Enter a new passphrase, then confirm it.
    CreateVault {
        pass: String,
        confirm: String,
        confirming: bool,
    },
    /// Vault exists: enter the passphrase to unlock.
    Unlock { input: String },
    /// Unlocked: browsing/CRUD on the open vault.
    Browse,
    /// Typing the name of a new secret.
    AddName { input: String },
    /// Typing the name for a new TOTP (2FA) entry.
    AddTotpName { input: String },
    /// Typing the otpauth:// URI or base32 seed for a new TOTP entry (masked).
    AddTotpSeed { name: String, input: String },
    /// Editing a secret's value (modal editor).
    EditValue { name: String, is_new: bool },
    /// Choosing how to generate a value: passphrase words vs random chars + count.
    Generate {
        name: String,
        is_new: bool,
        words: bool,
        count: String,
    },
    /// Confirming deletion of `name`.
    ConfirmDelete { name: String },
    /// Confirming the verification code (SAS) before storing a received secret.
    /// Holds the decrypted plaintext, zeroized whether stored or discarded.
    ConfirmImport {
        name: String,
        secret: Vec<u8>,
        sas: String,
    },
}

pub struct App {
    titles: Vec<String>,
    index: usize,
    editor: SecureEditor,
    manager: SecretManager,
    vault_path: PathBuf,
    secret_names: Vec<String>,
    selected: usize,
    mode: Mode,
    error: Option<String>,
    /// Transient informational status (e.g. "wrote pairing code to …").
    status: Option<String>,
    /// Lazily-created receiver pairing session + its shareable code (Network tab).
    pairing: Option<(PairingSession, String)>,
    /// Full-screen QR overlay content (pairing code or generated TOTP URI).
    qr_text: Option<String>,
    /// Until when the selected secret's value is shown in clear (else masked).
    reveal_until: Option<Instant>,
    /// Last key activity, and how long until the vault auto-locks.
    last_activity: Instant,
    idle_timeout: Duration,
}

/// Idle timeout before the TUI auto-locks (default 5 min; `SIMPLE_SECRETS_TUI_IDLE`
/// in seconds overrides; 0 disables).
fn idle_timeout() -> Duration {
    let secs = std::env::var("SIMPLE_SECRETS_TUI_IDLE")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(300);
    Duration::from_secs(secs)
}

impl Mode {
    /// Wipes any sensitive plaintext this mode is holding. Centralizing it here
    /// means every termination path (see `Drop for App`) covers every variant,
    /// including any added later.
    fn zeroize(&mut self) {
        match self {
            Mode::Unlock { input } => input.zeroize(),
            Mode::CreateVault { pass, confirm, .. } => {
                pass.zeroize();
                confirm.zeroize();
            }
            Mode::AddTotpSeed { input, .. } => input.zeroize(),
            Mode::ConfirmImport { secret, .. } => secret.zeroize(),
            _ => {}
        }
    }
}

impl Drop for App {
    /// Wipe the only plaintext not already covered by a member's own `Drop`: the
    /// buffers held inside the current `Mode`. (`SecureEditor` and the vault's
    /// master key zeroize themselves.) Runs on normal quit, Ctrl-C, and unwind.
    fn drop(&mut self) {
        self.mode.zeroize();
    }
}

impl App {
    /// Launch-time constructor: picks Create vs Unlock based on whether the vault
    /// file already exists. Does not open the vault (no passphrase yet).
    pub fn new(vault_path: PathBuf) -> App {
        let mode = if vault_path.exists() {
            Mode::Unlock {
                input: String::new(),
            }
        } else {
            Mode::CreateVault {
                pass: String::new(),
                confirm: String::new(),
                confirming: false,
            }
        };
        App {
            titles: vec!["Vault".into(), "Network".into()],
            index: 0,
            editor: SecureEditor::new(),
            manager: SecretManager::new(Arc::new(DefaultEntropySource)),
            vault_path,
            secret_names: Vec::new(),
            selected: 0,
            mode,
            error: None,
            status: None,
            pairing: None,
            qr_text: None,
            reveal_until: None,
            last_activity: Instant::now(),
            idle_timeout: idle_timeout(),
        }
    }

    /// Test/embedding seam: build an App around an already-open manager in Browse
    /// mode, so CRUD can be exercised headlessly without a terminal or full KDF.
    #[cfg(test)]
    fn with_open_manager(manager: SecretManager, vault_path: PathBuf) -> App {
        let mut app = App {
            titles: vec!["Vault".into(), "Network".into()],
            index: 0,
            editor: SecureEditor::new(),
            manager,
            vault_path,
            secret_names: Vec::new(),
            selected: 0,
            mode: Mode::Browse,
            error: None,
            status: None,
            pairing: None,
            qr_text: None,
            reveal_until: None,
            last_activity: Instant::now(),
            idle_timeout: idle_timeout(),
        };
        let _ = app.refresh_names();
        app
    }

    /// Ensures a receiver pairing session exists, generating one on first use.
    fn ensure_pairing(&mut self) {
        if self.pairing.is_none() {
            match transfer::new_pairing() {
                Ok(p) => self.pairing = Some(p),
                Err(e) => self.error = Some(e),
            }
        }
    }

    /// Writes the device's pairing code to `pairing-code.txt` in the working
    /// directory, so it can be transferred as a file rather than retyped.
    fn write_paircode(&mut self) {
        self.ensure_pairing();
        let code = self.pairing.as_ref().map(|(_, c)| c.clone());
        if let Some(code) = code {
            let path = std::env::current_dir()
                .unwrap_or_default()
                .join("pairing-code.txt");
            match std::fs::write(&path, code) {
                Ok(()) => {
                    self.error = None;
                    self.status = Some(format!("wrote pairing code to {}", path.display()));
                }
                Err(e) => self.error = Some(format!("write failed: {e}")),
            }
        }
    }

    /// Copies the selected secret to the clipboard (auto-clears after a delay).
    fn copy_selected(&mut self) {
        self.error = None;
        self.status = None;
        let Some(name) = self.selected_name().map(str::to_string) else {
            return;
        };
        match self.manager.get_secret(&name) {
            Ok(Some(mut v)) => {
                let r = clipboard::copy_with_autoclear(&v);
                v.zeroize();
                match r {
                    Ok(()) => {
                        self.status = Some("copied to clipboard — auto-clears in 15s".to_string())
                    }
                    Err(e) => self.error = Some(e),
                }
            }
            Ok(None) => {}
            Err(e) => self.error = Some(e),
        }
    }

    /// Mints a random TOTP secret, stores it as a canonical otpauth:// URI, and
    /// shows its QR so the same secret can be registered on the verifying side.
    fn store_generated_totp(&mut self, name: &str) -> Mode {
        use crate::core::totp::{TotpAlg, TotpConfig};
        match self.manager.random_bytes(20) {
            Ok(secret) => {
                let cfg = TotpConfig {
                    secret,
                    digits: 6,
                    period: 30,
                    algorithm: TotpAlg::Sha1,
                };
                let uri = crate::core::totp::to_uri(&cfg, name);
                match self
                    .manager
                    .put_secret(name, uri.as_bytes())
                    .and_then(|()| self.refresh_names())
                {
                    Ok(()) => {
                        self.select_name(name);
                        self.status = Some(format!(
                            "generated TOTP '{name}' — scan the QR to register it"
                        ));
                        self.qr_text = Some(uri); // overlay; any key dismisses
                    }
                    Err(e) => self.error = Some(e),
                }
            }
            Err(e) => self.error = Some(e),
        }
        Mode::Browse
    }

    /// Whether the selected value should be shown in clear (reveal not expired).
    fn value_revealed(&self) -> bool {
        self.reveal_until.is_some_and(|t| Instant::now() < t)
    }

    /// Locks the vault: closes it (master key zeroized on drop), wipes in-memory
    /// state, and returns to the passphrase prompt. Unsaved edits are discarded.
    fn lock(&mut self) {
        self.manager.lock();
        self.editor = SecureEditor::new();
        self.secret_names.clear();
        self.selected = 0;
        self.pairing = None;
        self.qr_text = None;
        self.reveal_until = None;
        self.error = None;
        self.status = Some("vault locked".to_string());
        self.mode = Mode::Unlock {
            input: String::new(),
        };
    }

    /// Auto-locks after `idle_timeout` of no key activity (0 disables).
    fn maybe_autolock(&mut self) {
        if self.idle_timeout.is_zero() {
            return;
        }
        let unlocked = !matches!(self.mode, Mode::Unlock { .. } | Mode::CreateVault { .. });
        if unlocked && self.last_activity.elapsed() >= self.idle_timeout {
            self.lock();
        }
    }

    /// Reads `./pairing-bundle.txt`, opens it, and transitions to a confirmation
    /// mode. The secret is **not stored** until the user confirms the verification
    /// code (anti-MitM). File-based (not pasted) so a ~1.5 KB bundle can't be
    /// mangled by the terminal. Returns the next mode.
    fn begin_import(&mut self) -> Mode {
        self.error = None;
        self.status = None;
        self.ensure_pairing();
        if self.pairing.is_none() {
            return Mode::Browse;
        }
        let path = std::env::current_dir()
            .unwrap_or_default()
            .join("pairing-bundle.txt");
        let bundle = match std::fs::read_to_string(&path) {
            Ok(b) => b,
            Err(e) => {
                self.error = Some(format!("cannot read {}: {e}", path.display()));
                return Mode::Browse;
            }
        };
        let opened = match self.pairing.as_ref() {
            Some((session, _)) => transfer::open_bundle(session, bundle.trim()),
            None => return Mode::Browse,
        };
        let mut opened = match opened {
            Ok(o) => o,
            Err(e) => {
                self.error = Some(e);
                return Mode::Browse;
            }
        };
        if self.secret_names.iter().any(|n| n == &opened.name) {
            opened.secret.zeroize();
            self.error = Some(format!(
                "'{}' already exists; delete it first or rename on the sender",
                opened.name
            ));
            return Mode::Browse;
        }
        let code_fp = self
            .pairing
            .as_ref()
            .and_then(|(_, code)| transfer::code_fingerprint(code).ok())
            .unwrap_or_default();
        Mode::ConfirmImport {
            name: opened.name,
            secret: opened.secret,
            sas: code_fp,
        }
    }

    // ── Headless operations (shared by the event loop and tests) ──────────

    fn refresh_names(&mut self) -> Result<(), String> {
        let mut names = self.manager.secret_names()?;
        names.sort();
        self.secret_names = names;
        if self.selected >= self.secret_names.len() {
            self.selected = self.secret_names.len().saturating_sub(1);
        }
        Ok(())
    }

    fn selected_name(&self) -> Option<&str> {
        self.secret_names.get(self.selected).map(String::as_str)
    }

    fn select_name(&mut self, name: &str) {
        if let Some(i) = self.secret_names.iter().position(|n| n == name) {
            self.selected = i;
        }
    }

    #[cfg(test)]
    fn add_secret(&mut self, name: &str, value: &[u8]) -> Result<(), String> {
        self.manager.put_secret(name, value)?;
        self.refresh_names()?;
        self.select_name(name);
        Ok(())
    }

    fn save_edited_value(&mut self, name: &str, value: &[u8]) -> Result<(), String> {
        self.manager.put_secret(name, value)?;
        self.refresh_names()
    }

    fn delete_named(&mut self, name: &str) -> Result<(), String> {
        self.manager.delete_secret(name)?;
        if self.selected > 0 {
            self.selected -= 1;
        }
        self.refresh_names()
    }

    fn try_unlock(&mut self, pass: &str) -> Result<(), String> {
        self.manager
            .open_vault(&self.vault_path, pass.as_bytes(), None)?;
        self.refresh_names()
    }

    fn try_create(&mut self, pass: &str) -> Result<(), String> {
        if let Some(parent) = self.vault_path.parent() {
            if !parent.as_os_str().is_empty() {
                paths::ensure_private_dir(parent)?;
            }
        }
        self.manager.create_vault(
            &self.vault_path,
            pass.as_bytes(),
            &Argon2Params::default(),
            0,
            None,
        )?;
        self.refresh_names()
    }

    // ── Navigation helpers ────────────────────────────────────────────────

    fn next_tab(&mut self) {
        self.index = (self.index + 1) % self.titles.len();
    }
    fn prev_tab(&mut self) {
        self.index = if self.index == 0 {
            self.titles.len() - 1
        } else {
            self.index - 1
        };
    }
    fn select_prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }
    fn select_next(&mut self) {
        if self.selected + 1 < self.secret_names.len() {
            self.selected += 1;
        }
    }

    /// Loads the selected secret's value into the editor and switches to the
    /// Editor tab, returning the next mode (EditValue, or Browse on failure).
    fn begin_edit(&mut self) -> Mode {
        let Some(name) = self.selected_name().map(str::to_string) else {
            return Mode::Browse;
        };
        match self.manager.get_secret(&name) {
            Ok(Some(mut v)) => {
                self.editor = SecureEditor::from_bytes(&v);
                v.zeroize(); // wipe the transient plaintext copy from get_secret
                self.index = 0;
                self.error = None;
                Mode::EditValue {
                    name,
                    is_new: false,
                }
            }
            Ok(None) => {
                self.error = Some(format!("'{name}' no longer exists"));
                Mode::Browse
            }
            Err(e) => {
                self.error = Some(e);
                Mode::Browse
            }
        }
    }

    // ── Key handling ──────────────────────────────────────────────────────

    /// Handles one key event, returning `true` if the app should quit.
    fn handle_key(&mut self, key: KeyEvent) -> bool {
        // Ctrl-C always quits.
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return true;
        }
        // Any key counts as activity (resets the idle auto-lock timer).
        self.last_activity = Instant::now();
        // Ctrl-L locks immediately (panic): close the vault, back to the prompt.
        if key.code == KeyCode::Char('l') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.lock();
            return false;
        }
        // The QR overlay is modal: any key dismisses it.
        if self.qr_text.is_some() {
            self.qr_text = None;
            return false;
        }
        // Own the current mode so the per-mode handlers can freely call &mut self.
        let mode = std::mem::replace(&mut self.mode, Mode::Browse);
        let (next, quit) = self.step(mode, key);
        self.mode = next;
        quit
    }

    fn step(&mut self, mode: Mode, key: KeyEvent) -> (Mode, bool) {
        match mode {
            Mode::Unlock { mut input } => match key.code {
                KeyCode::Esc => (Mode::Unlock { input }, true),
                KeyCode::Enter => {
                    let result = self.try_unlock(&input);
                    input.zeroize();
                    match result {
                        Ok(()) => {
                            self.error = None;
                            (Mode::Browse, false)
                        }
                        Err(e) => {
                            self.error = Some(e);
                            (
                                Mode::Unlock {
                                    input: String::new(),
                                },
                                false,
                            )
                        }
                    }
                }
                KeyCode::Backspace => {
                    input.pop();
                    (Mode::Unlock { input }, false)
                }
                KeyCode::Char(c) => {
                    input.push(c);
                    (Mode::Unlock { input }, false)
                }
                _ => (Mode::Unlock { input }, false),
            },

            Mode::CreateVault {
                mut pass,
                mut confirm,
                confirming,
            } => match key.code {
                KeyCode::Esc => (
                    Mode::CreateVault {
                        pass,
                        confirm,
                        confirming,
                    },
                    true,
                ),
                KeyCode::Enter => {
                    if !confirming {
                        return (
                            Mode::CreateVault {
                                pass,
                                confirm: String::new(),
                                confirming: true,
                            },
                            false,
                        );
                    }
                    let fresh = || Mode::CreateVault {
                        pass: String::new(),
                        confirm: String::new(),
                        confirming: false,
                    };
                    let next = if pass.is_empty() {
                        self.error = Some("passphrase cannot be empty".into());
                        fresh()
                    } else if pass != confirm {
                        self.error = Some("passphrases do not match".into());
                        fresh()
                    } else {
                        match self.try_create(&pass) {
                            Ok(()) => {
                                self.error = None;
                                Mode::Browse
                            }
                            Err(e) => {
                                self.error = Some(e);
                                fresh()
                            }
                        }
                    };
                    pass.zeroize();
                    confirm.zeroize();
                    (next, false)
                }
                KeyCode::Backspace => {
                    if confirming {
                        confirm.pop();
                    } else {
                        pass.pop();
                    }
                    (
                        Mode::CreateVault {
                            pass,
                            confirm,
                            confirming,
                        },
                        false,
                    )
                }
                KeyCode::Char(c) => {
                    if confirming {
                        confirm.push(c);
                    } else {
                        pass.push(c);
                    }
                    (
                        Mode::CreateVault {
                            pass,
                            confirm,
                            confirming,
                        },
                        false,
                    )
                }
                _ => (
                    Mode::CreateVault {
                        pass,
                        confirm,
                        confirming,
                    },
                    false,
                ),
            },

            Mode::Browse => {
                match key.code {
                    KeyCode::Esc => return (Mode::Browse, true),
                    KeyCode::Tab => {
                        self.next_tab();
                        return (Mode::Browse, false);
                    }
                    KeyCode::BackTab => {
                        self.prev_tab();
                        return (Mode::Browse, false);
                    }
                    _ => {}
                }
                if self.index == 0 {
                    match key.code {
                        KeyCode::Up => {
                            self.select_prev();
                            self.reveal_until = None; // re-mask on selection change
                        }
                        KeyCode::Down => {
                            self.select_next();
                            self.reveal_until = None;
                        }
                        KeyCode::Char('s') => {
                            self.reveal_until = Some(Instant::now() + Duration::from_secs(10));
                        }
                        KeyCode::Char('c') => self.copy_selected(),
                        KeyCode::Char('a') => {
                            self.error = None;
                            return (
                                Mode::AddName {
                                    input: String::new(),
                                },
                                false,
                            );
                        }
                        KeyCode::Char('e') => return (self.begin_edit(), false),
                        KeyCode::Char('t') => {
                            self.error = None;
                            return (
                                Mode::AddTotpName {
                                    input: String::new(),
                                },
                                false,
                            );
                        }
                        KeyCode::Char('d') => {
                            if let Some(name) = self.selected_name().map(str::to_string) {
                                return (Mode::ConfirmDelete { name }, false);
                            }
                        }
                        _ => {}
                    }
                } else if self.index == 1 {
                    // Network tab: r = receive a bundle, q = QR, w = write code.
                    match key.code {
                        KeyCode::Char('r') => return (self.begin_import(), false),
                        KeyCode::Char('q') => {
                            self.error = None;
                            self.status = None;
                            self.ensure_pairing();
                            self.qr_text = self.pairing.as_ref().map(|(_, c)| c.clone());
                        }
                        KeyCode::Char('w') => self.write_paircode(),
                        _ => {}
                    }
                }
                // The Editor tab is only interactive while editing a value
                // (Mode::EditValue); in Browse it just shows the buffer.
                (Mode::Browse, false)
            }

            Mode::AddName { mut input } => match key.code {
                KeyCode::Esc => {
                    self.error = None;
                    (Mode::Browse, false)
                }
                KeyCode::Enter => {
                    if input.is_empty() {
                        self.error = Some("name cannot be empty".into());
                        (Mode::AddName { input }, false)
                    } else if self.secret_names.iter().any(|n| n == &input) {
                        self.error = Some(format!("'{input}' already exists"));
                        (Mode::AddName { input }, false)
                    } else {
                        self.editor = SecureEditor::new();
                        self.index = 0;
                        self.error = None;
                        (
                            Mode::EditValue {
                                name: input,
                                is_new: true,
                            },
                            false,
                        )
                    }
                }
                KeyCode::Backspace => {
                    input.pop();
                    (Mode::AddName { input }, false)
                }
                KeyCode::Char(c) => {
                    input.push(c);
                    (Mode::AddName { input }, false)
                }
                _ => (Mode::AddName { input }, false),
            },

            Mode::AddTotpName { mut input } => match key.code {
                KeyCode::Esc => {
                    self.error = None;
                    (Mode::Browse, false)
                }
                KeyCode::Enter => {
                    if input.is_empty() {
                        self.error = Some("name cannot be empty".into());
                        (Mode::AddTotpName { input }, false)
                    } else if self.secret_names.iter().any(|n| n == &input) {
                        self.error = Some(format!("'{input}' already exists"));
                        (Mode::AddTotpName { input }, false)
                    } else {
                        self.error = None;
                        (
                            Mode::AddTotpSeed {
                                name: input,
                                input: String::new(),
                            },
                            false,
                        )
                    }
                }
                KeyCode::Backspace => {
                    input.pop();
                    (Mode::AddTotpName { input }, false)
                }
                KeyCode::Char(c) => {
                    input.push(c);
                    (Mode::AddTotpName { input }, false)
                }
                _ => (Mode::AddTotpName { input }, false),
            },

            Mode::AddTotpSeed { name, mut input }
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && key.code == KeyCode::Char('g') =>
            {
                // Mint a fresh random TOTP secret instead of pasting one.
                input.zeroize();
                (self.store_generated_totp(&name), false)
            }

            Mode::AddTotpSeed { name, mut input } => match key.code {
                KeyCode::Esc => {
                    input.zeroize(); // the seed is a 2FA secret
                    self.error = None;
                    (Mode::Browse, false)
                }
                KeyCode::Enter => match crate::core::totp::parse(input.trim()) {
                    Some(cfg) => {
                        let uri = crate::core::totp::to_uri(&cfg, &name);
                        input.zeroize();
                        match self
                            .manager
                            .put_secret(&name, uri.as_bytes())
                            .and_then(|()| self.refresh_names())
                        {
                            Ok(()) => {
                                self.select_name(&name);
                                self.status = Some(format!("added TOTP '{name}'"));
                                (Mode::Browse, false)
                            }
                            Err(e) => {
                                self.error = Some(e);
                                (Mode::Browse, false)
                            }
                        }
                    }
                    None => {
                        self.error = Some("not a valid otpauth:// URI or base32 seed".to_string());
                        (Mode::AddTotpSeed { name, input }, false)
                    }
                },
                KeyCode::Backspace => {
                    input.pop();
                    (Mode::AddTotpSeed { name, input }, false)
                }
                KeyCode::Char(c) => {
                    input.push(c);
                    (Mode::AddTotpSeed { name, input }, false)
                }
                _ => (Mode::AddTotpSeed { name, input }, false),
            },

            Mode::EditValue { name, is_new } => {
                let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
                if ctrl && key.code == KeyCode::Char('s') {
                    // Copy out, save, then wipe both the copy and the editor.
                    let value = Zeroizing::new(self.editor.as_bytes().to_vec());
                    match self.save_edited_value(&name, &value) {
                        Ok(()) => {
                            self.editor = SecureEditor::new();
                            self.index = 0;
                            self.select_name(&name);
                            self.error = None;
                            (Mode::Browse, false)
                        }
                        Err(e) => {
                            self.error = Some(e);
                            (Mode::EditValue { name, is_new }, false)
                        }
                    }
                } else if ctrl && key.code == KeyCode::Char('g') {
                    // Open the generator so the user chooses kind + length.
                    self.error = None;
                    (
                        Mode::Generate {
                            name,
                            is_new,
                            words: true,
                            count: String::new(),
                        },
                        false,
                    )
                } else if key.code == KeyCode::Esc {
                    self.editor = SecureEditor::new(); // discard edited plaintext
                    self.index = 0;
                    (Mode::Browse, false)
                } else {
                    match key.code {
                        KeyCode::Char(c) => self.editor.push_char(c),
                        KeyCode::Backspace => self.editor.backspace(),
                        KeyCode::Enter => self.editor.push_char('\n'),
                        _ => {}
                    }
                    (Mode::EditValue { name, is_new }, false)
                }
            }

            Mode::Generate {
                name,
                is_new,
                words,
                mut count,
            } => match key.code {
                KeyCode::Esc => (Mode::EditValue { name, is_new }, false),
                KeyCode::Char('w') => (
                    Mode::Generate {
                        name,
                        is_new,
                        words: true,
                        count,
                    },
                    false,
                ),
                KeyCode::Char('c') => (
                    Mode::Generate {
                        name,
                        is_new,
                        words: false,
                        count,
                    },
                    false,
                ),
                KeyCode::Char(d) if d.is_ascii_digit() && count.len() < 4 => {
                    count.push(d);
                    (
                        Mode::Generate {
                            name,
                            is_new,
                            words,
                            count,
                        },
                        false,
                    )
                }
                KeyCode::Backspace => {
                    count.pop();
                    (
                        Mode::Generate {
                            name,
                            is_new,
                            words,
                            count,
                        },
                        false,
                    )
                }
                KeyCode::Enter => {
                    // Empty count uses a sensible default per kind (words: 6, chars: 20).
                    let default = if words { 6 } else { 20 };
                    let n = if count.is_empty() {
                        default
                    } else {
                        count.parse::<usize>().unwrap_or(default)
                    }
                    .clamp(1, 256);
                    let generated = if words {
                        self.manager.generate_passphrase(n)
                    } else {
                        self.manager.generate_password(n, PASSWORD_CHARSET)
                    };
                    match generated {
                        Ok(value) => {
                            let value = Zeroizing::new(value);
                            self.editor = SecureEditor::from_bytes(value.as_bytes());
                            self.error = None;
                        }
                        Err(e) => self.error = Some(e),
                    }
                    (Mode::EditValue { name, is_new }, false)
                }
                _ => (
                    Mode::Generate {
                        name,
                        is_new,
                        words,
                        count,
                    },
                    false,
                ),
            },

            Mode::ConfirmDelete { name } => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    if let Err(e) = self.delete_named(&name) {
                        self.error = Some(e);
                    }
                    (Mode::Browse, false)
                }
                _ => (Mode::Browse, false),
            },

            Mode::ConfirmImport {
                name,
                mut secret,
                sas,
            } => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    let stored = self.manager.put_secret(&name, &secret);
                    secret.zeroize();
                    match stored.and_then(|()| self.refresh_names()) {
                        Ok(()) => {
                            self.select_name(&name);
                            self.index = 0;
                            self.status = Some(format!("imported '{name}' (code {sas} confirmed)"));
                        }
                        Err(e) => self.error = Some(e),
                    }
                    (Mode::Browse, false)
                }
                _ => {
                    secret.zeroize(); // discard the plaintext on cancel
                    self.status = Some("import cancelled".to_string());
                    (Mode::Browse, false)
                }
            },
        }
    }
}

pub fn launch_tui() -> Result<(), Box<dyn Error>> {
    let vault_path = paths::vault_path().map_err(Box::<dyn Error>::from)?;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let app = App::new(vault_path);
    let res = run_app(&mut terminal, app);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{err:?}");
    }
    Ok(())
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, mut app: App) -> io::Result<()> {
    loop {
        terminal.draw(|f| render(f, &app))?;
        // Poll so the screen still refreshes (~2×/s) for the live TOTP countdown
        // even when no key is pressed.
        if event::poll(Duration::from_millis(500))? {
            if let Event::Key(key) = event::read()? {
                // Only react to presses (Windows also emits Release/Repeat).
                if key.kind == KeyEventKind::Press && app.handle_key(key) {
                    return Ok(());
                }
            }
        }
        // On every tick (key or timeout), re-lock if idle too long.
        app.maybe_autolock();
    }
}

// ── Rendering ─────────────────────────────────────────────────────────────

fn render(f: &mut ratatui::Frame, app: &App) {
    if let Some(text) = &app.qr_text {
        render_qr(f, text);
        return;
    }
    match &app.mode {
        Mode::Unlock { input } => render_passphrase(
            f,
            "Unlock vault",
            &format!("Vault: {}", app.vault_path.display()),
            input.chars().count(),
            app.error.as_deref(),
        ),
        Mode::CreateVault {
            pass,
            confirm,
            confirming,
        } => {
            let (label, count) = if *confirming {
                ("Confirm new passphrase", confirm.chars().count())
            } else {
                ("Create vault — new passphrase", pass.chars().count())
            };
            render_passphrase(
                f,
                label,
                &format!("New vault: {}", app.vault_path.display()),
                count,
                app.error.as_deref(),
            );
        }
        _ => render_main(f, app),
    }
}

/// A centered masked-passphrase prompt used for unlock and create.
fn render_passphrase(
    f: &mut ratatui::Frame,
    title: &str,
    subtitle: &str,
    masked_len: usize,
    error: Option<&str>,
) {
    let area = centered_rect(60, 30, f.size());
    f.render_widget(Clear, area);
    let mut lines = vec![
        Line::from(subtitle.to_string()),
        Line::from(""),
        Line::from(format!("Passphrase: {}", "*".repeat(masked_len))),
        Line::from(""),
        Line::from("Enter = confirm    Esc = quit"),
    ];
    if let Some(e) = error {
        lines.push(Line::from(""));
        lines.push(Line::from(format!("⚠ {e}")).style(Style::default().fg(Color::Red)));
    }
    let p = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Simple Secrets — {title}")),
    );
    f.render_widget(p, area);
}

fn render_main(f: &mut ratatui::Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(f.size());

    let titles: Vec<Line> = app.titles.iter().cloned().map(Line::from).collect();
    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Simple Secrets GUI"),
        )
        .select(app.index)
        .style(Style::default().fg(Color::Cyan))
        .highlight_style(Style::default().fg(Color::Yellow));
    f.render_widget(tabs, chunks[0]);

    // The value editor is a modal over the current tab, not a separate tab.
    if matches!(app.mode, Mode::EditValue { .. } | Mode::Generate { .. }) {
        render_editor(f, chunks[1], app);
    } else {
        match app.index {
            0 => vault::render_vault(f, chunks[1], app),
            1 => network::render_network(f, chunks[1], app),
            _ => {}
        }
    }

    // Context-sensitive help / status bar.
    let help = match (&app.mode, app.index) {
        (Mode::EditValue { .. }, _) => {
            "Ctrl-S save   Ctrl-G generate (choose kind/length)   Esc cancel".to_string()
        }
        (Mode::Generate { .. }, _) => {
            "w words / c chars   type a length   Enter generate   Esc back".to_string()
        }
        (Mode::Browse, 0) => {
            "↑/↓ sel  s reveal  c copy  a add  t TOTP  e edit  d del  ^L lock  Esc quit".to_string()
        }
        (Mode::Browse, 1) => {
            "w write code   q QR   r import bundle   ^L lock   Tab tab   Esc quit".to_string()
        }
        (Mode::ConfirmImport { .. }, _) => {
            "Verify the code, then  y = import   else cancel".to_string()
        }
        _ => "Tab next tab   Esc quit".to_string(),
    };
    let help_line = match (&app.error, &app.status) {
        (Some(e), _) => Line::from(format!("⚠ {e}")).style(Style::default().fg(Color::Red)),
        (None, Some(s)) => Line::from(format!("✓ {s}")).style(Style::default().fg(Color::Cyan)),
        (None, None) => Line::from(help).style(Style::default().fg(Color::DarkGray)),
    };
    f.render_widget(Paragraph::new(help_line), chunks[2]);

    // Modal overlays.
    match &app.mode {
        Mode::AddName { input } => render_popup(
            f,
            "New secret name",
            &format!("{input}\n\nEnter = continue to value    Esc = cancel"),
        ),
        Mode::AddTotpName { input } => render_popup(
            f,
            "New TOTP / 2FA — name",
            &format!("{input}\n\nEnter = continue to the seed    Esc = cancel"),
        ),
        Mode::AddTotpSeed { name, input } => render_popup(
            f,
            "New TOTP / 2FA — seed",
            &format!(
                "Entry: {name}\n\nPaste an otpauth:// URI or base32 seed:\n{}\n\nEnter = save   Ctrl-G = generate a new one   Esc = cancel",
                "*".repeat(input.chars().count())
            ),
        ),
        Mode::ConfirmDelete { name } => render_popup(
            f,
            "Delete secret",
            &format!("Delete '{name}'?\n\ny = yes    any other key = no"),
        ),
        Mode::Generate {
            words, count, ..
        } => render_popup(
            f,
            "Generate value",
            &format!(
                "Kind:  [{}] words   [{}] random chars   (w / c to switch)\nLength: {}_   (digits; blank = default {})\n\nEnter = generate    Esc = back to the editor",
                if *words { "x" } else { " " },
                if *words { " " } else { "x" },
                count,
                if *words { 6 } else { 20 },
            ),
        ),
        Mode::ConfirmImport { name, sas, .. } => render_popup(
            f,
            "Confirm import (anti-MitM)",
            &format!(
                "Importing '{name}'.\n\nVERIFICATION CODE:  {sas}\n\nDoes it EXACTLY match the code on the sending device?\n\ny = import    any other key = discard"
            ),
        ),
        _ => {}
    }
}

/// Full-screen QR of the pairing code (modal; any key dismisses). A PQC key
/// makes a large QR, so it may overflow a small terminal — zoom out to scan.
fn render_qr(f: &mut ratatui::Frame, text: &str) {
    let area = f.size();
    f.render_widget(Clear, area);
    let body = match transfer::qr_code(text) {
        Ok(qr) => {
            format!("Scan with the other device (zoom out if clipped). Any key to dismiss.\n\n{qr}")
        }
        Err(e) => format!("QR error: {e}"),
    };
    f.render_widget(Paragraph::new(body).alignment(Alignment::Center), area);
}

/// Renders the secure value editor (Editor tab). The displayed text is a
/// transient plaintext copy; the editing buffer itself is mlock'd and zeroized.
fn render_editor(f: &mut ratatui::Frame, area: Rect, app: &App) {
    // Only shown while editing a value (EditValue) or choosing a generator.
    let title = "Editing value — Ctrl-S save · Ctrl-G generate · Esc cancel";
    let mut body = app.editor.display();
    body.push('▏'); // simple end-of-text cursor
    let p = Paragraph::new(body)
        .block(Block::default().borders(Borders::ALL).title(title))
        .wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

fn render_popup(f: &mut ratatui::Frame, title: &str, body: &str) {
    let area = centered_rect(60, 25, f.size());
    f.render_widget(Clear, area);
    let p = Paragraph::new(body.to_string())
        .alignment(Alignment::Left)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title.to_string()),
        );
    f.render_widget(p, area);
}

/// A `Rect` centered within `r`, sized to the given percentages.
fn centered_rect(pct_x: u16, pct_y: u16, r: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - pct_y) / 2),
            Constraint::Percentage(pct_y),
            Constraint::Percentage((100 - pct_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - pct_x) / 2),
            Constraint::Percentage(pct_x),
            Constraint::Percentage((100 - pct_x) / 2),
        ])
        .split(vertical[1])[1]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn temp_path() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("ss-ui-test-{}-{}.vault", std::process::id(), n))
    }

    fn fast_params() -> Argon2Params {
        Argon2Params {
            time: 1,
            memory: 8 * 1024,
            threads: 1,
        }
    }

    fn open_app() -> (App, PathBuf) {
        let path = temp_path();
        let mut mgr = SecretManager::new(Arc::new(DefaultEntropySource));
        mgr.create_vault(&path, b"pw", &fast_params(), 0, None)
            .unwrap();
        (App::with_open_manager(mgr, path.clone()), path)
    }

    #[test]
    fn mode_zeroize_wipes_held_plaintext() {
        let mut m = Mode::ConfirmImport {
            name: "x".into(),
            secret: vec![1u8, 2, 3, 4],
            sas: "AB".into(),
        };
        m.zeroize();
        match &m {
            Mode::ConfirmImport { secret, .. } => assert!(secret.iter().all(|&b| b == 0)),
            _ => unreachable!(),
        }
    }

    #[test]
    fn lock_clears_state_and_requires_unlock() {
        let (mut app, path) = open_app();
        app.add_secret("k", b"v").unwrap();
        assert!(app.manager.is_unlocked());
        app.lock();
        assert!(!app.manager.is_unlocked(), "vault must be closed");
        assert!(app.secret_names.is_empty());
        assert!(matches!(app.mode, Mode::Unlock { .. }));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn autolocks_after_idle() {
        let (mut app, path) = open_app();
        app.idle_timeout = Duration::from_millis(1);
        app.last_activity = Instant::now()
            .checked_sub(Duration::from_secs(10))
            .unwrap_or_else(Instant::now);
        app.maybe_autolock();
        assert!(!app.manager.is_unlocked(), "should auto-lock when idle");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn add_list_and_delete() {
        let (mut app, path) = open_app();
        app.add_secret("github", b"tok").unwrap();
        app.add_secret("aws", b"key").unwrap();
        assert_eq!(
            app.secret_names,
            vec!["aws".to_string(), "github".to_string()]
        );

        app.select_name("aws");
        app.delete_named("aws").unwrap();
        assert_eq!(app.secret_names, vec!["github".to_string()]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn edit_value_round_trips_through_disk() {
        let (mut app, path) = open_app();
        app.add_secret("k", b"v1").unwrap();
        app.save_edited_value("k", b"v2").unwrap();
        // Reopen from disk to confirm persistence.
        app.manager.lock();
        app.manager.open_vault(&path, b"pw", None).unwrap();
        assert_eq!(app.manager.get_secret("k").unwrap().unwrap(), b"v2");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn totp_value_is_detected() {
        let (mut app, path) = open_app();
        app.add_secret("2fa", b"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP")
            .unwrap();
        let v = app.manager.get_secret("2fa").unwrap().unwrap();
        assert!(crate::core::totp::parse(&String::from_utf8_lossy(&v)).is_some());
        std::fs::remove_file(&path).ok();
    }
}
