use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};

use crate::core::totp;
use crate::ui::App;

pub fn render_vault(f: &mut ratatui::Frame, area: ratatui::layout::Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(area);

    // Left pane: the live list of stored secret names.
    let items: Vec<ListItem> = app
        .secret_names
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let item = ListItem::new(name.to_string());
            if i == app.selected {
                item.style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                item
            }
        })
        .collect();
    let list = List::new(items).block(
        Block::default()
            .title("Secrets (↑/↓ select · a add · e edit · d delete)")
            .borders(Borders::ALL),
    );
    f.render_widget(list, chunks[0]);

    // Right pane: details for the selected secret. A TOTP value renders as a live
    // code + countdown (never the raw seed); everything else shows its plaintext.
    let detail_text = if app.secret_names.is_empty() {
        "Vault unlocked — no secrets yet.\n\nPress 'a' to add one.".to_string()
    } else {
        match app.secret_names.get(app.selected) {
            Some(name) => match app.manager.get_secret(name) {
                Ok(Some(value)) => render_value(name, &value, app.value_revealed()),
                Ok(None) => format!("selected: {name}\n(absent)"),
                Err(e) => format!("selected: {name}\n(decrypt error: {e})"),
            },
            None => "(no selection)".to_string(),
        }
    };
    let detail = Paragraph::new(detail_text)
        .block(Block::default().title("Details").borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    f.render_widget(detail, chunks[1]);
}

/// Renders the right-pane body for a decrypted value: a live TOTP code only when
/// the value is an explicit `otpauth://` URI, otherwise the plaintext. (A bare
/// base32 string is NOT auto-detected — too many ordinary values, e.g. an
/// all-letters passphrase, are valid base32 and would be mis-shown as a code.)
fn render_value(name: &str, value: &[u8], revealed: bool) -> String {
    let text = String::from_utf8_lossy(value);
    let totp = if text.trim_start().starts_with("otpauth://") {
        totp::parse(&text)
    } else {
        None
    };
    if let Some(cfg) = totp {
        let now = totp::unix_now();
        let code = totp::code_at(&cfg, now);
        let remaining = totp::seconds_remaining(&cfg, now);
        let alg = match cfg.algorithm {
            totp::TotpAlg::Sha1 => "SHA1",
            totp::TotpAlg::Sha256 => "SHA256",
            totp::TotpAlg::Sha512 => "SHA512",
        };
        // Group the digits for readability (e.g. "123 456").
        let grouped = group_code(&code);
        format!(
            "selected: {name}   [TOTP / 2FA]\n\n  {grouped}\n\nvalid for {remaining}s   ({alg}, {} digits, {}s period)\n\nThe seed is stored encrypted; only the rolling code is shown.",
            cfg.digits, cfg.period
        )
    } else if revealed {
        format!("selected: {name}\nvalue (revealed):\n  {text}")
    } else {
        // Masked by default — minimise on-screen exposure.
        let dots = "•".repeat(text.chars().count().clamp(1, 32));
        format!("selected: {name}\nvalue: {dots}   (press 's' to reveal · 'c' to copy)")
    }
}

/// Splits a code into two space-separated halves: "123456" -> "123 456".
fn group_code(code: &str) -> String {
    let mid = code.len() / 2;
    if mid == 0 {
        code.to_string()
    } else {
        format!("{} {}", &code[..mid], &code[mid..])
    }
}
