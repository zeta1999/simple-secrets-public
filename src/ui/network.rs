use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::ui::App;

pub fn render_network(f: &mut ratatui::Frame, area: ratatui::layout::Rect, app: &App) {
    let body = match &app.pairing {
        Some((_, code)) => {
            // The code is ~1.5 KB (a PQC key) — show only a short fingerprint
            // here; it is meant to be shared as a file ('w') or QR ('q'), not read.
            let head = &code[..code.len().min(46)];
            format!(
                "Device pairing — post-quantum (ML-KEM-768)\n\n\
                 Your pairing code is ready ({} chars) — share it as data, not by\n\
                 reading it:\n\n  \
                 [w] write it to ./pairing-code.txt    [q] show it as a QR to scan\n\n\
                 starts with: {head}…\n\n\
                 [r] import a received bundle saved as ./pairing-bundle.txt\n\n\
                 For a live transfer over the local network, use the CLI instead:\n  \
                 receiver:  simple-secrets pair-receive --listen\n  \
                 sender:    simple-secrets pair-send <name> --to-file <code-file>",
                code.len()
            )
        }
        None => "Device pairing — post-quantum (ML-KEM-768)\n\n\
             Press 'w' (write to file), 'q' (QR), or 'r' (receive) to generate\n\
             this device's pairing code and receive a secret.\n\n\
             To SEND a secret, use the CLI:\n  \
             simple-secrets pair-send <name> --to-file <their-code-file>\n\n\
             (Automatic networked transfer over Tor/I2P is planned — see TODOs.md.)"
            .to_string(),
    };
    let p = Paragraph::new(body)
        .block(
            Block::default()
                .title("Network & Pairing")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(p, area);
}
