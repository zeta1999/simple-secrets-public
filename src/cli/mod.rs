//! `op`-style command-line interface.
//!
//! A single binary serves both the interactive TUI (no arguments) and this
//! scriptable CLI (any subcommand). The CLI talks to a background *session
//! agent* that holds the unlocked vault in memory, so that after one `signin`
//! the `get`/`put`/`list` verbs run without re-prompting for the passphrase.
//!
//! [`run`] is the only public entry point; everything else is crate-internal.

mod agent;
mod client;
mod pairing;
pub(crate) mod paths;
mod protocol;
mod sharing;

use crate::core::entropy::DefaultEntropySource;
use crate::core::manager::SecretManager;
use clap::{Parser, Subcommand};
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "simple-secrets",
    about = "Post-quantum secret manager — run with no arguments for the TUI.",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Create the persistent vault (prompts for a passphrase twice).
    Init,
    /// Unlock the vault and start a background session agent.
    Signin,
    /// Lock the vault and stop the agent.
    Signout,
    /// Print a secret's value to stdout.
    Get {
        /// Name of the secret to fetch.
        name: String,
    },
    /// List the names of all stored secrets.
    List,
    /// Store a secret. Omit VALUE (or pass "-") to read it from stdin.
    Put {
        /// Name to store the secret under.
        name: String,
        /// The secret value. Omit (or pass "-") to read it from stdin — preferred,
        /// since an argument is visible in `ps` and shell history.
        value: Option<String>,
    },
    /// Generate a memorable passphrase.
    Generate {
        /// Number of words in the passphrase.
        #[arg(long, default_value_t = 6)]
        words: usize,
    },
    /// Print the live TOTP/2FA code for a stored otpauth:// or base32 secret.
    Otp {
        /// Name of the stored TOTP secret.
        name: String,
    },
    /// Add a TOTP/2FA secret: reads an otpauth:// URI or base32 seed from stdin,
    /// or mints a fresh one with --generate.
    OtpAdd {
        /// Name to store the TOTP entry under.
        name: String,
        /// Generate a new random TOTP secret (prints the URI + QR to register).
        #[arg(long)]
        generate: bool,
    },
    /// Show whether the agent is running and the vault unlocked.
    Status,
    /// Split a stored secret into N share files; any THRESHOLD reconstruct it.
    Share {
        /// Name of the stored secret to split.
        name: String,
        /// Number of shares required to reconstruct.
        #[arg(long)]
        threshold: usize,
        /// Total number of shares to produce.
        #[arg(long)]
        shares: usize,
        /// Directory to write the share files into.
        #[arg(long, default_value = ".")]
        out: String,
    },
    /// Reconstruct a secret from THRESHOLD share files (works offline).
    Reconstruct {
        /// Share files to combine (need at least THRESHOLD of them).
        files: Vec<String>,
        /// Store the result into the vault under this name instead of printing.
        #[arg(long)]
        into: Option<String>,
    },
    /// Send a stored secret to a paired device (prints an encrypted bundle).
    PairSend {
        /// Name of the stored secret to send.
        name: String,
        /// The receiving device's pairing code.
        #[arg(long = "to")]
        to: Option<String>,
        /// Read the receiving device's pairing code from a file.
        #[arg(long = "to-file")]
        to_file: Option<String>,
        /// Write the bundle to a file instead of stdout.
        #[arg(long = "bundle-out")]
        bundle_out: Option<String>,
        /// Skip the verification-code confirmation (bypasses MitM protection).
        #[arg(long)]
        yes: bool,
    },
    /// Receive a secret: emit this device's pairing code, then take the bundle
    /// (over the LAN with --listen, or from a file/stdin) and store it.
    PairReceive {
        /// Store under this name instead of the sender's label.
        #[arg(long)]
        into: Option<String>,
        /// Listen on the local network; embeds this device's ip:port in the code.
        #[arg(long)]
        listen: bool,
        /// TCP port to listen on with --listen (0 = pick a free port).
        #[arg(long, default_value_t = 0)]
        port: u16,
        /// Write the pairing code to a file instead of stdout.
        #[arg(long = "code-out")]
        code_out: Option<String>,
        /// Also display the pairing code as a scannable QR code.
        #[arg(long)]
        qr: bool,
        /// Read the bundle from a file instead of stdin (ignored with --listen).
        #[arg(long = "bundle-in")]
        bundle_in: Option<String>,
        /// Skip the interactive verification-code confirmation (for automation).
        /// WARNING: this bypasses man-in-the-middle protection.
        #[arg(long)]
        yes: bool,
    },
    /// Internal: the background session-agent process.
    #[command(name = "__agent", hide = true)]
    Agent,
}

/// Parses `args` (argv without the program name) and runs the selected command,
/// returning a process exit code. With no subcommand, launches the TUI.
pub fn run(args: &[String]) -> i32 {
    let argv = std::iter::once("simple-secrets".to_string()).chain(args.iter().cloned());
    let cli = match Cli::try_parse_from(argv) {
        Ok(cli) => cli,
        // Prints help/version (exit 0) or a usage error (exit 2) and terminates.
        Err(e) => e.exit(),
    };

    let Some(command) = cli.command else {
        return launch_tui();
    };

    let result = match command {
        Command::Init => client::init(),
        Command::Signin => client::signin(),
        Command::Signout => client::signout(),
        Command::Get { name } => client::get(&name),
        Command::List => client::list(),
        Command::Put { name, value } => client::put(&name, value.as_deref()),
        Command::Generate { words } => generate(words),
        Command::Otp { name } => client::otp(&name),
        Command::OtpAdd { name, generate } => client::otp_add(&name, generate),
        Command::Status => client::status(),
        Command::Share {
            name,
            threshold,
            shares,
            out,
        } => sharing::share(&name, threshold, shares, &out),
        Command::Reconstruct { files, into } => sharing::reconstruct(&files, into.as_deref()),
        Command::PairSend {
            name,
            to,
            to_file,
            bundle_out,
            yes,
        } => pairing::pair_send(
            &name,
            to.as_deref(),
            to_file.as_deref(),
            bundle_out.as_deref(),
            yes,
        ),
        Command::PairReceive {
            into,
            listen,
            port,
            code_out,
            qr,
            bundle_in,
            yes,
        } => pairing::pair_receive(
            into.as_deref(),
            code_out.as_deref(),
            qr,
            bundle_in.as_deref(),
            listen,
            port,
            yes,
        ),
        Command::Agent => return agent::run_agent(),
    };

    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("simple-secrets: {e}");
            1
        }
    }
}

/// `generate` — no vault needed; just draw a passphrase from the entropy source.
fn generate(words: usize) -> Result<(), String> {
    let manager = SecretManager::new(Arc::new(DefaultEntropySource));
    let phrase = manager.generate_passphrase(words)?;
    println!("{phrase}");
    Ok(())
}

fn launch_tui() -> i32 {
    match crate::ui::launch_tui() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("simple-secrets: fatal UI error: {e}");
            1
        }
    }
}
