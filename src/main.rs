//! Binary entrypoint for Simple Secrets.
//!
//! With no arguments, this drops the user straight into the interactive TUI (so
//! `cargo run` behaves as before). With any argument, it dispatches to the
//! `op`-style command-line interface. All real logic lives in the
//! `simple_secrets` library crate.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = if args.is_empty() {
        match simple_secrets::ui::launch_tui() {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("simple-secrets: fatal UI error: {e}");
                1
            }
        }
    } else {
        simple_secrets::cli::run(&args)
    };
    std::process::exit(code);
}
