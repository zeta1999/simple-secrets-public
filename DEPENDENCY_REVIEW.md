# Dependency Review — `simple-ui` and `simple-network`

Brutal, read-only reviews of the two sibling crates `simple-secrets` consumes:
- `tui = { path = "../simple-ui/tui" }` — the TUI/editor widgets.
- `simple_network = { path = "../simple-network" }` — networking/pairing.

These directly shape `PLAN.md` Phases C (networking) and D (TUI), so the findings
are recorded here. Line references are into those sibling repos.

---

## New direct dependencies — `op`-style CLI

The command-line interface (`src/cli/`) added two registry crates. Both are
confined to the CLI module; the cryptographic core, storage, and FFI surfaces do
not depend on them.

- **`clap` 4 (`derive`)** — argument parsing for the CLI subcommands. Ubiquitous,
  widely audited, used only to parse `argv` into the `Command` enum in
  `src/cli/mod.rs`; it never touches key material or vault bytes. Chosen over a
  hand-rolled parser for accurate `--help`/usage and to avoid bespoke parsing
  bugs.
- **`rpassword` 7** — no-echo passphrase prompt for `init`/`signin`
  (`src/cli/client.rs`). Tiny crate (a thin `termios` `ECHO` toggle on the tty);
  the alternative was hand-rolling the same `libc` `termios` dance. Passphrase
  `String`s read from it are `zeroize`d after use.

Everything else the CLI needs (Unix sockets, framing, token compare, base64,
randomness) reuses crates already in the tree (`std`, `bincode`, `serde`,
`subtle`, `base64`, `libc`, `zeroize`). The session agent itself adds **no** new
dependency.

---

## New direct dependencies — TOTP / 2FA

The TOTP module (`src/core/totp.rs`) added two RustCrypto crates, the same family
as the already-present `sha2`/`hkdf`:

- **`hmac` 0.12** — HMAC for RFC 4226/6238 code derivation. It was already in the
  tree transitively (via `hkdf`); this promotes it to a **direct** dependency so
  the module can `use hmac::{Hmac, Mac}` honestly rather than rely on a transitive
  re-export.
- **`sha1` 0.10** — SHA-1 is the default HMAC hash for TOTP; authenticator-app
  exports (Google Authenticator, Authy, …) overwhelmingly use it, so without it
  the common case is unusable. SHA-1 is used here **only** inside HMAC-SHA1 for
  one-time codes — never for vault/file integrity, where SHA-512 is used — so its
  collision weakness is not in scope. SHA-256/512 TOTP reuse the existing `sha2`.

base32 decoding (otpauth seeds) is **hand-rolled** in `totp.rs` (~30 lines, RFC
4648) rather than adding a crate. TOTP seeds are stored as ordinary vault secrets
(an `otpauth://` URI or bare base32), so no storage/schema dependency was added.

---

## New direct dependency — pairing-code QR

- **`qrcode` 0.14** — renders a device pairing code as a terminal QR
  (`network::transfer::qr_code`, surfaced via the CLI `pair-receive --qr` and the
  TUI Network tab). A pairing code is an ML-KEM-768 public key (~1.5 KB), far too
  long to retype, so it is shared as a file or a scannable QR. The crate is
  pure-Rust, encoding-only, and touches only the (public, non-secret) pairing
  code — never key material or vault contents.

---

## Update — fixes landed upstream

Many of the findings below have since been addressed on feature branches in the
sibling repos (open PRs from these branches):

**`simple-network` (branch `fix/network-hardening`):**
- ✅ Clippy `-D warnings` now passes (default **and** `--all-features`); added a
  `ci.sh` that lints on the real exit code and runs the security suite under
  `--features pqc` (previously skipped by a default `cargo test`).
- ✅ Misleading stubs now fail loudly: `security::pairing` no longer returns/prints
  `MOCKED_KEY_*` material, and `ClusterTransportBuilder::build` no longer hands
  back a broken no-client-auth TLS config — both `bail!` as unimplemented.
- ✅ **H3** replay/reflection: `SecureSession` now uses independent
  client→server / server→client keys and a per-direction sequence number bound
  as AEAD AAD (replayed/reflected/reordered records are rejected; regression
  tests added).
- ✅ **H4** pairing KDF stretch raised from 1 → 200k iterations.
- ⏳ Still open (lower priority, skeleton modules): `raft` log-matching (H5),
  `pubsub` u8 topic-length framing truncation.

**`simple-ui` (branch `fix/editor-and-ci`):**
- ✅ `CodeEditor` now has `lines()`/`text()` read-back, a private `textarea`
  field, and exact round-trip on load (no fabricated trailing newline / CRLF
  flattening); plaintext-only contract documented loudly.
- ✅ CI now runs `cargo fmt --check` and workspace `clippy -D warnings` (plus a
  local `ci.sh`).
- ⏳ Still open: the PTY/`syntect` "done-but-empty" features, and unicode-width
  truncation in `simple-ui-widgets`.

> **Resolved by removal.** `simple-secrets` no longer depends on `tui` at all.
> The TUI's secret-value editor was reimplemented in-house as
> `ui::editor::SecureEditor`, backed by `secure-memory`'s `LockedBuffer`
> (mlock'd, zeroized on drop) — so the un-zeroized-`String` exposure that made
> `CodeEditor` unsuitable for secret material no longer applies. The `tui`
> path dependency (and its `tui-textarea`/`syntect`/`portable-pty` tree) is
> dropped from `Cargo.toml`.

The original findings, retained below for the record:

---

## `simple-ui` (consumed crate: `tui`)

**Build health:** `cargo build`, `cargo clippy --all-targets -D warnings`, and
`cargo test` (26 tests) all pass. **But CI runs only build + test — not clippy or
fmt** — so lint rot passes silently, and several "done" features have no tests to
fail.

**Architectural mismatch:** the polished, tested crate is `simple-ui-widgets`, but
the widget `simple-secrets` actually imports — `tui::widgets::editor::CodeEditor`
— lives in the heavy `tui` demo crate the docs tell consumers *not* to depend on.
We inherit tokio/syntect/portable-pty for a 33-line wrapper.

### Findings affecting us

- **CRITICAL — `CodeEditor` is write-only.** No `lines()`/`text()`/`content()`
  accessor (`tui/src/widgets/editor.rs:5-33`). For a secret-note editor you
  cannot get the edited text back out without reaching through the `pub textarea`
  field (which also leaks the `tui-textarea` type into our API). *Action (Plan
  D1):* upstream a read-back accessor or vendor a minimal editor.
- **CRITICAL — secrets held as un-zeroized `String`s.** `CodeEditor` wraps
  `tui_textarea::TextArea` (plain `Vec<String>`); no zeroize, no locked memory.
  *Action:* never load real secret material into `CodeEditor` until a
  secure-buffer-backed variant exists (Plan D1/D2).
- **HIGH — lossy load.** `CodeEditor::new` rebuilds content via `lines()` +
  `insert_newline()` (`editor.rs:10-17`), fabricating a trailing newline and
  flattening CRLF — load→save is not idempotent. *Action:* construct from
  `content.lines().collect()` and define the trailing-newline contract.
- **HIGH — claimed features that don't exist:** the embedded PTY terminal
  (`portable-pty` declared, never used; colors hard-coded to `Gray`) and "syntax
  highlighting" (`syntect` declared, zero usage) are marked done in `TODOs.md`
  but are empty. Don't rely on them.
- **MEDIUM — no panic-safe terminal restore** (`tui/src/lib.rs:88-118`): a panic
  in the draw loop leaves the terminal in raw mode. We mirror this gap in our own
  `ui::launch_tui`. *Action (Plan D3):* install a panic hook / RAII guard.

**Verdict:** `simple-ui-widgets` is genuinely good; the `CodeEditor` we depend on
is the weakest code in that repo. Treat its `TODOs.md` checkmarks with suspicion.

---

## `simple-network` (consumed crate: `simple_network`)

**Build health:** `cargo build` passes with **4 warnings**; **`cargo clippy
--all-targets -D warnings` FAILS (exit 101)** with ~7+ additional errors (FFI raw
pointers in public fns not marked `unsafe`, `while let` suggestions, missing
`Default`s). A default `cargo test` runs **exactly one** test — the entire PQC
security suite is behind `#[cfg(feature = "pqc")]` and does not run by default. CI
here is green-washed.

**Tor/I2P verdict: not implemented at all.** No SOCKS proxy, no onion/`.i2p`
handling, no `arti` dependency — only the words "Tor"/"I2P" in docs. If we need
anonymized transport we must build it ourselves (Plan C3).

### What's trustworthy vs not

- **Trust:** `src/security/pqc.rs` — hybrid ML-KEM-768 + X25519 KEM, ML-DSA-65
  handshake signatures, pinned-key mutual auth, XChaCha20-Poly1305 records,
  `LockedBuffer` key material, real tests (roundtrip / tamper-reject / wrong-pin).
  This is the one module to build pairing on (Plan C1).
- **Do NOT consume — stubs / misleading:**
  - `transport/cluster.rs` — builds an **empty root store** and uses
    `with_no_client_auth()` while being named an mTLS cluster builder; passes an
    **empty cert chain and empty key**. Broken and dangerous (C1 in their review).
  - `security/pairing.rs` — returns `format!("...MOCKED_KEY_{node}...")` PEM and
    `println!`s "key material". Pure theater (C2).
  - `transport/quic.rs`, `transport/port_forward.rs`,
    `security/simple_secrets.rs` — `Err("not implemented")`.
  - `algorithms/raft.rs` — ignores `prev_log_index/term`, appends
    unconditionally: not consensus-safe.

### Hardening to request upstream before we depend on pairing

- **H3 — replay / no directional keys:** `SecureConnection` seal/open use one
  shared session key both directions with no sequence number → captured records
  replay and reflect cleanly. Need HKDF-separated send/recv keys + a monotonic
  counter in nonce/AAD with replay rejection.
- **H4 — weak pairing KDF:** the OOB secret is stretched a single iteration
  (`sequential_stretch(secret, 1)`) with no transcript binding. Need Argon2id-class
  stretching and channel binding; document that `pair_exchange` alone is not a
  secure channel.

**Verdict:** one excellent module (`pqc`) inside a crate of stubs. Consume `pqc`
only, pin to it explicitly, and treat the rest as absent. Fix their CI to run
clippy on the real exit code and tests with `--features pqc`.

---

## Net effect on `simple-secrets`

- Networking (Plan C) is viable **only** via `simple_network::security::pqc`, and
  only after upstream H3/H4 fixes; everything else there is off-limits.
- The TUI (Plan D) must not hold real secrets in `CodeEditor` until its write-only
  and zeroization defects are resolved upstream or vendored around.
- Tor/I2P is unbuilt in both the dependency and here; the manuals correctly no
  longer claim it.
