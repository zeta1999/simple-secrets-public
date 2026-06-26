# Simple Secrets - User Manual

Welcome to **Simple Secrets**, a terminal-based secret management tool powered by Post-Quantum Cryptography (ML-KEM-768 / ML-DSA-65) and GF(2^8) Shamir Secret Sharing.

> **Status:** The cryptographic core — Argon2id + sequential-hashing key
> derivation, post-quantum primitives, k-in-n secret sharing, and the encrypted
> on-disk vault — is implemented and tested. The **Vault tab is a real, full-CRUD
> front-end** over the persistent vault (the same one the CLI uses): unlock,
> add, edit, delete, generate, and live **TOTP / 2FA** codes. The **Network** tab
> shows this device's real post-quantum **pairing code** and can import a
> transferred secret (sending is via the CLI). For scripting/automation there is
> an `op`-style command-line interface (see below); the library API is also
> available directly (see `DEV_MANUAL.md`).

## Getting Started

### Option A — Pre-built binary (recommended)

If you received a distribution archive (`simple-secrets-<version>-<target>.tar.gz`),
no Rust toolchain is required. Verify, extract, and run:

```bash
# Verify integrity (optional but recommended)
sha256sum -c simple-secrets-<version>-<target>.tar.gz.sha256   # macOS: shasum -a 256 -c ...

# Extract and launch
tar -xzf simple-secrets-<version>-<target>.tar.gz
cd simple-secrets-<version>-<target>
./simple-secrets
```

This `USER_MANUAL.md` is bundled alongside the binary.

### Option B — From source

With Rust installed, from the repository root:

```bash
cargo run            # compile and launch the interactive TUI
```

Maintainers can produce a distribution archive (binary + this manual + checksum
under `dist/`) with:

```bash
./dist.sh                 # build for the host platform
./dist.sh <target-triple> # cross-build for an installed rustup target
```

Both paths launch the same interactive Terminal User Interface (TUI). Press
**Esc** at any time to exit.

## Command-line interface (`op`-style)

Run with **no arguments** for the TUI; run with **any subcommand** for the
scriptable CLI, modeled on 1Password's `op`. The CLI keeps a separate
**persistent** vault (the TUI's vault is a throwaway demo) and uses a background
**session agent** so that, after one `signin`, repeated commands run without
re-prompting for your passphrase.

```bash
simple-secrets init                  # create the persistent vault (prompts twice)
eval "$(simple-secrets signin)"      # unlock; starts the agent, sets $SIMPLE_SECRETS_SESSION
printf '%s' "$API_KEY" | simple-secrets put api-key   # store a secret (value from stdin)
simple-secrets put github-token ghp_xxx               # …or pass it as an argument (visible in ps/history)
simple-secrets get github-token      # print a secret to stdout
simple-secrets list                  # list secret names
simple-secrets status                # is the agent running / vault unlocked?
simple-secrets generate --words 6    # print a fresh memorable passphrase
simple-secrets otp github-2fa        # print the live TOTP/2FA code (see below)
simple-secrets signout               # lock the vault and stop the agent
```

**TOTP / 2FA.** A two-factor entry is stored as a canonical `otpauth://totp/…`
URI. Add one by feeding either the URI or just the **base32 seed** (the secret
behind a service's QR code) to `otp-add`; `otp` prints the current code:

```bash
printf '%s' 'JBSWY3DPEHPK3PXP'        | simple-secrets otp-add github-2fa   # bare seed
printf '%s' 'otpauth://totp/ACME:me?secret=JBSWY3DPEHPK3PXP&issuer=ACME' \
                                       | simple-secrets otp-add github-2fa   # …or full URI
simple-secrets otp github-2fa         # -> 123456   (countdown on stderr)
```

In the **TUI**, press **`t`** on the Vault tab: enter a name, then paste the URI
or base32 seed (masked). The Details pane then shows the live code + countdown.

**How to match a service exactly.** A code is reproducible only if every input
matches the service's:
- **Seed** — the exact base32 secret from the service's QR / "manual entry" screen.
- **Parameters** — `digits` (default **6**), `period` (default **30 s**), and
  `algorithm` (default **HMAC-SHA1**). These are what Google Authenticator / Authy
  use almost universally; SHA256/SHA512 and other digit/period values are
  supported if the service specifies them (carried in the `otpauth://` URI).
- **Clock, not timezone.** TOTP is computed from **Unix time — seconds since
  1970 UTC** — as `counter = floor(unixtime / period)`. It is therefore
  **timezone-independent**: a correct code is identical on every device regardless
  of local TZ. What *does* matter is the **device clock**: it must be accurate to
  within the 30-second window, so keep system time synced (NTP). A clock that is
  off by more than ~30 s will produce codes the service rejects — that, not the
  timezone, is the usual cause of "my code doesn't work."

So: same seed + SHA1/6/30 + an accurate clock ⇒ the same codes as the service's
own app, on any machine.

**Threshold sharing.** Split a stored secret into *N* custodian files such that
any *threshold* of them reconstruct it (k-of-n), and recombine them later —
`reconstruct` runs **offline** (no vault, no agent needed):

```bash
simple-secrets share db-master --threshold 2 --shares 3 --out ./shares
#   -> ./shares/db-master.share1.txt … share3.txt  (one per custodian, mode 0600)
simple-secrets reconstruct shares/db-master.share1.txt shares/db-master.share3.txt
#   -> prints the secret; or add --into NAME to store it back in the vault
```

Each share file is self-contained (its own custodian key, encrypted Shamir
share, and all commitments). They are **sensitive**: possessing any `threshold`
files recovers the secret, so distribute one per custodian and keep them secret.
The scheme is integrity-checked (a sub-threshold or inconsistent set is rejected,
never silently wrong) but not dealer-authenticated — see `sharing::multisig`.

**Device pairing.** Move a secret to another device using a post-quantum
(ML-KEM-768) handshake. The pairing code is an ML-KEM public key (~1.5 KB), and
it is **ephemeral** — a fresh one per `pair-receive`, used once.

*Over the local network* (recommended — both devices on the same LAN):

```bash
# RECEIVER — listen; the printed code embeds this device's ip:port:
simple-secrets pair-receive --listen                 # add --into NAME to rename on arrival
# SENDER — connect to that code and push the secret:
simple-secrets pair-send db-master --to-file code.txt   # or --to '<the code>'
#   -> the secret is transferred over TCP; both sides print "received/sent".
```

*Without a network* (manual handoff — the code/bundle are too long to retype, so
move them as a file or QR):

```bash
simple-secrets pair-receive --code-out code.txt          # share code.txt (or add --qr)
simple-secrets pair-send db --to-file code.txt --bundle-out bundle.txt
simple-secrets pair-receive --bundle-in bundle.txt       # import the returned bundle
```

In the **TUI Network tab**: `w` writes the code to `./pairing-code.txt`, `q`
shows a full-screen QR (zoom out if it's clipped), `r` imports a bundle saved as
`./pairing-bundle.txt`. (For a live LAN transfer, use the CLI `--listen` form.)

> **Verify the code (anti-MitM).** Both ends print a 64-bit **verification code**
> (e.g. `4D6C-5745-DAA7-0260`), and the receiver **prompts you to confirm it
> matches the sender's before storing**. A bare key exchange can be intercepted
> by an active man-in-the-middle; comparing this code **out of band** (read it
> aloud, in person) detects that — if they differ, answer `n` and it is
> discarded. For non-interactive/automated use, `pair-receive --yes` skips the
> prompt (this **bypasses MitM protection** — only use it on a trusted path). The
> receiver also **refuses to overwrite** an existing secret (use `--into <name>`).

The secret is encapsulated under the receiver's ML-KEM-768 public key and sealed
with the resulting shared key, so a bundle is useless to anyone but the intended
receiver. *Carrying these codes automatically over Tor/I2P (off-LAN, no VPN) is
planned — see `TODOs.md`.*

**How it works.** `signin` prompts for the passphrase, spawns a detached agent
that opens the vault and holds the master key **in memory only** (mlock'd,
zeroized on drop — never written to disk), and prints an
`export SIMPLE_SECRETS_SESSION=<token>` line. The `eval` installs that token in
your shell; each later command sends the token to the agent over a per-user Unix
socket, which the agent verifies in constant time. The agent locks itself and
exits on `signout` or after **30 minutes idle**.

**Environment & files.**
- `SIMPLE_SECRETS_SESSION` — session token, set by `eval "$(… signin)"`. `signout`
  ends the session; afterwards run `unset SIMPLE_SECRETS_SESSION`.
- `SIMPLE_SECRETS_VAULT` — override the vault path (default
  `$XDG_DATA_HOME/simple-secrets/vault.bin`, else
  `~/.local/share/simple-secrets/vault.bin`).
- The agent socket lives under `$XDG_RUNTIME_DIR/simple-secrets/` (else a
  uid-scoped directory under `$TMPDIR`), created `0700` with the socket `0600`.
- `get` appends a trailing newline for terminal friendliness; `put` reading from
  stdin strips a single trailing newline.

**Security notes.** The session token is visible to your own processes via the
environment, the same trust boundary as `op`'s session tokens. The CLI is
strictly local — it never opens a network connection.

## Navigating the Interface

The TUI opens the **same persistent vault** as the CLI (`$SIMPLE_SECRETS_VAULT`,
default `~/.local/share/simple-secrets/vault.bin`). On first run it prompts you to
**create** the vault (passphrase entered twice); thereafter it prompts to
**unlock** it. Two tabs — **Vault** and **Network** — switched with **Tab /
Shift+Tab**; press **Esc** to quit (or to cancel a prompt). The bottom bar always
shows the keys available in context.

### 1. Vault (full CRUD)
The real, unlocked vault — protected by Argon2id key derivation and per-entry
XChaCha20-Poly1305 encryption. The left pane lists your stored secret names; the
right pane shows details for the selected one.
- **↑/↓** select · **a** add · **t** add a TOTP/2FA · **e** edit · **d** delete
  (then **y** to confirm).
- **a**/**e** open a **modal value editor** (not a separate tab). **Ctrl-S**
  saves, **Esc** cancels, and **Ctrl-G** opens a **generator you control** —
  press **w** for passphrase *words* or **c** for random *characters*, type the
  **length**, then **Enter**. (No more silently-six-word default.)
- A TOTP entry (an explicit `otpauth://` value — see **TOTP / 2FA** above) shows
  the **live 2FA code + countdown**; ordinary values are never guessed as codes.
- Values are **masked** by default; **s** reveals the selected one for ~10 s,
  **c** copies it to the clipboard (auto-cleared after 15 s).
- **Lock-down:** **Ctrl-L** locks instantly (back to the passphrase prompt,
  master key zeroized); the vault also **auto-locks after 5 minutes idle**
  (`SIMPLE_SECRETS_TUI_IDLE=<seconds>`, `0` disables). Unsaved edits are discarded.

The editing buffer lives in **secure memory** (`rust-secure-memory`'s
`LockedBuffer`): mlock'd so it is never swapped to disk, and zeroized on save,
cancel, and drop — the only transient plaintext is what's drawn on screen.

This is a self-contained encrypted file vault that does **not** use any OS
keychain. The vault **file format is portable** (it carries its own salt + KDF
parameters), but the **application currently runs on Linux and macOS only** — the
agent uses Unix domain sockets, the passphrase prompt reads `/dev/tty`, and
memory is `mlock`'d via POSIX APIs; a Windows port would need named pipes and the
Win32 equivalents. (The TUI is its own session, independent of the CLI's
background agent; the vault file is written atomically, so concurrent edits are
last-writer-wins.)

### 2. Network & Pairing
Shows this device's real **pairing code** and its **verification code**. Press
**w** to write the code to `./pairing-code.txt`, **q** for a scannable QR, **r**
to import a bundle saved as `./pairing-bundle.txt`. To *send*, use
`simple-secrets pair-send`; for a live LAN transfer use `pair-receive --listen`
(above). *Deferred (`TODOs.md`):* carrying the codes automatically over Tor/I2P.

## Security Properties (Implemented in the Core Library)

> See **`SECURITY.md`** for the full threat model — what this protects against
> (offline attack, quantum harvest-now-decrypt-later, pairing MitM if you verify
> the code) and, just as importantly, what it does **not** (malware on an unlocked
> box, a wrong device clock, screen/clipboard exposure, skipped verification).


- **Threshold Sharing**: Splitting a secret into 5 shares with a threshold of 3 uses GF(2^8) polynomial interpolation so that any 3 shares reconstruct the secret while fewer than 3 reveal nothing about it. Each share is bound by a SHA-512 commitment to detect tampering on reconstruction.
- **Post-Quantum Key Exchange**: Secret transfer between devices uses ML-KEM-768 key encapsulation; authentication uses ML-DSA-65 signatures.
- **Memory Hygiene**: Derived key material and intermediate buffers are wiped with `zeroize`, and in-RAM secrets live in `LockedBuffer`s from `rust-secure-memory`.
