# Brutal Code Review — simple-secrets

Scope: the whole crate. The verdict is blunt on purpose. The cryptographic
*primitives* are reasonable; the *product* around them is still largely
scaffolding, but the dangerous correctness/secrecy bugs have now been closed.

Legend: **[FIXED]** addressed · **[OPEN]** flagged, see `PLAN.md`.

## Round 1 — CI / docs / hygiene (all fixed)

- **[FIXED]** Master key left in cleartext on the stack in `derive_key` (the `okm`
  array and `okm_vec`/`vdf_output` were never wiped). All KDF intermediates are
  now `zeroize`d.
- **[FIXED]** `cargo run` could not work — no binary target. Added `src/main.rs`.
- **[FIXED]** CI never actually passed: ~14 `clippy -D warnings` lints. All fixed
  with real changes, no `#[allow]`s.
- **[FIXED]** `ci.sh` aborted when the Android NDK was absent. Mobile cross-checks
  are now toolchain-aware and non-fatal; host gates stay hard.
- **[FIXED]** Zero tests. Added unit tests for the security-critical core.
- **[FIXED]** Docs overstated reality (nonexistent `SecretManager::load_vault`,
  TUI/Tor described as functional). Rewritten and status-tagged.

## Round 2 — correctness & secrecy (all fixed)

- **[FIXED] Silent sub-threshold reconstruction (the headline bug).**
  `shamir::reconstruct` cannot know the threshold and would return *wrong* bytes
  for fewer-than-`m` shares; `multisig` did not catch it because per-share
  commitments verify each share individually with no commitment to the secret.
  **Fix:** `multisig::split_secret` now appends a domain-separated SHA-512
  integrity tag *inside* the shared payload (`secret || tag`), and
  `reconstruct_secret` recomputes and constant-time-compares it after
  interpolation. A reconstruction from too few or inconsistent shares now returns
  an explicit `"integrity check failed"` error instead of garbage. Because the
  tag is part of the Shamir sharing, holders of fewer than `m` shares learn
  nothing about it and cannot forge it. Regression test:
  `fewer_than_threshold_is_rejected_not_silently_wrong`.

- **[FIXED] Vault was not self-describing (lose salt → lose vault).** `LocalStore`
  now writes an authenticated header (`magic | version | salt | Argon2 params |
  iteration count`) ahead of the AEAD ciphertext, binds the header in as
  associated data (no parameter downgrade), and `open` reads everything it needs
  from the file — only the passphrase is required.

- **[FIXED] `LocalStore::create` clobbered existing files.** It now refuses to
  overwrite an existing path.

- **[FIXED] Plaintext not zeroized in storage.** `save`/`open` now zeroize the
  serialized payload buffers after use.

- **[FIXED] "VDF" misnomer.** Documented honestly across code and manuals: the
  middle KDF step is a tunable *sequential SHA-512 iteration* (a wall-clock cost
  knob), not a Verifiable Delay Function.

- **[FIXED] Lean model contradicted the code.** The old `PerfectSecrecy` asserted
  `reconstruct = none` for `< k` shares, which the bare Shamir math does not give.
  Split into `SubThresholdRejected` (now true of the multisig API thanks to the
  integrity tag) and an information-theoretic `PerfectSecrecy` over a subset view.

- **[FIXED] TUI double key-dispatch.** On the Editor tab the arrow keys both moved
  the cursor and switched tabs. Tab navigation moved to `Tab`/`BackTab` (arrows
  still switch tabs off the Editor); the `unreachable!()` tab arm degrades to a
  no-op.

## Still open — design decisions (tracked in `PLAN.md`)

- **[OPEN] Non-constant-time field arithmetic.** `gf_mul`/`gf_inv` branch on
  secret-derived values. Move to constant-time GF(2^8) ops.
- **[OPEN] FFI exports nothing useful.** Both entrypoints are empty no-ops.
- **[OPEN] No overlay transport.** LAN TCP + copy/paste pairing exist; `tor_i2p.rs`
  is a stub and `simple-network` is unused by `network::*`. (See `DEPENDENCY_REVIEW.md`.)
- **[OPEN] Formal proofs absent.** `lean/Security.lean` states properties but the
  scheme-level theorems remain `sorry`. `lakefile.toml` exists; CI builds Lean when
  `lake` is installed.
- **[OPEN] Dependency risk: `tui::CodeEditor`.** Per `DEPENDENCY_REVIEW.md` it is
  write-only (no read-back) and stores content in un-zeroized `String`s — it must
  never hold a real secret until a secure-buffer-backed editor exists.

## Bottom line

The math core (Shamir + integrity tag, KDF pipeline, PQC wrappers) is now tested,
CI-clean, and free of the silent-wrong-answer and lose-your-vault failure modes.
The vault/TUI/CLI agent are wired. What remains is FFI, overlay transport, and
the hardening items above — laid out in `PLAN.md`.
