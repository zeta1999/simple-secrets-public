# Security model

An honest statement of what `simple-secrets` protects against and what it does
**not**. A secret manager that overstates its guarantees is worse than one that
is clear about its edges. If you find a gap not listed here, treat it as a bug.

## What it protects against

- **Offline attack on the vault file.** The vault is encrypted with a key derived
  by **Argon2id** (memory-hard) plus a sequential-hash step; each entry is sealed
  with **XChaCha20-Poly1305** under a per-entry key (HKDF-separated from the file
  key). An attacker with the file but not the passphrase faces the full Argon2
  cost per guess.
- **"Harvest now, decrypt later" by a future quantum computer.** Device-to-device
  transfer establishes its key with **ML-KEM-768** (post-quantum KEM); identity/
  signatures use **ML-DSA-65**. Recorded ciphertext is not retroactively broken by
  a quantum adversary.
- **Active man-in-the-middle during pairing — *if you compare the code*.** Pairing
  prints a 64-bit **verification code** (a fingerprint of the receiver's public
  key) that both sides know *before* the secret moves; the sender confirms it
  before sealing/sending and the receiver before storing. A key-substituting MitM
  makes the two codes differ (forging a match is a 2^64 grind). This only works if
  you actually compare them out of band (read aloud / in person).
- **Key material in memory.** Derived keys and in-RAM secrets live in
  `rust-secure-memory` `LockedBuffer`s — mlock'd (never swapped to disk) and
  zeroized on drop; the TUI value editor uses the same. Plaintext buffers are
  zeroized on the error paths too.
- **Unsolicited network traffic.** The tool makes no network connection on its
  own. The background agent is a local Unix socket (per-user, `0700`/`0600`);
  pairing/LAN transfer is explicit and user-initiated.

## What it does NOT protect against

- **Malware or a keylogger on an unlocked machine.** If your OS account is
  compromised while the vault is unlocked (or while you type the passphrase),
  the secrets are exposed. This tool is not a sandbox.
- **A wrong device clock.** TOTP codes are derived from UTC Unix time; a clock off
  by more than the 30-second window produces codes the service rejects. Keep NTP
  on. (Timezone does *not* matter; the clock does.)
- **Shoulder-surfing, screenshots, and the clipboard.** Revealed values and copied
  entries are visible to anyone watching the screen or any process that can read
  the clipboard. Reveal is time-boxed and the clipboard auto-clears (~15 s), but
  these are mitigations, not guarantees — prefer not revealing/copying at all.
- **Skipping verification.** If you do not compare the pairing code out of band,
  or you pass `--yes` / accept without checking, the MitM protection is void.
- **Concurrent writers.** The TUI and the CLI agent are independent sessions; the
  vault file is written atomically, so a crash won't corrupt it, but two writers
  are **last-writer-wins** — a concurrent edit can be lost (not silently merged).
- **Transient plaintext on screen.** Rendering a revealed value or an editor
  buffer necessarily puts that plaintext in a heap string for the duration of the
  frame; the stored vault stays encrypted, but the render copy is not mlock'd.
- **Dealer authentication in threshold sharing.** Share files are integrity-checked
  (a sub-threshold or inconsistent set is rejected, never silently wrong) but not
  signed by the dealer; anyone holding `threshold` files reconstructs the secret.

## Notes on cryptographic hygiene

- **No known-plaintext weakness ("cribs").** Enigma fell in part to predictable
  message structure; modern AEAD (XChaCha20-Poly1305) is IND-CPA, so known or
  guessable plaintext does **not** weaken it. Nonces are random per message, each
  transfer uses a fresh one-time KEM key, and sealed payloads carry no gratuitous
  fixed structure. We state this rather than relying on luck.
- **Key-derivation cost.** Vault unlock is gated by **Argon2id at 256 MiB / 4
  lanes**, which dominates the per-guess cost. The optional sequential-hash step
  (`vdf_iterations`) defaults to **0** on purpose — it adds wall-clock delay but
  no memory-hardness, so it is left off rather than shipped with a guessed value;
  `vdf_calibrate` is provided to tune it to a target if you want the extra delay.
- **Formal model is illustrative, not a proof of the shipped scheme.** The Lean
  model (`lean/`) builds in CI and discharges a worked example, but the
  scheme-level theorems (`Correctness`, `SubThresholdRejected`, `PerfectSecrecy`,
  KEM correctness) are tracked as `sorry` placeholders — **not** machine-checked
  against the Rust implementation. Treat the crypto as *reviewed and tested*, not
  *formally verified*.
- **Deferred work** (see `TODOs.md`): off-LAN networked transfer over Tor/I2P, a
  commit-reveal handshake that would allow a shorter verification code, a
  duress/decoy vault for plausible deniability, iOS/Android FFI, and `dudect`-style
  timing verification of the GF(2⁸) arithmetic.

## Reporting

This is research-grade software. Report security issues privately to the
maintainer rather than opening a public issue with reproduction details.
