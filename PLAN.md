# simple-secrets — Implementation Plan

This plan turns the tested cryptographic core into a working product. It is
ordered by dependency and risk: security hardening first, then the facade that
ties primitives together, then the user-facing surfaces. Each item lists intent,
the concrete change, and how it will be verified.

Status of the foundations (done): Argon2id + sequential-hash KDF with full
zeroization, GF(2^8) Shamir sharing with an **authenticated** multisig layer
(sub-threshold reconstruction is now rejected, not silently wrong), a
self-describing AEAD vault, ML-KEM-768 / ML-DSA-65 wrappers, and a green
`ci.sh` (fmt + clippy `-D warnings` + tests). See `CODE_REVIEW.md`.

---

## Phase A — Cryptographic hardening (highest priority)

**A1. Constant-time field arithmetic.**
`gf_mul`/`gf_inv` (`src/sharing/shamir.rs`) branch and loop on secret bytes.
Replace with constant-time implementations (branchless `gf_mul`, masked
conditional reductions; `gf_inv` already uses exponentiation — keep but ensure
the multiply is CT). Verify: existing round-trip tests plus a `dudect`-style or
manual timing-invariance check; confirm output equivalence against the current
impl for all 256×256 products.

**A2. Optional per-share authentication upgrade.**
The integrity tag protects the *secret*; consider a per-share MAC keyed from the
custodian key (in addition to the SHA-512 commitment) so a custodian cannot be
handed a share that decrypts but was authored by someone else. Verify: tamper
tests extended to cross-custodian substitution.

**A3. KDF calibration wiring.**
`vdf_calibrate`/`vdf_eval` are currently unused by `derive_key`. Either wire
`derive_key`'s sequential step through `vdf_eval` (single source of truth) or
expose calibration in the manager so a target wall-clock cost picks the iteration
count. Verify: a test that `vdf_calibrate(target)` produces an iteration count
whose measured cost is within a tolerance band.

---

## Phase B — Make `SecretManager` the real facade

Today `SecretManager` only funnels entropy. Grow it into the owner of the vault
and sharing lifecycle so embedders have one type to hold.

**B1. Vault lifecycle.** `SecretManager::create_vault/open_vault/lock` wrapping
`LocalStore`, generating the salt from the manager's `EntropySource`, and holding
the open store. Per-entry value encryption (so `LocalStore` blobs are real
ciphertext, not caller-supplied) lives here.

**B2. Passphrase generation.** Implement the SPEC's BIP-39-style 20/40-word
passphrase proposal, drawing from the `EntropySource`. Verify: entropy-count test
and round-trip (propose → derive → open).

**B3. Sharing API.** `SecretManager::share_secret(name, m, n, custodians)` and
`reconstruct(...)` delegating to `sharing::multisig`. Verify: end-to-end test
from stored secret → shares → reconstruct.

**B4. RAM-only secrets.** Surface `RamStore` through the manager for
load-to-RAM / pipe-to-env scenarios from SPECS.

---

## Phase C — Networking (depends on `simple-network`)

`DEPENDENCY_REVIEW.md` concludes that only `simple-network::security::pqc` is
trustworthy; `cluster.rs`/`pairing.rs`/`quic.rs` are stubs or actively
misleading, and Tor/I2P do **not** exist there.

**C1. Pairing on the vetted path.** Build device pairing on
`simple_network::security::pqc` (`Identity` + `pair_exchange` + pinned
`Initiator`/`Responder`), **after** upstream fixes for replay/directional keys
(their H3) and KDF strength (their H4) — file those as upstream issues. Wire
`network::pairing::PairingSession` to it. Verify: two in-process managers complete
a pairing and transfer a secret blob.

**C2. Transport.** Use `simple_network` TCP for the local-network case. Do **not**
consume their `cluster`/`pairing`/`quic` modules. Verify: loopback transfer test.

**C3. Tor/I2P.** Not present in `simple-network`. Either integrate `arti` (Tor)
directly here behind a feature flag, or descope it explicitly in SPECS. Until
then, the manuals must not claim it (they no longer do). Tracked in `TODOs.md`
("Tor/I2P-ready networked sharing") — the PQC pairing/transfer *crypto* already
ships via the manual copy/paste pairing flow; only the automatic transport is
deferred.

---

## Phase D — TUI wired to the core

`DEPENDENCY_REVIEW.md` flags two blockers in the consumed `tui::CodeEditor`:
it is **write-only** (no `lines()`/`text()` accessor) and stores content in
un-zeroized `String`s.

**D1. Upstream the editor fixes** (or vendor a minimal secure editor): add a
read-back accessor and a secure-buffer backing, or restrict the Editor tab to
non-secret notes until then. Do not place real secret material in `CodeEditor`.

**D2. Bind tabs to the manager.** Vault tab lists real entries from the open
`LocalStore`; Network tab shows the real pairing code from a `PairingSession`;
Editor edits a decrypted-in-RAM value via `RamStore`. Verify: manual run plus a
headless state-transition test of `App`.

**D3. Terminal-restore safety.** Install a panic hook / RAII guard so a panic in
the draw loop restores the terminal (raw mode + alternate screen), mirroring the
gap noted upstream.

---

## Phase E — FFI

**E1. Real C ABI** for iOS: `init`, `create/open vault`, `get/set`, returning
status codes and length-delimited buffers; document ownership/free. **E2. JNI**
equivalents for Android. **E3.** A C header (cbindgen) and a smoke test per
platform in `ci.sh` once toolchains are available.

---

## Phase F — Formal verification

**F1. Add a `lakefile`** and make CI build `lean/Security.lean` (so the model
can't rot). **F2. Prove** `Correctness` and `SubThresholdRejected` for a concrete
GF(2^8) Shamir+tag instantiation; state `PerfectSecrecy` over the real share view
and discharge as far as feasible (`sorry`s tracked, not hidden). **F3.** Model
the KEM correctness property against the actual API shape.

---

## Suggested sequencing

1. **A1** (constant-time) + **B1/B2** (vault facade + passphrase) — these make the
   library genuinely usable and safe to embed.
2. **B3/B4**, then **D2** (wire the TUI) for a demoable end-to-end flow.
3. **C1/C2** networking once upstream `simple-network` issues are addressed.
4. **E** and **F** in parallel as platform/proof toolchains allow.

Every phase keeps `ci.sh` green and adds tests with the change, not after it.
