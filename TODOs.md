# TODOs (deferred work)

Tracked-but-not-yet-built items. Each says what it is, why it's deferred, and
what it depends on. See `PLAN.md` for the phased roadmap.

## Tor/I2P-ready networked sharing (PQC, no-VPN)

**Goal:** transfer secrets between devices *automatically over the wire* — local
network and anonymity overlays (Tor / I2P) — with **no VPN requirement** and
post-quantum crypto (ML-KEM-768 key exchange, ML-DSA-65 authentication) end to
end. The user pairs two devices and a secret moves between them without either
device exposing a routable address or relying on a VPN.

**What already exists (so this is transport, not crypto):** the post-quantum
pairing + secret-transfer *crypto* is implemented and used by the manual,
copy/paste pairing flow — `network::pairing` (`PairingSession`,
`generate_encapsulated_secret`) and `network::{prepare,extract}_secret_blob`.
The deferred part is the **network transport** that carries the paircode and the
encrypted bundle automatically instead of by copy/paste.

**Why deferred:** `simple-network`'s transport modules (`cluster`, `quic`,
`port_forward`) are stubs or unsafe, and it has **no** Tor/I2P support (see
`DEPENDENCY_REVIEW.md`). Building this means either fixing/replacing that
transport or integrating an overlay client (e.g. `arti` for Tor) directly behind
a feature flag.

**Depends on:**
- Upstream `simple-network` fixes (H3 replay/directional keys, H4 pairing KDF) —
  or a self-contained transport in this crate.
- An overlay client (Tor via `arti`, and/or I2P) behind a feature flag.

**Acceptance sketch:** two devices on different networks (no shared VPN) complete
a pairing and transfer a secret over Tor/I2P; the wire carries only PQC-encrypted
material; loopback and LAN paths also work; the manuals only claim what ships.

Relates to `PLAN.md` Phase C (Networking), specifically **C2 transport** and
**C3 Tor/I2P**.

## Other deferred items (large or external — no small fix)

These are tracked so "outstanding work" is explicit, not implicit. The high-ROI
small fixes (durable zeroization, LAN receive deadline, IPv6 probe, doc honesty)
are **done**; the items below are genuinely large or out of a coding session's
scope.

- **Self-contained build + cloud CI.** The crate has path deps on sibling repos
  (`../rust-secure-memory`, `../simple-network`), so a clean clone can't
  build. By project preference we keep the local **`ci.sh`** as the gate (no
  GitHub Actions). Making it self-contained (git submodules or vendoring) is a
  prerequisite for any cloud CI and for external contributors; deferred pending a
  decision on the sibling repos.
- **iOS/Android FFI.** `src/ffi/` is ~16 lines of scaffolding. A real C ABI
  (`init`/`create`/`open`/`get`/`set`, status codes, length-delimited buffers) +
  JNI + a `cbindgen` header + per-platform smoke tests are needed; requires device
  toolchains. (`PLAN.md` Phase E.)
- **Windows port.** The vault file format is portable, but the agent (Unix
  sockets), passphrase prompt (`/dev/tty`), and `mlock`/`setsid`/`dup2` are POSIX;
  Windows needs named pipes and Win32 equivalents.
- **Duress / decoy vault** (plausible deniability) — needs a dual-vault or
  hidden-volume design.
- **Commit-reveal pairing handshake** — would let the verification code shrink
  from 64 bits to a short human code; a real protocol change.
- **`dudect`-style timing verification** of the GF(2⁸) arithmetic (the code is
  already branchless-by-construction; this would *measure* it).
- **Fuzzing** the parsers (bundle / wire-protocol / `otpauth://` / base32 /
  vault-file) — add a `cargo-fuzz` harness; running it is ongoing.
- **External security audit.** Research-grade today; an independent review is
  required before any "trust me with your keys" claim.
- **Constant-time field arithmetic audit & KDF calibration** (`PLAN.md` A1/A3).
- **Persistent secret *type* metadata** — today "type" is creation-time UX; real
  typing needs a `SecretEntry` schema field. **mDNS/`.local` discovery** so LAN
  pairing needs no copied `ip:port` code.

## Platform CI

- [x] Run tests and CI on **linux/arm64** and **linux/amd64** via Docker on Mac
  (QEMU for amd64).
