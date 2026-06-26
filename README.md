<p align="center">
  <img src="assets/logo.svg" alt="simple-secrets" width="150"/>
</p>

<h1 align="center">simple-secrets</h1>

<p align="center">
  <strong>A post-quantum secret manager built on advanced secret sharing.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/part%20of-simple%20tools-00d4ff.svg" alt="part of simple tools">
  <img src="https://img.shields.io/badge/Rust-2021-orange.svg?logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/status-released-success.svg" alt="released">
  <img src="https://img.shields.io/badge/crypto-post--quantum-purple.svg" alt="post-quantum">
  <img src="https://img.shields.io/badge/secret-sharing-blueviolet.svg" alt="secret sharing">
  <img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg" alt="license">
</p>

> Part of [**simple tools**](https://zeta1999.github.io/renoir42/simple-tools.html) — small, composable Rust libraries for building tooling fast from a harness.

---

## What it does

- **Secret sharing** — split secrets across shares so no single holder can recover them.
- **Post-quantum at rest and on the wire** — built on [`rust-secure-memory`](https://github.com/zeta1999/rust-secure-memory-public) (secure allocation, zeroize) and [`simple-network`](https://github.com/zeta1999/simple-network-public) (PQC secure channel) for pairing and transport.
- **TOTP** — import or mint fresh TOTP secrets.
- **A TUI** (ratatui) and QR support for pairing flows.

Standard primitives throughout: Argon2, HKDF, AES-GCM, SHA-2.

## Threat model

The threat model is written down — see [`SECURITY.md`](SECURITY.md). Read it before trusting this with anything that matters.

## Build

```sh
cargo build
```

## Dependencies

Links its `-public` siblings: [`rust-secure-memory-public`](https://github.com/zeta1999/rust-secure-memory-public) and [`simple-network-public`](https://github.com/zeta1999/simple-network-public).

## License

MIT OR Apache-2.0
