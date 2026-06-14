# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-14

### Added

- **EVM** validation: EIP-55 checksum, EIP-1191 (chain-id aware) via
  `checksumEvm`, all-one-case detection (`evm-no-checksum`, medium), and
  zero/burn-address flagging (high).
- **Solana** validation: base58 → 32 bytes, ed25519 on-curve vs off-curve (PDA)
  detection, and known program/system address flagging (high).
- **TRON** validation: real base58check (version `0x41` + double-SHA256
  checksum), hex form, and hex↔base58 cross-validation.
- **Transfer-safety layer**: network mismatch detection, `compareAddresses`
  (edit distance + prefix/suffix match → poisoning risk), fail-closed input
  scrubbing (rejects zero-width / bidi / homoglyph characters), and
  `assertSafeTransfer` with clipboard-hijack (`expectedAddress`) and optional
  on-chain is-contract (`rpcUrl`) checks.
- Structured `AddressResult` with `risk` + `warnings`; functions never throw
  except `assertSafeTransfer` (on high risk).
- Rust core compiled to **Node (napi-rs)** and **browser (WebAssembly)**; dual
  ESM + CJS with generated TypeScript declarations.
- CI (Rust fmt/clippy/tests + Node×WASM matrix) and a release pipeline with
  multi-platform prebuilds, npm provenance, and cosign-signed binaries.

[0.1.0]: https://github.com/cjmont/address-guard/releases/tag/v0.1.0
