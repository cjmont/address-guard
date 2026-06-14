# address-guard

Fast, **safety-first** address validation for **EVM, Solana and TRON** — not just
"is this address valid?" but **"is it safe to send funds here?"**. A Rust core
compiled to both native (Node via napi) and WebAssembly (browser/wallets).

The published package and full documentation live in
[`packages/address-guard`](packages/address-guard/README.md).

## Repository layout

```
address-guard/
├─ crates/
│  ├─ address-guard-core/   # all validation + transfer-safety logic (Rust, tested)
│  ├─ address-guard-napi/   # Node.js binding (napi-rs)
│  └─ address-guard-wasm/   # browser binding (wasm-bindgen)
├─ packages/address-guard/  # npm package (TypeScript, dual ESM/CJS, Node + browser)
├─ examples/                # node-transfer.mjs, browser-wasm/
└─ .github/workflows/       # ci.yml, release.yml
```

## Develop

```bash
cargo test -p address-guard-core          # core logic + adversarial vectors
cd packages/address-guard
npm ci && npm run build && npm test       # napi + wasm + TypeScript + Node tests
```

## Security

`address-guard` fails closed and returns structured risk + warnings. See
[SECURITY.md](SECURITY.md) for the warning taxonomy and reporting policy.

## License

[Apache-2.0](LICENSE)
