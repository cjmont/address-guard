# address-guard

> Fast, **safety-first** address validation for **EVM, Solana and TRON**.
> Not just "is this address valid?" but **"is it safe to send funds here?"**.
> Rust core, compiled to native (Node) and WebAssembly (browser/wallets).

`address-guard` never returns a bare boolean for anything risky. Every check
returns a structured result with a **risk level** and a list of **warnings**, and
it **fails closed**: when in doubt, it raises risk instead of approving.

## Install

```bash
npm install address-guard
```

Prebuilt native binaries ship for Linux (x64/arm64), macOS (x64/arm64) and
Windows (x64) — **`npm install` never compiles anything**. A WebAssembly build is
included for browsers/wallets.

## Quickstart

```js
import { validate, isValid, assertSafeTransfer } from "address-guard";

// Structured result with risk + warnings (never throws)
const r = validate("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
// { valid: true, format: "evm", normalized: "0x5aAeb…", networks: ["ethereum", …],
//   risk: "none", warnings: [] }

// Simple boolean (false if there are high-severity warnings)
isValid("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "ethereum"); // false — network mismatch

// Guard a transfer: throws AddressGuardError when risk is "high"
await assertSafeTransfer(recipient, {
  network: "ethereum",
  expectedAddress, // optional: defends against clipboard-hijack / poisoning
  rpcUrl,          // optional: on-chain is-contract check
});
```

## Safety measures

| Area | What it catches |
| --- | --- |
| **EVM** | EIP-55 checksum; EIP-1191 (chain-id aware) via `checksumEvm(addr, chainId)`; all-one-case → `evm-no-checksum` (medium, no typo protection); zero address & known burn (`0x…dEaD`) → high |
| **Solana** | base58 decoded to exactly 32 bytes; ed25519 **on-curve vs off-curve** (off-curve = PDA → medium); known program/system addresses (System, Token, Token-2022, ATA, Incinerator) → high |
| **TRON** | real base58check (version `0x41` + double-SHA256 checksum); hex (`41…`) and base58 (`T…`) **cross-validated**; wrong version byte / bad checksum rejected |
| **Network mismatch** | format detected ≠ requested `network` → high (e.g. a `T…` address when `network: "ethereum"`) |
| **Address poisoning** | `compareAddresses(a, b)` → edit distance + prefix/suffix match; `poisoningRisk: "high"` when both ends match but the addresses differ |
| **Clipboard hijack** | `assertSafeTransfer(..., { expectedAddress })` compares the **full** string; any difference → high |
| **Invisible / confusable input** | fail-closed scrub: zero-width chars, bidi controls and unicode homoglyphs are **rejected** (addresses must be pure ASCII); surrounding whitespace is trimmed |
| **Contract destination** | `assertSafeTransfer(..., { rpcUrl })` flags sending to a contract (EVM `eth_getCode`) → high |

## Safe transfer before sending

```js
import { assertSafeTransfer, AddressGuardError } from "address-guard";

try {
  const report = await assertSafeTransfer(userInput, {
    network: "ethereum",
    expectedAddress: addressFromAddressBook, // clipboard-hijack / poisoning defense
    rpcUrl: "https://eth.llamarpc.com",      // optional on-chain is-contract check
  });
  // safe to proceed; report.warnings may still contain low/medium notes
  send(report.normalized);
} catch (e) {
  if (e instanceof AddressGuardError) {
    // risk === "high" — block the transfer and show e.result.warnings
    console.error("Unsafe:", e.result.warnings.map((w) => w.code));
  }
}
```

## API

```ts
validate(address: string, opts?: { network?: Network }): AddressResult
isValid(address: string, network: Network): boolean
detectNetworks(address: string): Network[]
checksumEvm(address: string, chainId?: number): string   // EIP-55 / EIP-1191
compareAddresses(a: string, b: string): Comparison
assertSafeTransfer(address: string, opts: {
  network: Network
  expectedAddress?: string
  rpcUrl?: string
}): Promise<AddressResult>   // throws AddressGuardError if risk === "high"
```

`validate` and friends **never throw**; only `assertSafeTransfer` throws (on high
risk). All functions accept `string` and return fully-typed results.

## Browser / WASM

```js
import { init, validate } from "address-guard/browser";

await init();                 // load the WASM module once
validate("0x…");              // same API as Node
```

## Networks & types

`Network = 'ethereum' | 'evm' | 'polygon' | 'bsc' | 'avalanche' | 'arbitrum' | 'optimism' | 'base' | 'solana' | 'tron'`
`Risk = 'none' | 'low' | 'medium' | 'high'`

See [SECURITY.md](https://github.com/cjmont/address-guard/blob/main/SECURITY.md)
for the full warning taxonomy.

## License

[Apache-2.0](https://github.com/cjmont/address-guard/blob/main/LICENSE)
