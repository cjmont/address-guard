# Security Policy

## Warning taxonomy

`address-guard` returns structured `warnings`, each with a `code`, a `message`
and a `severity` (`low` | `medium` | `high`). The overall `risk` of a result is
the maximum severity among its warnings.

| Code | Severity | Meaning |
| --- | --- | --- |
| `INPUT_NON_ASCII` | high | Non-ASCII / invisible / confusable character (zero-width, bidi, homoglyph) — rejected. |
| `INPUT_INTERNAL_WHITESPACE` | high | Internal whitespace or control character — rejected. |
| `UNRECOGNIZED_FORMAT` | high | Does not match any supported address format. |
| `EVM_CHECKSUM_MISMATCH` | high | Mixed-case EVM address fails its EIP-55/EIP-1191 checksum (likely a typo). |
| `EVM_NO_CHECKSUM` | medium | EVM address is all one case — valid but has no checksum protection. |
| `EVM_ZERO_ADDRESS` | high | The zero address (`0x0…0`). |
| `EVM_BURN_ADDRESS` | high | A known burn address (`0x…dEaD`). |
| `EVM_CHAIN_INFO` | low | Valid on every EVM chain; "valid" ≠ funds safe on this specific chain. |
| `SOLANA_OFF_CURVE_PDA` | medium | Off-curve address (likely a PDA / program address); cannot sign. |
| `SOLANA_KNOWN_PROGRAM` | high | A known program/system address (System, Token, ATA, Incinerator, …). |
| `TRON_CHECKSUM_INVALID` | high | TRON base58check checksum failed (likely a typo). |
| `NETWORK_MISMATCH` | high | Detected format cannot belong to the requested network. |
| `EXPECTED_MISMATCH` | high | Address differs from the provided `expectedAddress` (possible clipboard hijack). |
| `ADDRESS_POISONING` | high | Both ends match the expected address but the address differs. |
| `IS_CONTRACT` | high | Destination is a contract (on-chain `eth_getCode` check). |
| `RPC_CHECK_FAILED` | low | The optional on-chain check could not be performed. |

`validate`, `isValid`, `detectNetworks`, `checksumEvm` and `compareAddresses`
never throw. Only `assertSafeTransfer` throws (`AddressGuardError`) when the
computed `risk` is `high`.

## Input handling

Addresses must be pure ASCII. Any non-ASCII character — including zero-width
characters, bidirectional controls and unicode homoglyphs — is **rejected**
(fail-closed). Leading/trailing ASCII whitespace is trimmed.

## Supported versions

Pre-1.0: security fixes land on the latest published `0.x`.

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.** Report privately via
GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
(the repository's **Security** tab → "Report a vulnerability"), or to the
maintainer (**carlosmontanor** on npm).

Please include a description, reproduction steps or a proof of concept, and the
affected version/platform. Expect acknowledgement within 72 hours and coordinated
disclosure.
