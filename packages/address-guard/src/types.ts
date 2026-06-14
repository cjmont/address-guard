/** The public type surface of address-guard (single source of truth). */

export type Network =
  | "ethereum"
  | "evm"
  | "polygon"
  | "bsc"
  | "avalanche"
  | "arbitrum"
  | "optimism"
  | "base"
  | "solana"
  | "tron";

export type Risk = "none" | "low" | "medium" | "high";

export type Format =
  | "evm"
  | "evm-no-checksum"
  | "solana"
  | "tron-base58"
  | "tron-hex";

export interface Warning {
  code: string;
  message: string;
  severity: Risk;
}

export interface AddressResult {
  valid: boolean;
  format: Format | null;
  normalized: string | null;
  /** Networks the address could belong to. */
  networks: Network[];
  risk: Risk;
  warnings: Warning[];
}

export interface Comparison {
  equal: boolean;
  editDistance: number;
  /** Number of identical leading characters. */
  prefixMatch: number;
  /** Number of identical trailing characters. */
  suffixMatch: number;
  /** High when both ends match but the addresses are not equal. */
  poisoningRisk: Risk;
}

export interface AssertSafeTransferOptions {
  network: Network;
  /** If given, the address is compared against it (clipboard-hijack defense). */
  expectedAddress?: string;
  /** Optional JSON-RPC URL for an on-chain is-contract check (EVM). */
  rpcUrl?: string;
}

/** Thrown by `assertSafeTransfer` when the computed risk is `high`. */
export class AddressGuardError extends Error {
  readonly result: AddressResult;
  constructor(result: AddressResult) {
    const codes = result.warnings.map((w) => w.code).join(", ");
    super(`unsafe transfer (risk=${result.risk}): ${codes}`);
    this.name = "AddressGuardError";
    this.result = result;
  }
}
