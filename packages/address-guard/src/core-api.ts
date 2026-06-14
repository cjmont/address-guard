/** Shared API built on top of the native (napi or wasm) JSON-returning core. */

import {
  AddressGuardError,
  type AddressResult,
  type Comparison,
  type Network,
  type Risk,
  type AssertSafeTransferOptions,
} from "./types.js";

/** The low-level binding surface implemented by both napi and wasm. */
export interface Native {
  validate(address: string): string;
  validateForNetwork(address: string, network: string): string;
  detectNetworks(address: string): string;
  checksumEvm(address: string, chainId?: number): string;
  compareAddresses(a: string, b: string): string;
  isValid(address: string, network: string): boolean;
}

const RISK_ORDER: Record<Risk, number> = { none: 0, low: 1, medium: 2, high: 3 };

function maxRisk(warnings: { severity: Risk }[]): Risk {
  let r: Risk = "none";
  for (const w of warnings) {
    if (RISK_ORDER[w.severity] > RISK_ORDER[r]) r = w.severity;
  }
  return r;
}

const EVM_NETWORKS: Network[] = [
  "ethereum",
  "evm",
  "polygon",
  "bsc",
  "avalanche",
  "arbitrum",
  "optimism",
  "base",
];

async function isContract(
  address: string,
  network: Network,
  rpcUrl: string,
): Promise<boolean> {
  // EVM only: eth_getCode returns "0x" for externally-owned accounts.
  if (!EVM_NETWORKS.includes(network)) return false;
  const res = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "eth_getCode",
      params: [address, "latest"],
    }),
  });
  const data = (await res.json()) as { result?: string };
  return (
    typeof data.result === "string" &&
    data.result !== "0x" &&
    data.result !== "0x0"
  );
}

export function createApi(native: Native) {
  function validate(
    address: string,
    opts?: { network?: Network },
  ): AddressResult {
    const json = opts?.network
      ? native.validateForNetwork(address, opts.network)
      : native.validate(address);
    return JSON.parse(json) as AddressResult;
  }

  function isValid(address: string, network: Network): boolean {
    return native.isValid(address, network);
  }

  function detectNetworks(address: string): Network[] {
    return JSON.parse(native.detectNetworks(address)) as Network[];
  }

  function checksumEvm(address: string, chainId?: number): string {
    return native.checksumEvm(address, chainId);
  }

  function compareAddresses(a: string, b: string): Comparison {
    return JSON.parse(native.compareAddresses(a, b)) as Comparison;
  }

  async function assertSafeTransfer(
    address: string,
    opts: AssertSafeTransferOptions,
  ): Promise<AddressResult> {
    const result = validate(address, { network: opts.network });

    // Clipboard-hijack / poisoning defense: compare against the expected one.
    if (opts.expectedAddress) {
      const cmp = compareAddresses(address, opts.expectedAddress);
      if (!cmp.equal) {
        result.warnings.push({
          code: "EXPECTED_MISMATCH",
          message:
            "address does not match the expected address (possible clipboard hijack)",
          severity: "high",
        });
        if (cmp.poisoningRisk === "high") {
          result.warnings.push({
            code: "ADDRESS_POISONING",
            message:
              "address shares both ends with the expected address but differs — likely poisoning",
            severity: "high",
          });
        }
      }
    }

    // Optional on-chain is-contract check.
    if (opts.rpcUrl) {
      try {
        if (await isContract(address, opts.network, opts.rpcUrl)) {
          result.warnings.push({
            code: "IS_CONTRACT",
            message:
              "destination is a contract; sending tokens to a token contract usually loses them",
            severity: "high",
          });
        }
      } catch {
        result.warnings.push({
          code: "RPC_CHECK_FAILED",
          message: "on-chain is-contract check could not be performed",
          severity: "low",
        });
      }
    }

    result.risk = maxRisk(result.warnings);
    if (result.risk === "high") {
      throw new AddressGuardError(result);
    }
    return result;
  }

  return {
    validate,
    isValid,
    detectNetworks,
    checksumEvm,
    compareAddresses,
    assertSafeTransfer,
  };
}
