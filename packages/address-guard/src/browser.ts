/**
 * address-guard (browser/WASM entry).
 *
 * WebAssembly must be initialized before use:
 *
 * ```js
 * import { init, validate } from "address-guard/browser";
 * await init();
 * validate("0x…");
 * ```
 */
import initWasm, * as wasm from "../wasm/address-guard.js";
import { createApi, type Native } from "./core-api.js";

export * from "./types.js";

type Api = ReturnType<typeof createApi>;
let api: Api | null = null;

/** Load and initialize the WASM module. Call once before using the API.
 *  `source` may be a URL/path, a `Response`, a `WebAssembly.Module`, or the
 *  wasm bytes; omit it to fetch the default `.wasm` next to this module. */
export async function init(
  source?: string | URL | Response | WebAssembly.Module | BufferSource,
): Promise<void> {
  await initWasm(source === undefined ? undefined : { module_or_path: source });
  api = createApi(wasm as unknown as Native);
}

function ready(): Api {
  if (!api) {
    throw new Error(
      "address-guard/browser: call await init() before using the API",
    );
  }
  return api;
}

export const validate: Api["validate"] = (...a) => ready().validate(...a);
export const isValid: Api["isValid"] = (...a) => ready().isValid(...a);
export const detectNetworks: Api["detectNetworks"] = (...a) =>
  ready().detectNetworks(...a);
export const checksumEvm: Api["checksumEvm"] = (...a) =>
  ready().checksumEvm(...a);
export const compareAddresses: Api["compareAddresses"] = (...a) =>
  ready().compareAddresses(...a);
export const assertSafeTransfer: Api["assertSafeTransfer"] = (...a) =>
  ready().assertSafeTransfer(...a);
