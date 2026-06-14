/**
 * address-guard (Node.js entry) — safety-first address validation for EVM,
 * Solana and TRON, backed by a Rust core via napi.
 */
import native from "../binding.js";
import { createApi, type Native } from "./core-api.js";

export * from "./types.js";

const api = createApi(native as unknown as Native);

export const validate = api.validate;
export const isValid = api.isValid;
export const detectNetworks = api.detectNetworks;
export const checksumEvm = api.checksumEvm;
export const compareAddresses = api.compareAddresses;
export const assertSafeTransfer = api.assertSafeTransfer;
