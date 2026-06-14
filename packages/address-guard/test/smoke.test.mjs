import test from "node:test";
import assert from "node:assert/strict";

import {
  validate,
  isValid,
  detectNetworks,
  checksumEvm,
  compareAddresses,
  assertSafeTransfer,
  AddressGuardError,
} from "../dist/index.mjs";

const EVM = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
const TRON = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

test("validate EVM returns structured result", () => {
  const r = validate(EVM);
  assert.equal(r.valid, true);
  assert.equal(r.format, "evm");
  assert.equal(r.risk, "none");
  assert.ok(r.networks.includes("ethereum"));
});

test("validate detects TRON", () => {
  const r = validate(TRON);
  assert.equal(r.format, "tron-base58");
  assert.deepEqual(r.networks, ["tron"]);
});

test("checksumEvm normalizes and supports EIP-1191", () => {
  assert.equal(checksumEvm(EVM.toLowerCase()), EVM);
  assert.notEqual(checksumEvm(EVM.toLowerCase(), 30), EVM); // chain-id aware differs
});

test("isValid and detectNetworks", () => {
  assert.equal(isValid(EVM, "ethereum"), true);
  assert.equal(isValid(TRON, "ethereum"), false); // network mismatch
  assert.deepEqual(detectNetworks(TRON), ["tron"]);
});

test("network mismatch raises high", () => {
  const r = validate(TRON, { network: "ethereum" });
  assert.equal(r.risk, "high");
  assert.ok(r.warnings.some((w) => w.code === "NETWORK_MISMATCH"));
});

test("scrub rejects invisible characters", () => {
  const r = validate(EVM + "​");
  assert.equal(r.valid, false);
  assert.ok(r.warnings.some((w) => w.code === "INPUT_NON_ASCII"));
});

test("compareAddresses flags poisoning", () => {
  const a = "0x" + "abcd" + "0".repeat(32) + "abcd";
  const b = "0x" + "abcd" + "1".repeat(32) + "abcd";
  const c = compareAddresses(a, b);
  assert.equal(c.equal, false);
  assert.equal(c.poisoningRisk, "high");
});

test("assertSafeTransfer resolves for a safe transfer", async () => {
  const r = await assertSafeTransfer(EVM, { network: "ethereum" });
  assert.equal(r.valid, true);
});

test("assertSafeTransfer throws on zero address", async () => {
  await assert.rejects(
    () => assertSafeTransfer("0x0000000000000000000000000000000000000000", { network: "ethereum" }),
    AddressGuardError,
  );
});

test("assertSafeTransfer throws on expected-address mismatch", async () => {
  await assert.rejects(
    () => assertSafeTransfer(EVM, { network: "ethereum", expectedAddress: "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359" }),
    AddressGuardError,
  );
});
