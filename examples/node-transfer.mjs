// Example: safe transfer validation in Node.js.
//
// In a real project the import is simply:
//   import { validate, assertSafeTransfer, AddressGuardError } from "address-guard";
// Here we import the locally-built package so the example runs from the repo.
import {
  validate,
  compareAddresses,
  assertSafeTransfer,
  AddressGuardError,
} from "../packages/address-guard/dist/index.mjs";

const recipient = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";

// 1. Structured validation (never throws).
console.log("validate:", validate(recipient));

// 2. Network mismatch is caught: a TRON address requested as ethereum.
console.log(
  "mismatch risk:",
  validate("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", { network: "ethereum" }).risk,
);

// 3. Address poisoning: same first/last chars, different middle.
const a = "0x" + "abcd" + "0".repeat(32) + "abcd";
const b = "0x" + "abcd" + "1".repeat(32) + "abcd";
console.log("poisoning:", compareAddresses(a, b).poisoningRisk);

// 4. Guard a transfer. Throws when risk is high (here: clipboard-hijack —
//    the pasted address differs from the one in the user's address book).
const expectedAddress = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359";
try {
  await assertSafeTransfer(recipient, { network: "ethereum", expectedAddress });
  console.error("FAIL: should have thrown");
  process.exit(1);
} catch (e) {
  if (e instanceof AddressGuardError) {
    console.log(
      "blocked transfer:",
      e.result.warnings.map((w) => w.code).join(", "),
    );
  } else {
    throw e;
  }
}

// 5. A safe transfer resolves with the report.
const report = await assertSafeTransfer(recipient, { network: "ethereum" });
console.log("safe transfer ok, normalized:", report.normalized);
