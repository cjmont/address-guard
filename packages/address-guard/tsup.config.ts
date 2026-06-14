import { defineConfig } from "tsup";

export default defineConfig([
  {
    // Node entry (napi). Dual ESM + CJS. The native loader stays external.
    entry: { index: "src/index.ts" },
    format: ["esm", "cjs"],
    outExtension({ format }) {
      return { js: format === "esm" ? ".mjs" : ".cjs" };
    },
    dts: true,
    sourcemap: true,
    clean: true,
    external: ["../binding.js"],
  },
  {
    // Browser entry (WASM). ESM only; the wasm glue stays external.
    entry: { browser: "src/browser.ts" },
    format: ["esm"],
    outExtension() {
      return { js: ".mjs" };
    },
    dts: true,
    sourcemap: true,
    clean: false,
    external: ["../wasm/address-guard.js"],
  },
]);
