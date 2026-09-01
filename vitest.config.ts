import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    // Seeding a demo world runs dozens of real Schnorr proofs, and the scenario
    // suite seeds one per assertion. That is genuinely slow rather than hung —
    // ~20s on an idle machine, but minutes on a loaded one, so the ceiling is
    // set for the loaded case rather than letting contention read as a failure.
    testTimeout: 300_000,
    hookTimeout: 300_000,
  },
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
});
