import { defineConfig } from "vitest/config";

/**
 * The SDK is shared by the browser bundle and the Node CLI stand-in, so the tests run in
 * the Node environment: it is the harsher of the two (no DOM to lean on) and it is what
 * `cli/sign-on.ts` and `scripts/integration-test.sh` actually use.
 */
export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
  },
});
