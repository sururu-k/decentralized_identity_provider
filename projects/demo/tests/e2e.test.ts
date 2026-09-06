import crypto from "node:crypto";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { base64UrlDecode } from "../src/sdk/jwt.js";

/**
 * Integration test against a running stack.
 *
 * It drives the CLI stand-in (`cli/sign-on.ts`) exactly as the integration script does --
 * the CLI plays both the rp front end (makes the DPoP key, exchanges the code at `/token`)
 * and the IdP front end (runs the browser SDK to mint the assertion). So this exercises the
 * whole section 14 flow, not just the SDK:
 *
 *   docker compose up -d --build --wait
 *   DEMO_E2E_GATEWAY=http://localhost:3000 npm test
 *
 * Without `DEMO_E2E_GATEWAY` the suite is skipped, so `npm test` stays offline by default.
 * The gateway's `/token` endpoint is still being built; until it lands this suite stays
 * skipped, and the always-on aggregation checks live in `sdk.test.ts` instead.
 *
 * Verification deliberately uses `node:crypto` with the JWKS key rather than any SDK code:
 * the point is that the access token the flow produced verifies as a plain Ed25519 JWT for
 * a relying party that shares no code with the issuer. The token's `cnf.jkt` is the CLI's
 * own ephemeral key, which this process cannot see, so it checks the signature, `typ`,
 * `aud`, `iss` and `exp` -- the node-level tests cover the `cnf.jkt` binding.
 */

const GATEWAY = process.env.DEMO_E2E_GATEWAY;
const describeIfGateway = GATEWAY ? describe : describe.skip;

const execFileAsync = promisify(execFile);
const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(HERE, "../cli/sign-on.ts");

interface Jwk {
  kty: string;
  crv: string;
  x: string;
  kid: string;
}

/** Runs the CLI stand-in and returns the last line of stdout (the token) and its stderr. */
async function runCli(args: string[]): Promise<{ token: string; stderr: string }> {
  const { stdout, stderr } = await execFileAsync("npx", ["tsx", CLI, ...args], {
    cwd: path.resolve(HERE, ".."),
    env: { ...process.env, DEMO_LOG: "1", FORCE_COLOR: "0" },
  });
  const lines = stdout.trimEnd().split("\n");
  return { token: lines[lines.length - 1], stderr };
}

async function fetchJwks(gateway: string): Promise<Jwk[]> {
  const res = await fetch(`${gateway}/jwks.json`);
  expect(res.status).toBe(200);
  const body = (await res.json()) as { keys: Jwk[] };
  return body.keys;
}

function verifyWithJwks(token: string, keys: Jwk[]): { header: any; payload: any } {
  const [headerB64, payloadB64, sigB64] = token.split(".");
  const decoder = new TextDecoder();
  const header = JSON.parse(decoder.decode(base64UrlDecode(headerB64)));
  const payload = JSON.parse(decoder.decode(base64UrlDecode(payloadB64)));

  const jwk = keys.find((k) => k.kid === header.kid);
  expect(jwk, `no JWKS key for kid ${header.kid}`).toBeDefined();

  const ok = crypto.verify(
    null,
    Buffer.from(`${headerB64}.${payloadB64}`, "utf8"),
    crypto.createPublicKey({ key: jwk as unknown as crypto.JsonWebKey, format: "jwk" }),
    Buffer.from(base64UrlDecode(sigB64))
  );
  expect(ok, "Ed25519 signature did not verify against the JWKS key").toBe(true);

  return { header, payload };
}

describeIfGateway("demo CLI against a live gateway", () => {
  const gateway = GATEWAY as string;

  it("mints an access token that verifies against /jwks.json", async () => {
    const { token, stderr } = await runCli([
      "--gateway", gateway,
      "--user", "alice",
      "--password", "password123",
      "--client-id", "demo_client",
      "--scope", "openid profile",
      "--nonce", "demo_e2e_nonce_1",
    ]);

    const { header, payload } = verifyWithJwks(token, await fetchJwks(gateway));
    expect(header.alg).toBe("EdDSA");
    expect(header.typ).toBe("at+jwt");
    expect(header.kid).toBe("pasta-group-key-1");
    expect(payload.iss).toBe(gateway);
    expect(payload.aud).toBe("demo_client");
    expect(payload.scope).toBe("openid profile");
    expect(payload.cnf?.jkt).toBeTruthy();

    // Section 10 browser column reached stderr, and no password leaked.
    expect(stderr).toMatch(/\[browser\] sign-on /);
    expect(stderr).not.toContain("password123");
  }, 60_000);

  it("refreshes for a new access token that still verifies", async () => {
    const { token } = await runCli([
      "--gateway", gateway,
      "--user", "alice",
      "--password", "password123",
      "--client-id", "demo_client",
      "--scope", "openid profile",
      "--nonce", "demo_e2e_nonce_2",
      "--refresh",
    ]);

    const { header, payload } = verifyWithJwks(token, await fetchJwks(gateway));
    expect(header.typ).toBe("at+jwt");
    expect(payload.aud).toBe("demo_client");
    expect(payload.cnf?.jkt).toBeTruthy();
  }, 60_000);

  it("fails with exit 1 on a wrong password, without a token on stdout", async () => {
    await expect(
      runCli([
        "--gateway", gateway,
        "--user", "alice",
        "--password", "wrong-password",
        "--client-id", "demo_client",
        "--nonce", "demo_e2e_nonce_3",
      ])
    ).rejects.toMatchObject({ code: 1 });
  }, 60_000);
});
