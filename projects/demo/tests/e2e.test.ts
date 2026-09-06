import crypto from "node:crypto";
import { describe, expect, it } from "vitest";
import { DecentralizedClientSdk } from "../src/sdk/client.js";
import { CONTINUATION_INDENT, type DemoEvent } from "../src/sdk/events.js";
import { base64UrlDecode } from "../src/sdk/jwt.js";

/**
 * Integration test against a running stack.
 *
 * Standing up three fake nodes plus a gateway inside vitest would duplicate
 * `projects/gateway/tests/`, so this exercises the real thing instead:
 *
 *   docker compose up -d --build --wait
 *   DEMO_E2E_GATEWAY=http://localhost:3000 npm test
 *
 * Without `DEMO_E2E_GATEWAY` the suite is skipped, so `npm test` stays offline by default.
 *
 * Signature verification deliberately uses `node:crypto` with the JWKS key rather than
 * the SDK's own `verifyJwt`: the point is that a token this SDK assembled verifies as a
 * plain Ed25519 JWT for a relying party that shares no code with it.
 */

const GATEWAY = process.env.DEMO_E2E_GATEWAY;
const describeIfGateway = GATEWAY ? describe : describe.skip;

interface Jwk {
  kty: string;
  crv: string;
  x: string;
  kid: string;
}

async function fetchJwks(gateway: string): Promise<Jwk[]> {
  const res = await fetch(`${gateway}/jwks.json`);
  expect(res.status).toBe(200);
  const body = (await res.json()) as { keys: Jwk[] };
  return body.keys;
}

function verifyWithJwks(idToken: string, keys: Jwk[]): { header: any; payload: any } {
  const [headerB64, payloadB64, sigB64] = idToken.split(".");
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

describeIfGateway("demo SDK against a live gateway", () => {
  const gateway = GATEWAY as string;

  it("signs alice on, and the token verifies against /jwks.json", async () => {
    const events: DemoEvent[] = [];
    const sdk = new DecentralizedClientSdk({
      proxyUrl: gateway,
      issuer: gateway,
      onEvent: (e) => events.push(e),
    });

    const { id_token, sessionId } = await sdk.signOn({
      username: "alice",
      password: "password123",
      clientId: "demo_client",
      nonce: "demo_e2e_nonce_1",
    });
    expect(sessionId).toBeTruthy();

    const { header, payload } = verifyWithJwks(id_token, await fetchJwks(gateway));
    expect(header.alg).toBe("EdDSA");
    expect(header.kid).toBe("pasta-group-key-1");
    expect(payload.iss).toBe(gateway);
    expect(payload.sub).toBe("usr_alice_12345");
    expect(payload.aud).toBe("demo_client");
    expect(payload.nonce).toBe("demo_e2e_nonce_1");
    expect(payload.cnf.jkt).toBe(sdk.cnfJkt);

    // Section 10: one sign-on event of three lines -- blind, response, aggregate.
    expect(events.map((e) => e.step)).toEqual([
      "signon-blind",
      "signon-response",
      "signon-aggregate",
    ]);
    const lines = events.flatMap((e) => e.lines);
    expect(lines).toHaveLength(3);
    expect(lines[0]).toMatch(/^\[browser\] sign-on   user=alice nonce=demo_e2e_nonce_1 {2}→ r /);
    expect(lines[1]).toBe(`${CONTINUATION_INDENT}${lines[1].slice(CONTINUATION_INDENT.length)}`);
    expect(lines[1]).toContain("← B_i×3 ct_i×3 (D,E)×3  sess=");
    expect(lines[2]).toContain("→ h=finalize(pw, unblind(r,B_i))");
    expect(lines[2]).toContain("✔ assembled only here");
    // No secret leaks into a log line.
    for (const line of lines) {
      expect(line).not.toContain("password123");
    }
  }, 30_000);

  it("refreshes with a DPoP proof and the new token still verifies", async () => {
    const events: DemoEvent[] = [];
    const sdk = new DecentralizedClientSdk({
      proxyUrl: gateway,
      issuer: gateway,
      onEvent: (e) => events.push(e),
    });

    const first = await sdk.signOn({
      username: "alice",
      password: "password123",
      clientId: "demo_client",
      nonce: "demo_e2e_nonce_2",
    });

    const refreshed = await sdk.refresh({
      clientId: "demo_client",
      nonce: "demo_e2e_nonce_2",
      refreshEndpointUrl: `${gateway}/api/pasta/refresh`,
    });

    expect(refreshed.sessionId).toBe(first.sessionId);
    expect(refreshed.id_token).not.toBe(first.id_token);

    const { payload } = verifyWithJwks(refreshed.id_token, await fetchJwks(gateway));
    expect(payload.sub).toBe("usr_alice_12345");
    expect(payload.cnf.jkt).toBe(sdk.cnfJkt);
    expect(sdk.getCurrentSession()?.counter).toBe(1);

    // Refresh is a single line (section 10).
    expect(events.at(-1)?.step).toBe("refresh");
    expect(events.at(-1)?.lines).toHaveLength(1);
    expect(events.at(-1)?.lines[0]).toMatch(/^\[browser\] refresh   sess=\S+ ctr=1 {2}→ DPoP proof/);
    expect(events.at(-1)?.lines[0]).toContain("rk_i=HKDF(rs_i,ctr)×");
  }, 30_000);

  it("fails locally on a wrong password, with the nodes none the wiser", async () => {
    const events: DemoEvent[] = [];
    const sdk = new DecentralizedClientSdk({
      proxyUrl: gateway,
      issuer: gateway,
      onEvent: (e) => events.push(e),
    });

    await expect(
      sdk.signOn({
        username: "alice",
        password: "wrong-password",
        clientId: "demo_client",
        nonce: "demo_e2e_nonce_3",
      })
    ).rejects.toThrow(/Failed to decrypt share from node/);

    // The gateway answered normally; the failure is the AEAD tag in this process.
    expect(events.map((e) => e.step)).toContain("signon-response");
    expect(events.at(-1)?.kind).toBe("reject");
    expect(events.at(-1)?.lines).toEqual([
      "[browser] ✖ sign-on failed: ct_1 decrypt failed → wrong password (nodes cannot tell)",
    ]);
    expect(sdk.getCurrentSession()).toBeNull();
  }, 30_000);
});
