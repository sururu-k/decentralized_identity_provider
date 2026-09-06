import crypto from "node:crypto";
import { describe, expect, it } from "vitest";
import { DPOP_SCRIPT, renderCallbackPage, renderLandingPage } from "../src/html.js";

/**
 * The rp pages carry their DPoP logic as inline JavaScript with no build step, so nothing
 * type-checks it and no browser runs it here. These tests stand in for that:
 *
 * 1. `DPOP_SCRIPT` is evaluated under Node's WebCrypto, which implements the same
 *    `crypto.subtle` surface the browser does, and its thumbprint is compared against one
 *    computed independently with `node:crypto`. That fixes the byte-level agreement with
 *    `calculateJwkThumbprint` on the node side: SHA-256 over the `{crv,kty,x}` members in
 *    lexicographic order, base64url without padding.
 * 2. Every `<script>` block of both pages is parsed with `new Function`, which catches a
 *    syntax error introduced while editing the string without executing anything.
 *
 * What these cannot cover: IndexedDB has no Node implementation, so `openDb`, `idbGet`,
 * `idbPut` and `ensureKeyPair`'s reuse path are reviewed by reading, not by running.
 * `projects/rp/README.md` records that gap.
 */

/** Evaluates the shared helper and hands back its `PastaDpop` namespace. */
function loadPastaDpop(): {
  jktFromJwk: (jwk: { crv: string; kty: string; x: string }) => Promise<string>;
  unavailableReason: () => string;
} {
  return new Function(`${DPOP_SCRIPT}\nreturn PastaDpop;`)();
}

/** The expected thumbprint, derived without touching the code under test. */
function referenceJkt(jwk: { crv: string; kty: string; x: string }): string {
  const canonical = `{"crv":${JSON.stringify(jwk.crv)},"kty":${JSON.stringify(
    jwk.kty
  )},"x":${JSON.stringify(jwk.x)}}`;
  return crypto.createHash("sha256").update(canonical, "utf8").digest("base64url");
}

/** Pulls the body out of every `<script>…</script>` block of a page. */
function scriptBlocks(html: string): string[] {
  return [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
}

describe("the inline DPoP helper", () => {
  it("derives the same jkt as an independent SHA-256 of the canonical JWK", async () => {
    const PastaDpop = loadPastaDpop();

    for (let i = 0; i < 5; i++) {
      const pair = (await globalThis.crypto.subtle.generateKey({ name: "Ed25519" }, false, [
        "sign",
        "verify",
      ])) as CryptoKeyPair;
      const exported = (await globalThis.crypto.subtle.exportKey(
        "jwk",
        pair.publicKey
      )) as JsonWebKey;
      const jwk = {
        crv: String(exported.crv),
        kty: String(exported.kty),
        x: String(exported.x),
      };

      const jkt = await PastaDpop.jktFromJwk(jwk);
      expect(jkt).toBe(referenceJkt(jwk));
      // base64url SHA-256, the shape /authorize enforces.
      expect(jkt).toMatch(/^[A-Za-z0-9_-]{43}$/);
    }
  });

  it("matches the frozen thumbprint the SDK test pins for a known public key", async () => {
    // Same vector as projects/demo/tests/sdk.test.ts, which pins the node-side
    // calculateJwkThumbprint. Both sides must land on this string.
    const PastaDpop = loadPastaDpop();
    const jwk = {
      kty: "OKP",
      crv: "Ed25519",
      x: "Ag0YIy45RE9aZXB7hpGcp7K9yNPe6fT_ChUgKzZBTFc",
    };

    expect(await PastaDpop.jktFromJwk(jwk)).toBe("b0JFnFHOoQOqFk3sGvEnW6tC8VOBT9NIXtYjIrhAHTA");
  });

  it("ignores JWK members outside crv/kty/x, as RFC 7638 requires", async () => {
    const PastaDpop = loadPastaDpop();
    const base = {
      kty: "OKP",
      crv: "Ed25519",
      x: "Ag0YIy45RE9aZXB7hpGcp7K9yNPe6fT_ChUgKzZBTFc",
    };
    const noisy = { ext: true, key_ops: ["verify"], ...base, use: "sig" };

    expect(await PastaDpop.jktFromJwk(noisy)).toBe(await PastaDpop.jktFromJwk(base));
  });

  it("reports a missing IndexedDB rather than throwing", () => {
    // Node has crypto.subtle but no indexedDB, which is exactly the branch the pages use
    // to disable the login button with a reason instead of failing silently.
    expect(loadPastaDpop().unavailableReason()).toContain("IndexedDB");
  });
});

describe("the inline page scripts", () => {
  const landing = renderLandingPage({ authorizeUrl: "http://idp.test/authorize?nonce=n1" });
  const callback = renderCallbackPage({
    valid: true,
    payload: { sub: "usr_alice_12345", cnf: { jkt: "b0JFnFHOoQOqFk3sGvEnW6tC8VOBT9NIXtYjIrhAHTA" } },
    issuer: "http://idp.test",
  });

  it("parse as JavaScript on both pages", () => {
    const blocks = [...scriptBlocks(landing), ...scriptBlocks(callback)];
    expect(blocks).toHaveLength(4); // the shared helper plus one page script each

    for (const body of blocks) {
      expect(body.trim().length).toBeGreaterThan(0);
      expect(() => new Function(body)).not.toThrow();
    }
  });

  it("never close a script block from inside the JavaScript", () => {
    // A stray </script> in a string literal would end the block early and dump the rest
    // of the helper into the document as text.
    expect(DPOP_SCRIPT).not.toContain("</script");
  });

  it("build the authorize URL with dpop_jkt on the landing page", () => {
    expect(landing).toContain("crypto.subtle");
    expect(landing).toContain('"&dpop_jkt=" + encodeURIComponent(jkt)');
    // The link is inert until the thumbprint is known.
    expect(landing).toContain('id="login-btn" aria-disabled="true"');
    expect(landing).toContain('data-authorize-url="http://idp.test/authorize?nonce=n1"');
    expect(landing).not.toContain('href="http://idp.test/authorize');
    expect(landing).toContain("my DPoP jkt:");
  });

  it("compare the stored key against cnf.jkt on the callback page", () => {
    expect(callback).toContain("crypto.subtle");
    expect(callback).toContain(
      'data-cnf-jkt="b0JFnFHOoQOqFk3sGvEnW6tC8VOBT9NIXtYjIrhAHTA"'
    );
    expect(callback).toContain('id="my-dpop-jkt"');
    expect(callback).toContain('id="jkt-match"');
    expect(callback).toContain("jkt === tokenJkt");
  });

  it("render an empty cnf.jkt attribute when the token carries no binding", () => {
    const html = renderCallbackPage({
      valid: true,
      payload: { sub: "usr_alice_12345" },
      issuer: "http://idp.test",
    });

    expect(html).toContain('data-cnf-jkt=""');
    expect(html).toContain("(なし)");
  });

  it("escape a hostile cnf.jkt instead of breaking out of the attribute", () => {
    const html = renderCallbackPage({
      valid: true,
      payload: { sub: "usr_alice_12345", cnf: { jkt: '"><img src=x onerror=alert(1)>' } },
      issuer: "http://idp.test",
    });

    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&quot;&gt;&lt;img");
  });
});
