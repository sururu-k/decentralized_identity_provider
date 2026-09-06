import { describe, expect, it } from "vitest";
import {
  generateDPoPKeyPair,
  exportDPoPJwk,
  calculateJwkThumbprint,
  createDPoPProof,
  verifyDPoPProof,
} from "../src/client-sdk/dpop.js";
import { generateFormPostHtml, escapeHtml } from "../src/client-sdk/form-post.js";
import { OidcEndpointHandler } from "../src/gateway/oidc.js";
import { generateShamirShares, randomScalar } from "../src/crypto/frost.js";

/**
 * DPoP, form_post and OIDC unit tests, ported from the monolith's
 * `tests/gateway_and_dpop.test.ts` (`docs/container-split.md` section 6). The sign-on and
 * refresh integration cases from that file live in `e2e.test.ts`, where they run over
 * HTTP against fake node servers instead of in-process `IdentityNode` objects.
 */

/** A real RFC 7638 thumbprint: SHA-256, base64url, 43 characters (section 13). */
const RP_JKT = "b0JFnFHOoQOqFk3sGvEnW6tC8VOBT9NIXtYjIrhAHTA";

describe("DPoP (RFC 9449) & cnf.jkt (Holes 4 & 7)", () => {
  it("generates valid Ed25519 DPoP key pair and computes RFC 7638 thumbprint", () => {
    const keyPair = generateDPoPKeyPair();
    expect(keyPair.publicKey).toHaveLength(32);
    expect(keyPair.privateKey).toHaveLength(32);

    const jwk = exportDPoPJwk(keyPair.publicKey);
    expect(jwk.kty).toBe("OKP");
    expect(jwk.crv).toBe("Ed25519");
    expect(typeof jwk.x).toBe("string");

    const jkt = calculateJwkThumbprint(jwk);
    expect(typeof jkt).toBe("string");
    expect(jkt.length).toBeGreaterThan(40); // 32 bytes in base64url is 43 chars
  });

  it("creates and verifies RFC 9449 DPoP proof JWT", () => {
    const keyPair = generateDPoPKeyPair();
    const htm = "POST";
    const htu = "https://idp.example.com/api/pasta/refresh";

    const proof = createDPoPProof(keyPair, htm, htu);
    expect(proof.split(".")).toHaveLength(3);

    const verification = verifyDPoPProof(proof, {
      expectedHtm: htm,
      expectedHtu: htu,
    });

    expect(verification.valid).toBe(true);
    expect(verification.jkt).toBe(calculateJwkThumbprint(exportDPoPJwk(keyPair.publicKey)));
  });

  it("rejects DPoP proof with mismatched htm or htu", () => {
    const keyPair = generateDPoPKeyPair();
    const proof = createDPoPProof(keyPair, "POST", "https://idp.example.com/api/pasta/refresh");

    // Mismatched HTM
    const badHtm = verifyDPoPProof(proof, {
      expectedHtm: "GET",
      expectedHtu: "https://idp.example.com/api/pasta/refresh",
    });
    expect(badHtm.valid).toBe(false);
    expect(badHtm.error).toContain("htm mismatch");

    // Mismatched HTU
    const badHtu = verifyDPoPProof(proof, {
      expectedHtm: "POST",
      expectedHtu: "https://idp.example.com/other-endpoint",
    });
    expect(badHtu.valid).toBe(false);
    expect(badHtu.error).toContain("htu mismatch");
  });

  it("rejects DPoP proof when thumbprint does not match expected cnf.jkt", () => {
    const keyPair = generateDPoPKeyPair();
    const proof = createDPoPProof(keyPair, "POST", "https://idp.example.com/refresh");

    const verification = verifyDPoPProof(proof, {
      expectedHtm: "POST",
      expectedHtu: "https://idp.example.com/refresh",
      expectedJkt: "different_unmatched_thumbprint",
    });

    expect(verification.valid).toBe(false);
    expect(verification.error).toContain("DPoP thumbprint mismatch");
  });
});

describe("OAuth 2.0 Form Post Response Mode (Hole 2)", () => {
  it("escapes HTML to prevent XSS injection", () => {
    const malicious = '<script>alert("xss")</script>&"\'';
    const escaped = escapeHtml(malicious);
    expect(escaped).not.toContain("<script>");
    expect(escaped).toContain("&lt;script&gt;");
    expect(escaped).toContain("&amp;");
    expect(escaped).toContain("&quot;");
  });

  it("generates auto-submitting form_post HTML targeting RP redirect_uri", () => {
    const redirectUri = "https://rp.example.com/callback";
    const idToken = "ey.mock.jwt";
    const state = "csrf_state_123";

    const html = generateFormPostHtml(redirectUri, { id_token: idToken, state });

    expect(html).toContain(`action="${redirectUri}"`);
    expect(html).toContain('name="id_token" value="ey.mock.jwt"');
    expect(html).toContain('name="state" value="csrf_state_123"');
    expect(html).toContain("document.forms[0].submit()");
  });
});

describe("OIDC Gateway Endpoints (Holes 2 & 4)", () => {
  const masterSecret = randomScalar();
  const { groupPublicKey } = generateShamirShares(masterSecret, 2, 3);
  const oidc = new OidcEndpointHandler({
    issuer: "https://idp.example.com",
    groupPublicKey,
  });

  it("exposes an OAuth authorization-code discovery document (section 14)", () => {
    const config = oidc.getDiscoveryConfiguration() as any;
    expect(config.issuer).toBe("https://idp.example.com");
    expect(config.response_types_supported).toEqual(["code"]);
    expect(config.grant_types_supported).toEqual(["authorization_code", "refresh_token"]);
    expect(config.token_endpoint).toBe("https://idp.example.com/token");
    expect(config.dpop_signing_alg_values_supported).toContain("EdDSA");
    expect(config.token_endpoint_auth_methods_supported).toEqual(["none"]);
    // The id_token flow is gone: no response modes, no id_token signing algs.
    expect(config.response_modes_supported).toBeUndefined();
    expect(config.id_token_signing_alg_values_supported).toBeUndefined();
  });

  it("publishes group public key via standard Ed25519 JWKS (RFC 8037)", () => {
    const jwks = oidc.getJwks() as any;
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0].kty).toBe("OKP");
    expect(jwks.keys[0].crv).toBe("Ed25519");
    expect(jwks.keys[0].alg).toBe("EdDSA");
    expect(typeof jwks.keys[0].x).toBe("string");
  });

  it("accepts response_type=code and refuses anything else (section 14)", () => {
    const valid = oidc.validateAuthorizeRequest({
      client_id: "test_client",
      redirect_uri: "https://rp.example.com/cb",
      response_type: "code",
      scope: "openid profile",
      dpop_jkt: RP_JKT,
    });
    expect(valid.valid).toBe(true);
    expect(valid.params?.dpopJkt).toBe(RP_JKT);
    expect(valid.params?.responseType).toBe("code");

    const idTokenFlow = oidc.validateAuthorizeRequest({
      client_id: "test_client",
      redirect_uri: "https://rp.example.com/cb",
      response_type: "id_token", // the id_token flow is gone
      scope: "openid",
      dpop_jkt: RP_JKT,
    });
    expect(idTokenFlow.valid).toBe(false);
    expect(idTokenFlow.error).toContain("only 'code' is supported");
  });

  describe("dpop_jkt (docs/container-split.md section 13)", () => {
    const base = {
      client_id: "test_client",
      redirect_uri: "https://rp.example.com/cb",
      response_type: "code",
      scope: "openid",
    };

    it("requires it, because the RP front end owns the DPoP key", () => {
      const result = oidc.validateAuthorizeRequest(base);
      expect(result.valid).toBe(false);
      expect(result.error).toContain("dpop_jkt");
    });

    it("rejects anything that is not a 43-character base64url thumbprint", () => {
      const bad = [
        RP_JKT + "A", // 44 characters
        RP_JKT.slice(0, 42), // 42 characters
        RP_JKT.slice(0, 42) + "=", // padding is never part of a thumbprint
        RP_JKT.slice(0, 42) + "+", // standard base64 alphabet, not base64url
        RP_JKT.slice(0, 42) + "/",
        "",
      ];
      for (const dpop_jkt of bad) {
        const result = oidc.validateAuthorizeRequest({ ...base, dpop_jkt });
        expect(result.valid, `expected ${JSON.stringify(dpop_jkt)} to be rejected`).toBe(false);
        expect(result.error).toContain("dpop_jkt");
      }
    });

    it("carries the thumbprint and the challenge through to the demo URL verbatim", () => {
      const html = oidc.renderAuthorizePage({
        clientId: "test_client",
        redirectUri: "https://rp.example.com/cb",
        state: "st",
        scope: "openid",
        dpopJkt: RP_JKT,
        challenge: "c-abc123",
      });
      expect(html).toContain(`dpop_jkt=${RP_JKT}`);
      expect(html).toContain("c=c-abc123");
    });
  });
});
