import { describe, expect, it } from "vitest";
import {
  generateDPoPKeyPair,
  exportDPoPJwk,
  calculateJwkThumbprint,
  createDPoPProof,
  verifyDPoPProof,
} from "../src/client-sdk/dpop.js";
import {
  generateFormPostHtml,
  escapeHtml,
} from "../src/client-sdk/form-post.js";
import { OidcEndpointHandler } from "../src/gateway/oidc.js";
import { PastaOAuthProxy } from "../src/gateway/proxy.js";
import { GatewaySessionManager } from "../src/gateway/session.js";
import { IdentityNode, registerUserToNodes } from "../src/protocol/node.js";
import { DecentralizedClientSdk } from "../src/client-sdk/client.js";
import { generateShamirShares, randomScalar } from "../src/crypto/frost.js";
import { verifyJwt } from "../src/jwt/jwt.js";

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
    expect(html).toContain('document.forms[0].submit()');
  });
});

describe("OIDC Gateway Endpoints (Holes 2 & 4)", () => {
  const masterSecret = randomScalar();
  const { groupPublicKey } = generateShamirShares(masterSecret, 2, 3);
  const oidc = new OidcEndpointHandler({
    issuer: "https://idp.example.com",
    groupPublicKey,
  });

  it("exposes discovery configuration declaring response_modes_supported=['form_post']", () => {
    const config = oidc.getDiscoveryConfiguration() as any;
    expect(config.issuer).toBe("https://idp.example.com");
    expect(config.response_modes_supported).toContain("form_post");
    expect(config.id_token_signing_alg_values_supported).toContain("EdDSA");
    expect(config.dpop_signing_alg_values_supported).toContain("EdDSA");
  });

  it("publishes group public key via standard Ed25519 JWKS (RFC 8037)", () => {
    const jwks = oidc.getJwks() as any;
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0].kty).toBe("OKP");
    expect(jwks.keys[0].crv).toBe("Ed25519");
    expect(jwks.keys[0].alg).toBe("EdDSA");
    expect(typeof jwks.keys[0].x).toBe("string");
  });

  it("enforces response_mode=form_post at /authorize", () => {
    const valid = oidc.validateAuthorizeRequest({
      client_id: "test_client",
      redirect_uri: "https://rp.example.com/cb",
      response_type: "id_token",
      response_mode: "form_post",
      scope: "openid profile",
      nonce: "nonce123",
    });
    expect(valid.valid).toBe(true);

    const invalidMode = oidc.validateAuthorizeRequest({
      client_id: "test_client",
      redirect_uri: "https://rp.example.com/cb",
      response_type: "id_token",
      response_mode: "query", // invalid: proxy cannot hold tokens (Hole 2)
      scope: "openid",
      nonce: "nonce123",
    });
    expect(invalidMode.valid).toBe(false);
    expect(invalidMode.error).toContain("only 'form_post' is supported");
  });
});

describe("Decentralized Sign-On & Refresh Integration (Holes 2, 4, 5, 7)", () => {
  it("executes full sign-on, RP verification, and DPoP refresh", async () => {
    const masterSecret = randomScalar();
    const { groupPublicKey, shares } = generateShamirShares(masterSecret, 2, 3);

    const nodes = [
      new IdentityNode(1, shares.get(1)!, groupPublicKey),
      new IdentityNode(2, shares.get(2)!, groupPublicKey),
      new IdentityNode(3, shares.get(3)!, groupPublicKey),
    ];

    const username = "alice";
    const password = "my-secure-password";
    const userSub = "usr_alice_999";

    registerUserToNodes(nodes, username, password, userSub, 2);

    const proxy = new PastaOAuthProxy(nodes, 2);
    const clientSdk = new DecentralizedClientSdk({
      proxy,
      issuer: "https://idp.example.com",
    });

    // 1. Sign-on
    const nonce = "nonce_xyz_1";
    const { id_token, sessionId } = await clientSdk.signOn({
      username,
      password,
      clientId: "rp_client",
      nonce,
      participants: [1, 2, 3],
    });

    expect(typeof id_token).toBe("string");
    expect(typeof sessionId).toBe("string");

    // 2. RP Verification
    const rpVerify = verifyJwt(id_token, groupPublicKey, {
      iss: "https://idp.example.com",
      aud: "rp_client",
      nonce,
    });
    expect(rpVerify.valid).toBe(true);
    expect(rpVerify.payload.sub).toBe(userSub);
    expect(rpVerify.payload.cnf.jkt).toBe(clientSdk.cnfJkt);

    // 3. Refresh with DPoP
    const refreshUrl = "https://idp.example.com/api/pasta/refresh";
    const refreshed = await clientSdk.refresh({
      clientId: "rp_client",
      refreshEndpointUrl: refreshUrl,
      nonce: "nonce_refreshed_2",
      participants: [2, 3],
    });

    expect(typeof refreshed.id_token).toBe("string");

    const refreshedVerify = verifyJwt(refreshed.id_token, groupPublicKey, {
      iss: "https://idp.example.com",
      aud: "rp_client",
      nonce: "nonce_refreshed_2",
    });
    expect(refreshedVerify.valid).toBe(true);
    expect(refreshedVerify.payload.sub).toBe(userSub);
  });

  it("fails sign-on when user enters incorrect password due to TOPRF authentication failure", async () => {
    const masterSecret = randomScalar();
    const { groupPublicKey, shares } = generateShamirShares(masterSecret, 2, 3);

    const nodes = [
      new IdentityNode(1, shares.get(1)!, groupPublicKey),
      new IdentityNode(2, shares.get(2)!, groupPublicKey),
      new IdentityNode(3, shares.get(3)!, groupPublicKey),
    ];

    registerUserToNodes(nodes, "bob", "correct-password", "usr_bob_888", 2);

    const proxy = new PastaOAuthProxy(nodes, 2);
    const clientSdk = new DecentralizedClientSdk({
      proxy,
      issuer: "https://idp.example.com",
    });

    await expect(
      clientSdk.signOn({
        username: "bob",
        password: "WRONG-password",
        clientId: "rp_client",
        nonce: "nonce_fail_1",
      })
    ).rejects.toThrow("Invalid password or corrupted share");
  });
});
