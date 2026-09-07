import crypto from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { ristretto255 } from "@noble/curves/ed25519";
import {
  assembleJwt,
  base64UrlDecode,
  base64UrlEncode,
  createSigningInput,
  deterministicJsonStringify,
} from "../src/sdk/jwt.js";
import { DecentralizedClientSdk } from "../src/sdk/client.js";
import { calculateJwkThumbprint, exportDPoPJwk } from "../src/sdk/dpop.js";
import { BrowserBuffer } from "../src/sdk/buffer-shim.js";
import {
  computeSignatureShare,
  generateFrostNonces,
  generateShamirShares,
  randomScalar,
  type FrostCommitment,
  type FrostNonces,
} from "../src/sdk/crypto/frost.js";
import {
  blind,
  deriveServerKey,
  evaluate,
  finalize,
  generateToprfKey,
  unblind,
} from "../src/sdk/crypto/toprf.js";
import { aeadEncrypt, deriveAeadNonce } from "../src/sdk/crypto/aead.js";
import type { Share } from "../src/sdk/crypto/shamir.js";

/**
 * The port is only useful if it produces the same bytes as the code it was ported from.
 *
 * Every expected value below was produced by running
 * `projects/gateway/src/jwt/jwt.ts` and `projects/gateway/src/client-sdk/dpop.ts` under
 * Node (where they use `Buffer`), then frozen here. A regression in the browser
 * `btoa`/`atob` plumbing, in the key ordering of `deterministicJsonStringify` or in the
 * signing input would break the AEAD AAD a node authenticates against, so it must break
 * one of these instead.
 */

describe("base64UrlEncode matches the Node implementation", () => {
  const byteVectors: Array<[number[], string]> = [
    [[], ""],
    [[0], "AA"],
    [[0, 1], "AAE"],
    [[0, 1, 2], "AAEC"],
    [[251, 255, 190, 239], "-_--7w"],
    [
      Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff),
      "AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dw",
    ],
  ];

  it.each(byteVectors)("encodes %j", (bytes, expected) => {
    expect(base64UrlEncode(Uint8Array.from(bytes))).toBe(expected);
  });

  const stringVectors: Array<[string, string]> = [
    ["", ""],
    ["a", "YQ"],
    ["ab", "YWI"],
    ["abc", "YWJj"],
    ["hello world", "aGVsbG8gd29ybGQ"],
    ["パスタ 分散IdP", "44OR44K544K_IOWIhuaVo0lkUA"],
    ['{"z":1,"a":[1,2]}', "eyJ6IjoxLCJhIjpbMSwyXX0"],
  ];

  it.each(stringVectors)("encodes the UTF-8 of %j", (input, expected) => {
    expect(base64UrlEncode(input)).toBe(expected);
  });

  it("never emits padding or the + / characters", () => {
    for (let len = 0; len < 40; len++) {
      const bytes = Uint8Array.from({ length: len }, (_, i) => (i * 251 + 17) & 0xff);
      expect(base64UrlEncode(bytes)).not.toMatch(/[+/=]/);
    }
  });
});

describe("base64UrlDecode matches the Node implementation", () => {
  const vectors: Array<[string, number[]]> = [
    ["", []],
    ["YQ", [97]],
    ["YWI", [97, 98]],
    ["YWJj", [97, 98, 99]],
    ["aGVsbG8gd29ybGQ", [104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100]],
    [
      "44OR44K544K_IOWIhuaVo0lkUA",
      [227, 131, 145, 227, 130, 185, 227, 130, 191, 32, 229, 136, 134, 230, 149, 163, 73, 100, 80],
    ],
    ["-_--7w", [251, 255, 190, 239]],
  ];

  it.each(vectors)("decodes %j", (input, expected) => {
    expect(Array.from(base64UrlDecode(input))).toEqual(expected);
  });

  it("round-trips arbitrary byte strings", () => {
    for (let len = 0; len < 200; len++) {
      const bytes = Uint8Array.from({ length: len }, (_, i) => (i * 97 + len) & 0xff);
      expect(Array.from(base64UrlDecode(base64UrlEncode(bytes)))).toEqual(Array.from(bytes));
    }
  });
});

describe("deterministicJsonStringify matches the Node implementation", () => {
  const vectors: Array<[unknown, string]> = [
    [null, "null"],
    [1, "1"],
    ["x", '"x"'],
    [true, "true"],
    [{ b: 1, a: 2 }, '{"a":2,"b":1}'],
    [
      { z: { y: 1, x: 2 }, a: [3, { d: 4, c: 5 }] },
      '{"a":[3,{"c":5,"d":4}],"z":{"x":2,"y":1}}',
    ],
    [
      { alg: "EdDSA", typ: "JWT", kid: "pasta-group-key-1" },
      '{"alg":"EdDSA","kid":"pasta-group-key-1","typ":"JWT"}',
    ],
    [
      {
        iss: "http://localhost:3000",
        sub: "usr_alice_12345",
        aud: "demo_client",
        iat: 1757000000,
        exp: 1757003600,
        nonce: "n1",
        cnf: { jkt: "AAAA" },
      },
      '{"aud":"demo_client","cnf":{"jkt":"AAAA"},"exp":1757003600,"iat":1757000000,' +
        '"iss":"http://localhost:3000","nonce":"n1","sub":"usr_alice_12345"}',
    ],
    [{ crv: "Ed25519", kty: "OKP", x: "AAAA" }, '{"crv":"Ed25519","kty":"OKP","x":"AAAA"}'],
    [[1, [2, 3], { a: null }], '[1,[2,3],{"a":null}]'],
  ];

  it.each(vectors)("stringifies %j", (input, expected) => {
    expect(deterministicJsonStringify(input)).toBe(expected);
  });
});

describe("JWT assembly matches the Node implementation", () => {
  const header = { alg: "EdDSA", typ: "JWT", kid: "pasta-group-key-1" };
  const payload = {
    iss: "http://localhost:3000",
    sub: "usr_alice_12345",
    aud: "demo_client",
    iat: 1757000000,
    exp: 1757003600,
    nonce: "n1",
    cnf: { jkt: "6cPQNImfbhqmjHz5XD9U826uZYL5KR5Sm9bm3NuQXM" },
  };

  const expectedHeaderB64 =
    "eyJhbGciOiJFZERTQSIsImtpZCI6InBhc3RhLWdyb3VwLWtleS0xIiwidHlwIjoiSldUIn0";
  const expectedPayloadB64 =
    "eyJhdWQiOiJkZW1vX2NsaWVudCIsImNuZiI6eyJqa3QiOiI2Y1BRTkltZmJocW1qSHo1WEQ5VTgyNnVaWUw1S1I1U205Ym0zTnVRWE0ifSwiZXhwIjoxNzU3MDAzNjAwLCJpYXQiOjE3NTcwMDAwMDAsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsIm5vbmNlIjoibjEiLCJzdWIiOiJ1c3JfYWxpY2VfMTIzNDUifQ";

  it("produces the frozen signing input", () => {
    const { signingInput, headerB64, payloadB64 } = createSigningInput(header, payload);
    expect(headerB64).toBe(expectedHeaderB64);
    expect(payloadB64).toBe(expectedPayloadB64);
    expect(new TextDecoder().decode(signingInput)).toBe(
      `${expectedHeaderB64}.${expectedPayloadB64}`
    );
  });

  it("produces the frozen token", () => {
    const { headerB64, payloadB64 } = createSigningInput(header, payload);
    const signature = Uint8Array.from({ length: 64 }, (_, i) => (i * 5 + 1) & 0xff);
    expect(assembleJwt(headerB64, payloadB64, signature)).toBe(
      `${expectedHeaderB64}.${expectedPayloadB64}.` +
        "AQYLEBUaHyQpLjM4PUJHTFFWW2Blam90eX6DiI2Sl5yhpquwtbq_xMnO09jd4ufs8fb7AAUKDxQZHiMoLTI3PA"
    );
  });
});

describe("DPoP thumbprint matches the Node implementation", () => {
  it("derives the frozen cnf.jkt", () => {
    const publicKey = Uint8Array.from({ length: 32 }, (_, i) => (i * 11 + 2) & 0xff);
    const jwk = exportDPoPJwk(publicKey);
    expect(jwk).toEqual({
      kty: "OKP",
      crv: "Ed25519",
      x: "Ag0YIy45RE9aZXB7hpGcp7K9yNPe6fT_ChUgKzZBTFc",
    });
    expect(calculateJwkThumbprint(jwk)).toBe("b0JFnFHOoQOqFk3sGvEnW6tC8VOBT9NIXtYjIrhAHTA");
  });
});

describe("the SDK takes the DPoP thumbprint instead of making a key", () => {
  const config = { proxyUrl: "http://gateway.test", issuer: "http://gateway.test" };
  const jkt = "b0JFnFHOoQOqFk3sGvEnW6tC8VOBT9NIXtYjIrhAHTA";

  it("uses the supplied thumbprint verbatim", () => {
    // Section 13: this value came from the rp front end through /authorize, and the token
    // must be bound to it rather than to anything this process generated.
    expect(new DecentralizedClientSdk(config, jkt).cnfJkt).toBe(jkt);
  });

  it("refuses to run without one", () => {
    expect(() => new DecentralizedClientSdk(config, "")).toThrow(/cnfJkt is required/);
  });

  it("exposes no key material at all", () => {
    const sdk = new DecentralizedClientSdk(config, jkt) as unknown as Record<string, unknown>;
    expect(sdk.getDPoPKeyPair).toBeUndefined();
    expect(sdk.dpopKeyPair).toBeUndefined();
  });

  it("has no refresh method: the IdP front end does not refresh (section 14)", () => {
    const sdk = new DecentralizedClientSdk(config, jkt) as unknown as Record<string, unknown>;
    expect(sdk.refresh).toBeUndefined();
  });
});

describe("Buffer shim behaves like the Node Buffer the frozen crypto copies expect", () => {
  it("hex-encodes bytes the way frost.ts needs", () => {
    const bytes = Uint8Array.from({ length: 32 }, (_, i) => (i * 13 + 5) & 0xff);
    expect(BrowserBuffer.from(bytes).toString("hex")).toBe(Buffer.from(bytes).toString("hex"));
  });

  it("UTF-8 encodes strings the way kdf.ts needs", () => {
    for (const s of ["", "sess_123", "pasta-refresh-ctr:7", "パスタ"]) {
      expect(Array.from(BrowserBuffer.from(s, "utf8"))).toEqual(
        Array.from(Buffer.from(s, "utf8"))
      );
    }
  });

  it("stays a Uint8Array, so @noble accepts it", () => {
    expect(BrowserBuffer.from("x", "utf8")).toBeInstanceOf(Uint8Array);
  });

  it("refuses encodings it does not implement instead of guessing", () => {
    expect(() => BrowserBuffer.from("x", "base64url")).toThrow(/unsupported/);
    expect(() => BrowserBuffer.from(Uint8Array.of(1)).toString("base64")).toThrow(/unsupported/);
  });
});

describe("the assertion's signed payload matches the node README byte for byte", () => {
  // docs/container-split.md section 14 / projects/node/README.md: the assertion the node
  // signs, and the browser must reproduce identically because it is both the JWT payload
  // and the AEAD AAD guarding every ct_i. Keys sort lexicographically at every level.
  const header = { alg: "EdDSA", typ: "JWT", kid: "pasta-group-key-1" };
  // Built in the same object order the SDK builds it (see client.ts signOn).
  const payload = {
    iss: "http://localhost:3000",
    sub: "usr_alice_12345",
    aud: "http://localhost:3000",
    client_id: "demo_client",
    scope: "openid profile",
    cnf: { jkt: "QJkBBMt5oLQ3lJ3JgV8p0k1r7cQnB2xXe1a9mVYt0aM" },
    nonce: "9f3c1a20",
    iat: 1757030400,
    exp: 1757030430,
  };

  // The canonical serializations quoted verbatim from projects/node/README.md.
  const canonicalHeader = '{"alg":"EdDSA","kid":"pasta-group-key-1","typ":"JWT"}';
  const canonicalPayload =
    '{"aud":"http://localhost:3000","client_id":"demo_client",' +
    '"cnf":{"jkt":"QJkBBMt5oLQ3lJ3JgV8p0k1r7cQnB2xXe1a9mVYt0aM"},' +
    '"exp":1757030430,"iat":1757030400,"iss":"http://localhost:3000",' +
    '"nonce":"9f3c1a20","scope":"openid profile","sub":"usr_alice_12345"}';

  it("serializes to the node README's canonical JSON", () => {
    expect(deterministicJsonStringify(header)).toBe(canonicalHeader);
    expect(deterministicJsonStringify(payload)).toBe(canonicalPayload);
  });

  it("produces the base64url a node computes independently (node:crypto Buffer)", () => {
    // Independent expected values: base64url of the canonical bytes, via Node's own Buffer.
    const expectedHeaderB64 = Buffer.from(canonicalHeader, "utf8").toString("base64url");
    const expectedPayloadB64 = Buffer.from(canonicalPayload, "utf8").toString("base64url");

    const { signingInput, headerB64, payloadB64 } = createSigningInput(header, payload);
    expect(headerB64).toBe(expectedHeaderB64);
    expect(payloadB64).toBe(expectedPayloadB64);
    expect(new TextDecoder().decode(signingInput)).toBe(
      `${expectedHeaderB64}.${expectedPayloadB64}`
    );
  });
});

describe("signOn decrypts and aggregates a group-signed assertion", () => {
  // A faithful in-test stand-in for the gateway and its three nodes, built from the same
  // frozen crypto the real node uses. It proves the SDK's decrypt-and-aggregate path
  // yields an assertion that verifies under the group public key as a plain Ed25519 JWT --
  // the property the whole port exists to preserve. `fetch` is stubbed for one sign-on.
  const password = "password123";
  const sub = "usr_alice_12345";
  const participants = [1, 2, 3];
  const threshold = 2;

  const savedFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = savedFetch;
  });

  function buildStack() {
    // FROST signing group.
    const groupSecret = randomScalar();
    const { groupPublicKey, shares: keyShares } = generateShamirShares(
      groupSecret,
      threshold,
      participants.length
    );
    // TOPRF key, and the master PRF value h. h is independent of any blinding factor, so
    // the stack recovers it with its own blind() exactly as the client will with its own.
    const toprfShares: Share[] = generateToprfKey(participants.length, threshold);
    const { blinding: hb, blinded: hA } = blind(password);
    const hPartials = toprfShares.map((s) => ({ id: s.id, point: evaluate(s, hA) }));
    const h = finalize(password, unblind(hb, hPartials));
    return { groupPublicKey, keyShares, toprfShares, h };
  }

  function installFetch(stack: ReturnType<typeof buildStack>): void {
    globalThis.fetch = (async (_url: string, init: any) => {
      const body = JSON.parse(init.body);
      const A = ristretto255.Point.fromBytes(base64UrlDecode(body.blinded));
      const sessionNonce = base64UrlDecode(body.sessionNonce);
      const sessionId = "sess-" + body.nonce;

      // Rebuild the assertion payload exactly as the SDK does, from the request's own
      // iat/exp so both sides serialize identical bytes.
      const header = { alg: "EdDSA", typ: "JWT", kid: "pasta-group-key-1" };
      const payload = {
        iss: body.iss,
        sub,
        aud: body.aud,
        client_id: body.clientId,
        scope: body.scope,
        cnf: { jkt: body.cnfJkt },
        nonce: body.nonce,
        iat: body.iat,
        exp: body.exp,
      };
      const { signingInput } = createSigningInput(header, payload);

      // FROST round 1: one nonce pair per node.
      const nonces = new Map<number, FrostNonces>();
      const commitments: FrostCommitment[] = [];
      for (const id of participants) {
        const g = generateFrostNonces();
        nonces.set(id, g.nonces);
        commitments.push({ nodeId: id, D: g.commitment.D, E: g.commitment.E });
      }

      const nodeResponses = participants.map((id) => {
        const share = stack.toprfShares.find((s) => s.id === id)!;
        const B_i = evaluate(share, A);
        const z_i = computeSignatureShare(
          id,
          nonces.get(id)!,
          stack.keyShares.get(id)!,
          signingInput,
          commitments,
          stack.groupPublicKey,
          participants
        );
        const h_i = deriveServerKey(stack.h, id);
        const aeadNonce = deriveAeadNonce(sessionNonce, id);
        // Section 14: ct_i encrypts { z_i } alone, z_i as a decimal string (node.ts uses
        // `z_i.toString()`), AAD = signingInput.
        const ct = aeadEncrypt(
          h_i,
          aeadNonce,
          new TextEncoder().encode(JSON.stringify({ z_i: z_i.toString() })),
          signingInput
        );
        const c = commitments[id - 1];
        return {
          nodeId: id,
          commitment: { D: base64UrlEncode(c.D), E: base64UrlEncode(c.E) },
          toprfPartial: base64UrlEncode(B_i.toRawBytes()),
          ct_i: base64UrlEncode(ct),
          sessionId,
          sub,
        };
      });

      const wire = {
        sessionId,
        commitments: commitments.map((c) => ({
          nodeId: c.nodeId,
          D: base64UrlEncode(c.D),
          E: base64UrlEncode(c.E),
        })),
        nodeResponses,
      };
      return { ok: true, status: 200, json: async () => wire };
    }) as unknown as typeof fetch;
  }

  function verifyAssertion(assertion: string, groupPublicKey: Uint8Array) {
    const [headerB64, payloadB64, sigB64] = assertion.split(".");
    const jwk = {
      kty: "OKP",
      crv: "Ed25519",
      x: base64UrlEncode(groupPublicKey),
    } as crypto.JsonWebKey;
    const ok = crypto.verify(
      null,
      Buffer.from(`${headerB64}.${payloadB64}`, "utf8"),
      crypto.createPublicKey({ key: jwk, format: "jwk" }),
      Buffer.from(base64UrlDecode(sigB64))
    );
    return {
      ok,
      header: JSON.parse(new TextDecoder().decode(base64UrlDecode(headerB64))),
      payload: JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64))),
    };
  }

  const jkt = "QJkBBMt5oLQ3lJ3JgV8p0k1r7cQnB2xXe1a9mVYt0aM";

  it("assembles an assertion the group public key verifies", async () => {
    const stack = buildStack();
    installFetch(stack);

    const sdk = new DecentralizedClientSdk(
      { proxyUrl: "http://gateway.test", issuer: "http://gateway.test" },
      jkt
    );
    const { assertion, sessionId } = await sdk.signOn({
      username: "alice",
      password,
      clientId: "demo_client",
      scope: "openid profile",
      nonce: "c_abc123",
    });

    expect(sessionId).toBe("sess-c_abc123");
    const { ok, header, payload } = verifyAssertion(assertion, stack.groupPublicKey);
    expect(ok).toBe(true);
    expect(header).toEqual({ alg: "EdDSA", typ: "JWT", kid: "pasta-group-key-1" });
    // The assertion is addressed to the gateway; client_id and scope travel separately.
    expect(payload.iss).toBe("http://gateway.test");
    expect(payload.aud).toBe("http://gateway.test");
    expect(payload.sub).toBe(sub);
    expect(payload.client_id).toBe("demo_client");
    expect(payload.scope).toBe("openid profile");
    expect(payload.nonce).toBe("c_abc123");
    expect(payload.cnf).toEqual({ jkt });
    expect(payload.exp - payload.iat).toBe(30);
  });

  it("fails at the AEAD tag on a wrong password, leaving no session", async () => {
    const stack = buildStack();
    installFetch(stack);

    const sdk = new DecentralizedClientSdk(
      { proxyUrl: "http://gateway.test", issuer: "http://gateway.test" },
      jkt
    );
    await expect(
      sdk.signOn({
        username: "alice",
        password: "wrong-password",
        clientId: "demo_client",
        scope: "openid profile",
        nonce: "c_wrong",
      })
    ).rejects.toThrow(/Failed to decrypt share from node/);
    expect(sdk.getCurrentSession()).toBeNull();
  });
});
