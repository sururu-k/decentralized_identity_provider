import { describe, expect, it } from "vitest";
import {
  assembleJwt,
  base64UrlDecode,
  base64UrlEncode,
  createSigningInput,
  deterministicJsonStringify,
} from "../src/sdk/jwt.js";
import { calculateJwkThumbprint, exportDPoPJwk } from "../src/sdk/dpop.js";
import { BrowserBuffer } from "../src/sdk/buffer-shim.js";

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
