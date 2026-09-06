import { describe, expect, it } from "vitest";
import crypto from "node:crypto";
import { base64UrlDecode, base64UrlEncode } from "../src/jwt/jwt.js";
import type { SignOnResponse, SignResponse } from "../src/protocol/node.js";
import {
  SignEnvelopeWire,
  SignOnEnvelopeWire,
  SignOnRequestWire,
  SignRequestWire,
  WireError,
  commitEnvelopeFromWire,
  commitmentFromWire,
  signEnvelopeFromWire,
  signOnEnvelopeFromWire,
  signOnRequestFromWire,
  signOnResponseToWire,
  signRequestFromWire,
  signResponseToWire,
} from "../src/wire.js";

/**
 * The node decodes requests and encodes responses, so these tests drive exactly those two
 * directions. Requests are written out as the literal JSON the gateway is expected to
 * send, rather than produced by an encoder of our own, so the test pins the contract of
 * docs/container-split.md sections 5 and 14 and not just our own round trip.
 */

const D1 = crypto.randomBytes(32);
const E1 = crypto.randomBytes(32);
const D2 = crypto.randomBytes(32);
const E2 = crypto.randomBytes(32);

const commitmentsWire = [
  { nodeId: 1, D: base64UrlEncode(D1), E: base64UrlEncode(E1) },
  { nodeId: 2, D: base64UrlEncode(D2), E: base64UrlEncode(E2) },
];

// The refresh token is a second signature, so it needs a second round of its own.
const refreshCommitmentsWire = [
  { nodeId: 1, D: base64UrlEncode(D2), E: base64UrlEncode(E1) },
  { nodeId: 2, D: base64UrlEncode(D1), E: base64UrlEncode(E2) },
];

const signOnRequestWire: SignOnRequestWire = {
  sessionId: "session-1",
  username: "alice",
  blinded: base64UrlEncode(crypto.randomBytes(32)),
  sessionNonce: base64UrlEncode(crypto.randomBytes(16)),
  cnfJkt: "jkt-value",
  clientId: "demo_client",
  scope: "openid profile",
  nonce: "challenge-1",
  iat: 1_700_000_000,
  exp: 1_700_000_060,
  iss: "http://localhost:3000",
  commitments: commitmentsWire,
  allParticipants: [1, 2],
};

const signRequestWire: SignRequestWire = {
  grant: "authorization_code",
  assertion: "aaa.bbb.ccc",
  dpopProof: "ddd.eee.fff",
  claims: { iat: 1_700_000_000, exp: 1_700_003_600, jti: "token-id-1" },
  commitments: commitmentsWire,
  refreshCommitments: refreshCommitmentsWire,
  allParticipants: [1, 2],
};

/** Sends a value through JSON, as the real HTTP hop does. */
function overTheWire<T>(value: T): unknown {
  return JSON.parse(JSON.stringify(value));
}

describe("decoding requests", () => {
  it("turns base64url commitments back into bytes", () => {
    expect(commitmentFromWire(overTheWire(commitmentsWire[0]))).toEqual({
      nodeId: 1,
      D: D1,
      E: E1,
    });
  });

  it("decodes a sign-on request field for field", () => {
    const req = signOnRequestFromWire(overTheWire(signOnRequestWire));

    expect(req).toEqual({
      sessionId: "session-1",
      username: "alice",
      blinded: signOnRequestWire.blinded,
      sessionNonce: signOnRequestWire.sessionNonce,
      cnfJkt: "jkt-value",
      clientId: "demo_client",
      scope: "openid profile",
      nonce: "challenge-1",
      iat: 1_700_000_000,
      exp: 1_700_000_060,
      iss: "http://localhost:3000",
      commitments: [
        { nodeId: 1, D: D1, E: E1 },
        { nodeId: 2, D: D2, E: E2 },
      ],
      allParticipants: [1, 2],
    });
  });

  it("accepts an empty scope but not an empty client id", () => {
    expect(signOnRequestFromWire({ ...signOnRequestWire, scope: "" }).scope).toBe("");
    expect(() => signOnRequestFromWire({ ...signOnRequestWire, clientId: "" })).toThrowError(
      /clientId must not be empty/
    );
  });

  it("leaves nonce absent rather than undefined when the caller omits it", () => {
    const { nonce, ...withoutNonce } = signOnRequestWire;
    const req = signOnRequestFromWire(overTheWire(withoutNonce));

    expect("nonce" in req).toBe(false);
    expect(req.nonce).toBeUndefined();
  });

  it("drops fields the caller was not asked for, such as a spoofed sub", () => {
    const req = signOnRequestFromWire(
      overTheWire({ ...signOnRequestWire, sub: "admin", aud: "another_client", extra: 1 })
    );

    expect(req).not.toHaveProperty("sub");
    expect(req).not.toHaveProperty("aud");
    expect(req).not.toHaveProperty("extra");
  });

  it("decodes a sign request field for field", () => {
    const req = signRequestFromWire(overTheWire(signRequestWire));

    expect(req.grant).toBe("authorization_code");
    expect(req.assertion).toBe("aaa.bbb.ccc");
    expect(req.refreshToken).toBeUndefined();
    expect(req.dpopProof).toBe("ddd.eee.fff");
    expect(req.claims).toEqual({ iat: 1_700_000_000, exp: 1_700_003_600, jti: "token-id-1" });
    expect(req.refreshExp).toBeUndefined();
    expect(req.commitments).toEqual([
      { nodeId: 1, D: D1, E: E1 },
      { nodeId: 2, D: D2, E: E2 },
    ]);
    expect(req.refreshCommitments).toEqual([
      { nodeId: 1, D: D2, E: E1 },
      { nodeId: 2, D: D1, E: E2 },
    ]);
    expect(req.allParticipants).toEqual([1, 2]);
  });

  it("reads only the credential the grant names", () => {
    const both = { ...signRequestWire, refreshToken: "rrr.sss.ttt" };
    const authz = signRequestFromWire(overTheWire(both));
    expect(authz.assertion).toBe("aaa.bbb.ccc");
    expect(authz.refreshToken).toBeUndefined();

    const refresh = signRequestFromWire(
      overTheWire({ ...both, grant: "refresh_token" })
    );
    expect(refresh.refreshToken).toBe("rrr.sss.ttt");
    expect(refresh.assertion).toBeUndefined();

    // The named credential has to be there, and the grant has to be one of the two.
    const { assertion, ...noAssertion } = signRequestWire;
    expect(() => signRequestFromWire(noAssertion)).toThrowError(/assertion must be a string/);
    expect(() =>
      signRequestFromWire({ ...signRequestWire, grant: "refresh_token" })
    ).toThrowError(/refreshToken must be a string/);
    expect(() => signRequestFromWire({ ...signRequestWire, grant: "password" })).toThrowError(
      /grant must be "authorization_code" or "refresh_token"/
    );
  });

  it("takes an optional refreshExp", () => {
    const req = signRequestFromWire({ ...signRequestWire, refreshExp: 1_702_592_000 });
    expect(req.refreshExp).toBe(1_702_592_000);
    expect(() => signRequestFromWire({ ...signRequestWire, refreshExp: "later" })).toThrowError(
      /refreshExp must be a number/
    );
  });

  it("parses the /commit, /sign-on and /sign envelopes", () => {
    expect(commitEnvelopeFromWire(overTheWire({ roundId: "r0" }))).toEqual({ roundId: "r0" });

    const signOnBody: SignOnEnvelopeWire = { roundId: "r1", request: signOnRequestWire };
    const signOn = signOnEnvelopeFromWire(overTheWire(signOnBody));
    expect(signOn.roundId).toBe("r1");
    expect(signOn.request.username).toBe("alice");
    expect(signOn.request.commitments[0].D).toEqual(D1);

    const signBody: SignEnvelopeWire = {
      roundId: "r2",
      refreshRoundId: "r3",
      request: signRequestWire,
    };
    const sign = signEnvelopeFromWire(overTheWire(signBody));
    expect(sign.accessRoundId).toBe("r2");
    expect(sign.refreshRoundId).toBe("r3");
    expect(sign.request.assertion).toBe("aaa.bbb.ccc");
    expect(sign.request.dpopProof).toBe("ddd.eee.fff");

    // One nonce pair over two messages would leak the key share, so the two rounds of a
    // /sign must be different ones.
    expect(() =>
      signEnvelopeFromWire({ ...signBody, refreshRoundId: "r2" })
    ).toThrowError(/refreshRoundId must differ from body.roundId/);
  });
});

describe("rejecting malformed requests", () => {
  it("rejects commitments that are not 32 bytes of unpadded base64url", () => {
    expect(() => commitmentFromWire({ nodeId: 1, D: "AAAA", E: "AAAA" })).toThrowError(WireError);
    expect(() => commitmentFromWire({ nodeId: 1, D: "AAAA", E: "AAAA" })).toThrowError(
      /must decode to 32 bytes/
    );

    const padded = base64UrlEncode(crypto.randomBytes(32)) + "==";
    expect(() => commitmentFromWire({ nodeId: 1, D: padded, E: padded })).toThrowError(
      /base64url without padding/
    );

    expect(() => commitmentFromWire({ nodeId: "1", D: "x", E: "y" })).toThrowError(
      /nodeId must be a number/
    );
  });

  it("rejects requests missing a required field", () => {
    const { username, ...noUsername } = signOnRequestWire;
    expect(() => signOnRequestFromWire(noUsername)).toThrowError(/username must be a string/);

    expect(() =>
      signOnRequestFromWire({ ...signOnRequestWire, allParticipants: "1,2,3" })
    ).toThrowError(/allParticipants must be an array/);

    expect(() => signOnRequestFromWire({ ...signOnRequestWire, iat: "soon" })).toThrowError(
      /iat must be a number/
    );
    expect(() => signOnRequestFromWire({ ...signOnRequestWire, exp: 1.5 })).toThrowError(
      /exp must be an integer/
    );

    const { dpopProof, ...noProof } = signRequestWire;
    expect(() => signRequestFromWire(noProof)).toThrowError(/dpopProof must be a string/);

    expect(() =>
      signRequestFromWire({ ...signRequestWire, claims: { ...signRequestWire.claims, iat: 1.5 } })
    ).toThrowError(/claims.iat must be an integer/);
    expect(() =>
      signRequestFromWire({ ...signRequestWire, claims: { ...signRequestWire.claims, jti: "" } })
    ).toThrowError(/claims.jti must not be empty/);
    const { refreshCommitments, ...noRefreshSet } = signRequestWire;
    expect(() => signRequestFromWire(noRefreshSet)).toThrowError(
      /refreshCommitments must be an array/
    );
  });

  it("rejects a malformed envelope", () => {
    expect(() => signOnEnvelopeFromWire({ request: {} })).toThrowError(/roundId must be a string/);
    expect(() => signOnEnvelopeFromWire({ roundId: "", request: {} })).toThrowError(
      /roundId must not be empty/
    );
    expect(() => signOnEnvelopeFromWire("nope")).toThrowError(/body must be an object/);
    expect(() => commitEnvelopeFromWire({})).toThrowError(/roundId must be a string/);
    expect(() => signEnvelopeFromWire({ roundId: "r" })).toThrowError(
      /body.refreshRoundId must be a string/
    );
    expect(() => signEnvelopeFromWire({ roundId: "r", refreshRoundId: "r2" })).toThrowError(
      /body.request must be an object/
    );
  });
});

describe("encoding responses", () => {
  const signOnResponse: SignOnResponse = {
    nodeId: 2,
    commitment: { D: D2, E: E2 },
    toprfPartial: base64UrlEncode(crypto.randomBytes(32)),
    ct_i: base64UrlEncode(crypto.randomBytes(80)),
    sessionId: "session-1",
    sub: "usr_alice_12345",
  };

  const signResponse: SignResponse = {
    nodeId: 3,
    at: { commitment: { D: D1, E: E1 }, z_i: "0".repeat(63) + "7" },
    rt: { commitment: { D: D2, E: E2 }, z_i: "0".repeat(62) + "2a" },
  };

  it("base64url encodes the sign-on commitment and keeps the rest verbatim", () => {
    const wire = signOnResponseToWire(signOnResponse);

    expect(wire).toEqual({
      nodeId: 2,
      commitment: { D: base64UrlEncode(D2), E: base64UrlEncode(E2) },
      toprfPartial: signOnResponse.toprfPartial,
      ct_i: signOnResponse.ct_i,
      sessionId: "session-1",
      sub: "usr_alice_12345",
    });
    expect(base64UrlDecode(wire.commitment.D)).toEqual(D2);
  });

  it("base64url encodes both sign commitments and carries both shares as hex", () => {
    const wire = signResponseToWire(signResponse);

    expect(wire).toEqual({
      nodeId: 3,
      at: {
        commitment: { D: base64UrlEncode(D1), E: base64UrlEncode(E1) },
        z_i: signResponse.at.z_i,
      },
      rt: {
        commitment: { D: base64UrlEncode(D2), E: base64UrlEncode(E2) },
        z_i: signResponse.rt.z_i,
      },
    });
    // 64 hex digits, big-endian, read back with BigInt("0x" + hex).
    expect(wire.at.z_i).toMatch(/^[0-9a-f]{64}$/);
    expect(BigInt("0x" + wire.at.z_i)).toBe(7n);
    expect(BigInt("0x" + wire.rt.z_i)).toBe(42n);
  });

  it("never leaks a Uint8Array into the JSON body", () => {
    const json = JSON.stringify({
      signOn: signOnResponseToWire(signOnResponse),
      sign: signResponseToWire(signResponse),
    });

    // A serialized Uint8Array looks like {"0":12,"1":250,...}
    expect(json).not.toMatch(/\{"0":\d/);
    expect(json).not.toContain("Uint8Array");
  });
});
