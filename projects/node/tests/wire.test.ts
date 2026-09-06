import { describe, expect, it } from "vitest";
import crypto from "node:crypto";
import { base64UrlDecode, base64UrlEncode } from "../src/jwt/jwt.js";
import type { RefreshResponse, SignOnResponse } from "../src/protocol/node.js";
import {
  RefreshEnvelopeWire,
  RefreshRequestWire,
  SignOnEnvelopeWire,
  SignOnRequestWire,
  WireError,
  commitEnvelopeFromWire,
  commitmentFromWire,
  refreshEnvelopeFromWire,
  refreshRequestFromWire,
  refreshResponseToWire,
  signOnEnvelopeFromWire,
  signOnRequestFromWire,
  signOnResponseToWire,
} from "../src/wire.js";

/**
 * The node decodes requests and encodes responses, so these tests drive exactly those two
 * directions. Requests are written out as the literal JSON the gateway is expected to
 * send, rather than produced by an encoder of our own, so the test pins the contract of
 * docs/container-split.md section 5 and not just our own round trip.
 */

const D1 = crypto.randomBytes(32);
const E1 = crypto.randomBytes(32);
const D2 = crypto.randomBytes(32);
const E2 = crypto.randomBytes(32);

const commitmentsWire = [
  { nodeId: 1, D: base64UrlEncode(D1), E: base64UrlEncode(E1) },
  { nodeId: 2, D: base64UrlEncode(D2), E: base64UrlEncode(E2) },
];

const signOnRequestWire: SignOnRequestWire = {
  sessionId: "session-1",
  username: "alice",
  blinded: base64UrlEncode(crypto.randomBytes(32)),
  sessionNonce: base64UrlEncode(crypto.randomBytes(16)),
  cnfJkt: "jkt-value",
  nonce: "nonce-1",
  iat: 1_700_000_000,
  exp: 1_700_003_600,
  aud: "demo_client",
  iss: "http://localhost:3000",
  commitments: commitmentsWire,
  allParticipants: [1, 2],
};

const refreshRequestWire: RefreshRequestWire = {
  sessionId: "session-1",
  dpopProof: "aaa.bbb.ccc",
  expectedHtu: "http://localhost:3000/api/pasta/refresh",
  nonce: "nonce-2",
  iat: 1_700_000_000,
  exp: 1_700_003_600,
  aud: "demo_client",
  iss: "http://localhost:3000",
  commitments: commitmentsWire,
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
      nonce: "nonce-1",
      iat: 1_700_000_000,
      exp: 1_700_003_600,
      aud: "demo_client",
      iss: "http://localhost:3000",
      commitments: [
        { nodeId: 1, D: D1, E: E1 },
        { nodeId: 2, D: D2, E: E2 },
      ],
      allParticipants: [1, 2],
    });
  });

  it("leaves nonce absent rather than undefined when the caller omits it", () => {
    const { nonce, ...withoutNonce } = signOnRequestWire;
    const req = signOnRequestFromWire(overTheWire(withoutNonce));

    expect("nonce" in req).toBe(false);
    expect(req.nonce).toBeUndefined();
  });

  it("drops fields the caller was not asked for, such as a spoofed sub", () => {
    const req = signOnRequestFromWire(
      overTheWire({ ...signOnRequestWire, sub: "admin", extra: 1 })
    );

    expect(req).not.toHaveProperty("sub");
    expect(req).not.toHaveProperty("extra");
  });

  it("decodes a refresh request field for field", () => {
    const req = refreshRequestFromWire(overTheWire(refreshRequestWire));

    expect(req.sessionId).toBe("session-1");
    expect(req.dpopProof).toBe("aaa.bbb.ccc");
    expect(req.expectedHtu).toBe("http://localhost:3000/api/pasta/refresh");
    expect(req.nonce).toBe("nonce-2");
    expect(req.commitments).toEqual([
      { nodeId: 1, D: D1, E: E1 },
      { nodeId: 2, D: D2, E: E2 },
    ]);
    expect(req.allParticipants).toEqual([1, 2]);
  });

  it("parses the /commit, /sign-on and /refresh envelopes", () => {
    expect(commitEnvelopeFromWire(overTheWire({ roundId: "r0" }))).toEqual({ roundId: "r0" });

    const signOnBody: SignOnEnvelopeWire = { roundId: "r1", request: signOnRequestWire };
    const signOn = signOnEnvelopeFromWire(overTheWire(signOnBody));
    expect(signOn.roundId).toBe("r1");
    expect(signOn.request.username).toBe("alice");
    expect(signOn.request.commitments[0].D).toEqual(D1);

    const refreshBody: RefreshEnvelopeWire = { roundId: "r2", request: refreshRequestWire };
    const refresh = refreshEnvelopeFromWire(overTheWire(refreshBody));
    expect(refresh.roundId).toBe("r2");
    expect(refresh.request.dpopProof).toBe("aaa.bbb.ccc");
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

    const { dpopProof, ...noProof } = refreshRequestWire;
    expect(() => refreshRequestFromWire(noProof)).toThrowError(/dpopProof must be a string/);
  });

  it("rejects a malformed envelope", () => {
    expect(() => signOnEnvelopeFromWire({ request: {} })).toThrowError(/roundId must be a string/);
    expect(() => signOnEnvelopeFromWire({ roundId: "", request: {} })).toThrowError(
      /roundId must not be empty/
    );
    expect(() => signOnEnvelopeFromWire("nope")).toThrowError(/body must be an object/);
    expect(() => commitEnvelopeFromWire({})).toThrowError(/roundId must be a string/);
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

  const refreshResponse: RefreshResponse = {
    nodeId: 3,
    commitment: { D: D1, E: E1 },
    ct_i: base64UrlEncode(crypto.randomBytes(64)),
    ctr: 4,
    sub: "usr_alice_12345",
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

  it("base64url encodes the refresh commitment and carries the counter", () => {
    const wire = refreshResponseToWire(refreshResponse);

    expect(wire).toEqual({
      nodeId: 3,
      commitment: { D: base64UrlEncode(D1), E: base64UrlEncode(E1) },
      ct_i: refreshResponse.ct_i,
      ctr: 4,
      sub: "usr_alice_12345",
    });
  });

  it("never leaks a Uint8Array into the JSON body", () => {
    const json = JSON.stringify({
      signOn: signOnResponseToWire(signOnResponse),
      refresh: refreshResponseToWire(refreshResponse),
    });

    // A serialized Uint8Array looks like {"0":12,"1":250,...}
    expect(json).not.toMatch(/\{"0":\d/);
    expect(json).not.toContain("Uint8Array");
  });
});
