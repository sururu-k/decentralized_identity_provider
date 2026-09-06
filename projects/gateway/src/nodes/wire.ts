import { FrostCommitment } from "../crypto/frost.js";
import { base64UrlDecode, base64UrlEncode } from "../jwt/jwt.js";
import {
  RefreshRequest,
  RefreshResponse,
  SignOnRequest,
  SignOnResponse,
} from "../protocol/types.js";

/**
 * Wire types and codecs for the node API (`docs/container-split.md` sections 3 and 5).
 *
 * A `Uint8Array` never travels inside JSON. Every byte string on the wire is base64url
 * without padding, produced by the `base64UrlEncode` / `base64UrlDecode` of
 * `jwt/jwt.ts`. The fields that were already base64url strings in the in-process types
 * (`blinded`, `sessionNonce`, `toprfPartial`, `ct_i`) pass through untouched.
 *
 * These declarations mirror `node/src/wire.ts`. They are re-declared rather than shared:
 * the two projects are independent by contract (section 1), and this file carries only
 * the direction the gateway actually needs -- encode requests, decode responses.
 */

export interface CommitmentWire {
  nodeId: number;
  D: string;
  E: string;
}

export interface CommitResponseWire {
  nodeId: number;
  D: string;
  E: string;
}

export interface SignOnRequestWire {
  sessionId: string;
  username: string;
  blinded: string;
  sessionNonce: string;
  cnfJkt: string;
  nonce?: string;
  iat: number;
  exp: number;
  aud: string;
  iss: string;
  commitments: CommitmentWire[];
  allParticipants: number[];
}

export interface SignOnResponseWire {
  nodeId: number;
  commitment: { D: string; E: string };
  toprfPartial: string;
  ct_i: string;
  sessionId: string;
  sub: string;
}

export interface RefreshRequestWire {
  sessionId: string;
  dpopProof: string;
  expectedHtu: string;
  nonce?: string;
  iat: number;
  exp: number;
  aud: string;
  iss: string;
  commitments: CommitmentWire[];
  allParticipants: number[];
}

export interface RefreshResponseWire {
  nodeId: number;
  commitment: { D: string; E: string };
  ct_i: string;
  ctr: number;
  sub: string;
}

export interface HealthResponseWire {
  status: string;
  nodeId: number;
  groupPublicKey: string;
}

/** Thrown when a node answers with something that is not the shape section 5 promises. */
export class NodeWireError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NodeWireError";
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireObject(where: string, value: unknown): Record<string, unknown> {
  if (!isPlainObject(value)) {
    throw new NodeWireError(`${where} must be an object`);
  }
  return value;
}

function requireNonEmptyString(where: string, value: unknown): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new NodeWireError(`${where} must be a non-empty string`);
  }
  return value;
}

function requireInteger(where: string, value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new NodeWireError(`${where} must be an integer`);
  }
  return value;
}

/** base64url -> bytes, rejecting anything that is not exactly `byteLength` bytes. */
export function decodePoint(where: string, value: unknown, byteLength = 32): Uint8Array {
  const s = requireNonEmptyString(where, value);
  if (!/^[A-Za-z0-9_-]+$/.test(s)) {
    throw new NodeWireError(`${where} must be base64url without padding`);
  }
  const bytes = base64UrlDecode(s);
  if (bytes.length !== byteLength) {
    throw new NodeWireError(`${where} must decode to ${byteLength} bytes, got ${bytes.length}`);
  }
  return bytes;
}

export function commitmentToWire(commitment: FrostCommitment): CommitmentWire {
  return {
    nodeId: commitment.nodeId,
    D: base64UrlEncode(commitment.D),
    E: base64UrlEncode(commitment.E),
  };
}

/**
 * Encodes the one optional field of a round-2 request.
 *
 * `nonce` is left off the wire entirely when the caller omitted it, so that `"nonce" in
 * req` stays false on the node and the payload it signs matches the one the client built.
 * A caller that posts a literal `null` is a different matter: the node refuses `null`
 * with a 400 (`node/src/wire.ts`), so relaying it would burn a FROST round and hand back
 * a message about a field the caller thinks it set. It is refused here instead, before
 * the request leaves, with a message that names the mistake.
 */
function nonceToWire(where: string, value: unknown): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string") {
    throw new NodeWireError(
      `${where}.nonce must be a string when present, got ${value === null ? "null" : typeof value}`
    );
  }
  return value;
}

export function signOnRequestToWire(req: SignOnRequest): SignOnRequestWire {
  const wire: SignOnRequestWire = {
    sessionId: req.sessionId,
    username: req.username,
    blinded: req.blinded,
    sessionNonce: req.sessionNonce,
    cnfJkt: req.cnfJkt,
    iat: req.iat,
    exp: req.exp,
    aud: req.aud,
    iss: req.iss,
    commitments: req.commitments.map(commitmentToWire),
    allParticipants: [...req.allParticipants],
  };
  const nonce = nonceToWire("request", req.nonce);
  if (nonce !== undefined) {
    wire.nonce = nonce;
  }
  return wire;
}

export function refreshRequestToWire(req: RefreshRequest): RefreshRequestWire {
  const wire: RefreshRequestWire = {
    sessionId: req.sessionId,
    dpopProof: req.dpopProof,
    expectedHtu: req.expectedHtu,
    iat: req.iat,
    exp: req.exp,
    aud: req.aud,
    iss: req.iss,
    commitments: req.commitments.map(commitmentToWire),
    allParticipants: [...req.allParticipants],
  };
  const nonce = nonceToWire("request", req.nonce);
  if (nonce !== undefined) {
    wire.nonce = nonce;
  }
  return wire;
}

export function commitResponseFromWire(value: unknown, where = "response"): FrostCommitment {
  const raw = requireObject(where, value);
  return {
    nodeId: requireInteger(`${where}.nodeId`, raw.nodeId),
    D: decodePoint(`${where}.D`, raw.D),
    E: decodePoint(`${where}.E`, raw.E),
  };
}

export function signOnResponseFromWire(value: unknown, where = "response"): SignOnResponse {
  const raw = requireObject(where, value);
  const commitment = requireObject(`${where}.commitment`, raw.commitment);
  return {
    nodeId: requireInteger(`${where}.nodeId`, raw.nodeId),
    commitment: {
      D: decodePoint(`${where}.commitment.D`, commitment.D),
      E: decodePoint(`${where}.commitment.E`, commitment.E),
    },
    toprfPartial: requireNonEmptyString(`${where}.toprfPartial`, raw.toprfPartial),
    ct_i: requireNonEmptyString(`${where}.ct_i`, raw.ct_i),
    sessionId: requireNonEmptyString(`${where}.sessionId`, raw.sessionId),
    sub: requireNonEmptyString(`${where}.sub`, raw.sub),
  };
}

export function refreshResponseFromWire(value: unknown, where = "response"): RefreshResponse {
  const raw = requireObject(where, value);
  const commitment = requireObject(`${where}.commitment`, raw.commitment);
  return {
    nodeId: requireInteger(`${where}.nodeId`, raw.nodeId),
    commitment: {
      D: decodePoint(`${where}.commitment.D`, commitment.D),
      E: decodePoint(`${where}.commitment.E`, commitment.E),
    },
    ct_i: requireNonEmptyString(`${where}.ct_i`, raw.ct_i),
    ctr: requireInteger(`${where}.ctr`, raw.ctr),
    sub: requireNonEmptyString(`${where}.sub`, raw.sub),
  };
}

export function healthResponseFromWire(value: unknown, where = "response"): HealthResponseWire {
  const raw = requireObject(where, value);
  return {
    status: requireNonEmptyString(`${where}.status`, raw.status),
    nodeId: requireInteger(`${where}.nodeId`, raw.nodeId),
    groupPublicKey: requireNonEmptyString(`${where}.groupPublicKey`, raw.groupPublicKey),
  };
}
