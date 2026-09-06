import { FrostCommitment } from "./crypto/frost.js";
import { base64UrlDecode, base64UrlEncode } from "./jwt/jwt.js";
import {
  RefreshRequest,
  RefreshResponse,
  SignOnRequest,
  SignOnResponse,
} from "./protocol/node.js";

/**
 * HTTP wire types for the node API (docs/container-split.md section 5).
 *
 * These mirror the in-process types of `protocol/node.ts` one field at a time. The only
 * difference is the encoding contract of section 3: a `Uint8Array` never travels inside
 * JSON, so every byte string is **base64url without padding**, produced by the
 * `base64UrlEncode` / `base64UrlDecode` of `jwt/jwt.ts`.
 *
 * Fields that were already base64url strings in the in-process types (`blinded`,
 * `sessionNonce`, `toprfPartial`, `ct_i`) are carried through untouched.
 *
 * The node only ever decodes requests and encodes responses, so only those directions
 * have functions here. The opposite halves belong to the caller, and the gateway is a
 * separate project that writes its own.
 */

/** One node's FROST round-1 commitment. */
export interface CommitmentWire {
  nodeId: number;
  D: string;
  E: string;
}

/** `POST /commit` request body. */
export interface CommitRequestWire {
  roundId: string;
}

/** `POST /commit` response body. */
export interface CommitResponseWire {
  nodeId: number;
  D: string;
  E: string;
}

/** `SignOnRequest` with `commitments[].D` / `.E` as base64url. */
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

/** `SignOnResponse` with `commitment.D` / `.E` as base64url. */
export interface SignOnResponseWire {
  nodeId: number;
  commitment: { D: string; E: string };
  toprfPartial: string;
  ct_i: string;
  sessionId: string;
  sub: string;
}

/** `RefreshRequest` with `commitments[].D` / `.E` as base64url. */
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

/** `RefreshResponse` with `commitment.D` / `.E` as base64url. */
export interface RefreshResponseWire {
  nodeId: number;
  commitment: { D: string; E: string };
  ct_i: string;
  ctr: number;
  sub: string;
}

/** `POST /sign-on` request body. */
export interface SignOnEnvelopeWire {
  roundId: string;
  request: SignOnRequestWire;
}

/** `POST /refresh` request body. */
export interface RefreshEnvelopeWire {
  roundId: string;
  request: RefreshRequestWire;
}

/** `GET /health` response body. */
export interface HealthResponseWire {
  status: "ok";
  nodeId: number;
  groupPublicKey: string;
}

/** Thrown when a request body does not match the wire contract. Surfaces as HTTP 400. */
export class WireError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WireError";
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireObject(where: string, value: unknown): Record<string, unknown> {
  if (!isPlainObject(value)) {
    throw new WireError(`${where} must be an object`);
  }
  return value;
}

function requireString(where: string, value: unknown): string {
  if (typeof value !== "string") {
    throw new WireError(`${where} must be a string`);
  }
  return value;
}

function requireNonEmptyString(where: string, value: unknown): string {
  const s = requireString(where, value);
  if (s.length === 0) {
    throw new WireError(`${where} must not be empty`);
  }
  return s;
}

function optionalString(where: string, value: unknown): string | undefined {
  if (value === undefined) return undefined;
  return requireString(where, value);
}

function requireNumber(where: string, value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new WireError(`${where} must be a number`);
  }
  return value;
}

function requireInteger(where: string, value: unknown): number {
  const n = requireNumber(where, value);
  if (!Number.isInteger(n)) {
    throw new WireError(`${where} must be an integer`);
  }
  return n;
}

/** base64url -> bytes, rejecting anything that is not exactly `byteLength` bytes. */
function decodePoint(where: string, value: unknown, byteLength = 32): Uint8Array {
  const s = requireString(where, value);
  if (!/^[A-Za-z0-9_-]*$/.test(s)) {
    throw new WireError(`${where} must be base64url without padding`);
  }
  const bytes = base64UrlDecode(s);
  if (bytes.length !== byteLength) {
    throw new WireError(`${where} must decode to ${byteLength} bytes, got ${bytes.length}`);
  }
  return bytes;
}

function requireIntegerArray(where: string, value: unknown): number[] {
  if (!Array.isArray(value)) {
    throw new WireError(`${where} must be an array`);
  }
  return value.map((v, i) => requireInteger(`${where}[${i}]`, v));
}

// ---------------------------------------------------------------------------
// Commitments
// ---------------------------------------------------------------------------

export function commitmentFromWire(value: unknown, where = "commitment"): FrostCommitment {
  const raw = requireObject(where, value);
  return {
    nodeId: requireInteger(`${where}.nodeId`, raw.nodeId),
    D: decodePoint(`${where}.D`, raw.D),
    E: decodePoint(`${where}.E`, raw.E),
  };
}

function commitmentsFromWire(value: unknown, where: string): FrostCommitment[] {
  if (!Array.isArray(value)) {
    throw new WireError(`${where} must be an array`);
  }
  return value.map((c, i) => commitmentFromWire(c, `${where}[${i}]`));
}

/** The `{ D, E }` half of a response, base64url encoded. */
function commitmentPairToWire(commitment: { D: Uint8Array; E: Uint8Array }): {
  D: string;
  E: string;
} {
  return { D: base64UrlEncode(commitment.D), E: base64UrlEncode(commitment.E) };
}

// ---------------------------------------------------------------------------
// Fields shared by both round-2 requests
// ---------------------------------------------------------------------------

/**
 * The token claims and FROST round-1 context that `SignOnRequest` and `RefreshRequest`
 * carry identically. Only the leading identity fields differ between the two, so this is
 * decoded once and spread into either.
 */
type RoundFields = Pick<
  SignOnRequest,
  "iat" | "exp" | "aud" | "iss" | "commitments" | "allParticipants"
> & { nonce?: string };

function roundFieldsFromWire(where: string, raw: Record<string, unknown>): RoundFields {
  const fields: RoundFields = {
    iat: requireNumber(`${where}.iat`, raw.iat),
    exp: requireNumber(`${where}.exp`, raw.exp),
    aud: requireString(`${where}.aud`, raw.aud),
    iss: requireString(`${where}.iss`, raw.iss),
    commitments: commitmentsFromWire(raw.commitments, `${where}.commitments`),
    allParticipants: requireIntegerArray(`${where}.allParticipants`, raw.allParticipants),
  };
  // `nonce` is the one optional field. It is left off entirely when the caller omits it,
  // so `"nonce" in req` stays false and the signed payload matches a request that never
  // mentioned a nonce. A literal `null` is a caller mistake and is refused.
  const nonce = optionalString(`${where}.nonce`, raw.nonce);
  if (nonce !== undefined) {
    fields.nonce = nonce;
  }
  return fields;
}

// ---------------------------------------------------------------------------
// Sign-on
// ---------------------------------------------------------------------------

export function signOnRequestFromWire(value: unknown, where = "request"): SignOnRequest {
  const raw = requireObject(where, value);
  return {
    sessionId: requireNonEmptyString(`${where}.sessionId`, raw.sessionId),
    username: requireNonEmptyString(`${where}.username`, raw.username),
    blinded: requireNonEmptyString(`${where}.blinded`, raw.blinded),
    sessionNonce: requireNonEmptyString(`${where}.sessionNonce`, raw.sessionNonce),
    cnfJkt: requireNonEmptyString(`${where}.cnfJkt`, raw.cnfJkt),
    ...roundFieldsFromWire(where, raw),
  };
}

export function signOnResponseToWire(res: SignOnResponse): SignOnResponseWire {
  return {
    nodeId: res.nodeId,
    commitment: commitmentPairToWire(res.commitment),
    toprfPartial: res.toprfPartial,
    ct_i: res.ct_i,
    sessionId: res.sessionId,
    sub: res.sub,
  };
}

// ---------------------------------------------------------------------------
// Refresh
// ---------------------------------------------------------------------------

export function refreshRequestFromWire(value: unknown, where = "request"): RefreshRequest {
  const raw = requireObject(where, value);
  return {
    sessionId: requireNonEmptyString(`${where}.sessionId`, raw.sessionId),
    dpopProof: requireNonEmptyString(`${where}.dpopProof`, raw.dpopProof),
    expectedHtu: requireNonEmptyString(`${where}.expectedHtu`, raw.expectedHtu),
    ...roundFieldsFromWire(where, raw),
  };
}

export function refreshResponseToWire(res: RefreshResponse): RefreshResponseWire {
  return {
    nodeId: res.nodeId,
    commitment: commitmentPairToWire(res.commitment),
    ct_i: res.ct_i,
    ctr: res.ctr,
    sub: res.sub,
  };
}

// ---------------------------------------------------------------------------
// Envelopes
// ---------------------------------------------------------------------------

export function commitEnvelopeFromWire(value: unknown): CommitRequestWire {
  const raw = requireObject("body", value);
  return { roundId: requireNonEmptyString("body.roundId", raw.roundId) };
}

export function signOnEnvelopeFromWire(value: unknown): { roundId: string; request: SignOnRequest } {
  const raw = requireObject("body", value);
  return {
    roundId: requireNonEmptyString("body.roundId", raw.roundId),
    request: signOnRequestFromWire(raw.request, "body.request"),
  };
}

export function refreshEnvelopeFromWire(value: unknown): { roundId: string; request: RefreshRequest } {
  const raw = requireObject("body", value);
  return {
    roundId: requireNonEmptyString("body.roundId", raw.roundId),
    request: refreshRequestFromWire(raw.request, "body.request"),
  };
}
