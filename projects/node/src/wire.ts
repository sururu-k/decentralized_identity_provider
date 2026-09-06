import { FrostCommitment } from "./crypto/frost.js";
import { base64UrlDecode, base64UrlEncode } from "./jwt/jwt.js";
import {
  Grant,
  SignOnRequest,
  SignOnResponse,
  SignRequest,
  SignResponse,
  SignRounds,
} from "./protocol/node.js";

/**
 * HTTP wire types for the node API (docs/container-split.md sections 5 and 14).
 *
 * There is no session on the node, so no request carries a session identifier except
 * `/sign-on`, which only echoes it back for the gateway's own bookkeeping.
 *
 * These mirror the in-process types of `protocol/node.ts` one field at a time. The only
 * difference is the encoding contract of section 3: a `Uint8Array` never travels inside
 * JSON, so every byte string is **base64url without padding**, produced by the
 * `base64UrlEncode` / `base64UrlDecode` of `jwt/jwt.ts`.
 *
 * Fields that were already strings in the in-process types (`blinded`, `sessionNonce`,
 * `toprfPartial`, `ct_i`, `z_i`) are carried through untouched. `z_i` is the one scalar on
 * the wire and follows the scalar convention of section 3: 64 lowercase hex digits,
 * big-endian, read back with `BigInt("0x" + hex)`.
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
  clientId: string;
  scope: string;
  nonce?: string;
  iat: number;
  exp: number;
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

/** The token claims the gateway pins so all nodes sign the same bytes. */
export interface AccessTokenClaimsWire {
  iat: number;
  exp: number;
  jti: string;
}

/** `SignRequest` with every commitment as base64url. */
export interface SignRequestWire {
  grant: Grant;
  /** `authorization_code`: the assertion assembled at sign-on, i.e. the code itself. */
  assertion?: string;
  /** `refresh_token`: a refresh token this group signed earlier. */
  refreshToken?: string;
  dpopProof: string;
  claims: AccessTokenClaimsWire;
  /** Optional `exp` for the new refresh token. Defaults to `claims.iat` + 30 days. */
  refreshExp?: number;
  /** Round-1 commitments of the access token round. */
  commitments: CommitmentWire[];
  /** Round-1 commitments of the refresh token round. */
  refreshCommitments: CommitmentWire[];
  allParticipants: number[];
}

/** One signature's half of a `/sign` answer, base64url commitment and plaintext hex share. */
export interface SignedShareWire {
  commitment: { D: string; E: string };
  z_i: string;
}

/** `SignResponse` with both commitments base64url. Both shares are plaintext hex. */
export interface SignResponseWire {
  nodeId: number;
  at: SignedShareWire;
  rt: SignedShareWire;
}

/** `POST /sign-on` request body. */
export interface SignOnEnvelopeWire {
  roundId: string;
  request: SignOnRequestWire;
}

/**
 * `POST /sign` request body.
 *
 * Two FROST rounds, because two different messages are signed: the access token and the
 * refresh token. They must be different rounds -- one nonce pair over two messages would
 * leak the key share -- so the gateway calls `/commit` twice per node before `/sign`.
 */
export interface SignEnvelopeWire {
  roundId: string;
  refreshRoundId: string;
  request: SignRequestWire;
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
// Sign-on
// ---------------------------------------------------------------------------

export function signOnRequestFromWire(value: unknown, where = "request"): SignOnRequest {
  const raw = requireObject(where, value);
  const req: SignOnRequest = {
    sessionId: requireNonEmptyString(`${where}.sessionId`, raw.sessionId),
    username: requireNonEmptyString(`${where}.username`, raw.username),
    blinded: requireNonEmptyString(`${where}.blinded`, raw.blinded),
    sessionNonce: requireNonEmptyString(`${where}.sessionNonce`, raw.sessionNonce),
    cnfJkt: requireNonEmptyString(`${where}.cnfJkt`, raw.cnfJkt),
    clientId: requireNonEmptyString(`${where}.clientId`, raw.clientId),
    // An empty scope is a legitimate OAuth request, so this one may be "".
    scope: requireString(`${where}.scope`, raw.scope),
    iat: requireInteger(`${where}.iat`, raw.iat),
    exp: requireInteger(`${where}.exp`, raw.exp),
    iss: requireNonEmptyString(`${where}.iss`, raw.iss),
    commitments: commitmentsFromWire(raw.commitments, `${where}.commitments`),
    allParticipants: requireIntegerArray(`${where}.allParticipants`, raw.allParticipants),
  };
  // `nonce` is the one optional field. It is left off entirely when the caller omits it,
  // so `"nonce" in req` stays false and the signed payload matches a request that never
  // mentioned a nonce. A literal `null` is a caller mistake and is refused.
  const nonce = optionalString(`${where}.nonce`, raw.nonce);
  if (nonce !== undefined) {
    req.nonce = nonce;
  }
  return req;
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
// Sign
// ---------------------------------------------------------------------------

function claimsFromWire(value: unknown, where: string): SignRequest["claims"] {
  const raw = requireObject(where, value);
  return {
    iat: requireInteger(`${where}.iat`, raw.iat),
    exp: requireInteger(`${where}.exp`, raw.exp),
    jti: requireNonEmptyString(`${where}.jti`, raw.jti),
  };
}

function grantFromWire(where: string, value: unknown): Grant {
  const grant = requireString(where, value);
  if (grant !== "authorization_code" && grant !== "refresh_token") {
    throw new WireError(`${where} must be "authorization_code" or "refresh_token"`);
  }
  return grant;
}

export function signRequestFromWire(value: unknown, where = "request"): SignRequest {
  const raw = requireObject(where, value);
  const grant = grantFromWire(`${where}.grant`, raw.grant);
  const req: SignRequest = {
    grant,
    dpopProof: requireNonEmptyString(`${where}.dpopProof`, raw.dpopProof),
    claims: claimsFromWire(raw.claims, `${where}.claims`),
    commitments: commitmentsFromWire(raw.commitments, `${where}.commitments`),
    refreshCommitments: commitmentsFromWire(
      raw.refreshCommitments,
      `${where}.refreshCommitments`
    ),
    allParticipants: requireIntegerArray(`${where}.allParticipants`, raw.allParticipants),
  };
  // Exactly the credential the grant names is read. The other field is ignored rather
  // than refused, so a gateway that always sends both cannot pick which one is verified.
  if (grant === "authorization_code") {
    req.assertion = requireNonEmptyString(`${where}.assertion`, raw.assertion);
  } else {
    req.refreshToken = requireNonEmptyString(`${where}.refreshToken`, raw.refreshToken);
  }
  if (raw.refreshExp !== undefined) {
    req.refreshExp = requireInteger(`${where}.refreshExp`, raw.refreshExp);
  }
  return req;
}

export function signResponseToWire(res: SignResponse): SignResponseWire {
  const share = (signed: SignResponse["at"]): SignedShareWire => ({
    commitment: commitmentPairToWire(signed.commitment),
    z_i: signed.z_i,
  });
  return { nodeId: res.nodeId, at: share(res.at), rt: share(res.rt) };
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

export function signEnvelopeFromWire(value: unknown): SignRounds & { request: SignRequest } {
  const raw = requireObject("body", value);
  const rounds: SignRounds = {
    accessRoundId: requireNonEmptyString("body.roundId", raw.roundId),
    refreshRoundId: requireNonEmptyString("body.refreshRoundId", raw.refreshRoundId),
  };
  if (rounds.accessRoundId === rounds.refreshRoundId) {
    throw new WireError("body.refreshRoundId must differ from body.roundId");
  }
  return { ...rounds, request: signRequestFromWire(raw.request, "body.request") };
}
