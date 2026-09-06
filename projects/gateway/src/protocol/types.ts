import { FrostCommitment } from "../crypto/frost.js";

/**
 * In-process shapes of the node protocol (`docs/container-split.md` sections 5 and 14).
 *
 * These mirror the request and response shapes of `node/src/protocol/node.ts`. The
 * `IdentityNode` class itself is not part of this project: the gateway only ever talks to
 * a node over HTTP (section 5), so it needs the request and response shapes and nothing
 * else.
 *
 * Byte strings here follow the in-process convention of the original: `blinded`,
 * `sessionNonce`, `toprfPartial` and `ct_i` are already base64url strings, while a FROST
 * commitment carries raw `Uint8Array` points. The wire form of section 3 base64url
 * encodes the latter; see `src/nodes/wire.ts`. A FROST signature share `z_i` is a scalar,
 * carried in process as a `bigint` and on the wire as 64 lowercase hex digits.
 */

export interface SignOnRequest {
  sessionId: string;
  username: string;
  blinded: string; // base64url of Ristretto255 point A = r * H1(password)
  sessionNonce: string; // base64url of 16-byte random session nonce
  cnfJkt: string;
  /** OAuth `client_id`, signed into the assertion as the access token's future `aud`. */
  clientId: string;
  /** OAuth `scope`, signed into the assertion. May be empty. */
  scope: string;
  nonce?: string;
  iat: number;
  exp: number;
  iss: string;
  commitments: FrostCommitment[];
  allParticipants: number[];
}

export interface SignOnResponse {
  nodeId: number;
  commitment: { D: Uint8Array; E: Uint8Array };
  toprfPartial: string; // base64url of Ristretto255 point B_i = k_i * A
  ct_i: string; // base64url of ChaCha20-Poly1305 ciphertext of { z_i }
  sessionId: string;
  sub: string;
}

/** Which credential the caller spends at `/sign`. */
export type Grant = "authorization_code" | "refresh_token";

/** The access token claims the gateway pins, so every node signs the same bytes. */
export interface AccessTokenClaims {
  iat: number;
  exp: number;
  jti: string;
}

export interface SignRequest {
  grant: Grant;
  /** `authorization_code`: the assembled assertion, i.e. the code. */
  assertion?: string;
  /** `refresh_token`: a refresh token this group signed earlier. */
  refreshToken?: string;
  /** RFC 9449 proof for `POST <ISSUER>/token`, from the credential's DPoP key. */
  dpopProof: string;
  claims: AccessTokenClaims;
  /** `exp` of the new refresh token; the node defaults to `claims.iat` + 30 days. */
  refreshExp?: number;
  /** Round-1 commitments of the access token's round. */
  commitments: FrostCommitment[];
  /** Round-1 commitments of the refresh token's round. A different round, necessarily. */
  refreshCommitments: FrostCommitment[];
  allParticipants: number[];
}

/** One signature's half of a `/sign` answer: the node's commitment and its plaintext share. */
export interface SignedShare {
  commitment: { D: Uint8Array; E: Uint8Array };
  /** Plaintext FROST signature share (big-endian scalar). */
  z_i: bigint;
}

export interface SignResponse {
  nodeId: number;
  /** The access token. */
  at: SignedShare;
  /** The refresh token, signed in its own FROST round. */
  rt: SignedShare;
}
