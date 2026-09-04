import type { ParticipantId, Share } from '../crypto/shamir.js';
import type { Commitment, Nonces } from '../crypto/tsign.js';
import type { Blinding } from '../crypto/toprf.js';

export type { ParticipantId, Share, Commitment, Nonces, Blinding };

/**
 * Public metadata of the IdP distributed service, published e.g. at /.well-known/openid-configuration.
 */
export interface IdpMetadata {
  issuer: string;
  audience: string;
  kid: string;
  publicKey: Uint8Array; // 32 bytes compressed Ed25519 public key Y
}

/**
 * Record stored on each IdP node for a registered user.
 */
export interface UserRecord {
  toprfKeyShare: Share;
  serverKey: Uint8Array; // 32 bytes h_i = H'(h, i)
}

/**
 * Round 2 request sent by client to each IdP node.
 * Notice: the target payload itself is NOT included in the request.
 * The node constructs the payload from its own internal record.
 */
export interface SignOnRequest {
  username: string;
  blinded: Uint8Array; // 32 bytes compressed Ristretto255 point A
  cnfJkt: string;
  sessionNonce: Uint8Array; // 16 bytes random session nonce
  iat: number; // Unix timestamp in seconds proposed by client
  commitments: Commitment[]; // Complete set of Round 1 commitments
}

/**
 * Round 2 response returned by each IdP node.
 */
export interface SignOnResponse {
  id: ParticipantId;
  toprfPartial: Uint8Array; // 32 bytes compressed Ristretto255 point B_i
  ciphertext: Uint8Array; // ChaCha20-Poly1305 ciphertext containing z_i
}

/**
 * Client-side in-flight sign-on state kept between Round 1 and completion.
 */
export interface PendingSignOn {
  blinding: Blinding;
  username: string;
  cnfJkt: string;
  sessionNonce: Uint8Array;
  iat: number;
  commitments: Commitment[];
}

/**
 * Standard protocol error codes.
 */
export type ProtocolErrorCode =
  | 'UnknownUser'
  | 'ClockSkew'
  | 'NoPreprocessedNonce'
  | 'AuthenticationFailed'
  | 'NotEnoughShares'
  | 'InvalidSignature';

export class ProtocolError extends Error {
  readonly code: ProtocolErrorCode;

  constructor(code: ProtocolErrorCode, message?: string) {
    super(message || code);
    this.name = 'ProtocolError';
    this.code = code;
  }
}
