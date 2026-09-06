import { FrostCommitment } from "../crypto/frost.js";

/**
 * In-process shapes of the node protocol.
 *
 * These are the type declarations of the monolith's `src/protocol/node.ts`, copied field
 * for field. The `IdentityNode` class itself is not part of this project: the gateway
 * only ever talks to a node over HTTP (`docs/container-split.md` section 5), so it needs
 * the request and response shapes and nothing else.
 *
 * Byte strings here follow the in-process convention of the original: `blinded`,
 * `sessionNonce`, `toprfPartial` and `ct_i` are already base64url strings, while a FROST
 * commitment carries raw `Uint8Array` points. The wire form of section 3 base64url
 * encodes the latter; see `src/nodes/wire.ts`.
 */

export interface SignOnRequest {
  sessionId: string;
  username: string;
  blinded: string; // base64url of Ristretto255 point A = r * H1(password)
  sessionNonce: string; // base64url of 16-byte random session nonce
  cnfJkt: string;
  nonce?: string;
  iat: number;
  exp: number;
  aud: string;
  iss: string;
  commitments: FrostCommitment[];
  allParticipants: number[];
}

export interface SignOnResponse {
  nodeId: number;
  commitment: { D: Uint8Array; E: Uint8Array };
  toprfPartial: string; // base64url of Ristretto255 point B_i = k_i * A
  ct_i: string; // base64url of ChaCha20-Poly1305 ciphertext { z_i, rs_i }
  sessionId: string;
  sub: string;
}

export interface RefreshRequest {
  sessionId: string;
  dpopProof: string;
  expectedHtu: string;
  nonce?: string;
  iat: number;
  exp: number;
  aud: string;
  iss: string;
  commitments: FrostCommitment[];
  allParticipants: number[];
}

export interface RefreshResponse {
  nodeId: number;
  commitment: { D: Uint8Array; E: Uint8Array };
  ct_i: string; // base64url of ChaCha20-Poly1305 ciphertext
  ctr: number;
  sub: string;
}
