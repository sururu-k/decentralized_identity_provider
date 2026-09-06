import { FrostCommitment } from "./crypto/frost.js";

/**
 * In-process shapes the client SDK works in.
 *
 * `SignOnResponse` / `RefreshResponse` are copied field for field from the gateway's
 * `src/protocol/types.ts`; `ProxySignOnResult` / `ProxyRefreshResult` from its
 * `src/gateway/proxy.ts`. The browser never runs `PastaOAuthProxy`, so only the result
 * shapes travel, not the class.
 *
 * Byte strings follow the original in-process convention: `blinded`, `sessionNonce`,
 * `toprfPartial` and `ct_i` are already base64url strings, while a FROST commitment
 * carries raw `Uint8Array` points. The wire form of section 3 base64url encodes the
 * latter too; see `wire.ts`.
 */

export interface SignOnResponse {
  nodeId: number;
  commitment: { D: Uint8Array; E: Uint8Array };
  toprfPartial: string; // base64url of Ristretto255 point B_i = k_i * A
  ct_i: string; // base64url of ChaCha20-Poly1305 ciphertext { z_i, rs_i }
  sessionId: string;
  sub: string;
}

export interface RefreshResponse {
  nodeId: number;
  commitment: { D: Uint8Array; E: Uint8Array };
  ct_i: string; // base64url of ChaCha20-Poly1305 ciphertext
  ctr: number;
  sub: string;
}

/** Request body of `POST /api/pasta/sign-on` (docs/container-split.md section 6). */
export interface ProxySignOnRequestBody {
  username: string;
  blinded: string; // base64url of Ristretto255 blinded point A
  sessionNonce: string; // base64url of session nonce
  cnfJkt: string;
  nonce?: string;
  iat: number;
  exp: number;
  aud: string;
  iss: string;
  participants?: number[];
}

export interface ProxySignOnResult {
  sessionId: string;
  commitments: FrostCommitment[];
  nodeResponses: SignOnResponse[];
}

/** Request body of `POST /api/pasta/refresh` (docs/container-split.md section 6). */
export interface ProxyRefreshRequestBody {
  sessionId: string;
  dpopProof: string;
  expectedHtu: string;
  nonce?: string;
  iat: number;
  exp: number;
  aud: string;
  iss: string;
  participants?: number[];
}

export interface ProxyRefreshResult {
  sessionId: string;
  commitments: FrostCommitment[];
  nodeResponses: RefreshResponse[];
}
