import { FrostCommitment } from "./crypto/frost.js";

/**
 * In-process shapes the client SDK works in.
 *
 * `SignOnResponse` is copied field for field from the gateway's `src/protocol/types.ts`;
 * `ProxySignOnResult` from its `src/gateway/proxy.ts`. The browser never runs
 * `PastaOAuthProxy`, so only the result shapes travel, not the class. Since section 14 the
 * IdP front end does not refresh, so the refresh shapes are gone.
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
  ct_i: string; // base64url of ChaCha20-Poly1305 ciphertext { z_i }
  sessionId: string;
  sub: string;
}

/**
 * Request body of `POST /api/pasta/sign-on` (docs/container-split.md sections 6 and 14).
 * Since section 14 it carries the assertion's `clientId` and `scope`, `nonce` is the
 * authorize challenge `c`, and `aud` is the issuer (the assertion is addressed to the
 * gateway).
 */
export interface ProxySignOnRequestBody {
  username: string;
  blinded: string; // base64url of Ristretto255 blinded point A
  sessionNonce: string; // base64url of session nonce
  cnfJkt: string;
  nonce: string; // the authorize challenge c
  clientId: string;
  scope: string;
  iat: number;
  exp: number;
  aud: string; // the issuer; the assertion is addressed to the gateway
  iss: string;
  participants?: number[];
}

export interface ProxySignOnResult {
  sessionId: string;
  commitments: FrostCommitment[];
  nodeResponses: SignOnResponse[];
}
