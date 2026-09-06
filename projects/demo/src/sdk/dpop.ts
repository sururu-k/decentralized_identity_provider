import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { base64UrlEncode, deterministicJsonStringify } from "./jwt.js";

/**
 * Browser port of the gateway's `src/client-sdk/dpop.ts`
 * (docs/container-split.md section 11).
 *
 * Two changes: `crypto.randomUUID()` from `node:crypto` became
 * `globalThis.crypto.randomUUID()`, and `verifyDPoPProof` (plus its option/result
 * interfaces) is gone. Verification is a node's job, never the browser's, and the
 * reference implementation of it decoded with `Buffer.from(s, "base64url")`. The header
 * and payload of the proof, their key order and the signing input are untouched, so the
 * proofs this file produces are the same bytes the reference produced.
 */

export interface DPoPKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface DPoPJwk {
  kty: "OKP";
  crv: "Ed25519";
  x: string; // base64url encoded public key
}

export interface DPoPProofHeader {
  typ: "dpop+jwt";
  alg: "EdDSA";
  jwk: DPoPJwk;
}

export interface DPoPProofPayload {
  jti: string;
  htm: string;
  htu: string;
  iat: number;
  ath?: string;
  [key: string]: any;
}

/**
 * Generate RFC 9449 compliant Ed25519 DPoP key pair (ephemeral key)
 */
export function generateDPoPKeyPair(): DPoPKeyPair {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

/**
 * Export public key to RFC 7638 / RFC 9449 JWK format
 */
export function exportDPoPJwk(publicKey: Uint8Array): DPoPJwk {
  return {
    kty: "OKP",
    crv: "Ed25519",
    x: base64UrlEncode(publicKey),
  };
}

/**
 * Compute RFC 7638 JWK Thumbprint (cnf.jkt) using SHA-256 base64url
 * For OKP (Ed25519), the required lexicographical keys are: crv, kty, x
 */
export function calculateJwkThumbprint(jwk: DPoPJwk): string {
  const canonical = deterministicJsonStringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
  });
  const hash = sha256(new TextEncoder().encode(canonical));
  return base64UrlEncode(hash);
}

/**
 * Generate RFC 9449 DPoP proof JWT
 *
 * @param keyPair DPoP ephemeral key pair
 * @param htm HTTP method (e.g. "POST")
 * @param htu HTTP URI (normalized URI without query or fragment)
 * @param accessToken Optional access token for calculating 'ath' (RFC 9449 §4.2)
 */
export function createDPoPProof(
  keyPair: DPoPKeyPair,
  htm: string,
  htu: string,
  accessToken?: string
): string {
  const jwk = exportDPoPJwk(keyPair.publicKey);
  const header: DPoPProofHeader = {
    typ: "dpop+jwt",
    alg: "EdDSA",
    jwk,
  };

  const payload: DPoPProofPayload = {
    jti: globalThis.crypto.randomUUID(),
    htm: htm.toUpperCase(),
    htu,
    iat: Math.floor(Date.now() / 1000),
  };

  if (accessToken) {
    const atHash = sha256(new TextEncoder().encode(accessToken));
    payload.ath = base64UrlEncode(atHash);
  }

  const headerB64 = base64UrlEncode(deterministicJsonStringify(header));
  const payloadB64 = base64UrlEncode(deterministicJsonStringify(payload));
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);

  const signature = ed25519.sign(signingInput, keyPair.privateKey);
  const sigB64 = base64UrlEncode(signature);

  return `${headerB64}.${payloadB64}.${sigB64}`;
}
