import crypto from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { base64UrlDecode, base64UrlEncode, deterministicJsonStringify } from "../jwt/jwt.js";
import { verifyEd25519 } from "../crypto/frost.js";

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
    jti: crypto.randomUUID(),
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

export interface VerifyDPoPProofOptions {
  expectedHtm: string;
  expectedHtu: string;
  expectedJkt?: string;
  maxAgeSeconds?: number;
}

export interface VerifyDPoPProofResult {
  valid: boolean;
  jkt?: string;
  payload?: DPoPProofPayload;
  error?: string;
}

/**
 * Verify DPoP proof JWT according to RFC 9449 §4.3
 */
export function verifyDPoPProof(
  proofJwt: string,
  options: VerifyDPoPProofOptions
): VerifyDPoPProofResult {
  try {
    const parts = proofJwt.split(".");
    if (parts.length !== 3) {
      return { valid: false, error: "Invalid DPoP proof JWT format" };
    }
    const [headerB64, payloadB64, sigB64] = parts;

    const header = JSON.parse(Buffer.from(headerB64, "base64url").toString("utf8")) as DPoPProofHeader;
    const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8")) as DPoPProofPayload;
    const signature = base64UrlDecode(sigB64);

    if (header.typ !== "dpop+jwt") {
      return { valid: false, error: `Invalid typ: ${header.typ}, expected 'dpop+jwt'` };
    }
    if (header.alg !== "EdDSA") {
      return { valid: false, error: `Invalid alg: ${header.alg}, expected 'EdDSA'` };
    }
    if (!header.jwk || header.jwk.kty !== "OKP" || header.jwk.crv !== "Ed25519") {
      return { valid: false, error: "Invalid or missing OKP/Ed25519 jwk in header" };
    }

    const publicKey = base64UrlDecode(header.jwk.x);
    if (publicKey.length !== 32) {
      return { valid: false, error: "Invalid public key length in jwk" };
    }

    // Verify signature
    const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const sigValid = verifyEd25519(signature, signingInput, publicKey);
    if (!sigValid) {
      return { valid: false, error: "DPoP signature verification failed" };
    }

    // Verify htm and htu
    if (payload.htm.toUpperCase() !== options.expectedHtm.toUpperCase()) {
      return { valid: false, error: `htm mismatch: expected ${options.expectedHtm}, got ${payload.htm}` };
    }
    if (payload.htu !== options.expectedHtu) {
      return { valid: false, error: `htu mismatch: expected ${options.expectedHtu}, got ${payload.htu}` };
    }

    // Verify timestamp (freshness)
    const now = Math.floor(Date.now() / 1000);
    const maxAge = options.maxAgeSeconds ?? 300; // 5 minutes default
    if (Math.abs(now - payload.iat) > maxAge) {
      return { valid: false, error: "DPoP proof timestamp expired or out of allowed window" };
    }

    const jkt = calculateJwkThumbprint(header.jwk);
    if (options.expectedJkt && jkt !== options.expectedJkt) {
      return { valid: false, error: `DPoP thumbprint mismatch: expected ${options.expectedJkt}, got ${jkt}` };
    }

    return { valid: true, jkt, payload };
  } catch (err: any) {
    return { valid: false, error: err.message || String(err) };
  }
}
