import { ed25519 } from '@noble/curves/ed25519';
import { base64urlDecode } from './builder.js';

export interface DecodedJwt<T = Record<string, unknown>> {
  header: {
    alg: string;
    typ?: string;
    kid?: string;
    [key: string]: unknown;
  };
  payload: T;
  signature: Uint8Array;
  signingInput: string;
}

/**
 * Decodes a compact JWT string into its components (header, payload, signature).
 *
 * @param token Compact JWT string "header.payload.signature"
 */
export function decodeJwt<T = Record<string, unknown>>(token: string): DecodedJwt<T> {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error(`Invalid JWT format: expected 3 dot-separated parts, got ${parts.length}`);
  }

  const [headerB64, payloadB64, sigB64] = parts;
  const headerJson = new TextDecoder().decode(base64urlDecode(headerB64));
  const payloadJson = new TextDecoder().decode(base64urlDecode(payloadB64));
  const signature = base64urlDecode(sigB64);

  const header = JSON.parse(headerJson);
  const payload = JSON.parse(payloadJson);
  const signingInput = `${headerB64}.${payloadB64}`;

  return {
    header,
    payload,
    signature,
    signingInput,
  };
}

/**
 * Verifies a JWT token using standard Ed25519 verification.
 * Supports verifying with @noble/curves/ed25519.
 *
 * @param token Compact JWT string
 * @param publicKey 32-byte Ed25519 public key
 * @returns true if signature is valid, false otherwise
 */
export function verifyJwt(token: string, publicKey: Uint8Array): boolean {
  if (!token || publicKey.length !== 32) {
    return false;
  }

  const lastDot = token.lastIndexOf('.');
  if (lastDot === -1) {
    return false;
  }

  const signingInput = token.slice(0, lastDot);
  const encodedSig = token.slice(lastDot + 1);

  let signature: Uint8Array;
  try {
    signature = base64urlDecode(encodedSig);
  } catch {
    return false;
  }

  if (signature.length !== 64) {
    return false;
  }

  const msgBytes = new TextEncoder().encode(signingInput);
  try {
    return ed25519.verify(signature, msgBytes, publicKey);
  } catch {
    return false;
  }
}
