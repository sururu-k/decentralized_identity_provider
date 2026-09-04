import { sha512 } from '@noble/hashes/sha512';

/**
 * Time quantum for rounding iat (in seconds) to absorb clock skew across nodes.
 */
export const TIME_QUANTUM: number = 30;

/**
 * Access token lifetime (in seconds).
 */
export const TOKEN_LIFETIME: number = 300;

/**
 * Rounds unix timestamp (in seconds) down to nearest TIME_QUANTUM multiple.
 */
export function quantizeTime(unixSeconds: number): number {
  return unixSeconds - (unixSeconds % TIME_QUANTUM);
}

/**
 * Base64URL encoding without padding (RFC 4648 Section 5).
 */
export function base64urlEncode(input: Uint8Array | string): string {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Base64URL decoding without padding.
 */
export function base64urlDecode(input: string): Uint8Array {
  let base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

function u64ToBytesLE(n: number | bigint): Uint8Array {
  const buf = new Uint8Array(8);
  const view = new DataView(buf.buffer);
  view.setBigUint64(0, BigInt(n), true);
  return buf;
}

/**
 * Deterministically derives JWT ID (jti) from username, session nonce, and iat.
 * All nodes arrive at the exact same jti without coordination.
 */
export function deriveJti(username: string, sessionNonce: Uint8Array, iat: number): string {
  const prefix = new TextEncoder().encode('PASTA-JTI');
  const userBytes = new TextEncoder().encode(username);
  const iatBytes = u64ToBytesLE(iat);

  const input = new Uint8Array(prefix.length + userBytes.length + sessionNonce.length + iatBytes.length);
  let offset = 0;
  input.set(prefix, offset);
  offset += prefix.length;
  input.set(userBytes, offset);
  offset += userBytes.length;
  input.set(sessionNonce, offset);
  offset += sessionNonce.length;
  input.set(iatBytes, offset);

  const digest = sha512(input);
  return bytesToHex(digest.slice(0, 16));
}

function escapeJsonString(str: string): string {
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if (code < 0x20 || (code >= 0x7f && code <= 0x9f)) {
      throw new Error('Control characters not allowed in claims');
    }
  }
  return str.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

export interface JwtClaims {
  iss: string;
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  jti: string;
  cnfJkt: string;
}

/**
 * Builds deterministic JSON representation of JWT claims with fixed key order and no whitespace.
 * Exactly matches Rust implementation format:
 * {"iss":"...","sub":"...","aud":"...","iat":...,"exp":...,"jti":"...","cnf":{"jkt":"..."}}
 */
export function claimsToJson(claims: JwtClaims): string {
  return (
    `{"iss":"${escapeJsonString(claims.iss)}"` +
    `,"sub":"${escapeJsonString(claims.sub)}"` +
    `,"aud":"${escapeJsonString(claims.aud)}"` +
    `,"iat":${claims.iat}` +
    `,"exp":${claims.exp}` +
    `,"jti":"${escapeJsonString(claims.jti)}"` +
    `,"cnf":{"jkt":"${escapeJsonString(claims.cnfJkt)}"}}`
  );
}

/**
 * Builds standard EdDSA JWT header JSON:
 * {"alg":"EdDSA","typ":"JWT","kid":"..."}
 */
export function buildHeader(kid: string): string {
  return `{"alg":"EdDSA","typ":"JWT","kid":"${escapeJsonString(kid)}"}`;
}

/**
 * Builds JWT signing input:
 * base64url(header) || "." || base64url(payload)
 */
export function buildSigningInput(headerJson: string, payloadJson: string): string {
  return `${base64urlEncode(headerJson)}.${base64urlEncode(payloadJson)}`;
}

/**
 * Assembles final compact JWT string:
 * signingInput || "." || base64url(signature)
 */
export function assembleJwt(signingInput: string, signature: Uint8Array): string {
  return `${signingInput}.${base64urlEncode(signature)}`;
}
