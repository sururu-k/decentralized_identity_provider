import { verifyEd25519 } from "./crypto/frost.js";

/**
 * Browser port of the gateway's `src/jwt/jwt.ts` (docs/container-split.md section 11).
 *
 * Only the byte plumbing changed: `Buffer.from(...).toString("base64url")` became
 * `btoa` over a binary string with the base64url alphabet, and `Buffer.from(str,
 * "base64url")` became `atob` after re-padding. `deterministicJsonStringify`,
 * `createSigningInput` and `assembleJwt` are character-for-character the original, so the
 * signing input bytes a node authenticates as AEAD AAD are unchanged.
 */

export function base64UrlEncode(data: Uint8Array | string): string {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlDecode(str: string): Uint8Array {
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function deterministicJsonStringify(obj: any): string {
  if (obj === null || typeof obj !== "object") {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return "[" + obj.map(deterministicJsonStringify).join(",") + "]";
  }
  const keys = Object.keys(obj).sort();
  return (
    "{" +
    keys.map((k) => JSON.stringify(k) + ":" + deterministicJsonStringify(obj[k])).join(",") +
    "}"
  );
}

export interface IdTokenHeader {
  alg: "EdDSA";
  typ: "JWT";
  kid: string;
}

export interface IdTokenPayload {
  iss: string;
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  nonce?: string;
  cnf?: {
    jkt: string;
  };
  [key: string]: any;
}

/**
 * Creates deterministic signing input for JWT: base64url(header) + "." + base64url(payload)
 */
export function createSigningInput(
  header: object,
  payload: object
): { signingInput: Uint8Array; headerB64: string; payloadB64: string } {
  const headerJson = deterministicJsonStringify(header);
  const payloadJson = deterministicJsonStringify(payload);
  const headerB64 = base64UrlEncode(headerJson);
  const payloadB64 = base64UrlEncode(payloadJson);
  const rawInput = `${headerB64}.${payloadB64}`;
  return {
    signingInput: new TextEncoder().encode(rawInput),
    headerB64,
    payloadB64,
  };
}

/**
 * Assemble final JWT from parts
 */
export function assembleJwt(
  headerB64: string,
  payloadB64: string,
  signature: Uint8Array
): string {
  const sigB64 = base64UrlEncode(signature);
  return `${headerB64}.${payloadB64}.${sigB64}`;
}

export interface VerifyJwtResult {
  valid: boolean;
  header?: any;
  payload?: any;
  error?: string;
}

/**
 * Verifies standard Ed25519 JWT (EdDSA)
 */
export function verifyJwt(
  token: string,
  publicKey: Uint8Array,
  expected?: { iss?: string; aud?: string; nonce?: string }
): VerifyJwtResult {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) {
      return { valid: false, error: "Malformed JWT: expected 3 parts" };
    }
    const [headerB64, payloadB64, sigB64] = parts;
    const decoder = new TextDecoder();
    const header = JSON.parse(decoder.decode(base64UrlDecode(headerB64)));
    const payload = JSON.parse(decoder.decode(base64UrlDecode(payloadB64)));
    const signature = base64UrlDecode(sigB64);

    if (header.alg !== "EdDSA") {
      return { valid: false, error: `Unsupported alg: ${header.alg}` };
    }

    const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const isSigValid = verifyEd25519(signature, signingInput, publicKey);
    if (!isSigValid) {
      return { valid: false, error: "Invalid Ed25519 signature" };
    }

    const nowSec = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < nowSec) {
      return { valid: false, error: `Token expired (exp: ${payload.exp}, now: ${nowSec})` };
    }
    if (expected?.iss && payload.iss !== expected.iss) {
      return { valid: false, error: `Issuer mismatch: expected ${expected.iss}, got ${payload.iss}` };
    }
    if (expected?.aud && payload.aud !== expected.aud) {
      return { valid: false, error: `Audience mismatch: expected ${expected.aud}, got ${payload.aud}` };
    }
    if (expected?.nonce && payload.nonce !== expected.nonce) {
      return { valid: false, error: `Nonce mismatch: expected ${expected.nonce}, got ${payload.nonce}` };
    }

    return { valid: true, header, payload };
  } catch (err: any) {
    return { valid: false, error: err.message || String(err) };
  }
}
