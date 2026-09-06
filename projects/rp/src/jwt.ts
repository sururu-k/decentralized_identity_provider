import crypto from "node:crypto";
import type { Jwk } from "./jwks.js";

/**
 * Minimal, self-contained JWT handling for the Relying Party.
 *
 * This deliberately shares no code with the IdP: parsing is plain base64url +
 * JSON.parse, and signature verification is `node:crypto` treating the token as
 * an ordinary EdDSA (Ed25519) JWS. If this file verifies a token, any standard
 * OIDC library would too.
 */

export interface JwtHeader {
  alg?: string;
  typ?: string;
  kid?: string;
  [key: string]: unknown;
}

export interface JwtPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  nbf?: number;
  nonce?: string;
  [key: string]: unknown;
}

export interface DecodedJwt {
  header: JwtHeader;
  payload: JwtPayload;
  signature: Buffer;
  /** The exact ASCII bytes covered by the signature: "<headerB64>.<payloadB64>". */
  signingInput: string;
}

/** Clock skew tolerated on `iat` / `nbf`, in seconds. */
export const CLOCK_SKEW_SECONDS = 60;

const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

/**
 * Decodes one base64url segment. Rejects any character outside the base64url
 * alphabet rather than silently dropping it the way Buffer does.
 */
export function base64UrlDecode(segment: string): Buffer {
  if (!BASE64URL_RE.test(segment)) {
    throw new Error("Invalid base64url segment");
  }
  return Buffer.from(segment, "base64url");
}

function decodeJsonSegment(segment: string, what: string): Record<string, unknown> {
  let text: string;
  try {
    text = base64UrlDecode(segment).toString("utf8");
  } catch {
    throw new Error(`Malformed JWT: ${what} is not valid base64url`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`Malformed JWT: ${what} is not valid JSON`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(`Malformed JWT: ${what} is not a JSON object`);
  }
  return parsed as Record<string, unknown>;
}

/** Splits a compact JWS into header / payload / signature. Throws if malformed. */
export function decodeJwt(token: string): DecodedJwt {
  if (typeof token !== "string" || token.length === 0) {
    throw new Error("Malformed JWT: empty token");
  }
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error(`Malformed JWT: expected 3 dot-separated parts, got ${parts.length}`);
  }
  const [headerB64, payloadB64, signatureB64] = parts;
  const header = decodeJsonSegment(headerB64, "header") as JwtHeader;
  const payload = decodeJsonSegment(payloadB64, "payload") as JwtPayload;

  let signature: Buffer;
  try {
    signature = base64UrlDecode(signatureB64);
  } catch {
    throw new Error("Malformed JWT: signature is not valid base64url");
  }

  return { header, payload, signature, signingInput: `${headerB64}.${payloadB64}` };
}

/**
 * Verifies the Ed25519 signature with the given JWK.
 *
 * Only `kty` / `crv` / `x` are handed to node:crypto; JWKS bookkeeping fields
 * such as `kid`, `use` and `alg` are not part of the key material.
 */
export function verifySignature(decoded: DecodedJwt, jwk: Jwk): boolean {
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
    return false;
  }
  if (jwk.alg !== undefined && jwk.alg !== "EdDSA") {
    return false;
  }
  if (decoded.signature.length !== 64) {
    return false;
  }
  const key = { kty: "OKP", crv: "Ed25519", x: jwk.x };
  try {
    return crypto.verify(
      null,
      Buffer.from(decoded.signingInput, "ascii"),
      { key, format: "jwk" },
      decoded.signature
    );
  } catch {
    return false;
  }
}

export interface ClaimCheckOptions {
  issuer: string;
  clientId: string;
  /** Current time in seconds since the epoch. Defaults to the wall clock. */
  now?: number;
}

/**
 * Compares the `iss` claim with the configured issuer, ignoring a trailing
 * slash on either side.
 *
 * `http://idp` and `http://idp/` name the same issuer, but the IdP does not
 * normalise its own `ISSUER` while this RP has to strip the slash to join paths
 * onto it. Without this, giving both services the identical `ISSUER=.../` would
 * make every token fail here. Nothing but trailing slashes is normalised, so
 * two different issuers can still never compare equal.
 */
function sameIssuer(claim: unknown, expected: string): boolean {
  if (typeof claim !== "string") return false;
  return claim.replace(/\/+$/, "") === expected.replace(/\/+$/, "");
}

/** Returns an error message, or `null` when every claim check passes. */
export function validateClaims(payload: JwtPayload, options: ClaimCheckOptions): string | null {
  const now = options.now ?? Math.floor(Date.now() / 1000);

  if (!sameIssuer(payload.iss, options.issuer)) {
    return `iss mismatch: expected "${options.issuer}", got "${String(payload.iss)}"`;
  }

  const aud = payload.aud;
  const audList = Array.isArray(aud) ? aud : aud === undefined ? [] : [aud];
  if (!audList.includes(options.clientId)) {
    return `aud mismatch: expected "${options.clientId}", got "${JSON.stringify(aud)}"`;
  }

  if (typeof payload.exp !== "number" || !Number.isFinite(payload.exp)) {
    return "exp claim is missing or is not a number";
  }
  if (payload.exp <= now) {
    return "token has expired";
  }

  if (typeof payload.nbf === "number" && payload.nbf > now + CLOCK_SKEW_SECONDS) {
    return "token is not valid yet (nbf)";
  }
  if (typeof payload.iat === "number" && payload.iat > now + CLOCK_SKEW_SECONDS) {
    return "token was issued in the future (iat)";
  }

  return null;
}

/** Verifies the alg header, the signature and the claim set in one call. */
export function verifyIdToken(
  decoded: DecodedJwt,
  jwk: Jwk,
  options: ClaimCheckOptions
): { valid: boolean; error?: string } {
  if (decoded.header.alg !== "EdDSA") {
    return { valid: false, error: `unsupported alg: ${String(decoded.header.alg)}` };
  }
  if (!verifySignature(decoded, jwk)) {
    return { valid: false, error: "Ed25519 signature verification failed" };
  }
  const claimError = validateClaims(decoded.payload, options);
  if (claimError) {
    return { valid: false, error: claimError };
  }
  return { valid: true };
}
