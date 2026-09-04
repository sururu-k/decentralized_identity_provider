import crypto from "node:crypto";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

export interface EncryptedPayload {
  iv: string; // base64url
  ciphertext: string; // base64url
  tag: string; // base64url
}

/**
 * Derive per-node encryption key h_i from password and node identifier.
 * In production PASTA this uses TOPRF evaluation; here we simulate the TOPRF output
 * using HKDF-SHA256 salted by username and info specifying the node index.
 */
export function deriveNodeKey(password: string, username: string, nodeId: number): Uint8Array {
  const ikm = Buffer.from(password, "utf8");
  const salt = Buffer.from(`pasta-toprf-salt:${username}`, "utf8");
  const info = Buffer.from(`pasta-node-key:${nodeId}`, "utf8");
  return hkdf(sha256, ikm, salt, info, 32);
}

/**
 * Derive refresh encryption key rk_i = HKDF(rs_i, ctr)
 * docs/refresh-token.md & docs/whiteboard-gaps.md Hole 5:
 * rk_i = HKDF(rs_i, ctr)
 */
export function deriveRefreshKey(rs_i: Uint8Array, ctr: number, sessionId: string): Uint8Array {
  const salt = Buffer.from(sessionId, "utf8");
  const info = Buffer.from(`pasta-refresh-ctr:${ctr}`, "utf8");
  return hkdf(sha256, rs_i, salt, info, 32);
}

/**
 * Encrypt plaintext using AES-256-GCM with optional AAD (e.g. signing payload).
 */
export function encryptAead(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array
): EncryptedPayload {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", Buffer.from(key), iv);
  if (aad) {
    cipher.setAAD(Buffer.from(aad));
  }
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    iv: iv.toString("base64url"),
    ciphertext: ct.toString("base64url"),
    tag: tag.toString("base64url"),
  };
}

/**
 * Decrypt AES-256-GCM encrypted payload with optional AAD.
 */
export function decryptAead(
  key: Uint8Array,
  payload: EncryptedPayload,
  aad?: Uint8Array
): Uint8Array {
  const iv = Buffer.from(payload.iv, "base64url");
  const ct = Buffer.from(payload.ciphertext, "base64url");
  const tag = Buffer.from(payload.tag, "base64url");

  const decipher = crypto.createDecipheriv("aes-256-gcm", Buffer.from(key), iv);
  decipher.setAuthTag(tag);
  if (aad) {
    decipher.setAAD(Buffer.from(aad));
  }

  return Buffer.concat([decipher.update(ct), decipher.final()]);
}
