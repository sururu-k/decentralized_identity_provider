import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

/**
 * Derive refresh encryption key rk_i = HKDF(rs_i, ctr)
 * docs/refresh-token.md & docs/whiteboard-gaps.md Hole 5:
 * rk_i = HKDF(rs_i, ctr)
 *
 * Each distributed node uses this key to encrypt new signature shares during token refresh.
 * The client independently computes rk_i using the stored session secret rs_i and counter.
 */
export function deriveRefreshKey(rs_i: Uint8Array, ctr: number, sessionId: string): Uint8Array {
  const salt = Buffer.from(sessionId, "utf8");
  const info = Buffer.from(`pasta-refresh-ctr:${ctr}`, "utf8");
  return hkdf(sha256, rs_i, salt, info, 32);
}
