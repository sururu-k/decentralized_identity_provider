/**
 * Hex encoding helpers for dealer output files.
 *
 * Encoding contract (docs/container-split.md section 3):
 * secrets files carry byte strings and scalars as lowercase hex.
 * A scalar (bigint) is 64 hex digits: 32 bytes, big-endian, zero padded.
 */

/** Encodes a byte string as lowercase hex. */
export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

/** Decodes a lowercase or uppercase hex string into bytes. */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error(`Invalid hex length: ${hex.length}`);
  }
  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("Invalid hex string");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Encodes a scalar as 64 lowercase hex digits (32 bytes, big-endian, zero padded). */
export function scalarToHex(scalar: bigint): string {
  if (scalar < 0n) {
    throw new Error("Scalar must be non-negative");
  }
  const hex = scalar.toString(16);
  if (hex.length > 64) {
    throw new Error("Scalar does not fit in 32 bytes");
  }
  return hex.padStart(64, "0");
}

/** Decodes a 64 hex digit scalar (32 bytes, big-endian). */
export function hexToScalar(hex: string): bigint {
  if (hex.length !== 64) {
    throw new Error(`Expected 64 hex digits, got ${hex.length}`);
  }
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error("Invalid hex string");
  }
  return BigInt("0x" + hex);
}
