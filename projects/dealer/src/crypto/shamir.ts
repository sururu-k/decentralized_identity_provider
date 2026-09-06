import { ed25519 } from '@noble/curves/ed25519';

/**
 * The order of the Ed25519 prime-order subgroup / scalar field:
 * ℓ = 2^252 + 27742317777372353535851937790883648493
 */
export const ED25519_ORDER: bigint = ed25519.CURVE.n;

/**
 * Participant identifier (positive integer, e.g. 1, 2, ...).
 */
export type ParticipantId = number;

/**
 * A secret share evaluated at participant's ID.
 */
export interface Share {
  id: ParticipantId;
  value: bigint;
}

/**
 * Standard positive modulo arithmetic.
 */
export function mod(a: bigint, m: bigint = ED25519_ORDER): bigint {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

/**
 * Modular inverse using Fermat's Little Theorem: a^(p-2) mod p.
 */
export function invert(a: bigint, m: bigint = ED25519_ORDER): bigint {
  const norm = mod(a, m);
  if (norm === 0n) {
    throw new Error('Zero has no modular inverse');
  }
  return modPow(norm, m - 2n, m);
}

/**
 * Modular exponentiation: (base^exp) mod m.
 */
export function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let res = 1n;
  let b = mod(base, m);
  let e = exp;
  while (e > 0n) {
    if ((e & 1n) === 1n) {
      res = mod(res * b, m);
    }
    b = mod(b * b, m);
    e >>= 1n;
  }
  return res;
}

/**
 * Converts little-endian bytes to a BigInt.
 */
export function bytesToBigIntLE(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    acc = (acc << 8n) | BigInt(bytes[i]);
  }
  return acc;
}

/**
 * Converts a BigInt to a little-endian Uint8Array of fixed length (default 32 bytes).
 */
export function bigIntToBytesLE(value: bigint, length: number = 32): Uint8Array {
  const norm = mod(value, ED25519_ORDER);
  const out = new Uint8Array(length);
  let cur = norm;
  for (let i = 0; i < length; i++) {
    out[i] = Number(cur & 0xffn);
    cur >>= 8n;
  }
  return out;
}

/**
 * Converts 32-byte canonical little-endian representation to scalar mod ℓ.
 */
export function bytesToScalar(bytes: Uint8Array): bigint {
  return mod(bytesToBigIntLE(bytes), ED25519_ORDER);
}

/**
 * Converts scalar to 32-byte canonical little-endian representation.
 */
export function scalarToBytes(scalar: bigint): Uint8Array {
  return bigIntToBytesLE(scalar, 32);
}

/**
 * Generates a cryptographically uniform random scalar mod ℓ by taking 64 bytes
 * of OS entropy and reducing mod ℓ (equivalent to Scalar::from_bytes_mod_order_wide).
 */
export function randomScalar(): bigint {
  const bytes = new Uint8Array(64);
  globalThis.crypto.getRandomValues(bytes);
  return mod(bytesToBigIntLE(bytes), ED25519_ORDER);
}

/**
 * Splits a secret scalar into n shares with threshold t using Shamir's secret sharing scheme.
 * The polynomial is f(x) = secret + c_1*x + ... + c_{t-1}*x^{t-1} mod ℓ.
 * Participant IDs are 1-indexed (1, 2, ..., total).
 *
 * @param secret The secret scalar to share (f(0) = secret).
 * @param threshold The minimum number of shares required to reconstruct the secret (t).
 * @param total The total number of shares to produce (n).
 */
export function splitSecret(secret: bigint, threshold: number, total: number): Share[] {
  if (threshold < 1 || threshold > total) {
    throw new Error(`Invalid threshold: must satisfy 1 <= threshold (${threshold}) <= total (${total})`);
  }

  // Generate random coefficients c_1, ..., c_{t-1}
  const coeffs: bigint[] = [];
  for (let i = 1; i < threshold; i++) {
    coeffs.push(randomScalar());
  }

  const shares: Share[] = [];
  for (let id = 1; id <= total; id++) {
    const x = BigInt(id);
    // Evaluate f(x) using Horner's method
    let acc = 0n;
    for (let j = coeffs.length - 1; j >= 0; j--) {
      acc = mod(mod(acc * x, ED25519_ORDER) + coeffs[j], ED25519_ORDER);
    }
    const val = mod(mod(acc * x, ED25519_ORDER) + secret, ED25519_ORDER);
    shares.push({ id, value: val });
  }

  return shares;
}

/**
 * Computes the Lagrange basis polynomial coefficient λ_i(0) for participant `targetId`
 * evaluated at 0 with respect to the set of participant `ids`:
 * λ_i(0) = ∏_{j ∈ ids, j ≠ i} (x_j / (x_j - x_i)) mod ℓ.
 */
export function lagrangeCoeff(ids: number[], targetId: number): bigint {
  const xi = BigInt(targetId);
  let num = 1n;
  let den = 1n;

  for (const j of ids) {
    if (j === targetId) continue;
    const xj = BigInt(j);
    num = mod(num * xj, ED25519_ORDER);
    den = mod(den * (xj - xi), ED25519_ORDER);
  }

  return mod(num * invert(den, ED25519_ORDER), ED25519_ORDER);
}

/**
 * Combines t or more shares using Lagrange interpolation to reconstruct the secret scalar.
 * Reconstructed secret = ∑_{i} λ_i(0) * y_i mod ℓ.
 *
 * @param shares Array of shares from distinct participants.
 */
export function combineShares(shares: Share[]): bigint {
  if (shares.length === 0) {
    throw new Error('At least one share is required to combine');
  }

  const ids = shares.map((s) => s.id);
  const uniqueIds = new Set(ids);
  if (uniqueIds.size !== ids.length) {
    throw new Error('Duplicate participant IDs found in shares');
  }

  let secret = 0n;
  for (const s of shares) {
    const lambda = lagrangeCoeff(ids, s.id);
    secret = mod(secret + mod(lambda * s.value, ED25519_ORDER), ED25519_ORDER);
  }

  return secret;
}
