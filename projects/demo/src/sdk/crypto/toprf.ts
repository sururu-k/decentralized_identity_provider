import { ristretto255 } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import {
  ED25519_ORDER,
  ParticipantId,
  Share,
  invert,
  lagrangeCoeff,
  mod,
  randomScalar,
  splitSecret,
} from './shamir.js';

export type RistrettoPoint = typeof ristretto255.Point.BASE;

export interface Blinding {
  r: bigint;
}

export interface PartialEvaluation {
  id: ParticipantId;
  point: RistrettoPoint;
}

function toBytes(input: Uint8Array | string): Uint8Array {
  return typeof input === 'string' ? new TextEncoder().encode(input) : input;
}

function u64ToBytesLE(n: number | bigint): Uint8Array {
  const buf = new Uint8Array(8);
  const view = new DataView(buf.buffer);
  view.setBigUint64(0, BigInt(n), true);
  return buf;
}

function u16ToBytesLE(n: number): Uint8Array {
  const buf = new Uint8Array(2);
  const view = new DataView(buf.buffer);
  view.setUint16(0, n, true);
  return buf;
}

/**
 * H_1: Maps a password to a point on Ristretto255 curve.
 * Hash to uniform 64 bytes with SHA-512, then map to Ristretto255 group.
 */
export function hashToGroup(password: Uint8Array | string): RistrettoPoint {
  const pw = toBytes(password);
  const prefix = new TextEncoder().encode('PASTA-TOPRF-H2');
  const lenBytes = u64ToBytesLE(pw.length);

  const input = new Uint8Array(prefix.length + lenBytes.length + pw.length);
  input.set(prefix, 0);
  input.set(lenBytes, prefix.length);
  input.set(pw, prefix.length + lenBytes.length);

  const digest = sha512(input);
  return ristretto255.Point.hashToCurve(digest);
}

/**
 * Client-side blinding:
 * Computes A = r * H_1(pw) where r is a secret random scalar.
 *
 * @param password User's password
 * @returns Secret blinding factor `r` and blinded group point `A`.
 */
export function blind(password: Uint8Array | string): {
  blinding: Blinding;
  blinded: RistrettoPoint;
} {
  const r = randomScalar();
  const h1 = hashToGroup(password);
  const A = h1.multiply(r);
  return { blinding: { r }, blinded: A };
}

/**
 * Server i partial evaluation:
 * Computes B_i = k_i * A
 * The server learns nothing about the password due to the blinding factor r and discrete log.
 *
 * @param keyShare Server i's share of the TOPRF key
 * @param blinded The blinded point A from client
 */
export function evaluate(keyShare: Share, blinded: RistrettoPoint): RistrettoPoint {
  return blinded.multiply(keyShare.value);
}

/**
 * Client-side unblinding:
 * Combines partial evaluations using Lagrange interpolation:
 * C = ∑ λ_i * B_i
 * v = r^(-1) * C = H_1(pw)^k
 *
 * @param blinding Blinding factor containing secret r
 * @param partials Array of partial evaluations from servers (id and B_i)
 */
export function unblind(
  blinding: Blinding,
  partials: Array<{ id: ParticipantId; point: RistrettoPoint }>
): RistrettoPoint {
  if (partials.length === 0) {
    throw new Error('At least one partial evaluation is required');
  }

  const ids = partials.map((p) => p.id);
  let combined = ristretto255.Point.ZERO;

  for (const partial of partials) {
    const lambda = lagrangeCoeff(ids, partial.id);
    const term = partial.point.multiply(lambda);
    combined = combined.add(term);
  }

  const rInv = invert(blinding.r, ED25519_ORDER);
  return combined.multiply(rInv);
}

/**
 * H_2: X × G -> {0, 1}^256.
 * Finalizes PRF value: h = H_2(password, v).
 *
 * @param password User's password
 * @param v Unblinded group point
 * @returns 32-byte master PRF output h
 */
export function finalize(password: Uint8Array | string, v: RistrettoPoint): Uint8Array {
  const pw = toBytes(password);
  const prefix = new TextEncoder().encode('PASTA-TOPRF-H1');
  const lenBytes = u64ToBytesLE(pw.length);
  const vBytes = v.toRawBytes();

  const input = new Uint8Array(prefix.length + lenBytes.length + pw.length + vBytes.length);
  let offset = 0;
  input.set(prefix, offset);
  offset += prefix.length;
  input.set(lenBytes, offset);
  offset += lenBytes.length;
  input.set(pw, offset);
  offset += pw.length;
  input.set(vBytes, offset);

  const digest = sha512(input);
  return digest.slice(0, 32);
}

/**
 * H_3: Derives server i-specific key h_i = H_3(h, i).
 * Uses SHA-512 matching PASTA specification to prevent client impersonation.
 *
 * @param h Master PRF output (32 bytes)
 * @param id Server participant ID
 * @returns 32-byte server key h_i
 */
export function deriveServerKey(h: Uint8Array, id: ParticipantId): Uint8Array {
  const prefix = new TextEncoder().encode('PASTA-TOPRF-H-PRIME');
  const idBytes = u16ToBytesLE(id);

  const input = new Uint8Array(prefix.length + h.length + idBytes.length);
  input.set(prefix, 0);
  input.set(h, prefix.length);
  input.set(idBytes, prefix.length + h.length);

  const digest = sha512(input);
  return digest.slice(0, 32);
}

/**
 * Optional HKDF-based server key derivation (H_3 via HKDF-SHA256).
 */
export function deriveServerKeyHkdf(h: Uint8Array, id: ParticipantId): Uint8Array {
  const info = new Uint8Array(new TextEncoder().encode(`PASTA-TOPRF-SERVER-KEY-${id}`));
  return hkdf(sha256, h, undefined, info, 32);
}

/**
 * Generates a client-specific TOPRF key and shares it via (t, n) Shamir secret sharing.
 * Generated once per client during registration.
 *
 * @param total Number of servers (n)
 * @param threshold Threshold number of servers (t)
 */
export function generateToprfKey(total: number, threshold: number): Share[] {
  const masterKey = randomScalar();
  return splitSecret(masterKey, threshold, total);
}
