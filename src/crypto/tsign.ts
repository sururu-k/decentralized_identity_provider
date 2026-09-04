import { ed25519 } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import {
  ED25519_ORDER,
  ParticipantId,
  Share,
  bytesToBigIntLE,
  bytesToScalar,
  lagrangeCoeff,
  mod,
  randomScalar,
  scalarToBytes,
  splitSecret,
} from './shamir.js';

export type ExtendedPoint = typeof ed25519.ExtendedPoint.BASE;

export interface Nonces {
  d: bigint;
  e: bigint;
}

export interface Commitment {
  id: ParticipantId;
  bigD: Uint8Array; // 32 bytes compressed Edwards point
  bigE: Uint8Array; // 32 bytes compressed Edwards point
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
 * Generates an Ed25519 group signing key split into (t, n) Shamir shares.
 * Returns the key shares and the compressed 32-byte group public key Y = s * B.
 */
export function generateKey(
  total: number,
  threshold: number
): {
  keyShares: Share[];
  publicKey: Uint8Array;
} {
  const masterSecret = randomScalar();
  const publicKeyPoint = ed25519.ExtendedPoint.BASE.multiply(masterSecret);
  const publicKey = publicKeyPoint.toRawBytes();
  const keyShares = splitSecret(masterSecret, threshold, total);
  return { keyShares, publicKey };
}

/**
 * Round 1: Each node generates nonces (d_i, e_i) and public commitments:
 * D_i = d_i * B, E_i = e_i * B.
 * Precomputable before knowing the message.
 */
export function commit(id: ParticipantId): {
  nonces: Nonces;
  commitment: Commitment;
} {
  const d = randomScalar();
  const e = randomScalar();
  const bigD = ed25519.ExtendedPoint.BASE.multiply(d).toRawBytes();
  const bigE = ed25519.ExtendedPoint.BASE.multiply(e).toRawBytes();

  return {
    nonces: { d, e },
    commitment: { id, bigD, bigE },
  };
}

/**
 * Deterministically encodes a set of participant commitments.
 * Commitments are sorted by participant ID.
 * Each entry is: id (2 bytes LE) || bigD (32 bytes) || bigE (32 bytes)
 */
export function encodeCommitments(commitments: Commitment[]): Uint8Array {
  const sorted = [...commitments].sort((a, b) => a.id - b.id);
  const out = new Uint8Array(sorted.length * 66);
  let offset = 0;
  for (const c of sorted) {
    out.set(u16ToBytesLE(c.id), offset);
    offset += 2;
    out.set(c.bigD, offset);
    offset += 32;
    out.set(c.bigE, offset);
    offset += 32;
  }
  return out;
}

/**
 * Computes FROST binding factor ρ_i for participant id:
 * ρ_i = SHA-512("PASTA-FROST-RHO" || id_le || msg_len_le || msg || encoded_commitments) mod ℓ
 */
export function bindingFactor(
  id: ParticipantId,
  message: Uint8Array,
  encodedCommitments: Uint8Array
): bigint {
  const prefix = new TextEncoder().encode('PASTA-FROST-RHO');
  const idBytes = u16ToBytesLE(id);
  const msgLenBytes = u64ToBytesLE(message.length);

  const input = new Uint8Array(
    prefix.length + idBytes.length + msgLenBytes.length + message.length + encodedCommitments.length
  );
  let offset = 0;
  input.set(prefix, offset);
  offset += prefix.length;
  input.set(idBytes, offset);
  offset += idBytes.length;
  input.set(msgLenBytes, offset);
  offset += msgLenBytes.length;
  input.set(message, offset);
  offset += message.length;
  input.set(encodedCommitments, offset);

  const digest = sha512(input);
  return mod(bytesToBigIntLE(digest), ED25519_ORDER);
}

/**
 * Computes the aggregate group commitment point R:
 * R_j = D_j + ρ_j * E_j
 * R = ∑_j R_j
 */
export function computeGroupCommitment(
  message: Uint8Array,
  commitments: Commitment[]
): ExtendedPoint {
  const encoded = encodeCommitments(commitments);
  let R = ed25519.ExtendedPoint.ZERO;

  for (const c of commitments) {
    const rho = bindingFactor(c.id, message, encoded);
    const bigD = ed25519.ExtendedPoint.fromHex(c.bigD);
    const bigE = ed25519.ExtendedPoint.fromHex(c.bigE);
    const Rj = bigD.add(bigE.multiply(rho));
    R = R.add(Rj);
  }

  return R;
}

/**
 * Computes standard Ed25519 challenge:
 * c = SHA-512(R || Y || message) mod ℓ
 *
 * Matching RFC 8032 standard challenge computation is essential for
 * verifying FROST signatures with any standard Ed25519 verifier.
 */
export function computeChallenge(
  R_bytes: Uint8Array,
  Y_bytes: Uint8Array,
  message: Uint8Array
): bigint {
  const input = new Uint8Array(32 + 32 + message.length);
  input.set(R_bytes, 0);
  input.set(Y_bytes, 32);
  input.set(message, 64);

  const digest = sha512(input);
  return mod(bytesToBigIntLE(digest), ED25519_ORDER);
}

/**
 * Round 2: Computes participant i's signature share z_i:
 * z_i = d_i + ρ_i * e_i + λ_i * s_i * c mod ℓ
 *
 * Fully linear local computation without any interaction or multiplication protocol.
 */
export function signShare(
  keyShare: Share,
  nonces: Nonces,
  message: Uint8Array,
  commitments: Commitment[],
  publicKeyBytes: Uint8Array
): bigint {
  const encoded = encodeCommitments(commitments);
  const rho = bindingFactor(keyShare.id, message, encoded);
  const R = computeGroupCommitment(message, commitments);
  const c = computeChallenge(R.toRawBytes(), publicKeyBytes, message);

  const ids = commitments.map((c) => c.id);
  const lambda = lagrangeCoeff(ids, keyShare.id);

  // z_i = (d_i + rho_i * e_i + lambda_i * s_i * c) mod ℓ
  const rho_e = mod(rho * nonces.e, ED25519_ORDER);
  const lambda_s_c = mod(mod(lambda * keyShare.value, ED25519_ORDER) * c, ED25519_ORDER);
  const zi = mod(mod(nonces.d + rho_e, ED25519_ORDER) + lambda_s_c, ED25519_ORDER);

  return zi;
}

/**
 * Aggregates signature shares into a standard 64-byte Ed25519 signature:
 * R = ∑ (D_j + ρ_j * E_j)
 * z = ∑ z_i mod ℓ
 * signature = R (32 bytes) || z (32 bytes LE)
 */
export function aggregateSignatures(
  message: Uint8Array,
  commitments: Commitment[],
  shares: Array<bigint | Uint8Array>
): Uint8Array {
  const R = computeGroupCommitment(message, commitments);
  let z = 0n;

  for (const s of shares) {
    const val = typeof s === 'bigint' ? s : bytesToScalar(s);
    z = mod(z + val, ED25519_ORDER);
  }

  const sig = new Uint8Array(64);
  sig.set(R.toRawBytes(), 0);
  sig.set(scalarToBytes(z), 32);
  return sig;
}

/**
 * Verifies standard RFC 8032 Ed25519 signature (64 bytes) against group public key Y.
 * Verified with @noble/curves ed25519 standard verifier.
 */
export function verifySignature(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array
): boolean {
  if (signature.length !== 64 || publicKey.length !== 32) {
    return false;
  }
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}
