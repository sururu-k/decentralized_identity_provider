import { ed25519 } from "@noble/curves/ed25519";
import { sha512 } from "@noble/hashes/sha512";

// Ed25519 group order L
export const L = ed25519.CURVE.n;
export const B = ed25519.ExtendedPoint.BASE;

export function mod(n: bigint, m: bigint = L): bigint {
  return ((n % m) + m) % m;
}

export function modInverse(a: bigint, m: bigint = L): bigint {
  a = mod(a, m);
  let [old_r, r] = [a, m];
  let [old_s, s_] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s_] = [s_, old_s - q * s_];
  }
  return mod(old_s, m);
}

export function bytesToScalar(bytes: Uint8Array): bigint {
  let res = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    res = (res << 8n) | BigInt(bytes[i]);
  }
  return res % L;
}

export function scalarToBytes(s: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let temp = mod(s);
  for (let i = 0; i < 32; i++) {
    bytes[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }
  return bytes;
}

export function randomScalar(): bigint {
  const bytes = ed25519.utils.randomPrivateKey();
  return bytesToScalar(sha512(bytes));
}

/**
 * Shamir secret sharing (t-of-n)
 */
export function generateShamirShares(
  secret: bigint,
  threshold: number,
  totalNodes: number
): { groupPublicKey: Uint8Array; shares: Map<number, bigint> } {
  const groupPubKey = B.multiply(secret).toRawBytes();

  // Coefficients for polynomial f(x) = secret + a_1 x + ... + a_{t-1} x^{t-1}
  const coeffs: bigint[] = [secret];
  for (let i = 1; i < threshold; i++) {
    coeffs.push(randomScalar());
  }

  const shares = new Map<number, bigint>();
  for (let i = 1; i <= totalNodes; i++) {
    const x = BigInt(i);
    let y = 0n;
    let xPow = 1n;
    for (let c of coeffs) {
      y = mod(y + c * xPow);
      xPow = mod(xPow * x);
    }
    shares.set(i, y);
  }

  return { groupPublicKey: groupPubKey, shares };
}

/**
 * Lagrange interpolation coefficient lambda_i for participant set
 * lambda_i = prod_{j in S, j != i} (0 - j) / (i - j) = prod ( -j / (i - j) )
 */
export function lagrangeCoefficient(i: number, participants: number[]): bigint {
  const xi = BigInt(i);
  let num = 1n;
  let den = 1n;
  for (const p of participants) {
    if (p === i) continue;
    const xj = BigInt(p);
    num = mod(num * -xj);
    den = mod(den * (xi - xj));
  }
  return mod(num * modInverse(den));
}

export interface FrostCommitment {
  nodeId: number;
  D: Uint8Array; // 32 bytes
  E: Uint8Array; // 32 bytes
}

export interface FrostNonces {
  d: bigint;
  e: bigint;
}

export function generateFrostNonces(): { nonces: FrostNonces; commitment: { D: Uint8Array; E: Uint8Array } } {
  const d = randomScalar();
  const e = randomScalar();
  const D = B.multiply(d).toRawBytes();
  const E = B.multiply(e).toRawBytes();
  return { nonces: { d, e }, commitment: { D, E } };
}

/**
 * Compute binding coefficient rho_i = H_1(nodeId, msg, commitments)
 */
export function computeBindingFactor(
  nodeId: number,
  msg: Uint8Array,
  commitments: FrostCommitment[]
): bigint {
  // Sort commitments by nodeId to ensure determinism
  const sorted = [...commitments].sort((a, b) => a.nodeId - b.nodeId);
  const commBytes: number[] = [];
  for (const c of sorted) {
    commBytes.push(c.nodeId);
    commBytes.push(...c.D);
    commBytes.push(...c.E);
  }

  const hashInput = new Uint8Array(1 + msg.length + commBytes.length);
  hashInput[0] = nodeId;
  hashInput.set(msg, 1);
  hashInput.set(commBytes, 1 + msg.length);

  return bytesToScalar(sha512(hashInput));
}

/**
 * Compute group commitment R = sum_{i in S} (D_i + rho_i * E_i)
 */
export function computeGroupCommitment(
  msg: Uint8Array,
  commitments: FrostCommitment[]
): Uint8Array {
  let R = ed25519.ExtendedPoint.ZERO;
  for (const comm of commitments) {
    const rho = computeBindingFactor(comm.nodeId, msg, commitments);
    const D = ed25519.ExtendedPoint.fromHex(Buffer.from(comm.D).toString("hex"));
    const E = ed25519.ExtendedPoint.fromHex(Buffer.from(comm.E).toString("hex"));
    const part = D.add(E.multiply(rho));
    R = R.add(part);
  }
  return R.toRawBytes();
}

/**
 * Compute Ed25519 challenge c = SHA-512(R || GroupPublicKey || msg) mod L
 */
export function computeChallenge(
  R_bytes: Uint8Array,
  groupPublicKey: Uint8Array,
  msg: Uint8Array
): bigint {
  const hashInput = new Uint8Array(32 + 32 + msg.length);
  hashInput.set(R_bytes, 0);
  hashInput.set(groupPublicKey, 32);
  hashInput.set(msg, 64);
  return bytesToScalar(sha512(hashInput));
}

/**
 * Compute signature share for node i:
 * z_i = d_i + rho_i * e_i + lambda_i * s_i * c mod L
 */
export function computeSignatureShare(
  nodeId: number,
  nonces: FrostNonces,
  secretKeyShare: bigint,
  msg: Uint8Array,
  commitments: FrostCommitment[],
  groupPublicKey: Uint8Array,
  allParticipants: number[]
): bigint {
  const rho_i = computeBindingFactor(nodeId, msg, commitments);
  const R_bytes = computeGroupCommitment(msg, commitments);
  const c = computeChallenge(R_bytes, groupPublicKey, msg);
  const lambda_i = lagrangeCoefficient(nodeId, allParticipants);

  const z_i = mod(nonces.d + rho_i * nonces.e + lambda_i * secretKeyShare * c);
  return z_i;
}

/**
 * Aggregate signature shares into a valid Ed25519 signature: (R || z)
 */
export function aggregateSignatureShares(
  R_bytes: Uint8Array,
  shares: bigint[]
): Uint8Array {
  let z = 0n;
  for (const s of shares) {
    z = mod(z + s);
  }
  const z_bytes = scalarToBytes(z);
  const signature = new Uint8Array(64);
  signature.set(R_bytes, 0);
  signature.set(z_bytes, 32);
  return signature;
}

/**
 * Verify Ed25519 signature against group public key
 */
export function verifyEd25519(
  signature: Uint8Array,
  msg: Uint8Array,
  publicKey: Uint8Array
): boolean {
  try {
    return ed25519.verify(signature, msg, publicKey);
  } catch {
    return false;
  }
}
