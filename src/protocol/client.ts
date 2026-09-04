import { ristretto255 } from '@noble/curves/ed25519';
import { aeadDecrypt, deriveAeadNonce } from '../crypto/aead.js';
import { bytesToScalar } from '../crypto/shamir.js';
import {
  blind,
  deriveServerKey,
  evaluate,
  finalize,
  generateToprfKey,
  unblind,
} from '../crypto/toprf.js';
import { aggregateSignatures, verifySignature } from '../crypto/tsign.js';
import { assembleJwt, quantizeTime } from '../jwt/builder.js';
import { verifyJwt } from '../jwt/verifier.js';
import { IdpServer, buildIdpSigningInput, now } from './server.js';
import {
  Commitment,
  IdpMetadata,
  PendingSignOn,
  ProtocolError,
  SignOnRequest,
  SignOnResponse,
  UserRecord,
} from './types.js';

/**
 * Client registration protocol:
 * Generates a client-specific TOPRF key, shares it via (t, n) Shamir secret sharing,
 * locally computes master PRF value h, and derives server-specific keys h_i = H'(h, i).
 *
 * @param servers Target IdP nodes
 * @param username Username to register
 * @param password User's secret password
 * @param threshold Threshold number of servers required to sign-on (t)
 */
export function registerUser(
  servers: IdpServer[],
  username: string,
  password: Uint8Array | string,
  threshold: number
): void {
  const total = servers.length;
  const keyShares = generateToprfKey(total, threshold);

  // Client knows the TOPRF key, so it can compute h locally during registration
  const { blinding, blinded } = blind(password);
  const partials = keyShares.slice(0, threshold).map((s) => ({
    id: s.id,
    point: evaluate(s, blinded),
  }));
  const v = unblind(blinding, partials);
  const h = finalize(password, v);

  for (let i = 0; i < servers.length; i++) {
    const server = servers[i];
    const keyShare = keyShares[i];
    const serverKey = deriveServerKey(h, server.id);
    const record: UserRecord = {
      toprfKeyShare: keyShare,
      serverKey,
    };
    server.register(username, record);
  }
}

/**
 * Begins sign-on flow:
 * Blinds the password and constructs the Round 2 SignOnRequest.
 *
 * @param username Username to authenticate
 * @param password User's password
 * @param cnfJkt DPoP key thumbprint for proof-of-possession binding (RFC 9449)
 * @param sessionNonce Random 16-byte session nonce
 * @param commitments Set of Round 1 commitments from participating servers
 */
export function beginSignOn(
  username: string,
  password: Uint8Array | string,
  cnfJkt: string,
  sessionNonce: Uint8Array,
  commitments: Commitment[]
): {
  pending: PendingSignOn;
  request: SignOnRequest;
} {
  const { blinding, blinded } = blind(password);
  const iat = now();

  const request: SignOnRequest = {
    username,
    blinded: blinded.toRawBytes(),
    cnfJkt,
    sessionNonce,
    iat,
    commitments,
  };

  const pending: PendingSignOn = {
    blinding,
    username,
    cnfJkt,
    sessionNonce,
    iat,
    commitments,
  };

  return { pending, request };
}

/**
 * Completes sign-on flow:
 * Reconstructs TOPRF master output h, derives h_i, decrypts signature shares,
 * aggregates FROST signature, and outputs standard JWT.
 *
 * Authentication physically occurs here: if the password was incorrect,
 * ChaCha20-Poly1305 decryption will fail to authenticate.
 *
 * @param pending Pending state from beginSignOn
 * @param password User's password
 * @param metadata Public metadata of the IdP
 * @param responses SignOnResponse array from participating servers
 * @param threshold Required threshold (t)
 * @returns Fully assembled standard JWT string
 */
export function finishSignOn(
  pending: PendingSignOn,
  password: Uint8Array | string,
  metadata: IdpMetadata,
  responses: SignOnResponse[],
  threshold: number
): string {
  if (responses.length < threshold) {
    throw new ProtocolError(
      'NotEnoughShares',
      `Insufficient responses: got ${responses.length}, required threshold is ${threshold}`
    );
  }

  // 1. Combine TOPRF partial evaluations to recover v and h
  const partials = responses.map((r) => ({
    id: r.id,
    point: ristretto255.Point.fromBytes(r.toprfPartial),
  }));
  const v = unblind(pending.blinding, partials);
  const h = finalize(password, v);

  // 2. Reconstruct the exact signing input that servers signed
  const quantizedIat = quantizeTime(pending.iat);
  const signingInput = buildIdpSigningInput(
    metadata,
    pending.username,
    pending.cnfJkt,
    pending.sessionNonce,
    quantizedIat
  );
  const signingInputBytes = new TextEncoder().encode(signingInput);

  // 3. Derive each h_i and decrypt signature shares
  const shares: bigint[] = [];
  for (const response of responses) {
    const serverKey = deriveServerKey(h, response.id);
    const aeadNonce = deriveAeadNonce(pending.sessionNonce, response.id);

    let plaintext: Uint8Array;
    try {
      plaintext = aeadDecrypt(serverKey, aeadNonce, response.ciphertext, signingInputBytes);
    } catch {
      throw new ProtocolError(
        'AuthenticationFailed',
        'Authentication failed: incorrect password or tampered share/payload'
      );
    }

    if (plaintext.length !== 32) {
      throw new ProtocolError(
        'AuthenticationFailed',
        `Invalid decrypted share length: expected 32 bytes, got ${plaintext.length}`
      );
    }

    shares.push(bytesToScalar(plaintext));
  }

  // 4. Aggregate signature shares and verify locally
  const signature = aggregateSignatures(signingInputBytes, pending.commitments, shares);
  if (!verifySignature(metadata.publicKey, signingInputBytes, signature)) {
    throw new ProtocolError(
      'InvalidSignature',
      'Aggregated signature failed Ed25519 verification against group public key'
    );
  }

  // 5. Assemble final JWT
  return assembleJwt(signingInput, signature);
}

/**
 * Verifies a JWT issued by the distributed IdP using the group public key.
 */
export function verifyIdpToken(metadata: IdpMetadata, token: string): boolean {
  return verifyJwt(token, metadata.publicKey);
}

/**
 * High-level Client / Aggregator class.
 */
export class IdpClient {
  private readonly metadata: IdpMetadata;
  private readonly threshold: number;

  constructor(metadata: IdpMetadata, threshold: number) {
    this.metadata = metadata;
    this.threshold = threshold;
  }

  /**
   * Registers a user across all IdP servers.
   */
  register(servers: IdpServer[], username: string, password: Uint8Array | string): void {
    registerUser(servers, username, password, this.threshold);
  }

  /**
   * Executes the full sign-on protocol across a chosen quorum of servers.
   */
  signOn(
    servers: IdpServer[],
    username: string,
    password: Uint8Array | string,
    cnfJkt: string,
    sessionNonce?: Uint8Array
  ): string {
    const nonce = sessionNonce ?? globalThis.crypto.getRandomValues(new Uint8Array(16));

    // Round 1: Gather preprocessed commitments
    const commitments = servers.map((s) => s.preprocess(nonce));

    // Round 2: Build request and collect responses
    const { pending, request } = beginSignOn(username, password, cnfJkt, nonce, commitments);
    const responses = servers.map((s) => s.signOn(request));

    // Finish sign-on and aggregate into JWT
    return finishSignOn(pending, password, this.metadata, responses, this.threshold);
  }
}
