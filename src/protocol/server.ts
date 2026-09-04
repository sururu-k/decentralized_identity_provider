import { ristretto255 } from '@noble/curves/ed25519';
import { aeadEncrypt, deriveAeadNonce } from '../crypto/aead.js';
import { scalarToBytes } from '../crypto/shamir.js';
import { evaluate } from '../crypto/toprf.js';
import { commit, signShare } from '../crypto/tsign.js';
import {
  JwtClaims,
  TIME_QUANTUM,
  TOKEN_LIFETIME,
  buildHeader,
  buildSigningInput,
  claimsToJson,
  deriveJti,
  quantizeTime,
} from '../jwt/builder.js';
import {
  Commitment,
  IdpMetadata,
  Nonces,
  ParticipantId,
  ProtocolError,
  Share,
  SignOnRequest,
  SignOnResponse,
  UserRecord,
} from './types.js';

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

export function now(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * Deterministically constructs the JWT signing input string.
 * Both server and client must run identical logic to produce bitwise-identical payloads.
 */
export function buildIdpSigningInput(
  metadata: IdpMetadata,
  username: string,
  cnfJkt: string,
  sessionNonce: Uint8Array,
  quantizedIat: number
): string {
  const jti = deriveJti(username, sessionNonce, quantizedIat);
  const claims: JwtClaims = {
    iss: metadata.issuer,
    sub: username,
    aud: metadata.audience,
    iat: quantizedIat,
    exp: quantizedIat + TOKEN_LIFETIME,
    jti,
    cnfJkt,
  };
  return buildSigningInput(buildHeader(metadata.kid), claimsToJson(claims));
}

/**
 * Distributed IdP Node Server.
 * Key security feature: The server NEVER verifies passwords!
 * It computes the signature share unconditionally and encrypts it with h_i.
 * Authentication manifests only when the client can successfully decrypt the share.
 */
export class IdpServer {
  readonly id: ParticipantId;
  private readonly signingKeyShare: Share;
  private readonly metadata: IdpMetadata;
  private readonly users: Map<string, UserRecord> = new Map();
  private readonly pendingNonces: Map<string, Nonces> = new Map();

  constructor(id: ParticipantId, signingKeyShare: Share, metadata: IdpMetadata) {
    this.id = id;
    this.signingKeyShare = signingKeyShare;
    this.metadata = metadata;
  }

  /**
   * Registers a user by storing their TOPRF key share and server key h_i.
   * Master password and master secret h are never revealed to the server.
   */
  register(username: string, record: UserRecord): void {
    this.users.set(username, record);
  }

  /**
   * Round 1 (Can be preprocessed).
   * Draws random nonces (d_i, e_i), stores them for the session, and publishes commitments (D_i, E_i).
   */
  preprocess(sessionNonce: Uint8Array): Commitment {
    const { nonces, commitment } = commit(this.id);
    this.pendingNonces.set(bytesToHex(sessionNonce), nonces);
    return commitment;
  }

  /**
   * Round 2: Computes TOPRF partial evaluation and encrypted signature share.
   * The server unconditionally executes without knowing or verifying the password.
   */
  signOn(request: SignOnRequest): SignOnResponse {
    const record = this.users.get(request.username);
    if (!record) {
      throw new ProtocolError('UnknownUser', `Unknown user: ${request.username}`);
    }

    // Verify clock skew against client's proposed timestamp
    const currentTime = now();
    if (Math.abs(request.iat - currentTime) > TIME_QUANTUM * 2) {
      throw new ProtocolError('ClockSkew', 'Clock skew exceeds acceptable quantum threshold');
    }

    const nonceKey = bytesToHex(request.sessionNonce);
    const nonces = this.pendingNonces.get(nonceKey);
    if (!nonces) {
      throw new ProtocolError(
        'NoPreprocessedNonce',
        'No preprocessed nonces found or nonces already consumed for this session'
      );
    }
    // Preprocessed nonces are single-use to strictly prevent Schnorr nonce reuse
    this.pendingNonces.delete(nonceKey);

    // 1. TOPRF partial evaluation B_i = k_i * A
    const blindedPoint = ristretto255.Point.fromBytes(request.blinded);
    const partialPoint = evaluate(record.toprfKeyShare, blindedPoint);

    // 2. Deterministically construct payload using the username from server's own record
    const quantizedIat = quantizeTime(request.iat);
    const signingInput = buildIdpSigningInput(
      this.metadata,
      request.username,
      request.cnfJkt,
      request.sessionNonce,
      quantizedIat
    );
    const signingInputBytes = new TextEncoder().encode(signingInput);

    // 3. Compute FROST signature share: z_i = d_i + ρ_i*e_i + λ_i*s_i*c mod ℓ
    const share = signShare(
      this.signingKeyShare,
      nonces,
      signingInputBytes,
      request.commitments,
      this.metadata.publicKey
    );
    const shareBytes = scalarToBytes(share);

    // 4. Encrypt share using h_i and ChaCha20-Poly1305 with signing input bound in AAD
    const aeadNonce = deriveAeadNonce(request.sessionNonce, this.id);
    const ciphertext = aeadEncrypt(record.serverKey, aeadNonce, shareBytes, signingInputBytes);

    return {
      id: this.id,
      toprfPartial: partialPoint.toRawBytes(),
      ciphertext,
    };
  }

  /**
   * Breach simulation helper for testing threat models.
   * Returns all stored data if this server were compromised.
   */
  breach(username: string): { record: UserRecord; signingKeyShare: Share } | undefined {
    const record = this.users.get(username);
    if (!record) return undefined;
    return {
      record: { ...record },
      signingKeyShare: { ...this.signingKeyShare },
    };
  }
}
