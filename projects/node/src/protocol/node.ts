import crypto from "node:crypto";
import { ristretto255 } from "@noble/curves/ed25519";
import {
  FrostCommitment,
  FrostNonces,
  computeSignatureShare,
  generateFrostNonces,
} from "../crypto/frost.js";
import { deriveRefreshKey } from "../crypto/kdf.js";
import { aeadEncrypt, deriveAeadNonce } from "../crypto/aead.js";
import { Share } from "../crypto/shamir.js";
import {
  blind,
  deriveServerKey,
  evaluate,
  finalize,
  generateToprfKey,
  unblind,
} from "../crypto/toprf.js";
import { verifyDPoPProof } from "../client-sdk/dpop.js";
import { base64UrlDecode, base64UrlEncode, createSigningInput } from "../jwt/jwt.js";

export interface NodeSessionRecord {
  sessionId: string;
  sub: string;
  cnfJkt: string;
  rs_i: Uint8Array; // 32-byte node session secret
  exp: number;
  ctr: number;
}

export interface UserRecord {
  sub: string;
  username: string;
  toprfKeyShare: Share; // Share of TOPRF key
  h_i: Uint8Array; // pre-computed / TOPRF derived key for node i
}

export interface SignOnRequest {
  sessionId: string;
  username: string;
  blinded: string; // base64url of Ristretto255 point A = r * H1(password)
  sessionNonce: string; // base64url of 16-byte random session nonce
  cnfJkt: string;
  nonce?: string;
  iat: number;
  exp: number;
  aud: string;
  iss: string;
  commitments: FrostCommitment[];
  allParticipants: number[];
}

export interface SignOnResponse {
  nodeId: number;
  commitment: { D: Uint8Array; E: Uint8Array };
  toprfPartial: string; // base64url of Ristretto255 point B_i = k_i * A
  ct_i: string; // base64url of ChaCha20-Poly1305 ciphertext { z_i, rs_i }
  sessionId: string;
  sub: string;
}

export interface RefreshRequest {
  sessionId: string;
  dpopProof: string;
  expectedHtu: string;
  nonce?: string;
  iat: number;
  exp: number;
  aud: string;
  iss: string;
  commitments: FrostCommitment[];
  allParticipants: number[];
}

export interface RefreshResponse {
  nodeId: number;
  commitment: { D: Uint8Array; E: Uint8Array };
  ct_i: string; // base64url of ChaCha20-Poly1305 ciphertext
  ctr: number;
  sub: string;
}

export class IdentityNode {
  public readonly nodeId: number;
  private readonly secretKeyShare: bigint;
  public readonly groupPublicKey: Uint8Array;
  private readonly users = new Map<string, UserRecord>();
  private readonly sessions = new Map<string, NodeSessionRecord>();

  // Temporary nonces for in-flight FROST rounds
  private activeNonces = new Map<string, FrostNonces>();

  constructor(nodeId: number, secretKeyShare: bigint, groupPublicKey: Uint8Array) {
    this.nodeId = nodeId;
    this.secretKeyShare = secretKeyShare;
    this.groupPublicKey = groupPublicKey;
  }

  /**
   * Register user with TOPRF key share and server-specific key h_i.
   * Master password and master secret h are NEVER revealed to the node!
   */
  public registerUser(
    username: string,
    sub: string,
    toprfKeyShare: Share,
    h_i: Uint8Array
  ): void {
    this.users.set(username, { username, sub, toprfKeyShare, h_i });
  }

  /**
   * Round 1: Generate FROST commitment for this node
   */
  public generateCommitment(roundId: string): { D: Uint8Array; E: Uint8Array } {
    const { nonces, commitment } = generateFrostNonces();
    this.activeNonces.set(roundId, nonces);
    return commitment;
  }

  /**
   * Round 2: Process Sign-On Request
   * 1. Evaluates TOPRF partial point B_i = k_i * A without learning password
   * 2. Signs byte-identical JWT payload using FROST share z_i
   * 3. Encrypts { z_i, rs_i } using h_i and ChaCha20-Poly1305 (AAD = signingInput)
   *
   * Security Guarantee:
   * The node NEVER knows or verifies the plaintext password.
   * Encryption with h_i ensures ONLY the client holding the correct password can decrypt the share!
   */
  public handleSignOn(
    roundId: string,
    req: SignOnRequest,
    commitment: { D: Uint8Array; E: Uint8Array }
  ): SignOnResponse {
    const user = this.users.get(req.username);
    if (!user) {
      throw new Error(`User not found on node ${this.nodeId}`);
    }

    const nonces = this.activeNonces.get(roundId);
    if (!nonces) {
      throw new Error(`Round ${roundId} expired or not found on node ${this.nodeId}`);
    }
    this.activeNonces.delete(roundId);

    // 1. TOPRF partial evaluation B_i = k_i * A
    const blindedPointBytes = base64UrlDecode(req.blinded);
    const blindedPoint = ristretto255.Point.fromBytes(blindedPointBytes);
    const partialPoint = evaluate(user.toprfKeyShare, blindedPoint);

    // 2. Build byte-identical payload
    const header = { alg: "EdDSA", typ: "JWT", kid: "pasta-group-key-1" };
    const payload = {
      iss: req.iss,
      sub: user.sub,
      aud: req.aud,
      iat: req.iat,
      exp: req.exp,
      nonce: req.nonce,
      cnf: { jkt: req.cnfJkt },
    };

    const { signingInput } = createSigningInput(header, payload);

    // 3. Compute FROST signature share z_i
    const z_i = computeSignatureShare(
      this.nodeId,
      nonces,
      this.secretKeyShare,
      signingInput,
      req.commitments,
      this.groupPublicKey,
      req.allParticipants
    );

    // 4. Generate node session secret rs_i (docs/refresh-token.md & Hole 5)
    const rs_i = crypto.randomBytes(32);
    const sessionId = req.sessionId;

    // Store session record locally on node
    const sessionRecord: NodeSessionRecord = {
      sessionId,
      sub: user.sub,
      cnfJkt: req.cnfJkt,
      rs_i,
      exp: req.exp + 86400 * 30, // 30 days refresh lifetime
      ctr: 0,
    };
    this.sessions.set(sessionId, sessionRecord);

    // 5. Encrypt { z_i, rs_i } using ChaCha20-Poly1305 with h_i and AAD = signingInput
    const sessionNonceBytes = base64UrlDecode(req.sessionNonce);
    const aeadNonce = deriveAeadNonce(sessionNonceBytes, this.nodeId);
    const shareBundle = JSON.stringify({
      z_i: z_i.toString(),
      rs_i: base64UrlEncode(rs_i),
    });

    const ct_i = aeadEncrypt(
      user.h_i,
      aeadNonce,
      new TextEncoder().encode(shareBundle),
      signingInput
    );

    return {
      nodeId: this.nodeId,
      commitment,
      toprfPartial: base64UrlEncode(partialPoint.toRawBytes()),
      ct_i: base64UrlEncode(ct_i),
      sessionId,
      sub: user.sub,
    };
  }

  /**
   * Process Refresh Request
   * Node independently verifies DPoP proof against stored cnf_jkt,
   * increments ctr, and encrypts new signature share with rk_i = HKDF(rs_i, ctr).
   */
  public handleRefresh(
    roundId: string,
    req: RefreshRequest,
    commitment: { D: Uint8Array; E: Uint8Array }
  ): RefreshResponse {
    const session = this.sessions.get(req.sessionId);
    if (!session) {
      throw new Error(`Session ${req.sessionId} not found on node ${this.nodeId}`);
    }

    const now = Math.floor(Date.now() / 1000);
    if (session.exp < now) {
      this.sessions.delete(req.sessionId);
      throw new Error(`Session expired on node ${this.nodeId}`);
    }

    // Hole 4 / 7: Node independently verifies DPoP proof and cnf.jkt binding
    const dpopVerification = verifyDPoPProof(req.dpopProof, {
      expectedHtm: "POST",
      expectedHtu: req.expectedHtu,
      expectedJkt: session.cnfJkt,
      maxAgeSeconds: 300,
    });

    if (!dpopVerification.valid) {
      throw new Error(
        `Node ${this.nodeId} rejected DPoP proof: ${dpopVerification.error || "invalid"}`
      );
    }

    const nonces = this.activeNonces.get(roundId);
    if (!nonces) {
      throw new Error(`Round ${roundId} expired on node ${this.nodeId}`);
    }
    this.activeNonces.delete(roundId);

    // Build refreshed payload
    const header = { alg: "EdDSA", typ: "JWT", kid: "pasta-group-key-1" };
    const payload = {
      iss: req.iss,
      sub: session.sub,
      aud: req.aud,
      iat: req.iat,
      exp: req.exp,
      nonce: req.nonce,
      cnf: { jkt: session.cnfJkt },
    };

    const { signingInput } = createSigningInput(header, payload);

    // Compute signature share
    const z_i = computeSignatureShare(
      this.nodeId,
      nonces,
      this.secretKeyShare,
      signingInput,
      req.commitments,
      this.groupPublicKey,
      req.allParticipants
    );

    // Advance session counter (rotation / anti-replay)
    session.ctr += 1;

    // Hole 5: rk_i = HKDF(rs_i, ctr)
    const rk_i = deriveRefreshKey(session.rs_i, session.ctr, session.sessionId);
    const refreshNonce = deriveAeadNonce(
      new TextEncoder().encode(`REFRESH:${session.sessionId}:${session.ctr}`),
      this.nodeId
    );

    const shareBundle = JSON.stringify({
      z_i: z_i.toString(),
    });

    // Encrypt share with rk_i and ChaCha20-Poly1305 with AAD = signingInput
    const ct_i = aeadEncrypt(
      rk_i,
      refreshNonce,
      new TextEncoder().encode(shareBundle),
      signingInput
    );

    return {
      nodeId: this.nodeId,
      commitment,
      ct_i: base64UrlEncode(ct_i),
      ctr: session.ctr,
      sub: session.sub,
    };
  }

  /**
   * Diagnostic / session check
   */
  public getSession(sessionId: string): NodeSessionRecord | undefined {
    return this.sessions.get(sessionId);
  }
}

/**
 * Client-side user registration utility:
 * Generates TOPRF key shares via Shamir secret sharing,
 * locally computes master PRF value h and per-node keys h_i,
 * and registers them to nodes.
 * The master password is NEVER revealed to any node!
 */
export function registerUserToNodes(
  nodes: IdentityNode[],
  username: string,
  password: string,
  sub: string,
  threshold: number = 2
): void {
  const total = nodes.length;
  const toprfKeyShares = generateToprfKey(total, threshold);

  const { blinding, blinded } = blind(password);
  const partials = toprfKeyShares.slice(0, threshold).map((s) => ({
    id: s.id,
    point: evaluate(s, blinded),
  }));
  const v = unblind(blinding, partials);
  const h = finalize(password, v);

  for (let i = 0; i < nodes.length; i++) {
    const node = nodes[i];
    const keyShare = toprfKeyShares[i];
    const serverKey = deriveServerKey(h, node.nodeId);
    node.registerUser(username, sub, keyShare, serverKey);
  }
}
