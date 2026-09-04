import crypto from "node:crypto";
import {
  FrostCommitment,
  FrostNonces,
  computeSignatureShare,
  generateFrostNonces,
} from "../crypto/frost.js";
import {
  EncryptedPayload,
  deriveNodeKey,
  deriveRefreshKey,
  encryptAead,
} from "../crypto/kdf.js";
import { verifyDPoPProof } from "../client-sdk/dpop.js";
import { base64UrlEncode, createSigningInput } from "../jwt/jwt.js";

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
  h_i: Uint8Array; // pre-computed / TOPRF derived key for node i
}

export interface SignOnRequest {
  sessionId: string;
  username: string;
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
  ct_i: EncryptedPayload;
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
  ct_i: EncryptedPayload;
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
   * Register user with password (simulating PASTA registration establishing h_i)
   */
  public registerUser(username: string, password: string, sub: string): void {
    const h_i = deriveNodeKey(password, username, this.nodeId);
    this.users.set(username, { username, sub, h_i });
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
   * Node signs user payload and encrypts { z_i, rs_i } using h_i.
   * Node NEVER verifies plaintext password — encryption with h_i ensures
   * only the legitimate user can decrypt the share!
   */
  public handleSignOn(
    roundId: string,
    req: SignOnRequest,
    commitment: { D: Uint8Array; E: Uint8Array }
  ): SignOnResponse {
    const user = this.users.get(req.username);
    if (!user) {
      // In PASTA, server still outputs blind evaluation even if user not found to prevent timing attacks,
      // but for deterministic simulation throw or use dummy.
      throw new Error(`User not found on node ${this.nodeId}`);
    }

    const nonces = this.activeNonces.get(roundId);
    if (!nonces) {
      throw new Error(`Round ${roundId} expired or not found on node ${this.nodeId}`);
    }
    this.activeNonces.delete(roundId);

    // Build byte-identical payload
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

    // Compute FROST signature share z_i
    const z_i = computeSignatureShare(
      this.nodeId,
      nonces,
      this.secretKeyShare,
      signingInput,
      req.commitments,
      this.groupPublicKey,
      req.allParticipants
    );

    // Generate node session secret rs_i (docs/refresh-token.md)
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

    // Encrypt { z_i, rs_i } with h_i and AAD = signingInput
    const shareBundle = JSON.stringify({
      z_i: z_i.toString(),
      rs_i: base64UrlEncode(rs_i),
    });

    const ct_i = encryptAead(user.h_i, new TextEncoder().encode(shareBundle), signingInput);

    return {
      nodeId: this.nodeId,
      commitment,
      ct_i,
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

    const shareBundle = JSON.stringify({
      z_i: z_i.toString(),
    });

    // Encrypt share with rk_i and AAD = signingInput
    const ct_i = encryptAead(rk_i, new TextEncoder().encode(shareBundle), signingInput);

    return {
      nodeId: this.nodeId,
      commitment,
      ct_i,
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
