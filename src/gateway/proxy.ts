import crypto from "node:crypto";
import { IdentityNode, SignOnResponse, RefreshResponse } from "../protocol/node.js";
import { FrostCommitment } from "../crypto/frost.js";
import { GatewaySessionManager } from "./session.js";

export interface ProxySignOnRequestBody {
  username: string;
  cnfJkt: string;
  nonce?: string;
  iat: number;
  exp: number;
  aud: string;
  iss: string;
  participants?: number[];
}

export interface ProxySignOnResult {
  sessionId: string;
  commitments: FrostCommitment[];
  nodeResponses: SignOnResponse[];
}

export interface ProxyRefreshRequestBody {
  sessionId: string;
  dpopProof: string;
  expectedHtu: string;
  nonce?: string;
  iat: number;
  exp: number;
  aud: string;
  iss: string;
  participants?: number[];
}

export interface ProxyRefreshResult {
  sessionId: string;
  commitments: FrostCommitment[];
  nodeResponses: RefreshResponse[];
}

/**
 * OAuth / PASTA Proxy
 *
 * Implements the core architecture from docs/whiteboard-gaps.md:
 * "The Proxy DOES NOT hold tokens, cannot forge signatures, and CANNOT decrypt ct_i."
 *
 * It purely acts as a blinded relay between the user's browser and threshold nodes.
 */
export class PastaOAuthProxy {
  private nodes: Map<number, IdentityNode>;
  private sessionManager: GatewaySessionManager;
  public readonly threshold: number;

  constructor(
    nodes: IdentityNode[],
    threshold: number = 2,
    sessionManager?: GatewaySessionManager
  ) {
    this.nodes = new Map(nodes.map((n) => [n.nodeId, n]));
    this.threshold = threshold;
    this.sessionManager = sessionManager || new GatewaySessionManager();
  }

  public getSessionManager(): GatewaySessionManager {
    return this.sessionManager;
  }

  /**
   * Relay endpoint for /api/pasta/sign-on
   *
   * Orchestrates 2-round FROST threshold signing across distributed nodes.
   * PROXY GUARANTEE:
   * The proxy receives only encrypted ciphertext shares ct_i from nodes.
   * Because the proxy never possesses user passwords or h_i,
   * it is mathematically impossible for the proxy to inspect, steal, or forge the token.
   */
  public async handleSignOn(body: ProxySignOnRequestBody): Promise<ProxySignOnResult> {
    const participantIds = body.participants || Array.from(this.nodes.keys());
    if (participantIds.length < this.threshold) {
      throw new Error(`Insufficient nodes for threshold quorum: need at least ${this.threshold}`);
    }

    const roundId = crypto.randomUUID();

    // Round 1: Gather FROST commitments from participants
    const commitments: FrostCommitment[] = [];
    for (const id of participantIds) {
      const node = this.nodes.get(id);
      if (!node) throw new Error(`Node ${id} not found in proxy`);
      const { D, E } = node.generateCommitment(roundId);
      commitments.push({ nodeId: id, D, E });
    }

    // Round 2: Relay sign-on request to each node with common session ID
    const sessionId = crypto.randomUUID();
    const nodeResponses: SignOnResponse[] = [];

    for (const comm of commitments) {
      const node = this.nodes.get(comm.nodeId)!;
      const resp = node.handleSignOn(
        roundId,
        {
          sessionId,
          username: body.username,
          cnfJkt: body.cnfJkt,
          nonce: body.nonce,
          iat: body.iat,
          exp: body.exp,
          aud: body.aud,
          iss: body.iss,
          commitments,
          allParticipants: participantIds,
        },
        { D: comm.D, E: comm.E }
      );

      nodeResponses.push(resp);
    }

    // Proxy registers opaque sessionId for routing, but cannot decrypt anything
    this.sessionManager.registerSession(sessionId);

    return {
      sessionId,
      commitments,
      nodeResponses,
    };
  }

  /**
   * Relay endpoint for /api/pasta/refresh
   *
   * Relays refresh requests with DPoP proof to distributed nodes.
   * PROXY GUARANTEE:
   * Nodes verify DPoP proof independently.
   * Nodes encrypt new shares with rk_i = HKDF(rs_i, ctr).
   * Proxy has no access to rs_i, so ct_i cannot be decrypted by the proxy.
   */
  public async handleRefresh(body: ProxyRefreshRequestBody): Promise<ProxyRefreshResult> {
    if (!this.sessionManager.isSessionActive(body.sessionId)) {
      throw new Error(`Session ${body.sessionId} is invalid or revoked`);
    }

    const participantIds = body.participants || Array.from(this.nodes.keys());
    if (participantIds.length < this.threshold) {
      throw new Error(`Insufficient nodes for threshold quorum: need at least ${this.threshold}`);
    }

    const roundId = crypto.randomUUID();

    // Round 1: Gather commitments
    const commitments: FrostCommitment[] = [];
    for (const id of participantIds) {
      const node = this.nodes.get(id);
      if (!node) throw new Error(`Node ${id} not found in proxy`);
      const { D, E } = node.generateCommitment(roundId);
      commitments.push({ nodeId: id, D, E });
    }

    // Round 2: Relay refresh request
    const nodeResponses: RefreshResponse[] = [];
    let updatedCtr = 0;

    for (const comm of commitments) {
      const node = this.nodes.get(comm.nodeId)!;
      const resp = node.handleRefresh(
        roundId,
        {
          sessionId: body.sessionId,
          dpopProof: body.dpopProof,
          expectedHtu: body.expectedHtu,
          nonce: body.nonce,
          iat: body.iat,
          exp: body.exp,
          aud: body.aud,
          iss: body.iss,
          commitments,
          allParticipants: participantIds,
        },
        { D: comm.D, E: comm.E }
      );

      nodeResponses.push(resp);
      updatedCtr = resp.ctr;
    }

    this.sessionManager.recordRefresh(body.sessionId, updatedCtr);

    return {
      sessionId: body.sessionId,
      commitments,
      nodeResponses,
    };
  }
}
