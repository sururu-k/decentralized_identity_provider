import crypto from "node:crypto";
import { RefreshResponse, SignOnResponse } from "../protocol/types.js";
import { FrostCommitment } from "../crypto/frost.js";
import { DemoLog, ExcludedNode, createDemoLog } from "../demolog.js";
import { NodeClient } from "../nodes/client.js";
import { GatewaySessionManager } from "./session.js";

export interface ProxySignOnRequestBody {
  username: string;
  blinded: string; // base64url of Ristretto255 blinded point A
  sessionNonce: string; // base64url of session nonce
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
 *
 * Ported from the monolith's `src/gateway/proxy.ts`. Two things changed and nothing else:
 * a node is now a `NodeClient` (an HTTP endpoint) instead of an in-process
 * `IdentityNode`, and round 1 tolerates nodes that fail to answer, so a quorum can still
 * form while one of three nodes is down. The orchestration order is the original's:
 * round id -> commitments from every participant -> session id -> round 2 to the same
 * participants -> register the session.
 *
 * The demo log (`docs/container-split.md` section 10) is emitted from here rather than
 * from the route handler because this is the only place that knows which nodes were left
 * out of the round, and because the whole event -- one line plus its continuation -- has
 * to be written in one go once both rounds are done, or concurrent requests would
 * interleave their lines.
 */
/**
 * A round that could not reach the threshold.
 *
 * The `message` is the one this class always produced and is what the HTTP response still
 * carries; the extra fields exist only so the demo log can render section 10's compact
 * `quorum 1 < 2 (node2, node3 unreachable)` reason without parsing that sentence back.
 */
export class QuorumError extends Error {
  constructor(
    message: string,
    /** How many nodes did answer round 1. */
    readonly committed: number,
    readonly threshold: number,
    /** Node ids that did not answer, ascending. */
    readonly unreachable: number[]
  ) {
    super(message);
    this.name = "QuorumError";
  }
}

export class PastaOAuthProxy {
  private nodes: Map<number, NodeClient>;
  private sessionManager: GatewaySessionManager;
  private demoLog: DemoLog;
  public readonly threshold: number;

  constructor(
    nodes: NodeClient[],
    threshold: number = 2,
    sessionManager?: GatewaySessionManager,
    demoLog?: DemoLog
  ) {
    this.nodes = new Map(nodes.map((n) => [n.nodeId, n]));
    this.threshold = threshold;
    this.sessionManager = sessionManager || new GatewaySessionManager();
    this.demoLog = demoLog ?? createDemoLog();
  }

  public getSessionManager(): GatewaySessionManager {
    return this.sessionManager;
  }

  /** Every node the gateway knows about, in ascending node id order. */
  public getNodes(): NodeClient[] {
    return [...this.nodes.values()].sort((a, b) => a.nodeId - b.nodeId);
  }

  /**
   * Round 1 across the requested participants.
   *
   * When the caller named `participants` explicitly, every one of them must answer: the
   * client asked for a specific quorum and silently substituting another one would
   * surprise it. When the caller named none, the gateway is free to choose, so a node
   * that fails to commit is simply left out and the round continues with whoever
   * answered -- as long as that is still at least `threshold` nodes.
   */
  private async collectCommitments(
    roundId: string,
    participantIds: number[],
    explicit: boolean
  ): Promise<{
    commitments: FrostCommitment[];
    participants: number[];
    excluded: ExcludedNode[];
  }> {
    const settled = await Promise.all(
      participantIds.map(
        async (id): Promise<FrostCommitment | { nodeId: number; error: Error }> => {
          const node = this.nodes.get(id);
          if (!node) return { nodeId: id, error: new Error(`Node ${id} not found in proxy`) };
          try {
            const { D, E } = await node.commit(roundId);
            return { nodeId: id, D, E };
          } catch (err) {
            return { nodeId: id, error: err instanceof Error ? err : new Error(String(err)) };
          }
        }
      )
    );

    const isFailure = (
      r: FrostCommitment | { nodeId: number; error: Error }
    ): r is { nodeId: number; error: Error } => "error" in r;

    const failures = settled.filter(isFailure);
    if (explicit && failures.length > 0) {
      throw new Error(
        `Requested participants did not all commit: ` +
          failures.map((f) => f.error.message).join("; ")
      );
    }

    const commitments = settled
      .filter((r): r is FrostCommitment => !isFailure(r))
      .sort((a, b) => a.nodeId - b.nodeId);

    if (commitments.length < this.threshold) {
      const detail = failures.map((f) => f.error.message).join("; ");
      throw new QuorumError(
        `Insufficient nodes for threshold quorum: need at least ${this.threshold}, ` +
          `${commitments.length} committed${detail ? ` (${detail})` : ""}`,
        commitments.length,
        this.threshold,
        failures.map((f) => f.nodeId).sort((a, b) => a - b)
      );
    }

    return {
      commitments,
      participants: commitments.map((c) => c.nodeId),
      excluded: failures
        .map((f) => ({ nodeId: f.nodeId, reason: f.error.message }))
        .sort((a, b) => a.nodeId - b.nodeId),
    };
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
    const explicit = body.participants !== undefined;
    const requested = body.participants || Array.from(this.nodes.keys());
    if (requested.length < this.threshold) {
      throw new QuorumError(
        `Insufficient nodes for threshold quorum: need at least ${this.threshold}`,
        requested.length,
        this.threshold,
        []
      );
    }

    const roundId = crypto.randomUUID();

    // Round 1: Gather FROST commitments from participants
    const { commitments, participants, excluded } = await this.collectCommitments(
      roundId,
      requested,
      explicit
    );

    // Round 2: Relay sign-on request to each node with common session ID
    // Every participant of round 2 must succeed: the group commitment R and the Lagrange
    // coefficients are fixed by the commitment set, so a partial answer cannot aggregate.
    const sessionId = crypto.randomUUID();
    const nodeResponses = await Promise.all(
      commitments.map((comm) => {
        const node = this.nodes.get(comm.nodeId)!;
        return node.signOn(
          roundId,
          {
            sessionId,
            username: body.username,
            blinded: body.blinded,
            sessionNonce: body.sessionNonce,
            cnfJkt: body.cnfJkt,
            nonce: body.nonce,
            iat: body.iat,
            exp: body.exp,
            aud: body.aud,
            iss: body.iss,
            commitments,
            allParticipants: participants,
          },
          { D: comm.D, E: comm.E }
        );
      })
    );

    // Proxy registers opaque sessionId for routing, but cannot decrypt anything.
    // The participant list is kept so a later refresh goes back to the same quorum:
    // only those nodes hold an rs_i for this session, and only for those does the
    // client hold the matching secret.
    this.sessionManager.registerSession(sessionId, participants);

    // Both rounds are done, so the whole event can be written at once. Note what is
    // absent: there is no password to redact, only the blinded point the gateway cannot
    // open (section 11 removed the one route that ever saw a password).
    this.demoLog.signOn({
      sessionId,
      roundId,
      participants,
      blinded: body.blinded,
      cnfJkt: body.cnfJkt,
      username: body.username,
      nonce: body.nonce ?? "",
      excluded,
    });

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

    const explicit = body.participants !== undefined;
    const requested =
      body.participants ||
      this.sessionManager.getSessionParticipants(body.sessionId) ||
      Array.from(this.nodes.keys());
    if (requested.length < this.threshold) {
      throw new QuorumError(
        `Insufficient nodes for threshold quorum: need at least ${this.threshold}`,
        requested.length,
        this.threshold,
        []
      );
    }

    const roundId = crypto.randomUUID();

    // Round 1: Gather commitments
    const { commitments, participants, excluded } = await this.collectCommitments(
      roundId,
      requested,
      explicit
    );

    // Round 2: Relay refresh request
    const nodeResponses = await Promise.all(
      commitments.map((comm) => {
        const node = this.nodes.get(comm.nodeId)!;
        return node.refresh(
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
            allParticipants: participants,
          },
          { D: comm.D, E: comm.E }
        );
      })
    );

    const updatedCtr = nodeResponses.length > 0 ? nodeResponses[nodeResponses.length - 1].ctr : 0;

    this.sessionManager.recordRefresh(body.sessionId, updatedCtr);

    this.demoLog.refresh({
      sessionId: body.sessionId,
      roundId,
      participants,
      dpopProof: body.dpopProof,
      excluded,
    });

    return {
      sessionId: body.sessionId,
      commitments,
      nodeResponses,
    };
  }
}
