export interface ProxySessionInfo {
  sessionId: string;
  createdAt: number;
  lastRefreshedAt: number;
  counter: number;
  revoked: boolean;
  /** Node ids that took part in the sign-on that created this session. */
  participants: number[];
}

export interface NodeSessionAudit {
  nodeId: number;
  hasRecord: boolean;
  cnfJkt?: string;
  ctr?: number;
  exp?: number;
}

/**
 * Gateway Session Manager
 *
 * Manages opaque refresh token (sessionId) tracking and audits session states across distributed nodes.
 * The proxy does NOT have access to node secrets (rs_i) or user plaintext data.
 *
 * Ported from the monolith's `src/gateway/session.ts`. Two changes: the session now
 * remembers which nodes signed it, so a refresh can be routed back to the same quorum
 * (only those nodes hold an `rs_i` for it, and only for those does the client hold the
 * matching secret); and `auditNodes` takes a structural `SessionAuditSource` instead of
 * an `IdentityNode`, because the gateway has no in-process node to audit.
 */
export class GatewaySessionManager {
  private sessions = new Map<string, ProxySessionInfo>();

  /**
   * Register a new distributed session established during sign-on
   */
  public registerSession(sessionId: string, participants: number[] = []): void {
    const now = Date.now();
    this.sessions.set(sessionId, {
      sessionId,
      createdAt: now,
      lastRefreshedAt: now,
      counter: 0,
      revoked: false,
      participants: [...participants],
    });
  }

  /**
   * Check if a session is currently valid on the proxy
   */
  public isSessionActive(sessionId: string): boolean {
    const session = this.sessions.get(sessionId);
    if (!session) return false;
    return !session.revoked;
  }

  /**
   * Node ids that established the session, or `undefined` if it is unknown.
   */
  public getSessionParticipants(sessionId: string): number[] | undefined {
    const session = this.sessions.get(sessionId);
    if (!session || session.participants.length === 0) return undefined;
    return [...session.participants];
  }

  /**
   * Record a successful refresh operation
   */
  public recordRefresh(sessionId: string, newCtr: number): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.counter = newCtr;
      session.lastRefreshedAt = Date.now();
    }
  }

  /**
   * Revoke a session
   */
  public revokeSession(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.revoked = true;
    }
  }

  /**
   * Audit session status across all participant nodes
   */
  public auditNodes(sessionId: string, nodes: SessionAuditSource[]): NodeSessionAudit[] {
    return nodes.map((node) => {
      const record = node.getSession(sessionId);
      if (!record) {
        return { nodeId: node.nodeId, hasRecord: false };
      }
      return {
        nodeId: node.nodeId,
        hasRecord: true,
        cnfJkt: record.cnfJkt,
        ctr: record.ctr,
        exp: record.exp,
      };
    });
  }
}

/** The part of a node `auditNodes` needs. In the monolith this was `IdentityNode`. */
export interface SessionAuditSource {
  readonly nodeId: number;
  getSession(sessionId: string): { cnfJkt: string; ctr: number; exp: number } | undefined;
}
