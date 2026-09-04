import { IdentityNode } from "../protocol/node.js";

export interface ProxySessionInfo {
  sessionId: string;
  createdAt: number;
  lastRefreshedAt: number;
  counter: number;
  revoked: boolean;
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
 */
export class GatewaySessionManager {
  private sessions = new Map<string, ProxySessionInfo>();

  /**
   * Register a new distributed session established during sign-on
   */
  public registerSession(sessionId: string): void {
    const now = Date.now();
    this.sessions.set(sessionId, {
      sessionId,
      createdAt: now,
      lastRefreshedAt: now,
      counter: 0,
      revoked: false,
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
  public auditNodes(sessionId: string, nodes: IdentityNode[]): NodeSessionAudit[] {
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
