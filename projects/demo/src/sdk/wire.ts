import { FrostCommitment } from "./crypto/frost.js";
import { base64UrlDecode } from "./jwt.js";
import { ProxyRefreshResult, ProxySignOnResult } from "./types.js";

/**
 * Browser port of the gateway's `src/gateway/wire.ts`
 * (docs/container-split.md sections 3 and 11).
 *
 * Only the decode direction is here. The browser reads `/api/pasta/sign-on` and
 * `/api/pasta/refresh` responses; it never produces them, so `signOnResultToWire` /
 * `refreshResultToWire` and the `base64UrlEncode` import they needed are dropped. The
 * decode functions and the wire field names are unchanged.
 */

export interface CommitmentWire {
  nodeId: number;
  D: string;
  E: string;
}

export interface ProxySignOnResultWire {
  sessionId: string;
  commitments: CommitmentWire[];
  nodeResponses: Array<{
    nodeId: number;
    commitment: { D: string; E: string };
    toprfPartial: string;
    ct_i: string;
    sessionId: string;
    sub: string;
  }>;
}

export interface ProxyRefreshResultWire {
  sessionId: string;
  commitments: CommitmentWire[];
  nodeResponses: Array<{
    nodeId: number;
    commitment: { D: string; E: string };
    ct_i: string;
    ctr: number;
    sub: string;
  }>;
}

function commitmentFromWire(c: CommitmentWire): FrostCommitment {
  return { nodeId: c.nodeId, D: base64UrlDecode(c.D), E: base64UrlDecode(c.E) };
}

export function signOnResultFromWire(wire: ProxySignOnResultWire): ProxySignOnResult {
  return {
    sessionId: wire.sessionId,
    commitments: wire.commitments.map(commitmentFromWire),
    nodeResponses: wire.nodeResponses.map((r) => ({
      nodeId: r.nodeId,
      commitment: {
        D: base64UrlDecode(r.commitment.D),
        E: base64UrlDecode(r.commitment.E),
      },
      toprfPartial: r.toprfPartial,
      ct_i: r.ct_i,
      sessionId: r.sessionId,
      sub: r.sub,
    })),
  };
}

export function refreshResultFromWire(wire: ProxyRefreshResultWire): ProxyRefreshResult {
  return {
    sessionId: wire.sessionId,
    commitments: wire.commitments.map(commitmentFromWire),
    nodeResponses: wire.nodeResponses.map((r) => ({
      nodeId: r.nodeId,
      commitment: {
        D: base64UrlDecode(r.commitment.D),
        E: base64UrlDecode(r.commitment.E),
      },
      ct_i: r.ct_i,
      ctr: r.ctr,
      sub: r.sub,
    })),
  };
}
