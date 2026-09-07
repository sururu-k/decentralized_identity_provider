import { FrostCommitment } from "./crypto/frost.js";
import { base64UrlDecode } from "./jwt.js";
import { ProxySignOnResult } from "./types.js";

/**
 * Browser port of the gateway's `src/gateway/wire.ts`
 * (docs/container-split.md sections 3 and 11).
 *
 * Only the sign-on decode direction is here. The browser reads the `/api/pasta/sign-on`
 * response; it never produces one, and since section 14 there is no `/api/pasta/refresh`
 * for the IdP front end to read, so the refresh decode and every encode helper are
 * dropped. The remaining field names are unchanged.
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
