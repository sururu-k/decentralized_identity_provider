import { FrostCommitment } from "../crypto/frost.js";
import { base64UrlDecode, base64UrlEncode } from "../jwt/jwt.js";
import { ProxySignOnResult } from "./proxy.js";

/**
 * Wire form of the browser-facing sign-on result (`docs/container-split.md` section 3).
 *
 * `PastaOAuthProxy` works in the in-process shapes, where a FROST commitment carries raw
 * `Uint8Array` points. Those must not reach JSON: the monolith serialised them directly
 * and produced `{"0":12,"1":240,...}`, which no client can turn back into a point. Every
 * byte string leaving `/api/pasta/sign-on` is therefore base64url without padding, and
 * the client decodes it back on arrival.
 *
 * Field names are unchanged from the monolith, as section 6 requires.
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

function commitmentToWire(c: FrostCommitment): CommitmentWire {
  return { nodeId: c.nodeId, D: base64UrlEncode(c.D), E: base64UrlEncode(c.E) };
}

function commitmentFromWire(c: CommitmentWire): FrostCommitment {
  return { nodeId: c.nodeId, D: base64UrlDecode(c.D), E: base64UrlDecode(c.E) };
}

export function signOnResultToWire(result: ProxySignOnResult): ProxySignOnResultWire {
  return {
    sessionId: result.sessionId,
    commitments: result.commitments.map(commitmentToWire),
    nodeResponses: result.nodeResponses.map((r) => ({
      nodeId: r.nodeId,
      commitment: {
        D: base64UrlEncode(r.commitment.D),
        E: base64UrlEncode(r.commitment.E),
      },
      toprfPartial: r.toprfPartial,
      ct_i: r.ct_i,
      sessionId: r.sessionId,
      sub: r.sub,
    })),
  };
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
