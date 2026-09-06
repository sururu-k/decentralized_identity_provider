import {
  RefreshRequest,
  RefreshResponse,
  SignOnRequest,
  SignOnResponse,
} from "../protocol/types.js";
import { NodeClient } from "./client.js";
import {
  HealthResponseWire,
  commitResponseFromWire,
  healthResponseFromWire,
  refreshRequestToWire,
  refreshResponseFromWire,
  signOnRequestToWire,
  signOnResponseFromWire,
} from "./wire.js";

/** How long the gateway waits on one node call before giving up on it. */
export const DEFAULT_NODE_TIMEOUT_MS = 5_000;

/**
 * A node reached over HTTP, speaking `docs/container-split.md` section 5.
 *
 * Every failure -- a refused connection, a timeout, a non-JSON body, a 4xx carrying
 * `{ error }` -- comes back as a plain `Error` whose message names the node. The proxy
 * treats them all the same way: that node did not answer this round.
 */
export class HttpNodeClient implements NodeClient {
  public readonly nodeId: number;
  public readonly url: string;
  private readonly timeoutMs: number;

  constructor(nodeId: number, url: string, timeoutMs: number = DEFAULT_NODE_TIMEOUT_MS) {
    this.nodeId = nodeId;
    this.url = url.replace(/\/+$/, "");
    this.timeoutMs = timeoutMs;
  }

  public async commit(roundId: string): Promise<{ D: Uint8Array; E: Uint8Array }> {
    const body = await this.post("/commit", { roundId });
    const commitment = commitResponseFromWire(body, `node ${this.nodeId} /commit response`);
    if (commitment.nodeId !== this.nodeId) {
      throw new Error(
        `Node at ${this.url} answered /commit as node ${commitment.nodeId}, expected ${this.nodeId}`
      );
    }
    return { D: commitment.D, E: commitment.E };
  }

  public async signOn(
    roundId: string,
    req: SignOnRequest,
    _ownCommitment: { D: Uint8Array; E: Uint8Array }
  ): Promise<SignOnResponse> {
    // The node picks its own commitment out of `req.commitments` by node id
    // (section 5), so the third argument is not sent separately over the wire.
    const body = await this.post("/sign-on", { roundId, request: signOnRequestToWire(req) });
    return signOnResponseFromWire(body, `node ${this.nodeId} /sign-on response`);
  }

  public async refresh(
    roundId: string,
    req: RefreshRequest,
    _ownCommitment: { D: Uint8Array; E: Uint8Array }
  ): Promise<RefreshResponse> {
    const body = await this.post("/refresh", { roundId, request: refreshRequestToWire(req) });
    return refreshResponseFromWire(body, `node ${this.nodeId} /refresh response`);
  }

  /**
   * `GET /health`. Used by discovery at startup and by the gateway's own `/health`.
   *
   * `timeoutMs` overrides the client's own budget. The gateway's `/health` probes every
   * node before it answers, so its total time is bounded by the slowest node; Docker's
   * `HEALTHCHECK --timeout` is shorter than a node call's default budget, and a single
   * hung node must not make the gateway itself look dead.
   */
  public async health(timeoutMs?: number): Promise<HealthResponseWire> {
    const body = await this.request("GET", "/health", undefined, timeoutMs);
    return healthResponseFromWire(body, `node at ${this.url} /health response`);
  }

  private post(path: string, payload: unknown): Promise<unknown> {
    return this.request("POST", path, payload);
  }

  private async request(
    method: string,
    path: string,
    payload: unknown,
    timeoutMs: number = this.timeoutMs
  ): Promise<unknown> {
    let res: Response;
    try {
      res = await fetch(`${this.url}${path}`, {
        method,
        headers: payload === undefined ? undefined : { "Content-Type": "application/json" },
        body: payload === undefined ? undefined : JSON.stringify(payload),
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      const reason =
        err instanceof Error && err.name === "TimeoutError"
          ? `timed out after ${timeoutMs}ms`
          : err instanceof Error
            ? err.message
            : String(err);
      throw new Error(`Node ${this.nodeId} at ${this.url}${path} unreachable: ${reason}`);
    }

    const text = await res.text();
    let parsed: unknown;
    try {
      parsed = text.length === 0 ? undefined : JSON.parse(text);
    } catch {
      parsed = undefined;
    }

    if (!res.ok) {
      const detail =
        parsed !== undefined &&
        typeof parsed === "object" &&
        parsed !== null &&
        typeof (parsed as { error?: unknown }).error === "string"
          ? (parsed as { error: string }).error
          : text.slice(0, 200) || res.statusText;
      throw new Error(`Node ${this.nodeId} at ${this.url}${path} failed (${res.status}): ${detail}`);
    }

    if (parsed === undefined) {
      throw new Error(`Node ${this.nodeId} at ${this.url}${path} returned a non-JSON body`);
    }
    return parsed;
  }
}
