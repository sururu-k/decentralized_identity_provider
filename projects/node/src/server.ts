import http from "node:http";
import { IdentityNode } from "./protocol/node.js";
import { base64UrlEncode } from "./jwt/jwt.js";
import { DemoLog, createDemoLog } from "./demolog.js";
import {
  CommitResponseWire,
  HealthResponseWire,
  RefreshResponseWire,
  SignOnResponseWire,
  WireError,
  commitEnvelopeFromWire,
  refreshEnvelopeFromWire,
  refreshResponseToWire,
  signOnEnvelopeFromWire,
  signOnResponseToWire,
} from "./wire.js";

/** Largest request body the node accepts, in bytes. */
export const MAX_BODY_BYTES = 1024 * 1024;

interface JsonError {
  error: string;
}

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  const payload = Buffer.from(JSON.stringify(body), "utf8");
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": payload.length,
    "Cache-Control": "no-store",
  });
  res.end(payload);
}

function sendError(res: http.ServerResponse, status: number, message: string): void {
  const body: JsonError = { error: message };
  sendJson(res, status, body);
}

/** How much of an over-long upload is drained before the socket is simply cut. */
const MAX_DRAIN_BYTES = 8 * MAX_BODY_BYTES;

type BodyResult =
  | { kind: "ok"; text: string }
  | { kind: "too-large" }
  | { kind: "aborted" };

/**
 * Collects the request body, refusing anything over `MAX_BODY_BYTES`.
 *
 * An over-long body is discarded as it arrives rather than buffered, and the 413 is sent
 * only once the client has finished writing. Answering mid-upload would tear the socket
 * down under the client, which then sees a broken pipe instead of the status. The drain
 * is capped, so a client that keeps sending gets the socket cut instead.
 */
function readBody(req: http.IncomingMessage): Promise<BodyResult> {
  return new Promise((resolve) => {
    let chunks: Buffer[] = [];
    let size = 0;
    let tooLarge = false;

    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        if (!tooLarge) {
          tooLarge = true;
          chunks = [];
        }
        if (size > MAX_DRAIN_BYTES) {
          req.destroy();
        }
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => {
      resolve(
        tooLarge ? { kind: "too-large" } : { kind: "ok", text: Buffer.concat(chunks).toString("utf8") }
      );
    });
    // A client that hangs up mid-upload is ordinary, not an internal error: both events
    // resolve as "aborted" so the handler simply stops instead of logging and trying to
    // write a 500 onto a socket that is already gone.
    req.on("close", () => resolve({ kind: "aborted" }));
    req.on("error", () => resolve({ kind: "aborted" }));
  });
}

/**
 * Picks this node's own round-1 commitment out of the request.
 *
 * `IdentityNode.handleSignOn` / `handleRefresh` take the commitment as their third
 * argument; over HTTP the gateway sends the whole commitment set, so the node looks up
 * the entry carrying its own id (docs/container-split.md section 5).
 */
function ownCommitment(
  nodeId: number,
  commitments: Array<{ nodeId: number; D: Uint8Array; E: Uint8Array }>
): { D: Uint8Array; E: Uint8Array } {
  const mine = commitments.find((c) => c.nodeId === nodeId);
  if (!mine) {
    throw new WireError(`commitments contains no entry for node ${nodeId}`);
  }
  return { D: mine.D, E: mine.E };
}

/**
 * Builds the node's HTTP server without binding a port, so callers (and tests) decide
 * where it listens.
 *
 * Routes (docs/container-split.md section 5):
 *   GET  /health   -> { status, nodeId, groupPublicKey }
 *   POST /commit   -> { nodeId, D, E }
 *   POST /sign-on  -> SignOnResponseWire
 *   POST /refresh  -> RefreshResponseWire
 *
 * `demoLog` prints the compact one-or-two-line trace of docs/container-split.md section 10.
 * It is created here rather than taken from the caller so that every entry point, tests
 * included, produces the same demo output; `index.ts` passes one that also knows `total`.
 */
export function createNodeServer(node: IdentityNode, demoLog?: DemoLog): http.Server {
  const demo = demoLog ?? createDemoLog({ nodeId: node.nodeId });
  return http.createServer((req, res) => {
    handle(node, demo, req, res).catch((err) => {
      if (res.headersSent) {
        res.destroy();
        return;
      }
      sendError(res, 500, "Internal server error");
      console.error("[node] unhandled request error:", err);
    });
  });
}

/** The demo-log event name for a round path, used in the heading and in `✖` lines. */
function eventName(path: string): string {
  return path.slice(1);
}

async function handle(
  node: IdentityNode,
  demo: DemoLog,
  req: http.IncomingMessage,
  res: http.ServerResponse
): Promise<void> {
  const method = req.method ?? "GET";
  const path = new URL(req.url ?? "/", "http://node.invalid").pathname;

  if (path === "/health") {
    if (method !== "GET" && method !== "HEAD") {
      res.setHeader("Allow", "GET, HEAD");
      sendError(res, 405, `Method ${method} not allowed on ${path}`);
      return;
    }
    const body: HealthResponseWire = {
      status: "ok",
      nodeId: node.nodeId,
      groupPublicKey: base64UrlEncode(node.groupPublicKey),
    };
    sendJson(res, 200, body);
    return;
  }

  if (path === "/commit" || path === "/sign-on" || path === "/refresh") {
    if (method !== "POST") {
      res.setHeader("Allow", "POST");
      sendError(res, 405, `Method ${method} not allowed on ${path}`);
      return;
    }

    const collected = await readBody(req);
    if (collected.kind === "aborted") {
      return;
    }
    if (collected.kind === "too-large") {
      res.setHeader("Connection", "close");
      sendError(res, 413, `Request body exceeds ${MAX_BODY_BYTES} bytes`);
      return;
    }

    let body: unknown;
    try {
      body = JSON.parse(collected.text);
    } catch {
      sendError(res, 400, "Request body is not valid JSON");
      return;
    }

    try {
      if (path === "/commit") {
        const { roundId } = commitEnvelopeFromWire(body);
        const { D, E } = node.generateCommitment(roundId);
        const out: CommitResponseWire = {
          nodeId: node.nodeId,
          D: base64UrlEncode(D),
          E: base64UrlEncode(E),
        };
        demo.commit({ roundId, D: out.D, E: out.E });
        sendJson(res, 200, out);
        return;
      }

      if (path === "/sign-on") {
        const { roundId, request } = signOnEnvelopeFromWire(body);
        const commitment = ownCommitment(node.nodeId, request.commitments);
        const out: SignOnResponseWire = signOnResponseToWire(
          node.handleSignOn(roundId, request, commitment)
        );
        // Everything logged is either already on the wire or a public parameter: the
        // blinded point hides the password, and z_i never leaves `IdentityNode` in the
        // clear, so the demo line states that it exists without a value.
        demo.signOn({
          roundId,
          sessionId: request.sessionId,
          username: request.username,
          blinded: request.blinded,
          sessionNonce: request.sessionNonce,
          cnfJkt: request.cnfJkt,
          participants: request.allParticipants.length,
          toprfPartial: out.toprfPartial,
          ct: out.ct_i,
        });
        sendJson(res, 200, out);
        return;
      }

      const { roundId, request } = refreshEnvelopeFromWire(body);
      const commitment = ownCommitment(node.nodeId, request.commitments);
      const out: RefreshResponseWire = refreshResponseToWire(
        node.handleRefresh(roundId, request, commitment)
      );
      demo.refresh({
        roundId,
        sessionId: request.sessionId,
        participants: request.allParticipants.length,
        ctr: out.ctr,
        ct: out.ct_i,
      });
      sendJson(res, 200, out);
      return;
    } catch (err) {
      // Both malformed bodies and every rejection from IdentityNode (unknown user,
      // expired round, bad DPoP proof) are client errors. The demo log carries the
      // rejection reason verbatim, so a refusal is visible next to the successes.
      const message = err instanceof Error ? err.message : String(err);
      demo.reject(eventName(path), message);
      sendError(res, 400, message);
      return;
    }
  }

  sendError(res, 404, `Not found: ${method} ${path}`);
}
