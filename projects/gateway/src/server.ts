import http from "node:http";
import url from "node:url";
import { renderDemoRpCallbackPage } from "./demo-callback.js";
import { DemoLog, createDemoLog } from "./demolog.js";
import { OidcEndpointHandler } from "./gateway/oidc.js";
import { PastaOAuthProxy, QuorumError } from "./gateway/proxy.js";
import { refreshResultToWire, signOnResultToWire } from "./gateway/wire.js";
import { verifyJwt } from "./jwt/jwt.js";
import { HttpNodeClient } from "./nodes/http-node-client.js";
import { lookupStatic } from "./static.js";

/** Largest request body the gateway accepts, in bytes. Matches the monolith. */
export const MAX_BODY_BYTES = 1e6;

export interface GatewayDeps {
  issuer: string;
  threshold: number;
  groupPublicKey: Uint8Array;
  keyId: string;
  proxy: PastaOAuthProxy;
  /** Node clients, used for `/health`. The proxy holds the same objects. */
  nodes: HttpNodeClient[];
  /** Directory holding the built demo UI. */
  demoDist: string;
  /** Demo log (`docs/container-split.md` section 10). Defaults to the process-wide one. */
  demoLog?: DemoLog;
}

/** How much of an over-long upload is drained before the socket is simply cut. */
const MAX_DRAIN_BYTES = 8 * MAX_BODY_BYTES;

/** An over-long request body. A caller error, so it answers 413 rather than 500. */
export class PayloadTooLargeError extends Error {
  constructor() {
    super(`Request body exceeds ${MAX_BODY_BYTES} bytes`);
    this.name = "PayloadTooLargeError";
  }
}

/** The client hung up before the body finished. Nothing is written back. */
export class RequestAbortedError extends Error {
  constructor() {
    super("Request aborted by the client");
    this.name = "RequestAbortedError";
  }
}

/** A body that arrived but is not the syntax the route expects. Answers 400. */
export class BadRequestBodyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BadRequestBodyError";
  }
}

type BodyResult = { kind: "ok"; text: string } | { kind: "too-large" } | { kind: "aborted" };

/**
 * Collects a request body, refusing anything over `MAX_BODY_BYTES`.
 *
 * The size is counted in bytes, not in the UTF-16 code units of a decoded string, so a
 * multi-byte body cannot slip past the limit. An over-long body is discarded as it
 * arrives rather than buffered, and the 413 is sent only once the client has finished
 * writing: answering mid-upload tears the socket down under the client, which then sees a
 * broken pipe instead of the status. The drain is capped, so a client that keeps sending
 * gets the socket cut instead.
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
        tooLarge
          ? { kind: "too-large" }
          : { kind: "ok", text: Buffer.concat(chunks).toString("utf8") }
      );
    });
    // A client that hangs up mid-upload is ordinary, not an internal error.
    req.on("close", () => resolve({ kind: "aborted" }));
    req.on("error", () => resolve({ kind: "aborted" }));
  });
}

async function readJsonBody(req: http.IncomingMessage): Promise<any> {
  const collected = await readBody(req);
  if (collected.kind === "too-large") {
    throw new PayloadTooLargeError();
  }
  if (collected.kind === "aborted") {
    throw new RequestAbortedError();
  }
  if (collected.text.length === 0) {
    return {};
  }
  try {
    return JSON.parse(collected.text);
  } catch {
    throw new BadRequestBodyError("Request body is not valid JSON");
  }
}

async function readUrlEncodedBody(req: http.IncomingMessage): Promise<Record<string, string>> {
  const collected = await readBody(req);
  if (collected.kind === "too-large") {
    throw new PayloadTooLargeError();
  }
  if (collected.kind === "aborted") {
    throw new RequestAbortedError();
  }
  const parsed = new url.URLSearchParams(collected.text);
  const result: Record<string, string> = {};
  for (const [key, value] of parsed.entries()) {
    result[key] = value;
  }
  return result;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * The reason text for a `✖ ... rejected:` demo line.
 *
 * A quorum failure is the one refusal the demo is built around, so section 10 gives it a
 * compact shape of its own -- `quorum 1 < 2 (node2, node3 unreachable)` -- instead of the
 * sentence that goes back to the client, which is left untouched.
 */
function rejectReason(err: unknown): string {
  if (err instanceof QuorumError) {
    const names = err.unreachable.map((id) => `node${id}`).join(", ");
    return `quorum ${err.committed} < ${err.threshold}${names ? ` (${names} unreachable)` : ""}`;
  }
  return errorMessage(err);
}

/**
 * How long `/health` waits on one node before calling it unreachable.
 *
 * Shorter than a node call's default budget on purpose: `/health` probes every node
 * before it answers, and Docker's `HEALTHCHECK --timeout` is 3s (`docs/container-split.md`
 * section 8). One hung node must not push the gateway's own answer past that and make a
 * healthy gateway look dead.
 */
export const HEALTH_PROBE_TIMEOUT_MS = 2_000;

/**
 * Reads a field that must be a non-empty string, or answers 400.
 *
 * `nonce` is the reason this exists. The reference `deterministicJsonStringify` walks
 * `Object.keys`, so a payload built with `nonce: undefined` is written out as
 * `"nonce":undefined` -- not valid JSON. Node and client agree on those bytes, so the
 * FROST signature over them is perfectly good and nothing downstream complains until a
 * relying party tries to `JSON.parse` the payload it just verified. `jwt.ts` is a frozen
 * copy, so the gateway refuses the request at the door instead (section 6). The same
 * reasoning covers `aud`, which reaches the payload as `clientId`.
 */
function requireField(body: unknown, field: string): string {
  const value = (body as Record<string, unknown> | null | undefined)?.[field];
  if (typeof value !== "string" || value.length === 0) {
    throw new BadRequestBodyError(
      `${field} is required and must be a non-empty string` +
        (value === undefined ? "" : `, got ${value === null ? "null" : typeof value}`)
    );
  }
  return value;
}

/**
 * Builds the gateway's HTTP server without binding a port, so callers (and tests) decide
 * where it listens.
 *
 * Routes (`docs/container-split.md` section 6):
 *   GET  /.well-known/openid-configuration
 *   GET  /jwks.json
 *   GET  /authorize
 *   POST /api/pasta/sign-on
 *   POST /api/pasta/refresh
 *   POST /demo/rp-callback
 *   GET  /, /demo, /assets/*
 *   GET  /health
 *
 * Ported from the monolith's `src/bin/gateway.ts`. The `/rp` and `/rp/callback` routes
 * are gone: they are the `rp` component now (section 7), and `/api/pasta/browser-sign-on`
 * is gone with them (section 11). That route ran the client SDK inside the gateway, which
 * meant handing the gateway a plaintext password -- exactly the thing the architecture
 * claims it never sees. The SDK now runs in the browser (`projects/demo`), so nothing
 * here accepts a password, and a request that carries one is not read for it: sign-on
 * takes `username` and `blinded` and nothing else off the body.
 */
export function createGatewayServer(deps: GatewayDeps): http.Server {
  const demoLog = deps.demoLog ?? createDemoLog();
  const oidc = new OidcEndpointHandler({
    issuer: deps.issuer,
    groupPublicKey: deps.groupPublicKey,
    keyId: deps.keyId,
  });

  return http.createServer(async (req, res) => {
    const reqUrl = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
    const pathname = reqUrl.pathname;
    const method = req.method || "GET";

    // CORS headers
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, DPoP, Authorization");

    if (method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    try {
      // 0. Liveness / node roster
      if ((method === "GET" || method === "HEAD") && pathname === "/health") {
        const nodes = await Promise.all(
          deps.nodes.map(async (node) => {
            try {
              await node.health(HEALTH_PROBE_TIMEOUT_MS);
              return { nodeId: node.nodeId, url: node.url, healthy: true };
            } catch {
              return { nodeId: node.nodeId, url: node.url, healthy: false };
            }
          })
        );
        const healthy = nodes.filter((n) => n.healthy).length;
        const quorum = healthy >= deps.threshold;
        res.writeHead(quorum ? 200 : 503, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ status: quorum ? "ok" : "degraded", nodes }));
        return;
      }

      // 1. OIDC Discovery Document
      if (method === "GET" && pathname === "/.well-known/openid-configuration") {
        demoLog.discovery();
        const config = oidc.getDiscoveryConfiguration();
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(config, null, 2));
        return;
      }

      // 2. OIDC JWKS Endpoint
      if (method === "GET" && pathname === "/jwks.json") {
        demoLog.jwks();
        const jwks = oidc.getJwks();
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(jwks, null, 2));
        return;
      }

      // 3. OIDC /authorize Endpoint
      if (method === "GET" && pathname === "/authorize") {
        const query: Record<string, string> = {};
        for (const [k, v] of reqUrl.searchParams.entries()) {
          query[k] = v;
        }
        const validation = oidc.validateAuthorizeRequest(query);
        if (!validation.valid || !validation.params) {
          demoLog.reject("authorize", validation.error ?? "invalid request");
          res.writeHead(400, { "Content-Type": "text/plain" });
          res.end(`Authorize Error: ${validation.error}`);
          return;
        }

        demoLog.authorize({
          clientId: validation.params.clientId,
          redirectUri: validation.params.redirectUri,
          nonce: validation.params.nonce,
          state: validation.params.state,
        });

        const html = oidc.renderAuthorizePage(validation.params);
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(html);
        return;
      }

      // 4. Proxy Sign-On Endpoint (Hole 2: Proxy only relays blinded ciphertext shares)
      if (method === "POST" && pathname === "/api/pasta/sign-on") {
        const body = await readJsonBody(req);
        let result;
        try {
          requireField(body, "nonce");
          result = await deps.proxy.handleSignOn(body);
        } catch (err) {
          // The successful event is logged by the proxy, which is the only place that
          // knows which nodes were excluded from the round.
          demoLog.reject("sign-on", rejectReason(err));
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: errorMessage(err) }));
          return;
        }
        // Byte strings leave as base64url (docs/container-split.md section 3).
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(signOnResultToWire(result)));
        return;
      }

      // 5. Proxy Refresh Endpoint (Hole 5: Nodes verify DPoP proof independently)
      if (method === "POST" && pathname === "/api/pasta/refresh") {
        const body = await readJsonBody(req);
        let result;
        try {
          requireField(body, "nonce");
          result = await deps.proxy.handleRefresh(body);
        } catch (err) {
          demoLog.reject("refresh", rejectReason(err));
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: errorMessage(err) }));
          return;
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(refreshResultToWire(result)));
        return;
      }

      // 6. Demo Relying Party (RP) form_post Callback Endpoint
      if (method === "POST" && pathname === "/demo/rp-callback") {
        const formParams = await readUrlEncodedBody(req);
        const idToken = formParams.id_token;

        if (!idToken) {
          demoLog.reject("rp-demo", "no id_token in the form_post body");
          res.writeHead(400, { "Content-Type": "text/html" });
          res.end("<h1>400 Bad Request: Missing id_token</h1>");
          return;
        }

        // The stand-in RP verifies the Ed25519 token the way any RP would. The page
        // escapes every value it echoes; see `demo-callback.ts`.
        const verifyRes = verifyJwt(idToken, deps.groupPublicKey, { iss: deps.issuer });
        demoLog.demoRpCallback({ idToken, verified: verifyRes.valid });

        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(renderDemoRpCallbackPage(verifyRes, formParams.state));
        return;
      }

      // 7. Serve React Web Demo UI
      if (method === "GET" || method === "HEAD") {
        const lookup = lookupStatic(deps.demoDist, pathname);
        if (lookup.kind === "forbidden") {
          res.writeHead(403, { "Content-Type": "text/plain" });
          res.end("Forbidden");
          return;
        }
        if (lookup.kind === "file") {
          res.writeHead(200, { "Content-Type": lookup.file.contentType });
          res.end(method === "HEAD" ? undefined : lookup.file.content);
          return;
        }
      }

      // Default 404
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("Not Found");
    } catch (err: any) {
      if (res.headersSent) {
        res.destroy();
        return;
      }
      // A client that hung up mid-upload gets nothing written back: the socket is gone.
      if (err instanceof RequestAbortedError) {
        return;
      }
      // An over-long or malformed body is the caller's mistake, not a gateway fault, so
      // it must not be logged as one or answered with a 500.
      if (err instanceof PayloadTooLargeError) {
        res.setHeader("Connection", "close");
        res.writeHead(413, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: err.message }));
        return;
      }
      if (err instanceof BadRequestBodyError) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: err.message }));
        return;
      }
      // Anything reaching here is a gateway fault, not a caller error. The detail goes
      // to the log; the answer says nothing about paths, hostnames or stack internals.
      console.error("Gateway Server Error:", err);
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Internal server error" }));
    }
  });
}
