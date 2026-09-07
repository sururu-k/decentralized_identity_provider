import crypto from "node:crypto";
import http from "node:http";
import url from "node:url";
import { verifyDPoPProof } from "./client-sdk/dpop.js";
import { DemoLog, createDemoLog } from "./demolog.js";
import { OidcEndpointHandler } from "./gateway/oidc.js";
import {
  InvalidCredentialError,
  PastaOAuthProxy,
  ProxyTokenResult,
  QuorumError,
  decodeCredentialClaims,
} from "./gateway/proxy.js";
import { signOnResultToWire } from "./gateway/wire.js";
import { HttpNodeClient } from "./nodes/http-node-client.js";
import { Grant } from "./protocol/types.js";
import { lookupStatic } from "./static.js";

/** Largest request body the gateway accepts, in bytes. Matches the monolith. */
export const MAX_BODY_BYTES = 1e6;

/** Default RP origin allowed to call `/token` and `/jwks.json` cross-origin (section 14.4). */
export const DEFAULT_RP_ORIGIN = "http://localhost:3001";

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
  /** Origin allowed to call `/token` and `/jwks.json` (section 14.4). */
  rpOrigin?: string;
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
 * Reads `scope`, which reaches the assertion payload but may legitimately be empty.
 *
 * An absent scope becomes `""`; a non-string is refused, because the reference
 * `deterministicJsonStringify` would otherwise write `"scope":undefined` into the payload
 * (`jwt.ts` is frozen, so the gateway guards the door instead, as with `nonce`).
 */
function requireScope(body: unknown): string {
  const value = (body as Record<string, unknown> | null | undefined)?.["scope"];
  if (value === undefined) {
    return "";
  }
  if (typeof value !== "string") {
    throw new BadRequestBodyError(`scope must be a string, got ${value === null ? "null" : typeof value}`);
  }
  return value;
}

/** An OAuth `/token` error carrying the RFC 6749 code and the HTTP status to answer with. */
export class TokenError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string
  ) {
    super(message);
    this.name = "TokenError";
  }
}

/**
 * The body of `POST /token` (section 14).
 *
 * Reads the grant, the DPoP proof from the header, and the credential the grant names.
 * The gateway's own check is the "proof key equals credential `cnf.jkt`" double defence
 * (section 14.2); the nodes verify everything else, each for itself. The credential and
 * the proof are then relayed to `handleSign`, which runs the two FROST rounds and
 * synthesises the two tokens.
 */
async function handleToken(
  proxy: PastaOAuthProxy,
  form: Record<string, string>,
  dpopHeader: string | string[] | undefined,
  tokenEndpoint: string
): Promise<ProxyTokenResult> {
  const grantType = form.grant_type;
  if (grantType !== "authorization_code" && grantType !== "refresh_token") {
    throw new TokenError(
      400,
      "unsupported_grant_type",
      `grant_type ${JSON.stringify(grantType ?? "")} is not supported`
    );
  }
  const grant: Grant = grantType;

  const proof =
    typeof dpopHeader === "string"
      ? dpopHeader
      : Array.isArray(dpopHeader)
        ? dpopHeader[0]
        : undefined;
  if (!proof) {
    throw new TokenError(400, "invalid_dpop_proof", "a DPoP header is required");
  }

  const credential = grant === "authorization_code" ? form.code : form.refresh_token;
  if (!credential) {
    throw new TokenError(
      400,
      "invalid_request",
      grant === "authorization_code" ? "code is required" : "refresh_token is required"
    );
  }

  let jkt: string;
  try {
    jkt = decodeCredentialClaims(credential).cnf.jkt;
  } catch (err) {
    throw new TokenError(400, "invalid_grant", errorMessage(err));
  }

  const verification = verifyDPoPProof(proof, {
    expectedHtm: "POST",
    expectedHtu: tokenEndpoint,
    expectedJkt: jkt,
    maxAgeSeconds: 60,
  });
  if (!verification.valid) {
    throw new TokenError(400, "invalid_dpop_proof", verification.error ?? "invalid DPoP proof");
  }

  try {
    return await proxy.handleSign(grant, credential, proof);
  } catch (err) {
    // The nodes rejected the credential or the proof, or a quorum could not form. Either
    // way the caller cannot mint a token with what it presented: an invalid grant.
    throw new TokenError(400, "invalid_grant", errorMessage(err));
  }
}

/** Maps a `/token` failure to its status and RFC 6749 error body. */
function tokenError(err: unknown): { status: number; error: string; description: string } {
  if (err instanceof TokenError) {
    return { status: err.status, error: err.code, description: err.message };
  }
  if (err instanceof InvalidCredentialError) {
    return { status: 400, error: "invalid_grant", description: err.message };
  }
  return { status: 400, error: "invalid_request", description: errorMessage(err) };
}

/**
 * Builds the gateway's HTTP server without binding a port, so callers (and tests) decide
 * where it listens.
 *
 * Routes (`docs/container-split.md` sections 6 and 14):
 *   GET  /.well-known/openid-configuration
 *   GET  /jwks.json
 *   GET  /authorize            (response_type=code)
 *   POST /api/pasta/sign-on
 *   POST /token                (authorization_code / refresh_token grants)
 *   GET  /, /demo, /assets/*
 *   GET  /health
 *
 * Ported from the monolith's `src/bin/gateway.ts`, then reshaped for OAuth (section 14).
 * The id_token flow is gone: `/authorize` issues a `code` (the assertion), and `/token`
 * exchanges it, with the DPoP proof and the credential relayed to the nodes. `/rp`,
 * `/rp/callback`, `/api/pasta/browser-sign-on`, `/api/pasta/refresh` and `/demo/rp-callback`
 * are all gone. The gateway holds no user state: sign-on takes `username` and `blinded`
 * and nothing else off the body, and `/token` keeps neither the code nor the refresh
 * token it relays.
 */
export function createGatewayServer(deps: GatewayDeps): http.Server {
  const demoLog = deps.demoLog ?? createDemoLog();
  const rpOrigin = deps.rpOrigin ?? DEFAULT_RP_ORIGIN;
  const tokenEndpoint = `${deps.issuer.replace(/\/+$/, "")}/token`;
  const oidc = new OidcEndpointHandler({
    issuer: deps.issuer,
    groupPublicKey: deps.groupPublicKey,
    keyId: deps.keyId,
  });

  return http.createServer(async (req, res) => {
    const reqUrl = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
    const pathname = reqUrl.pathname;
    const method = req.method || "GET";

    // CORS. `/token` and `/jwks.json` are called cross-origin by the RP front end, which
    // sends a non-simple `DPoP` header, so their preflight must name it. They are pinned
    // to the RP origin (section 14.4); every other route keeps the permissive default.
    if (pathname === "/token") {
      res.setHeader("Access-Control-Allow-Origin", rpOrigin);
      res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "DPoP, Content-Type");
    } else if (pathname === "/jwks.json") {
      res.setHeader("Access-Control-Allow-Origin", rpOrigin);
      res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    } else {
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type, DPoP, Authorization");
    }

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

        // The challenge `c` becomes the assertion's nonce and limits its replay window.
        // The gateway generates it and forgets it: nothing here is stored (section 14.1).
        const challenge = crypto.randomUUID();

        demoLog.authorize({
          clientId: validation.params.clientId,
          redirectUri: validation.params.redirectUri,
          nonce: challenge,
          state: validation.params.state,
          dpopJkt: validation.params.dpopJkt,
        });

        const html = oidc.renderAuthorizePage({ ...validation.params, challenge });
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(html);
        return;
      }

      // 4. Proxy Sign-On Endpoint. The gateway relays blinded ciphertext shares; it holds
      // no password and no session. The assertion the client assembles is the code.
      if (method === "POST" && pathname === "/api/pasta/sign-on") {
        const body = await readJsonBody(req);
        let result;
        try {
          // Both `nonce` (the authorize challenge `c`) and `clientId` reach the assertion
          // payload; the reference `deterministicJsonStringify` writes an absent one out
          // as `"...":undefined`, unparseable JSON, so the gateway refuses it at the door
          // (section 6). `scope` may be empty but must be a string.
          const signOnBody = {
            ...body,
            clientId: requireField(body, "clientId"),
            nonce: requireField(body, "nonce"),
            scope: requireScope(body),
          };
          result = await deps.proxy.handleSignOn(signOnBody);
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

      // 5. Token Endpoint (section 14). Exchanges a code (assertion) or a refresh token,
      // presented with a DPoP proof, for an access token and the next refresh token.
      if (method === "POST" && pathname === "/token") {
        const form = await readUrlEncodedBody(req);
        try {
          const { accessToken, refreshToken, expiresIn, scope } = await handleToken(
            deps.proxy,
            form,
            req.headers["dpop"],
            tokenEndpoint
          );
          res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
          res.end(
            JSON.stringify({
              access_token: accessToken,
              token_type: "DPoP",
              expires_in: expiresIn,
              refresh_token: refreshToken,
              scope,
            })
          );
        } catch (err) {
          const { status, error, description } = tokenError(err);
          demoLog.reject("token", `${error}: ${description}`);
          res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store" });
          res.end(JSON.stringify({ error, error_description: description }));
        }
        return;
      }

      // 6. Serve React Web Demo UI
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
