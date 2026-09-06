import http from "node:http";
import fs from "node:fs";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import { base64UrlDecode, base64UrlEncode } from "../../src/jwt/jwt.js";
import type { FrostCommitment } from "../../src/crypto/frost.js";
import { IdentityNode } from "./protocol/node.js";
import type {
  RefreshRequest,
  RefreshResponse,
  SignOnRequest,
  SignOnResponse,
} from "./protocol/node.js";

/**
 * A stand-in for the `node` container.
 *
 * It wraps a copy of `IdentityNode` in the HTTP API of `docs/container-split.md`
 * section 5, so the gateway's e2e tests exercise the real transport: base64url on the
 * wire, one process-visible endpoint per node, and a real socket that can be closed to
 * simulate an outage. Nothing here is imported from the `node` project -- the two are
 * independent by contract.
 *
 * `helpers/protocol/node.ts` is a byte-identical copy of the monolith's
 * `src/protocol/node.ts`. That file imports "../crypto/frost.js", "../jwt/jwt.js" and so
 * on, and those specifiers have to resolve relative to its own directory, so
 * `helpers/crypto/`, `helpers/client-sdk/` and `helpers/jwt/` hold one-line re-export
 * shims pointing at the real copies under `gateway/src/`. No cryptographic code is
 * duplicated, and the copy stays diff-clean against the original.
 */

export function fixturePath(name: string): string {
  return fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url));
}

export function readFixtureJson(name: string): any {
  return JSON.parse(fs.readFileSync(fixturePath(name), "utf8"));
}

/** Lowercase hex -> bytes. Secrets files use hex (section 3). */
export function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** A dealer scalar is 64 hex digits, big-endian (section 3). */
export function hexToScalar(hex: string): bigint {
  return BigInt("0x" + hex);
}

export function buildNodeFromFixture(name: string): IdentityNode {
  const config = readFixtureJson(name);
  const node = new IdentityNode(
    config.nodeId,
    hexToScalar(config.secretKeyShare),
    hexToBytes(config.groupPublicKey)
  );
  for (const user of config.users) {
    node.registerUser(
      user.username,
      user.sub,
      { id: user.toprfKeyShare.id, value: hexToScalar(user.toprfKeyShare.value) },
      hexToBytes(user.h_i)
    );
  }
  return node;
}

// --- wire codecs, the mirror image of the gateway's -------------------------

function requireObject(where: string, value: any): any {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${where} must be an object`);
  }
  return value;
}

function requireString(where: string, value: any): string {
  if (typeof value !== "string") {
    throw new Error(`${where} must be a string`);
  }
  return value;
}

function requireNonEmptyString(where: string, value: any): string {
  const s = requireString(where, value);
  if (s.length === 0) {
    throw new Error(`${where} must not be empty`);
  }
  return s;
}

function requireNumber(where: string, value: any): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`${where} must be a number`);
  }
  return value;
}

function requireIntegerArray(where: string, value: any): number[] {
  if (!Array.isArray(value)) {
    throw new Error(`${where} must be an array`);
  }
  return value.map((v, i) => {
    if (!Number.isInteger(v)) {
      throw new Error(`${where}[${i}] must be an integer`);
    }
    return v as number;
  });
}

function decodePoint(where: string, value: any): Uint8Array {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error(`${where} must be base64url without padding`);
  }
  const bytes = base64UrlDecode(value);
  if (bytes.length !== 32) {
    throw new Error(`${where} must decode to 32 bytes, got ${bytes.length}`);
  }
  return bytes;
}

function commitmentFromWire(raw: any, where = "commitment"): FrostCommitment {
  const obj = requireObject(where, raw);
  if (!Number.isInteger(obj.nodeId)) {
    throw new Error(`${where}.nodeId must be an integer`);
  }
  return {
    nodeId: obj.nodeId,
    D: decodePoint(`${where}.D`, obj.D),
    E: decodePoint(`${where}.E`, obj.E),
  };
}

function commitmentsFromWire(raw: any, where: string): FrostCommitment[] {
  if (!Array.isArray(raw)) {
    throw new Error(`${where} must be an array`);
  }
  return raw.map((c, i) => commitmentFromWire(c, `${where}[${i}]`));
}

/**
 * Decodes the optional `nonce` exactly as the real node does.
 *
 * An absent `nonce` stays absent, so the payload the node signs omits the claim and
 * matches the one the client built. A literal `null` is a caller mistake and is refused,
 * which is what holds the gateway to `docs/container-split.md` section 5 in these tests
 * rather than letting a lenient stand-in paper over it.
 */
function applyNonce(target: { nonce?: string }, raw: any, where: string): void {
  if (!("nonce" in raw) || raw.nonce === undefined) {
    return;
  }
  if (typeof raw.nonce !== "string") {
    throw new Error(`${where}.nonce must be a string when present`);
  }
  target.nonce = raw.nonce;
}

/**
 * The claim and round-1 fields both round-2 requests carry, validated exactly as
 * `node/src/wire.ts` validates them. A stand-in that accepted a body the real node
 * refuses would let a gateway bug pass the e2e suite.
 */
function roundFieldsFromWire(obj: any, where: string) {
  return {
    iat: requireNumber(`${where}.iat`, obj.iat),
    exp: requireNumber(`${where}.exp`, obj.exp),
    aud: requireString(`${where}.aud`, obj.aud),
    iss: requireString(`${where}.iss`, obj.iss),
    commitments: commitmentsFromWire(obj.commitments, `${where}.commitments`),
    allParticipants: requireIntegerArray(`${where}.allParticipants`, obj.allParticipants),
  };
}

function signOnRequestFromWire(raw: any, where = "body.request"): SignOnRequest {
  const obj = requireObject(where, raw);
  const req: SignOnRequest = {
    sessionId: requireNonEmptyString(`${where}.sessionId`, obj.sessionId),
    username: requireNonEmptyString(`${where}.username`, obj.username),
    blinded: requireNonEmptyString(`${where}.blinded`, obj.blinded),
    sessionNonce: requireNonEmptyString(`${where}.sessionNonce`, obj.sessionNonce),
    cnfJkt: requireNonEmptyString(`${where}.cnfJkt`, obj.cnfJkt),
    ...roundFieldsFromWire(obj, where),
  };
  applyNonce(req, obj, where);
  return req;
}

function refreshRequestFromWire(raw: any, where = "body.request"): RefreshRequest {
  const obj = requireObject(where, raw);
  const req: RefreshRequest = {
    sessionId: requireNonEmptyString(`${where}.sessionId`, obj.sessionId),
    dpopProof: requireNonEmptyString(`${where}.dpopProof`, obj.dpopProof),
    expectedHtu: requireNonEmptyString(`${where}.expectedHtu`, obj.expectedHtu),
    ...roundFieldsFromWire(obj, where),
  };
  applyNonce(req, obj, where);
  return req;
}

function signOnResponseToWire(res: SignOnResponse) {
  return {
    nodeId: res.nodeId,
    commitment: { D: base64UrlEncode(res.commitment.D), E: base64UrlEncode(res.commitment.E) },
    toprfPartial: res.toprfPartial,
    ct_i: res.ct_i,
    sessionId: res.sessionId,
    sub: res.sub,
  };
}

function refreshResponseToWire(res: RefreshResponse) {
  return {
    nodeId: res.nodeId,
    commitment: { D: base64UrlEncode(res.commitment.D), E: base64UrlEncode(res.commitment.E) },
    ct_i: res.ct_i,
    ctr: res.ctr,
    sub: res.sub,
  };
}

function ownCommitment(nodeId: number, commitments: FrostCommitment[]) {
  const mine = commitments.find((c) => c.nodeId === nodeId);
  if (!mine) throw new Error(`commitments contains no entry for node ${nodeId}`);
  return { D: mine.D, E: mine.E };
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  const payload = Buffer.from(JSON.stringify(body), "utf8");
  res.writeHead(status, { "Content-Type": "application/json", "Content-Length": payload.length });
  res.end(payload);
}

export function createFakeNodeServer(node: IdentityNode): http.Server {
  return http.createServer(async (req, res) => {
    const path = new URL(req.url ?? "/", "http://node.invalid").pathname;
    const method = req.method ?? "GET";

    try {
      if (path === "/health" && (method === "GET" || method === "HEAD")) {
        sendJson(res, 200, {
          status: "ok",
          nodeId: node.nodeId,
          groupPublicKey: base64UrlEncode(node.groupPublicKey),
        });
        return;
      }

      if (method !== "POST" || (path !== "/commit" && path !== "/sign-on" && path !== "/refresh")) {
        sendJson(res, 404, { error: `Not found: ${method} ${path}` });
        return;
      }

      const text = await readBody(req);
      let body: any;
      try {
        body = JSON.parse(text);
      } catch {
        sendJson(res, 400, { error: "Request body is not valid JSON" });
        return;
      }

      const envelope = requireObject("body", body);
      if (typeof envelope.roundId !== "string" || envelope.roundId.length === 0) {
        throw new Error("body.roundId must be a non-empty string");
      }

      if (path === "/commit") {
        const { D, E } = node.generateCommitment(body.roundId);
        sendJson(res, 200, {
          nodeId: node.nodeId,
          D: base64UrlEncode(D),
          E: base64UrlEncode(E),
        });
        return;
      }

      if (path === "/sign-on") {
        const request = signOnRequestFromWire(body.request);
        const result = node.handleSignOn(
          body.roundId,
          request,
          ownCommitment(node.nodeId, request.commitments)
        );
        sendJson(res, 200, signOnResponseToWire(result));
        return;
      }

      const request = refreshRequestFromWire(body.request);
      const result = node.handleRefresh(
        body.roundId,
        request,
        ownCommitment(node.nodeId, request.commitments)
      );
      sendJson(res, 200, refreshResponseToWire(result));
    } catch (err) {
      sendJson(res, 400, { error: err instanceof Error ? err.message : String(err) });
    }
  });
}

export interface RunningFakeNode {
  nodeId: number;
  url: string;
  node: IdentityNode;
  server: http.Server;
  close(): Promise<void>;
}

export async function startFakeNode(fixture: string): Promise<RunningFakeNode> {
  const node = buildNodeFromFixture(fixture);
  const server = createFakeNodeServer(node);

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve();
    });
  });

  const { port } = server.address() as AddressInfo;

  return {
    nodeId: node.nodeId,
    url: `http://127.0.0.1:${port}`,
    node,
    server,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

export async function startFakeNodes(): Promise<RunningFakeNode[]> {
  return Promise.all([
    startFakeNode("node-1.json"),
    startFakeNode("node-2.json"),
    startFakeNode("node-3.json"),
  ]);
}
