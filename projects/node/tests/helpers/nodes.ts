import http from "node:http";
import type { AddressInfo } from "node:net";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { loadNodeConfig, type NodeConfig } from "../../src/config.js";
import { createDemoLog, type DemoLog } from "../../src/demolog.js";
import { IdentityNode } from "../../src/protocol/node.js";
import { createNodeServer } from "../../src/server.js";

/** Absolute path of a file in `tests/fixtures/`. */
export function fixturePath(name: string): string {
  return fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url));
}

/** Reads a fixture as parsed JSON. */
export function readFixtureJson(name: string): any {
  return JSON.parse(fs.readFileSync(fixturePath(name), "utf8"));
}

/** Decodes lowercase hex into bytes (fixtures use the dealer's hex encoding). */
export function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Builds an `IdentityNode` from a fixture config, users already registered. */
export function buildNodeFromFixture(name: string): { node: IdentityNode; config: NodeConfig } {
  const config = loadNodeConfig(fixturePath(name));
  const node = new IdentityNode(config.nodeId, config.secretKeyShare, config.groupPublicKey);
  for (const user of config.users) {
    node.registerUser(user.username, user.sub, user.toprfKeyShare, user.h_i);
  }
  return { node, config };
}

export interface RunningNode {
  nodeId: number;
  url: string;
  node: IdentityNode;
  server: http.Server;
  close(): Promise<void>;
}

/**
 * Starts one node server on an ephemeral port (port 0), as a separate HTTP endpoint.
 *
 * The demo log is off unless a test asks for one: three nodes tracing every round would
 * bury the test output, and only `tests/demolog.test.ts` looks at those lines.
 */
export async function startNodeFromFixture(name: string, demoLog?: DemoLog): Promise<RunningNode> {
  const { node, config } = buildNodeFromFixture(name);
  const server = createNodeServer(
    node,
    demoLog ?? createDemoLog({ nodeId: config.nodeId, total: config.total, env: { DEMO_LOG: "0" } })
  );

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve();
    });
  });

  const { port } = server.address() as AddressInfo;

  return {
    nodeId: config.nodeId,
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

/** Starts node-1, node-2 and node-3 from the fixtures, each on its own port. */
export async function startAllNodes(): Promise<RunningNode[]> {
  return Promise.all([
    startNodeFromFixture("node-1.json"),
    startNodeFromFixture("node-2.json"),
    startNodeFromFixture("node-3.json"),
  ]);
}

export async function stopAll(nodes: RunningNode[]): Promise<void> {
  await Promise.all(nodes.map((n) => n.close()));
}

export interface JsonResponse {
  status: number;
  body: any;
  text: string;
}

/** POSTs JSON (or raw text, to exercise malformed bodies) and reads the JSON reply. */
export async function postJson(
  url: string,
  path: string,
  body: unknown,
  options: { raw?: string; contentType?: string } = {}
): Promise<JsonResponse> {
  const res = await fetch(`${url}${path}`, {
    method: "POST",
    headers: { "Content-Type": options.contentType ?? "application/json" },
    body: options.raw ?? JSON.stringify(body),
  });
  const text = await res.text();
  let parsed: any = undefined;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = undefined;
  }
  return { status: res.status, body: parsed, text };
}

export async function getJson(url: string, path: string): Promise<JsonResponse> {
  const res = await fetch(`${url}${path}`);
  const text = await res.text();
  let parsed: any = undefined;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = undefined;
  }
  return { status: res.status, body: parsed, text };
}

/** POSTs JSON and fails loudly on any non-200, so tests do not silently continue. */
export async function postJsonOrThrow(url: string, path: string, body: unknown): Promise<any> {
  const res = await postJson(url, path, body);
  if (res.status !== 200) {
    throw new Error(`POST ${path} -> ${res.status}: ${res.text}`);
  }
  return res.body;
}
