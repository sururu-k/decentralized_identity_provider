import http from "node:http";
import type { AddressInfo } from "node:net";
import { createDemoLog, type DemoLog } from "../../src/demolog.js";
import { PastaOAuthProxy } from "../../src/gateway/proxy.js";
import { discoverNodes } from "../../src/nodes/discovery.js";
import { createGatewayServer } from "../../src/server.js";
import { TEST_ISSUER, hexToBytes, readFixtureJson } from "./fake-node.js";

export { TEST_ISSUER };

/**
 * Starts a real gateway server on an ephemeral port, wired to real node URLs.
 *
 * `issuer` is deliberately independent of the listen URL. The gateway uses it for the
 * discovery document and for verifying tokens posted back to `/demo/rp-callback`; the
 * value that has to match between client and node is the `iss` the client sends, and the
 * tests pass the same string to both. That keeps the helper from having to know its port
 * before it binds one.
 *
 * The demo log is built with an explicit empty environment and `isTty: false` rather than
 * being left to read `process.env`, so the lines a test asserts on are the same whether
 * the suite runs in a terminal or in CI. Colour itself is covered by `demolog.test.ts`.
 */

export interface RunningGateway {
  url: string;
  issuer: string;
  rpOrigin: string;
  server: http.Server;
  proxy: PastaOAuthProxy;
  close(): Promise<void>;
}

export interface StartGatewayOptions {
  nodeUrls: string[];
  threshold?: number;
  demoDist?: string;
  issuer?: string;
  rpOrigin?: string;
  demoLog?: DemoLog;
}

export async function startGateway(options: StartGatewayOptions): Promise<RunningGateway> {
  const group = readFixtureJson("group.json");
  const groupPublicKey = hexToBytes(group.groupPublicKey);
  const threshold = options.threshold ?? group.threshold;
  const issuer = options.issuer ?? TEST_ISSUER;
  const rpOrigin = options.rpOrigin ?? "http://localhost:3001";

  const nodes = await discoverNodes({
    urls: options.nodeUrls,
    groupPublicKey,
    threshold,
    attempts: 3,
    retryDelayMs: 50,
  });

  const demoLog = options.demoLog ?? createDemoLog({ env: {}, isTty: false });
  const proxy = new PastaOAuthProxy(nodes, threshold, demoLog, issuer, group.keyId);
  const server = createGatewayServer({
    issuer,
    threshold,
    groupPublicKey,
    keyId: group.keyId,
    proxy,
    nodes,
    demoDist: options.demoDist ?? "/nonexistent-demo-dist",
    rpOrigin,
    demoLog,
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve();
    });
  });

  const { port } = server.address() as AddressInfo;

  return {
    url: `http://127.0.0.1:${port}`,
    issuer,
    rpOrigin,
    server,
    proxy,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

export interface JsonResponse {
  status: number;
  body: any;
  text: string;
}

async function readResponse(res: Response): Promise<JsonResponse> {
  const text = await res.text();
  let parsed: any;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = undefined;
  }
  return { status: res.status, body: parsed, text };
}

export async function getJson(url: string, path: string): Promise<JsonResponse> {
  return readResponse(await fetch(`${url}${path}`, { redirect: "manual" }));
}

export async function postJson(url: string, path: string, body: unknown): Promise<JsonResponse> {
  return readResponse(
    await fetch(`${url}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    })
  );
}

export async function postForm(
  url: string,
  path: string,
  fields: Record<string, string>
): Promise<JsonResponse> {
  return readResponse(
    await fetch(`${url}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(fields).toString(),
    })
  );
}

/** `POST /token`: form body plus an optional `DPoP` proof header (section 14). */
export async function postToken(
  url: string,
  fields: Record<string, string>,
  dpopProof?: string
): Promise<JsonResponse> {
  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded",
  };
  if (dpopProof !== undefined) {
    headers["DPoP"] = dpopProof;
  }
  return readResponse(
    await fetch(`${url}/token`, {
      method: "POST",
      headers,
      body: new URLSearchParams(fields).toString(),
    })
  );
}
