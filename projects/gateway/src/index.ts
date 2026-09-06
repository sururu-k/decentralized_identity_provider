import { ConfigError, bytesToHex, loadGroupConfig } from "./config.js";
import { createDemoLog } from "./demolog.js";
import { PastaOAuthProxy } from "./gateway/proxy.js";
import { DiscoveryError, discoverNodes, parseNodeUrls } from "./nodes/discovery.js";
import { createGatewayServer } from "./server.js";

const DEFAULT_PORT = 3000;
const DEFAULT_GROUP_CONFIG = "/secrets/group.json";
const DEFAULT_NODE_URLS = "http://localhost:4001,http://localhost:4002,http://localhost:4003";
const DEFAULT_DEMO_DIST = "/app/ui";
/** The `kid` the copied client SDK writes into every JWT header. */
const SDK_KEY_ID = "pasta-group-key-1";
const SHUTDOWN_GRACE_MS = 10_000;

function readPort(raw: string | undefined): number {
  if (raw === undefined || raw === "") {
    return DEFAULT_PORT;
  }
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new ConfigError(`Invalid PORT ${JSON.stringify(raw)}: expected an integer in 0..65535`);
  }
  return port;
}

function readThreshold(raw: string | undefined, fallback: number): number {
  if (raw === undefined || raw === "") {
    return fallback;
  }
  const threshold = Number(raw);
  if (!Number.isInteger(threshold) || threshold < 1) {
    throw new ConfigError(`Invalid THRESHOLD ${JSON.stringify(raw)}: expected an integer >= 1`);
  }
  return threshold;
}

async function main(): Promise<void> {
  const port = readPort(process.env.PORT);
  const issuer = (process.env.ISSUER || `http://localhost:${port}`).replace(/\/+$/, "");
  const groupConfigPath = process.env.GROUP_CONFIG || DEFAULT_GROUP_CONFIG;
  const demoDist = process.env.DEMO_DIST || DEFAULT_DEMO_DIST;
  const nodeUrls = parseNodeUrls(process.env.NODE_URLS || DEFAULT_NODE_URLS);

  const group = loadGroupConfig(groupConfigPath);
  const threshold = readThreshold(process.env.THRESHOLD, group.threshold);

  console.log(`[gateway] issuer=${issuer} threshold=${threshold} config=${groupConfigPath}`);
  if (group.keyId !== SDK_KEY_ID) {
    // The client SDK stamps a fixed `kid` on every token it assembles, and it is a frozen
    // copy of the reference implementation, so it cannot be told otherwise. A relying
    // party picks its verification key out of the JWKS by that `kid`, so a dealer run with
    // a different `--key-id` publishes a key no token points at.
    console.warn(
      `[gateway] WARNING: group.json keyId is "${group.keyId}" but the client SDK stamps ` +
        `"${SDK_KEY_ID}" on every token. Relying parties select the JWKS key by kid and ` +
        `will reject these tokens. Re-run the dealer with --key-id ${SDK_KEY_ID}.`
    );
  }
  console.log(`[gateway] groupPublicKey=${bytesToHex(group.groupPublicKey)}`);
  console.log(`[gateway] nodes=${nodeUrls.join(", ")}`);

  // Positions in NODE_URLS say nothing about identity; each node reports its own id.
  const nodes = await discoverNodes({
    urls: nodeUrls,
    groupPublicKey: group.groupPublicKey,
    threshold,
    log: (message) => console.log(message),
  });

  // One logger for the whole process, shared by the router and the proxy, so a single
  // `DEMO_LOG=0` switches every event off (`docs/container-split.md` section 10).
  const demoLog = createDemoLog();
  demoLog.startup({
    issuer,
    threshold,
    total: nodes.length,
    keyId: group.keyId,
    nodeUrls: nodes.map((n) => n.url),
  });

  const proxy = new PastaOAuthProxy(nodes, threshold, undefined, demoLog);
  const server = createGatewayServer({
    issuer,
    threshold,
    groupPublicKey: group.groupPublicKey,
    keyId: group.keyId,
    proxy,
    nodes,
    demoDist,
    demoLog,
  });

  server.listen(port, () => {
    const address = server.address();
    const boundPort = typeof address === "object" && address !== null ? address.port : port;
    console.log(`[gateway] OAuth Proxy & OIDC Gateway listening on http://0.0.0.0:${boundPort}`);
    console.log(`[gateway] Discovery: ${issuer}/.well-known/openid-configuration`);
    console.log(`[gateway] JWKS:      ${issuer}/jwks.json`);
    console.log(`[gateway] Demo UI:   ${issuer}/demo (served from ${demoDist})`);
  });

  server.on("error", (err) => {
    console.error(`[gateway] server error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });

  let shuttingDown = false;
  const shutdown = (signal: string): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`[gateway] ${signal} received, shutting down`);

    const timer = setTimeout(() => {
      console.error("[gateway] shutdown timed out, forcing exit");
      process.exit(1);
    }, SHUTDOWN_GRACE_MS);
    timer.unref();

    server.close(() => {
      console.log("[gateway] closed");
      process.exit(0);
    });
    server.closeIdleConnections();
  };

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

main().catch((err) => {
  if (err instanceof ConfigError || err instanceof DiscoveryError) {
    console.error(`[gateway] ${err.message}`);
  } else {
    console.error(`[gateway] startup failed: ${err instanceof Error ? err.message : String(err)}`);
  }
  process.exit(1);
});
