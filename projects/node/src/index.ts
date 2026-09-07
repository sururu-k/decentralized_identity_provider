import { ConfigError, loadNodeConfig, readIssuer, readPort } from "./config.js";
import { createDemoLog } from "./demolog.js";
import { IdentityNode } from "./protocol/node.js";
import { createNodeServer } from "./server.js";

const DEFAULT_CONFIG_PATH = "/secrets/node.json";
const SHUTDOWN_GRACE_MS = 10_000;

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

function main(): void {
  const configPath = process.env.NODE_CONFIG || DEFAULT_CONFIG_PATH;
  const port = readPort(process.env.PORT);
  const issuer = readIssuer(process.env.ISSUER);

  const config = loadNodeConfig(configPath);

  const node = new IdentityNode(
    config.nodeId,
    config.secretKeyShare,
    config.groupPublicKey,
    issuer
  );
  for (const user of config.users) {
    node.registerUser(user.username, user.sub, user.toprfKeyShare, user.h_i);
  }

  // docs/container-split.md section 10. Only usernames are listed: the shares themselves
  // and every h_i stay out of the log.
  const demo = createDemoLog({ nodeId: config.nodeId, total: config.total });
  const server = createNodeServer(node, demo);

  server.listen(port, () => {
    const address = server.address();
    const boundPort = typeof address === "object" && address !== null ? address.port : port;
    // Nothing secret is printed: the group public key is published through the
    // gateway's JWKS, and neither the FROST share nor any h_i is logged.
    console.log(
      `[node] nodeId=${config.nodeId} threshold=${config.threshold}/${config.total} ` +
        `users=${config.users.length} issuer=${issuer} config=${configPath}`
    );
    console.log(`[node] groupPublicKey=${bytesToHex(config.groupPublicKey)}`);
    console.log(`[node] listening on http://0.0.0.0:${boundPort}`);
    demo.startup({
      threshold: config.threshold,
      total: config.total,
      usernames: config.users.map((u) => u.username),
    });
  });

  server.on("error", (err) => {
    console.error(`[node] server error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });

  let shuttingDown = false;
  const shutdown = (signal: string): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`[node] ${signal} received, shutting down`);

    const timer = setTimeout(() => {
      console.error("[node] shutdown timed out, forcing exit");
      process.exit(1);
    }, SHUTDOWN_GRACE_MS);
    timer.unref();

    server.close(() => {
      console.log("[node] closed");
      process.exit(0);
    });
    server.closeIdleConnections();
  };

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

try {
  main();
} catch (err) {
  if (err instanceof ConfigError) {
    console.error(`[node] ${err.message}`);
  } else {
    console.error(`[node] startup failed: ${err instanceof Error ? err.message : String(err)}`);
  }
  process.exit(1);
}
