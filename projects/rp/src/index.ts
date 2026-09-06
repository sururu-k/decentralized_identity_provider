import { configFromEnv, portFromEnv } from "./config.js";
import { logStartup } from "./demolog.js";
import { createRpServer, redirectUriFor } from "./server.js";

const config = configFromEnv();
const port = portFromEnv();
const server = createRpServer(config);

server.listen(port, () => {
  console.log(`[RP] ZK-App Portal listening on port ${port} (${config.rpBaseUrl})`);
  console.log(`[RP] authorization server: ${config.issuer}`);
  console.log(`[RP] client_id:            ${config.clientId}`);
  console.log(`[RP] redirect_uri:         ${redirectUriFor(config)}`);
  console.log(`[RP] /token and /jwks.json are called by the browser, not by this process`);
  // The one place the rp states what it holds and what it never sees (section 10).
  logStartup({ issuer: config.issuer });
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    console.log(`[RP] received ${signal}, shutting down`);
    server.close(() => process.exit(0));
  });
}

export { server, config };
