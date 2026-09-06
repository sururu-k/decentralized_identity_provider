#!/usr/bin/env tsx
/**
 * CLI stand-in for the browser (docs/container-split.md sections 10 and 11).
 *
 * Runs exactly the code the demo UI runs -- `../src/sdk/` -- under Node 20 or newer,
 * where `globalThis.crypto` is WebCrypto and `fetch` is built in. Nothing in the SDK is
 * branched on the runtime, so a token minted here and a token minted in the browser are
 * produced by the same instructions.
 *
 * The id_token is the last line of stdout and nothing else goes there, so the integration
 * test can pipe it. The section 10 demo log goes to stderr, in yellow when stderr is a
 * TTY (`NO_COLOR` disables, `FORCE_COLOR=1` forces).
 *
 *   npm run -s sign-on -- --gateway http://localhost:3000 --user alice \
 *     --password password123 --client-id demo_client --nonce n1 [--refresh]
 */
import { DecentralizedClientSdk } from "../src/sdk/client.js";
import { colorizeDemoLine, type DemoEvent } from "../src/sdk/events.js";

interface Options {
  gateway: string;
  issuer: string;
  user: string;
  password: string;
  clientId: string;
  nonce: string;
  refresh: boolean;
}

const USAGE = `Usage: npm run -s sign-on -- [options]

  --gateway <url>     Gateway base URL (default http://localhost:3000)
  --issuer <url>      Expected JWT issuer (default: same as --gateway)
  --user <name>       Username (default alice)
  --password <pw>     Password (required)
  --client-id <id>    OAuth client_id / aud (default demo_client)
  --nonce <str>       OIDC nonce, required by the gateway (default cli_<random>)
  --refresh           After sign-on, run a DPoP refresh and print the new token
  -h, --help          This text
`;

function parseArgs(argv: string[]): Options {
  const values = new Map<string, string>();
  let refresh = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "-h" || arg === "--help") {
      process.stdout.write(USAGE);
      process.exit(0);
    }
    if (arg === "--refresh") {
      refresh = true;
      continue;
    }
    if (!arg.startsWith("--")) {
      throw new Error(`Unexpected argument: ${arg}`);
    }
    const eq = arg.indexOf("=");
    if (eq !== -1) {
      values.set(arg.slice(2, eq), arg.slice(eq + 1));
      continue;
    }
    const next = argv[i + 1];
    if (next === undefined || next.startsWith("--")) {
      throw new Error(`Missing value for ${arg}`);
    }
    values.set(arg.slice(2), next);
    i++;
  }

  const stripSlash = (url: string) => url.replace(/\/+$/, "");
  const gateway = stripSlash(values.get("gateway") ?? "http://localhost:3000");
  const password = values.get("password");
  if (password === undefined) {
    throw new Error("--password is required");
  }

  return {
    gateway,
    issuer: stripSlash(values.get("issuer") ?? gateway),
    user: values.get("user") ?? "alice",
    password,
    clientId: values.get("client-id") ?? "demo_client",
    nonce: values.get("nonce") ?? `cli_${Math.random().toString(36).slice(2, 10)}`,
    refresh,
  };
}

function useColor(): boolean {
  if (process.env.NO_COLOR) return false;
  if (process.env.FORCE_COLOR === "1") return true;
  return Boolean(process.stderr.isTTY);
}

function makeSink(): (event: DemoEvent) => void {
  if ((process.env.DEMO_LOG ?? "1") === "0") {
    return () => {};
  }
  const color = useColor();
  return (event: DemoEvent) => {
    for (const line of event.lines) {
      process.stderr.write(`${color ? colorizeDemoLine(line) : line}\n`);
    }
  };
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));

  const sdk = new DecentralizedClientSdk({
    proxyUrl: options.gateway,
    issuer: options.issuer,
    onEvent: makeSink(),
  });

  const signedOn = await sdk.signOn({
    username: options.user,
    password: options.password,
    clientId: options.clientId,
    nonce: options.nonce,
  });

  let idToken = signedOn.id_token;

  if (options.refresh) {
    const refreshed = await sdk.refresh({
      clientId: options.clientId,
      nonce: options.nonce,
      refreshEndpointUrl: `${options.gateway}/api/pasta/refresh`,
    });
    idToken = refreshed.id_token;
  }

  // Last line of stdout, and the only thing on it.
  process.stdout.write(`${idToken}\n`);
}

main().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`sign-on failed: ${message}\n`);
  process.exit(1);
});
