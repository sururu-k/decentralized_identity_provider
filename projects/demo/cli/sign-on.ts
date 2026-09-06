#!/usr/bin/env tsx
/**
 * CLI stand-in for the browser (docs/container-split.md sections 10, 11, 13 and 14).
 *
 * It plays both front-end roles of the OAuth authorization-code flow:
 *
 *   rp front end   makes the DPoP key (section 13), keeps it, publishes only the jkt, and
 *                  later signs the `/token` proof and exchanges the code.
 *   IdP front end  runs the same `../src/sdk/` the demo UI runs to turn a password into an
 *                  authentication assertion (the authorization code, section 14).
 *
 * Default action (with `--gateway`): authorize -> sign-on -> code(assertion) -> POST
 * `/token` with a DPoP proof -> print the **access token** as the last line of stdout.
 * `--refresh` then spends the returned refresh token for a new access token. The
 * integration test uses this as its "browser".
 *
 * `--jkt` binds the assertion to a key held somewhere else, so there is no private key here
 * to sign a `/token` proof: the CLI stops at the code and prints the **assertion** instead.
 * For the same reason `--jkt` cannot be combined with `--refresh`.
 *
 * Runs under Node 20+, where `globalThis.crypto` is WebCrypto and `fetch` is built in.
 * Nothing in the SDK branches on the runtime, so a code minted here and one minted in the
 * browser are produced by the same instructions.
 *
 * Only the final token is on stdout, and nothing else, so the test can pipe it. The
 * section 10 demo log goes to stderr, in yellow when stderr is a TTY (`NO_COLOR` disables,
 * `FORCE_COLOR=1` forces).
 *
 *   npm run -s sign-on -- --gateway http://localhost:3000 --user alice \
 *     --password password123 --client-id demo_client --scope "openid profile" [--refresh]
 */
import { DecentralizedClientSdk } from "../src/sdk/client.js";
import {
  calculateJwkThumbprint,
  createDPoPProof,
  exportDPoPJwk,
  generateDPoPKeyPair,
  type DPoPKeyPair,
} from "../src/sdk/dpop.js";
import { colorizeDemoLine, type DemoEvent } from "../src/sdk/events.js";

interface Options {
  gateway: string;
  issuer: string;
  user: string;
  password: string;
  clientId: string;
  scope: string;
  nonce: string;
  redirectUri: string;
  refresh: boolean;
  /** An externally supplied thumbprint; the key behind it stays wherever it was made. */
  jkt: string | undefined;
}

interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
}

const USAGE = `Usage: npm run -s sign-on -- [options]

  --gateway <url>       Gateway base URL (default http://localhost:3000)
  --issuer <url>        Expected JWT issuer (default: same as --gateway)
  --user <name>         Username (default alice)
  --password <pw>       Password (required)
  --client-id <id>      OAuth client_id / access-token aud (default demo_client)
  --scope <scope>       OAuth scope (default "openid profile")
  --nonce <str>         Authorize challenge c (default cli_<random>)
  --redirect-uri <url>  redirect_uri sent to /token (default http://localhost:3001/callback)
  --jkt <thumbprint>    Bind the assertion to an externally held DPoP key (43-char
                        base64url). Prints the assertion (code) instead of exchanging it,
                        since the private key is elsewhere. Cannot be combined with --refresh.
  --refresh             After the code exchange, spend the refresh token for a new access token
  -h, --help            This text
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

  const jkt = values.get("jkt");
  if (jkt !== undefined && refresh) {
    throw new Error(
      "--jkt cannot be combined with --refresh: a refresh needs the private key behind the " +
        "thumbprint, and --jkt means that key is held elsewhere"
    );
  }
  if (jkt !== undefined && !/^[A-Za-z0-9_-]{43}$/.test(jkt)) {
    throw new Error(
      "--jkt must be a base64url SHA-256 JWK thumbprint (43 characters, no padding)"
    );
  }

  return {
    gateway,
    issuer: stripSlash(values.get("issuer") ?? gateway),
    user: values.get("user") ?? "alice",
    password,
    clientId: values.get("client-id") ?? "demo_client",
    scope: values.get("scope") ?? "openid profile",
    nonce: values.get("nonce") ?? `cli_${Math.random().toString(36).slice(2, 10)}`,
    redirectUri: values.get("redirect-uri") ?? "http://localhost:3001/callback",
    refresh,
    jkt,
  };
}

function useColor(): boolean {
  if (process.env.NO_COLOR) return false;
  if (process.env.FORCE_COLOR === "1") return true;
  return Boolean(process.stderr.isTTY);
}

/** Writes the section 10 browser column to stderr. */
function makeSink(): { onEvent: (event: DemoEvent) => void; note: (line: string) => void } {
  if ((process.env.DEMO_LOG ?? "1") === "0") {
    return { onEvent: () => {}, note: () => {} };
  }
  const color = useColor();
  const write = (line: string) => process.stderr.write(`${color ? colorizeDemoLine(line) : line}\n`);
  return {
    onEvent: (event: DemoEvent) => event.lines.forEach(write),
    note: write,
  };
}

/** First 8 characters, matching the section 10 truncation for cryptographic byte strings. */
function head8(value: string): string {
  return value.slice(0, 8);
}

/**
 * The `/token` exchange the rp front end performs (section 14.1 steps 9-11). Sends a DPoP
 * proof over `POST <issuer>/token` and the form body; returns the token set the gateway
 * synthesised from the node shares.
 */
async function callToken(
  options: Options,
  keyPair: DPoPKeyPair,
  form: Record<string, string>
): Promise<TokenResponse> {
  const tokenUrl = `${options.gateway}/token`;
  const proof = createDPoPProof(keyPair, "POST", `${options.issuer}/token`);
  const res = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      DPoP: proof,
    },
    body: new URLSearchParams(form).toString(),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`/token ${form.grant_type} failed with HTTP ${res.status}: ${body}`);
  }
  return (await res.json()) as TokenResponse;
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const sink = makeSink();

  // The rp front end's job: make the key, keep it, publish only the thumbprint.
  const dpopKeyPair = generateDPoPKeyPair();
  const cnfJkt = options.jkt ?? calculateJwkThumbprint(exportDPoPJwk(dpopKeyPair.publicKey));

  const sdk = new DecentralizedClientSdk(
    {
      proxyUrl: options.gateway,
      issuer: options.issuer,
      onEvent: sink.onEvent,
    },
    cnfJkt
  );

  // Authorization: PASTA turns the password into the assertion (= the authorization code).
  const { assertion } = await sdk.signOn({
    username: options.user,
    password: options.password,
    clientId: options.clientId,
    scope: options.scope,
    nonce: options.nonce,
  });

  // With an externally held key there is no private key here to sign a /token proof, so the
  // CLI stops at the code and hands the assertion out (section 13, --jkt).
  if (options.jkt) {
    process.stdout.write(`${assertion}\n`);
    return;
  }

  // Issuance: exchange the code for an access token, DPoP-bound to our own key.
  const first = await callToken(options, dpopKeyPair, {
    grant_type: "authorization_code",
    code: assertion,
    client_id: options.clientId,
    redirect_uri: options.redirectUri,
  });
  sink.note(
    `[browser] token    → grant=authorization_code DPoP proof  ` +
      `← access_token ${head8(first.access_token)} (cnf.jkt bound)`
  );

  let accessToken = first.access_token;

  if (options.refresh) {
    if (!first.refresh_token) {
      throw new Error("/token returned no refresh_token to refresh with");
    }
    const refreshed = await callToken(options, dpopKeyPair, {
      grant_type: "refresh_token",
      refresh_token: first.refresh_token,
    });
    sink.note(
      `[browser] token    → grant=refresh_token new DPoP proof  ` +
        `← access_token ${head8(refreshed.access_token)} (rotated)`
    );
    accessToken = refreshed.access_token;
  }

  // Last line of stdout, and the only thing on it.
  process.stdout.write(`${accessToken}\n`);
}

main().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`sign-on failed: ${message}\n`);
  process.exit(1);
});
