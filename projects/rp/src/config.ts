/**
 * Runtime configuration for the RP (ZK-App Portal).
 *
 * The RP is an OAuth 2.0 client (docs/container-split.md section 14). Its server side
 * holds nothing: it builds an `/authorize` URL and serves the callback HTML. The token
 * request, the JWKS fetch and the signature check all happen in the browser, because the
 * DPoP private key lives only in this origin's IndexedDB (section 13).
 *
 * There is deliberately no JWKS host setting any more. The browser is the only party that
 * fetches `/jwks.json`, so the URL has to be the one the browser can reach — `ISSUER`.
 * `IDP_INTERNAL_URL`, which the previous server-side verifier used, has been removed.
 */
export interface RpConfig {
  /** Public base URL of this RP, used to build `redirect_uri`. */
  rpBaseUrl: string;
  /** Authorization server base URL: `/authorize`, `/token`, `/jwks.json` and the `iss` the browser checks. */
  issuer: string;
  /** OAuth `client_id`, and the `aud` the browser checks. */
  clientId: string;
}

export interface RpEnv {
  PORT?: string;
  RP_BASE_URL?: string;
  ISSUER?: string;
  CLIENT_ID?: string;
}

export const DEFAULT_PORT = 3001;
export const DEFAULT_RP_BASE_URL = "http://localhost:3001";
export const DEFAULT_ISSUER = "http://localhost:3000";
export const DEFAULT_CLIENT_ID = "demo_client";

/** Strips trailing slashes so URL joining never produces a double slash. */
function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

export function configFromEnv(env: RpEnv = process.env as RpEnv): RpConfig {
  return {
    rpBaseUrl: trimTrailingSlash(env.RP_BASE_URL || DEFAULT_RP_BASE_URL),
    issuer: trimTrailingSlash(env.ISSUER || DEFAULT_ISSUER),
    clientId: env.CLIENT_ID || DEFAULT_CLIENT_ID,
  };
}

/**
 * Parses `PORT`. Anything that is not a whole number in the TCP range falls back
 * to the default — in particular an empty or blank value, which `Number("")`
 * would otherwise turn into port 0 and make the service listen on a random port.
 */
export function portFromEnv(env: RpEnv = process.env as RpEnv): number {
  const raw = (env.PORT ?? "").trim();
  if (raw === "") return DEFAULT_PORT;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 0 || parsed > 65535) return DEFAULT_PORT;
  return parsed;
}
