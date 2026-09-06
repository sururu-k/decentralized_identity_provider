/**
 * Runtime configuration for the RP (ZK-App Portal).
 *
 * The RP is a pure OIDC Relying Party: it never reads dealer secrets and never
 * shares code with the IdP. Everything it needs to verify a token comes from
 * the IdP's public JWKS endpoint.
 */
export interface RpConfig {
  /** Public base URL of this RP, used to build `redirect_uri`. */
  rpBaseUrl: string;
  /** Expected `iss` of the id_token, and the base of the `/authorize` URL. */
  issuer: string;
  /** Base URL used server-side to fetch JWKS (compose-internal host). */
  idpInternalUrl: string;
  /** Expected `aud` of the id_token. */
  clientId: string;
}

export interface RpEnv {
  PORT?: string;
  RP_BASE_URL?: string;
  ISSUER?: string;
  IDP_INTERNAL_URL?: string;
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
  const issuer = trimTrailingSlash(env.ISSUER || DEFAULT_ISSUER);
  return {
    rpBaseUrl: trimTrailingSlash(env.RP_BASE_URL || DEFAULT_RP_BASE_URL),
    issuer,
    idpInternalUrl: trimTrailingSlash(env.IDP_INTERNAL_URL || issuer),
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
