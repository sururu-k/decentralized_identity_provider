import { base64UrlEncode } from "../jwt/jwt.js";

export interface OidcConfigOptions {
  issuer: string;
  groupPublicKey: Uint8Array;
  keyId?: string;
}

export interface AuthorizeQueryParams {
  client_id?: string;
  redirect_uri?: string;
  response_type?: string;
  scope?: string;
  state?: string;
  dpop_jkt?: string;
}

export interface AuthorizeValidationResult {
  valid: boolean;
  error?: string;
  params?: {
    clientId: string;
    redirectUri: string;
    responseType: string;
    scope: string;
    state?: string;
    dpopJkt: string;
  };
}

/**
 * `dpop_jkt` is the RFC 7638 thumbprint of the RP front end's DPoP public key: SHA-256
 * base64url encoded, which is always 43 characters and never carries padding
 * (docs/container-split.md section 13).
 */
const DPOP_JKT_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export class OidcEndpointHandler {
  private issuer: string;
  private groupPublicKey: Uint8Array;
  private keyId: string;

  constructor(options: OidcConfigOptions) {
    this.issuer = options.issuer;
    this.groupPublicKey = options.groupPublicKey;
    this.keyId = options.keyId || "pasta-group-key-1";
  }

  /**
   * GET /.well-known/openid-configuration
   *
   * OAuth 2.0 authorization code + DPoP (section 14). The id_token flow is gone: the only
   * response type is `code`, the grant types are `authorization_code` and
   * `refresh_token`, and there is a token endpoint.
   */
  public getDiscoveryConfiguration(): object {
    return {
      issuer: this.issuer,
      authorization_endpoint: `${this.issuer}/authorize`,
      token_endpoint: `${this.issuer}/token`,
      jwks_uri: `${this.issuer}/jwks.json`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      subject_types_supported: ["public"],
      token_endpoint_auth_methods_supported: ["none"],
      dpop_signing_alg_values_supported: ["EdDSA"],
      scopes_supported: ["openid", "profile", "email"],
      claims_supported: ["iss", "sub", "aud", "exp", "iat", "cnf", "scope", "client_id"],
    };
  }

  /**
   * GET /jwks.json
   * Publishes the single Ed25519 group public key in standard JWK Set format (RFC 8037).
   */
  public getJwks(): object {
    return {
      keys: [
        {
          kty: "OKP",
          crv: "Ed25519",
          x: base64UrlEncode(this.groupPublicKey),
          kid: this.keyId,
          use: "sig",
          alg: "EdDSA",
        },
      ],
    };
  }

  /**
   * Validates parameters for GET /authorize (section 14: `response_type=code`).
   *
   * The gateway stores no state: it checks the request and hands the parameters, plus a
   * fresh challenge `c`, through to the demo login. `nonce` is no longer required (the
   * id_token flow is gone); the challenge `c` the gateway generates becomes the
   * assertion's replay-limiting nonce. `dpop_jkt` stays required (section 13): the RP
   * front end owns the DPoP key, so the token binds to it.
   */
  public validateAuthorizeRequest(params: AuthorizeQueryParams): AuthorizeValidationResult {
    if (!params.client_id) {
      return { valid: false, error: "Missing required parameter: client_id" };
    }
    if (!params.redirect_uri) {
      return { valid: false, error: "Missing required parameter: redirect_uri" };
    }
    if (params.response_type !== "code") {
      return {
        valid: false,
        error: "Invalid response_type: only 'code' is supported (OAuth authorization code flow)",
      };
    }
    if (!params.scope || !params.scope.split(" ").includes("openid")) {
      return { valid: false, error: "Missing required scope: openid" };
    }
    if (!params.dpop_jkt) {
      return { valid: false, error: "Missing required parameter: dpop_jkt" };
    }
    if (!DPOP_JKT_PATTERN.test(params.dpop_jkt)) {
      return {
        valid: false,
        error:
          "Invalid dpop_jkt: expected a base64url SHA-256 JWK thumbprint (43 characters, no padding)",
      };
    }

    return {
      valid: true,
      params: {
        clientId: params.client_id,
        redirectUri: params.redirect_uri,
        responseType: params.response_type,
        scope: params.scope,
        state: params.state,
        dpopJkt: params.dpop_jkt,
      },
    };
  }

  /**
   * Renders the redirect page for GET /authorize.
   *
   * The gateway stores nothing: it carries `client_id`, `redirect_uri`, `scope`, `state`,
   * `dpop_jkt` and the freshly generated challenge `c` through to `/demo` in the URL. The
   * browser runs the client SDK there, mints the assertion whose `nonce` is `c`, and
   * redirects to `redirect_uri?code=<assertion>&state=<state>` (section 14.1).
   */
  public renderAuthorizePage(params: {
    clientId: string;
    redirectUri: string;
    state?: string;
    scope: string;
    dpopJkt: string;
    challenge: string;
  }): string {
    const demoUrl =
      `/demo?step=login` +
      `&c=${encodeURIComponent(params.challenge)}` +
      `&redirect_uri=${encodeURIComponent(params.redirectUri)}` +
      `&client_id=${encodeURIComponent(params.clientId)}` +
      `&state=${encodeURIComponent(params.state || "")}` +
      `&scope=${encodeURIComponent(params.scope)}` +
      `&dpop_jkt=${encodeURIComponent(params.dpopJkt)}`;
    return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="0; url=${demoUrl}">
</head>
<body></body>
</html>`;
  }
}
