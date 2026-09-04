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
  response_mode?: string;
  scope?: string;
  state?: string;
  nonce?: string;
}

export interface AuthorizeValidationResult {
  valid: boolean;
  error?: string;
  params?: {
    clientId: string;
    redirectUri: string;
    responseType: string;
    responseMode: string;
    scope: string;
    state?: string;
    nonce: string;
  };
}

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
   */
  public getDiscoveryConfiguration(): object {
    return {
      issuer: this.issuer,
      authorization_endpoint: `${this.issuer}/authorize`,
      jwks_uri: `${this.issuer}/jwks.json`,
      response_types_supported: ["id_token"],
      response_modes_supported: ["form_post"],
      grant_types_supported: ["implicit", "refresh_token"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["EdDSA"],
      scopes_supported: ["openid", "profile", "email"],
      token_endpoint_auth_methods_supported: ["none"],
      dpop_signing_alg_values_supported: ["EdDSA"],
      claims_supported: ["iss", "sub", "aud", "exp", "iat", "nonce", "cnf"],
    };
  }

  /**
   * GET /jwks.json
   * Publishes the single Ed25519 group public key in standard JWK Set format (RFC 8037)
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
   * Validates parameters for GET /authorize
   * Enforces Hole 2 requirement: response_mode=form_post
   */
  public validateAuthorizeRequest(params: AuthorizeQueryParams): AuthorizeValidationResult {
    if (!params.client_id) {
      return { valid: false, error: "Missing required parameter: client_id" };
    }
    if (!params.redirect_uri) {
      return { valid: false, error: "Missing required parameter: redirect_uri" };
    }
    if (!params.response_type || params.response_type !== "id_token") {
      return {
        valid: false,
        error: "Invalid response_type: only 'id_token' is supported (Hole 2: proxy cannot hold tokens)",
      };
    }
    if (params.response_mode && params.response_mode !== "form_post") {
      return {
        valid: false,
        error: "Invalid response_mode: only 'form_post' is supported to prevent proxy from holding tokens (Hole 2)",
      };
    }
    if (!params.scope || !params.scope.split(" ").includes("openid")) {
      return { valid: false, error: "Missing required scope: openid" };
    }
    if (!params.nonce) {
      return { valid: false, error: "Missing required parameter for id_token flow: nonce" };
    }

    return {
      valid: true,
      params: {
        clientId: params.client_id,
        redirectUri: params.redirect_uri,
        responseType: params.response_type,
        responseMode: params.response_mode || "form_post",
        scope: params.scope,
        state: params.state,
        nonce: params.nonce,
      },
    };
  }

  /**
   * Render HTML authorization consent and login screen for GET /authorize.
   *
   * The browser executes the cryptographic client logic locally:
   * 1. Collects password (never sent to server in plaintext)
   * 2. Generates ephemeral DPoP key
   * 3. Relays blind sign-on query to /api/pasta/sign-on
   * 4. Decrypts shares ct_i and aggregates Ed25519 signature
   * 5. Performs response_mode=form_post directly to RP redirect_uri
   */
  public renderAuthorizePage(params: {
    clientId: string;
    redirectUri: string;
    state?: string;
    nonce: string;
    scope: string;
  }): string {
    const demoUrl =
      `/demo?step=login` +
      `&redirect_uri=${encodeURIComponent(params.redirectUri)}` +
      `&client_id=${encodeURIComponent(params.clientId)}` +
      `&nonce=${encodeURIComponent(params.nonce)}` +
      `&state=${encodeURIComponent(params.state || '')}` +
      `&scope=${encodeURIComponent(params.scope)}`;
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
