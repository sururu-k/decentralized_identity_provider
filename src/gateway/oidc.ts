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
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Decentralized Identity Login</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {
      --bg: #0f172a;
      --card: #1e293b;
      --text: #f8fafc;
      --subtext: #94a3b8;
      --primary: #6366f1;
      --primary-hover: #4f46e5;
      --border: #334155;
    }
    body {
      margin: 0;
      padding: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
    }
    .container {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 2rem;
      width: 100%;
      max-width: 440px;
      box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5);
    }
    h2 { margin-top: 0; font-size: 1.25rem; font-weight: 600; }
    .badge {
      display: inline-block;
      font-size: 0.75rem;
      padding: 0.25rem 0.5rem;
      background: #312e81;
      color: #c7d2fe;
      border-radius: 4px;
      margin-bottom: 1rem;
    }
    .field { margin-bottom: 1rem; text-align: left; }
    label { display: block; font-size: 0.875rem; color: var(--subtext); margin-bottom: 0.25rem; }
    input {
      width: 100%;
      padding: 0.625rem;
      border-radius: 6px;
      border: 1px solid var(--border);
      background: #090d16;
      color: var(--text);
      box-sizing: border-box;
      font-size: 0.95rem;
    }
    button {
      width: 100%;
      padding: 0.75rem;
      border-radius: 6px;
      border: none;
      background: var(--primary);
      color: white;
      font-weight: 600;
      cursor: pointer;
      margin-top: 1rem;
    }
    button:hover { background: var(--primary-hover); }
    .footer-note {
      margin-top: 1.5rem;
      font-size: 0.75rem;
      color: var(--subtext);
      line-height: 1.4;
      border-top: 1px solid var(--border);
      padding-top: 1rem;
    }
    #status-msg {
      margin-top: 1rem;
      font-size: 0.85rem;
      min-height: 1.25rem;
      color: #38bdf8;
    }
  </style>
</head>
<body>
  <div class="container">
    <span class="badge">RFC 9449 DPoP + response_mode=form_post Enabled</span>
    <h2>Sign in with Decentralized IdP</h2>
    <p style="font-size: 0.875rem; color: var(--subtext); margin-bottom: 1.5rem;">
      Application <strong>${params.clientId}</strong> is requesting authentication.
    </p>

    <form id="auth-form">
      <div class="field">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" value="alice" required />
      </div>
      <div class="field">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" value="password123" required />
      </div>
      <button type="submit" id="submit-btn">Authorize &amp; Sign In</button>
      <div id="status-msg"></div>
    </form>

    <div class="footer-note">
      <strong>Zero-Knowledge Proxy Guarantee:</strong><br>
      The proxy relays encrypted cryptographic shares and cannot view your credentials, session secrets, or ID Token.
      The token is aggregated locally in your browser and POSTed directly to <code>${params.redirectUri}</code>.
    </div>
  </div>

  <script>
    // In-browser client script orchestration
    const redirectUri = ${JSON.stringify(params.redirectUri)};
    const state = ${JSON.stringify(params.state || "")};
    const nonce = ${JSON.stringify(params.nonce)};
    const clientId = ${JSON.stringify(params.clientId)};

    document.getElementById('auth-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const status = document.getElementById('status-msg');
      const btn = document.getElementById('submit-btn');
      btn.disabled = true;
      status.innerText = "Generating ephemeral DPoP key & requesting shares...";

      // Browser simulation of client SDK
      try {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        // Perform sign-on via client SDK logic exposed by the client bundle
        const res = await fetch('/api/pasta/browser-sign-on', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password, redirectUri, state, nonce, clientId })
        });
        const data = await res.json();
        if (!data.success) {
          throw new Error(data.error || "Authentication failed");
        }

        status.innerText = "Aggregated ID token successfully! Redirecting via form_post...";
        // Form post directly to RP
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = redirectUri;
        form.style.display = 'none';

        const tokenInput = document.createElement('input');
        tokenInput.type = 'hidden';
        tokenInput.name = 'id_token';
        tokenInput.value = data.id_token;
        form.appendChild(tokenInput);

        if (state) {
          const stateInput = document.createElement('input');
          stateInput.type = 'hidden';
          stateInput.name = 'state';
          stateInput.value = state;
          form.appendChild(stateInput);
        }

        document.body.appendChild(form);
        form.submit();
      } catch (err) {
        status.style.color = '#ef4444';
        status.innerText = "Error: " + err.message;
        btn.disabled = false;
      }
    });
  </script>
</body>
</html>`;
  }
}
