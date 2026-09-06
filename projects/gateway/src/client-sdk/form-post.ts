/**
 * OAuth 2.0 Form Post Response Mode Implementation
 *
 * Implements response_mode=form_post (OAuth 2.0 Form Post Response Mode / OIDC specification).
 * Resolves Hole 2 from docs/whiteboard-gaps.md:
 * Prevents the OAuth Proxy / Authorization Server from ever seeing or holding plaintext tokens.
 * Instead, the browser decrypts and aggregates the id_token client-side,
 * and POSTs the id_token and state directly to the RP redirect_uri.
 */

export interface FormPostParams {
  id_token: string;
  state?: string;
  [key: string]: string | undefined;
}

/**
 * Escapes HTML characters to prevent XSS injection in form posts
 */
export function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/**
 * Generates an auto-submitting HTML document that posts parameters (e.g. id_token, state)
 * directly to the RP redirect_uri from the user's browser.
 *
 * @param redirectUri RP callback endpoint URL
 * @param params Form parameters (id_token, state, etc.)
 * @returns Complete HTML document string
 */
export function generateFormPostHtml(
  redirectUri: string,
  params: FormPostParams
): string {
  const sanitizedAction = escapeHtml(redirectUri);
  const inputsHtml = Object.entries(params)
    .filter(([_, value]) => value !== undefined)
    .map(([key, value]) => {
      const sanitizedKey = escapeHtml(key);
      const sanitizedVal = escapeHtml(value as string);
      return `    <input type="hidden" name="${sanitizedKey}" value="${sanitizedVal}" />`;
    })
    .join("\n");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Submitting Authentication Token...</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0f172a;
      color: #f8fafc;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      height: 100vh;
      margin: 0;
    }
    .card {
      background: #1e293b;
      padding: 2rem;
      border-radius: 0.75rem;
      border: 1px solid #334155;
      text-align: center;
      max-width: 420px;
    }
    .spinner {
      border: 3px solid #334155;
      border-top: 3px solid #6366f1;
      border-radius: 50%;
      width: 32px;
      height: 32px;
      animation: spin 1s linear infinite;
      margin: 0 auto 1.5rem;
    }
    @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    button {
      margin-top: 1rem;
      padding: 0.5rem 1rem;
      background: #6366f1;
      color: white;
      border: none;
      border-radius: 0.375rem;
      cursor: pointer;
    }
  </style>
</head>
<body onload="javascript:document.forms[0].submit()">
  <div class="card">
    <div class="spinner"></div>
    <h3>Submitting Token to Relying Party</h3>
    <p style="font-size: 0.875rem; color: #94a3b8;">
      Completing decentralized authentication via <code>response_mode=form_post</code>.<br>
      The proxy never saw your plaintext credentials or ID token.
    </p>
    <form method="post" action="${sanitizedAction}">
${inputsHtml}
      <noscript>
        <p>JavaScript is disabled. Please click below to proceed:</p>
        <button type="submit">Continue to Application</button>
      </noscript>
    </form>
  </div>
</body>
</html>`;
}

/**
 * Submits form_post programmatically within a browser environment (DOM).
 * Creates and appends a temporary hidden form to document.body and invokes submit().
 *
 * @param redirectUri RP callback endpoint URL
 * @param params Form parameters (id_token, state, etc.)
 */
export function submitFormPost(
  redirectUri: string,
  params: FormPostParams
): void {
  if (typeof document === "undefined") {
    throw new Error("submitFormPost can only be called in a browser environment with DOM");
  }

  const form = document.createElement("form");
  form.method = "POST";
  form.action = redirectUri;
  form.style.display = "none";

  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) {
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = key;
      input.value = value;
      form.appendChild(input);
    }
  }

  document.body.appendChild(form);
  form.submit();
}
