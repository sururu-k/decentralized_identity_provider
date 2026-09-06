import "./buffer-shim.js";
import { ristretto255 } from "@noble/curves/ed25519";
import {
  aggregateSignatureShares,
  computeGroupCommitment,
} from "./crypto/frost.js";
import {
  blind,
  deriveServerKey,
  finalize,
  unblind,
} from "./crypto/toprf.js";
import { aeadDecrypt, deriveAeadNonce } from "./crypto/aead.js";
import { assembleJwt, base64UrlDecode, base64UrlEncode, createSigningInput } from "./jwt.js";
import { ProxySignOnResult } from "./types.js";
import { signOnResultFromWire } from "./wire.js";
import { DemoEventSink, DemoStep, rejectEvent, stepEvent, trunc, truncScalar } from "./events.js";

/**
 * The authentication assertion lives for this many seconds (docs/container-split.md
 * section 14): it is the OAuth authorization code, and a node refuses to sign one whose
 * `exp - iat` exceeds 30. Replay inside the window only yields tokens bound to the same
 * `cnf.jkt`, useless without the rp front end's DPoP private key.
 */
export const ASSERTION_LIFETIME_SECONDS = 30;

export interface ClientAuthConfig {
  /**
   * Base URL of the gateway. The empty string means "same origin", which is what the demo
   * UI uses: the page is served by the gateway itself.
   */
  proxyUrl: string;
  /**
   * The issuer the assertion is signed under, and its `aud`: the assertion is addressed to
   * the gateway. In the browser this is `window.location.origin`, the same string the
   * gateway publishes and every node requires.
   */
  issuer: string;
  /** Optional progress sink for the section 10 demo log. Added by this port. */
  onEvent?: DemoEventSink;
}

export interface ClientSignOnOptions {
  username: string;
  password: string;
  /** OAuth `client_id`; signed into the assertion, and the access token's future `aud`. */
  clientId: string;
  /** OAuth `scope`; signed into the assertion. May be the empty string. */
  scope: string;
  /** The gateway's authorize challenge `c`, signed into the assertion as `nonce`. */
  nonce: string;
  participants?: number[];
}

/**
 * The only per-session state the browser keeps. Since section 14 there is no refresh on
 * the IdP front end -- the rp front end refreshes at `/token` with its own DPoP key -- so
 * there is no `rs_i`, no counter and nothing to store between requests.
 */
export interface StoredSession {
  sessionId: string;
  sub: string;
  cnfJkt: string;
}

/**
 * Decentralized Client SDK
 *
 * The browser-side aggregator of the PASTA flow (docs/container-split.md section 14). It
 * turns a password into an **authentication assertion** -- a group-signed JWT that is the
 * OAuth authorization code -- without ever putting the password on the wire:
 *
 * 1. Blinds the password locally via TOPRF (A = r * H1(pw)); the gateway and nodes never
 *    see the password, `h` or `h_i`.
 * 2. Sends the blinded point plus the assertion's claims (`clientId`, `scope`, the
 *    authorize challenge `c` as `nonce`, `iat`, a 30-second `exp`) to the gateway.
 * 3. Unblinds the TOPRF partials B_i to recover `h`, derives each `h_i`, and decrypts the
 *    FROST share ct_i. A wrong password fails here, at the AEAD tag, and nowhere else.
 * 4. Aggregates the FROST Ed25519 threshold signature into the finished assertion.
 *
 * The DPoP key pair is *not* one of those responsibilities. Section 13 moved it to the rp
 * front end, which keeps the private key in its own origin's IndexedDB and passes only the
 * thumbprint down the chain. This SDK therefore takes `cnfJkt` as a constructor argument
 * and can neither mint a key nor sign a proof. The proof for the later `/token` exchange
 * belongs to whoever holds that key (the rp front end, or the CLI stand-in that plays it).
 *
 * Browser port of the gateway's `src/client-sdk/client.ts` (docs/container-split.md
 * section 11). What changed from the reference:
 *
 * - The in-process `proxy` branch and the `PastaOAuthProxy` import are gone. This SDK
 *   only speaks HTTP, so `proxyUrl` is a required string and `""` means same origin.
 * - Key generation and proof creation moved out (section 13).
 * - The signed payload is the section 14 assertion, not an id_token: it carries
 *   `client_id`, `scope`, `nonce=c`, `aud=issuer` and a 30-second `exp`, in the byte order
 *   the node README pins. `refresh()` was removed (section 14).
 * - `crypto.randomBytes(16)` -> `globalThis.crypto.getRandomValues`.
 * - `JSON.parse(Buffer.from(bytes).toString("utf8"))` -> `TextDecoder`.
 * - An optional `onEvent` sink emits the section 10 demo log.
 *
 * The cryptographic sequence is untouched: same blinding, same `createSigningInput` over a
 * key-sorted payload, same `deriveAeadNonce` arguments, same aggregation order. Only the
 * claim set the payload carries is different.
 */
export class DecentralizedClientSdk {
  private config: ClientAuthConfig;
  /** The RP front end's DPoP thumbprint, received through the `/authorize` redirect. */
  public readonly cnfJkt: string;
  private currentSession: StoredSession | null = null;

  constructor(config: ClientAuthConfig, cnfJkt: string) {
    if (!cnfJkt) {
      throw new Error(
        "cnfJkt is required: the DPoP thumbprint comes from the RP front end via dpop_jkt"
      );
    }
    this.config = config;
    this.cnfJkt = cnfJkt;
  }

  public getCurrentSession(): StoredSession | null {
    return this.currentSession;
  }

  /** One line of the section 10 browser column. `event` is undefined on a continuation. */
  private emitStep(step: DemoStep, event: string | undefined, text: string): void {
    this.config.onEvent?.(stepEvent(step, event, text));
  }

  private emitReject(step: DemoStep, event: string, reason: string): void {
    this.config.onEvent?.(rejectEvent(step, event, reason));
  }

  /**
   * Run the authorization step: turn the password into an authentication assertion.
   *
   * 1. Blind the password locally: A = r * H1(pw).
   * 2. Send A and the assertion's claims to the gateway (it never sees the password).
   * 3. Receive TOPRF partials B_i and encrypted FROST shares ct_i from the nodes.
   * 4. Unblind B_i to recover `h`, derive each `h_i`, decrypt ct_i.
   * 5. Aggregate the shares and assemble the assertion JWT (`header.payload.sigma`).
   *
   * The returned `assertion` is the OAuth authorization code. It is passed to the rp with a
   * plain redirect (`redirect_uri?code=<assertion>&state=<state>`); the gateway and nodes
   * verify it later at `/token`, so nothing here trusts it.
   */
  public async signOn(
    options: ClientSignOnOptions
  ): Promise<{ assertion: string; sessionId: string }> {
    const now = Math.floor(Date.now() / 1000);
    const exp = now + ASSERTION_LIFETIME_SECONDS;

    // 1. Client-side TOPRF Blinding: A = r * H_1(password)
    const { blinding, blinded } = blind(options.password);
    const sessionNonce = new Uint8Array(16);
    globalThis.crypto.getRandomValues(sessionNonce);

    const blindedB64 = base64UrlEncode(blinded.toRawBytes());
    const sessionNonceB64 = base64UrlEncode(sessionNonce);

    this.emitStep(
      "signon-blind",
      "sign-on",
      `user=${options.username} nonce=${options.nonce}  → r ${truncScalar(blinding.r)}  ` +
        `A=r·H1(pw) ${trunc(blindedB64)}  jkt(rp) ${trunc(this.cnfJkt)}  ` +
        `nonce_s ${trunc(sessionNonceB64)}`
    );

    let signOnResult: ProxySignOnResult;

    const res = await fetch(`${this.config.proxyUrl}/api/pasta/sign-on`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: options.username,
        blinded: blindedB64,
        sessionNonce: sessionNonceB64,
        cnfJkt: this.cnfJkt,
        // The authorize challenge c. The node signs it as the assertion's `nonce`; sent
        // without one, the payload would serialize to `"nonce":undefined` (invalid JSON)
        // and `/sign` could not read the assertion back (docs/container-split.md §14).
        nonce: options.nonce,
        clientId: options.clientId,
        scope: options.scope,
        iat: now,
        exp,
        // The assertion is addressed to the gateway, so its `aud` is the issuer, not the
        // client. `client_id` travels separately and becomes the access token's `aud`.
        aud: this.config.issuer,
        iss: this.config.issuer,
        participants: options.participants,
      }),
    });
    if (!res.ok) {
      this.emitReject("signon-reject", "sign-on", `gateway returned HTTP ${res.status}`);
      throw new Error(`Sign-on proxy failed with status ${res.status}`);
    }
    // Over HTTP the proxy result is base64url encoded (docs/container-split.md
    // section 3); decode it back into the in-process shape the aggregation below
    // expects, so both transports feed the same code.
    signOnResult = signOnResultFromWire(await res.json());

    const sub = signOnResult.nodeResponses[0]?.sub || options.username;

    this.emitStep(
      "signon-response",
      undefined,
      `← B_i×${signOnResult.nodeResponses.length} ct_i×${signOnResult.nodeResponses.length} ` +
        `(D,E)×${signOnResult.commitments.length}  sess=${signOnResult.sessionId.slice(0, 8)}`
    );

    // 2. Rebuild the assertion the nodes signed, in the byte order the node README pins
    // (docs/container-split.md section 14). `deterministicJsonStringify` sorts keys, so
    // the object order here does not reach the wire -- the alphabetical order does, and it
    // must match the node byte for byte, because it is both the JWT payload and the AEAD
    // AAD guarding each ct_i.
    const header = { alg: "EdDSA", typ: "JWT", kid: "pasta-group-key-1" };
    const payload = {
      iss: this.config.issuer,
      sub,
      aud: this.config.issuer,
      client_id: options.clientId,
      scope: options.scope,
      cnf: { jkt: this.cnfJkt },
      nonce: options.nonce,
      iat: now,
      exp,
    };

    const { signingInput, headerB64, payloadB64 } = createSigningInput(header, payload);

    // 3. Client unblinds TOPRF partial evaluations to derive master PRF value h
    const partials = signOnResult.nodeResponses.map((r) => ({
      id: r.nodeId,
      point: ristretto255.Point.fromBytes(base64UrlDecode(r.toprfPartial)),
    }));
    const v = unblind(blinding, partials);
    const h = finalize(options.password, v);

    // 4. Decrypt shares ct_i locally using derived h_i. Since section 14 ct_i carries the
    // FROST share alone -- `{ z_i }`, no `rs_i` -- because the IdP front no longer refreshes.
    const shares: bigint[] = [];

    for (const nodeResp of signOnResult.nodeResponses) {
      const h_i = deriveServerKey(h, nodeResp.nodeId);
      const aeadNonce = deriveAeadNonce(sessionNonce, nodeResp.nodeId);
      let decryptedBytes: Uint8Array;
      try {
        decryptedBytes = aeadDecrypt(h_i, aeadNonce, base64UrlDecode(nodeResp.ct_i), signingInput);
      } catch (err: any) {
        this.emitReject(
          "signon-reject",
          "sign-on",
          `ct_${nodeResp.nodeId} decrypt failed → wrong password (nodes cannot tell)`
        );
        throw new Error(
          `Failed to decrypt share from node ${nodeResp.nodeId}. Invalid password or corrupted share.`
        );
      }

      const parsed = JSON.parse(new TextDecoder().decode(decryptedBytes));
      shares.push(BigInt(parsed.z_i));
    }

    // 5. Aggregate FROST signature locally in client!
    const R_bytes = computeGroupCommitment(signingInput, signOnResult.commitments);
    const signature = aggregateSignatureShares(R_bytes, shares);

    // 6. Complete the assertion (the OAuth authorization code)
    const assertion = assembleJwt(headerB64, payloadB64, signature);

    this.emitStep(
      "signon-aggregate",
      undefined,
      `→ h=finalize(pw, unblind(r,B_i))  h_i×${signOnResult.nodeResponses.length}  ` +
        `z_i=dec(ct_i)×${shares.length} ${shares.map((z) => truncScalar(z)).join(" ")}  ` +
        `R ${trunc(base64UrlEncode(R_bytes))}  σ=Σz_i  ` +
        `assertion ${trunc(assertion)} ✔ (auth code, 30s, aud=gateway)`
    );

    this.currentSession = {
      sessionId: signOnResult.sessionId,
      sub,
      cnfJkt: this.cnfJkt,
    };

    return { assertion, sessionId: signOnResult.sessionId };
  }
}
