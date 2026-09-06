import "./buffer-shim.js";
import { ristretto255 } from "@noble/curves/ed25519";
import { DPoPKeyPair, calculateJwkThumbprint, createDPoPProof, exportDPoPJwk, generateDPoPKeyPair } from "./dpop.js";
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
import { deriveRefreshKey } from "./crypto/kdf.js";
import { assembleJwt, base64UrlDecode, base64UrlEncode, createSigningInput } from "./jwt.js";
import { ProxySignOnResult, ProxyRefreshResult } from "./types.js";
import { refreshResultFromWire, signOnResultFromWire } from "./wire.js";
import { DemoEventSink, DemoStep, rejectEvent, stepEvent, trunc, truncScalar } from "./events.js";

export interface ClientAuthConfig {
  /**
   * Base URL of the gateway. The empty string means "same origin", which is what the demo
   * UI uses: the page is served by the gateway itself.
   */
  proxyUrl: string;
  issuer: string;
  /** Optional progress sink for the section 10 demo log. Added by this port. */
  onEvent?: DemoEventSink;
}

export interface ClientSignOnOptions {
  username: string;
  password: string;
  clientId: string;
  nonce: string;
  participants?: number[];
  lifetimeSeconds?: number;
}

export interface ClientRefreshOptions {
  clientId: string;
  nonce?: string;
  refreshEndpointUrl: string;
  participants?: number[];
  lifetimeSeconds?: number;
}

export interface StoredSession {
  sessionId: string;
  sub: string;
  nodeSecrets: Map<number, Uint8Array>; // nodeId -> rs_i
  counter: number;
  dpopKeyPair: DPoPKeyPair;
  cnfJkt: string;
}

/**
 * Decentralized Client SDK
 *
 * Implements the browser/client-side aggregator from docs/whiteboard-gaps.md & docs/refresh-token.md:
 * 1. Manages ephemeral non-extractable DPoP keypair (Hole 4, 7)
 * 2. Blinds password locally via TOPRF (A = r * H1(pw)) and queries proxy (Hole 2: proxy never sees password, token, or h_i)
 * 3. Unblinds partial evaluations to reconstruct master PRF value h and derive h_i
 * 4. Decrypts ct_i locally using ChaCha20-Poly1305 with h_i
 * 5. Aggregates FROST Ed25519 threshold signature locally
 * 6. Stores session secrets rs_i locally for sender-constrained refresh (Hole 5)
 * 7. Generates RFC 9449 DPoP proofs for refresh requests
 *
 * Browser port of the gateway's `src/client-sdk/client.ts`
 * (docs/container-split.md section 11). What changed:
 *
 * - The in-process `proxy` branch and the `PastaOAuthProxy` import are gone. This SDK
 *   only speaks HTTP, so `proxyUrl` is a required string and `""` means same origin
 *   (the reference treated `""` as "not configured" because it tested truthiness).
 * - `crypto.randomBytes(16)` -> `globalThis.crypto.getRandomValues`.
 * - `JSON.parse(Buffer.from(bytes).toString("utf8"))` -> `TextDecoder`.
 * - An optional `onEvent` sink emits the section 10 demo log.
 *
 * The cryptographic sequence is untouched: same blinding, same header and payload
 * objects in the same key order, same `createSigningInput`, same `deriveAeadNonce`
 * arguments, same aggregation order.
 */
export class DecentralizedClientSdk {
  private config: ClientAuthConfig;
  private dpopKeyPair: DPoPKeyPair;
  public readonly cnfJkt: string;
  private currentSession: StoredSession | null = null;

  constructor(config: ClientAuthConfig, dpopKeyPair?: DPoPKeyPair) {
    this.config = config;
    this.dpopKeyPair = dpopKeyPair || generateDPoPKeyPair();
    const jwk = exportDPoPJwk(this.dpopKeyPair.publicKey);
    this.cnfJkt = calculateJwkThumbprint(jwk);
  }

  public getDPoPKeyPair(): DPoPKeyPair {
    return this.dpopKeyPair;
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
   * Execute Sign-On Flow:
   * 1. Blind password locally: A = r * H_1(pw)
   * 2. Send blinded point A and session nonce to proxy (proxy cannot decrypt or forge)
   * 3. Receive TOPRF partial points B_i and encrypted shares ct_i from nodes
   * 4. Unblind B_i locally to recover master h, derive h_i, and decrypt ct_i
   * 5. Aggregate signature shares and mint id_token JWT
   * 6. Save session secret rs_i for future refresh
   */
  public async signOn(options: ClientSignOnOptions): Promise<{ id_token: string; sessionId: string }> {
    const now = Math.floor(Date.now() / 1000);
    const exp = now + (options.lifetimeSeconds ?? 3600);

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
        `A=r·H1(pw) ${trunc(blindedB64)}  jkt ${trunc(this.cnfJkt)}  nonce_s ${trunc(sessionNonceB64)}`
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
        nonce: options.nonce,
        iat: now,
        exp,
        aud: options.clientId,
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

    // 2. Prepare signing payload for decryption AAD and JWT assembly
    const header = { alg: "EdDSA", typ: "JWT", kid: "pasta-group-key-1" };
    const payload = {
      iss: this.config.issuer,
      sub,
      aud: options.clientId,
      iat: now,
      exp,
      nonce: options.nonce,
      cnf: { jkt: this.cnfJkt },
    };

    const { signingInput, headerB64, payloadB64 } = createSigningInput(header, payload);

    // 3. Client unblinds TOPRF partial evaluations to derive master PRF value h
    const partials = signOnResult.nodeResponses.map((r) => ({
      id: r.nodeId,
      point: ristretto255.Point.fromBytes(base64UrlDecode(r.toprfPartial)),
    }));
    const v = unblind(blinding, partials);
    const h = finalize(options.password, v);

    // 4. Decrypt shares ct_i locally using derived h_i
    const shares: bigint[] = [];
    const nodeSecrets = new Map<number, Uint8Array>();

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
      nodeSecrets.set(nodeResp.nodeId, base64UrlDecode(parsed.rs_i));
    }

    // 5. Aggregate FROST signature locally in client!
    const R_bytes = computeGroupCommitment(signingInput, signOnResult.commitments);
    const signature = aggregateSignatureShares(R_bytes, shares);

    // 6. Complete JWT
    const id_token = assembleJwt(headerB64, payloadB64, signature);

    this.emitStep(
      "signon-aggregate",
      undefined,
      `→ h=finalize(pw, unblind(r,B_i))  h_i×${signOnResult.nodeResponses.length}  ` +
        `z_i=dec(ct_i)×${shares.length} ${shares.map((z) => truncScalar(z)).join(" ")}  ` +
        `R ${trunc(base64UrlEncode(R_bytes))}  σ=Σz_i  id_token ${trunc(id_token)} ✔ assembled only here`
    );

    // Store local session state for refresh (Hole 5)
    this.currentSession = {
      sessionId: signOnResult.sessionId,
      sub,
      nodeSecrets,
      counter: 0,
      dpopKeyPair: this.dpopKeyPair,
      cnfJkt: this.cnfJkt,
    };

    return { id_token, sessionId: signOnResult.sessionId };
  }

  /**
   * Execute Refresh Flow (Hole 5):
   * 1. Generate RFC 9449 DPoP proof bound to current ephemeral key
   * 2. Send refresh request with sessionId and DPoP proof to proxy
   * 3. Nodes verify DPoP proof and encrypt new shares using rk_i = HKDF(rs_i, ctr)
   * 4. Client decrypts new shares locally and aggregates fresh id_token JWT
   */
  public async refresh(
    options: ClientRefreshOptions
  ): Promise<{ id_token: string; sessionId: string }> {
    if (!this.currentSession) {
      throw new Error("No active session in Client SDK. Sign-on required first.");
    }

    const nextCtr = this.currentSession.counter + 1;
    const now = Math.floor(Date.now() / 1000);
    const exp = now + (options.lifetimeSeconds ?? 3600);

    // Create DPoP proof (Hole 4, 7)
    const dpopProof = createDPoPProof(
      this.currentSession.dpopKeyPair,
      "POST",
      options.refreshEndpointUrl
    );

    let refreshResult: ProxyRefreshResult;

    const res = await fetch(`${this.config.proxyUrl}/api/pasta/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sessionId: this.currentSession.sessionId,
        dpopProof,
        expectedHtu: options.refreshEndpointUrl,
        nonce: options.nonce,
        iat: now,
        exp,
        aud: options.clientId,
        iss: this.config.issuer,
        participants: options.participants,
      }),
    });
    if (!res.ok) {
      this.emitReject("refresh-reject", "refresh", `gateway returned HTTP ${res.status}`);
      throw new Error(`Refresh proxy failed with status ${res.status}`);
    }
    refreshResult = refreshResultFromWire(await res.json());

    // Build payload for new JWT
    const header = { alg: "EdDSA", typ: "JWT", kid: "pasta-group-key-1" };
    const payload = {
      iss: this.config.issuer,
      sub: this.currentSession.sub,
      aud: options.clientId,
      iat: now,
      exp,
      nonce: options.nonce,
      cnf: { jkt: this.currentSession.cnfJkt },
    };

    const { signingInput, headerB64, payloadB64 } = createSigningInput(header, payload);

    // Decrypt new shares locally using rk_i = HKDF(rs_i, nextCtr)
    const shares: bigint[] = [];
    for (const nodeResp of refreshResult.nodeResponses) {
      const rs_i = this.currentSession.nodeSecrets.get(nodeResp.nodeId);
      if (!rs_i) {
        throw new Error(`Missing rs_i for node ${nodeResp.nodeId} in client session`);
      }

      const rk_i = deriveRefreshKey(rs_i, nextCtr, this.currentSession.sessionId);
      const refreshNonce = deriveAeadNonce(
        new TextEncoder().encode(`REFRESH:${this.currentSession.sessionId}:${nextCtr}`),
        nodeResp.nodeId
      );

      let decryptedBytes: Uint8Array;
      try {
        decryptedBytes = aeadDecrypt(
          rk_i,
          refreshNonce,
          base64UrlDecode(nodeResp.ct_i),
          signingInput
        );
      } catch (err: any) {
        this.emitReject(
          "refresh-reject",
          "refresh",
          `ct_${nodeResp.nodeId} decrypt failed`
        );
        throw new Error(`Failed to decrypt refresh share from node ${nodeResp.nodeId}`);
      }

      const parsed = JSON.parse(new TextDecoder().decode(decryptedBytes));
      shares.push(BigInt(parsed.z_i));
    }

    // Aggregate updated signature
    const R_bytes = computeGroupCommitment(signingInput, refreshResult.commitments);
    const signature = aggregateSignatureShares(R_bytes, shares);

    const id_token = assembleJwt(headerB64, payloadB64, signature);

    this.currentSession.counter = nextCtr;

    this.emitStep(
      "refresh",
      "refresh",
      `sess=${this.currentSession.sessionId.slice(0, 8)} ctr=${nextCtr}  → DPoP proof  ` +
        `← ct_i×${refreshResult.nodeResponses.length} (D,E)×${refreshResult.commitments.length}  ` +
        `→ rk_i=HKDF(rs_i,ctr)×${refreshResult.nodeResponses.length}  ` +
        `z_i×${shares.length} ${shares.map((z) => truncScalar(z)).join(" ")}  ` +
        `R ${trunc(base64UrlEncode(R_bytes))}  σ  new id_token ${trunc(id_token)} ✔`
    );

    return { id_token, sessionId: this.currentSession.sessionId };
  }
}
