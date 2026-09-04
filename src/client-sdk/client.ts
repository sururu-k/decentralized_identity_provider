import crypto from "node:crypto";
import { ristretto255 } from "@noble/curves/ed25519";
import { DPoPKeyPair, calculateJwkThumbprint, createDPoPProof, exportDPoPJwk, generateDPoPKeyPair } from "./dpop.js";
import {
  aggregateSignatureShares,
  computeGroupCommitment,
} from "../crypto/frost.js";
import {
  blind,
  deriveServerKey,
  finalize,
  unblind,
} from "../crypto/toprf.js";
import { aeadDecrypt, deriveAeadNonce } from "../crypto/aead.js";
import { deriveRefreshKey } from "../crypto/kdf.js";
import { assembleJwt, base64UrlDecode, base64UrlEncode, createSigningInput } from "../jwt/jwt.js";
import { PastaOAuthProxy, ProxySignOnResult, ProxyRefreshResult } from "../gateway/proxy.js";

export interface ClientAuthConfig {
  proxyUrl?: string; // If calling over HTTP
  proxy?: PastaOAuthProxy; // If calling directly in-process
  issuer: string;
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
    const sessionNonce = crypto.randomBytes(16);

    let signOnResult: ProxySignOnResult;

    if (this.config.proxy) {
      signOnResult = await this.config.proxy.handleSignOn({
        username: options.username,
        blinded: base64UrlEncode(blinded.toRawBytes()),
        sessionNonce: base64UrlEncode(sessionNonce),
        cnfJkt: this.cnfJkt,
        nonce: options.nonce,
        iat: now,
        exp,
        aud: options.clientId,
        iss: this.config.issuer,
        participants: options.participants,
      });
    } else if (this.config.proxyUrl) {
      const res = await fetch(`${this.config.proxyUrl}/api/pasta/sign-on`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: options.username,
          blinded: base64UrlEncode(blinded.toRawBytes()),
          sessionNonce: base64UrlEncode(sessionNonce),
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
        throw new Error(`Sign-on proxy failed with status ${res.status}`);
      }
      signOnResult = await res.json();
    } else {
      throw new Error("No proxy or proxyUrl configured in Client SDK");
    }

    const sub = signOnResult.nodeResponses[0]?.sub || options.username;

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
        throw new Error(
          `Failed to decrypt share from node ${nodeResp.nodeId}. Invalid password or corrupted share.`
        );
      }

      const parsed = JSON.parse(Buffer.from(decryptedBytes).toString("utf8"));
      shares.push(BigInt(parsed.z_i));
      nodeSecrets.set(nodeResp.nodeId, base64UrlDecode(parsed.rs_i));
    }

    // 5. Aggregate FROST signature locally in client!
    const R_bytes = computeGroupCommitment(signingInput, signOnResult.commitments);
    const signature = aggregateSignatureShares(R_bytes, shares);

    // 6. Complete JWT
    const id_token = assembleJwt(headerB64, payloadB64, signature);

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

    if (this.config.proxy) {
      refreshResult = await this.config.proxy.handleRefresh({
        sessionId: this.currentSession.sessionId,
        dpopProof,
        expectedHtu: options.refreshEndpointUrl,
        nonce: options.nonce,
        iat: now,
        exp,
        aud: options.clientId,
        iss: this.config.issuer,
        participants: options.participants,
      });
    } else if (this.config.proxyUrl) {
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
        throw new Error(`Refresh proxy failed with status ${res.status}`);
      }
      refreshResult = await res.json();
    } else {
      throw new Error("No proxy or proxyUrl configured in Client SDK");
    }

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
        throw new Error(`Failed to decrypt refresh share from node ${nodeResp.nodeId}`);
      }

      const parsed = JSON.parse(Buffer.from(decryptedBytes).toString("utf8"));
      shares.push(BigInt(parsed.z_i));
    }

    // Aggregate updated signature
    const R_bytes = computeGroupCommitment(signingInput, refreshResult.commitments);
    const signature = aggregateSignatureShares(R_bytes, shares);

    const id_token = assembleJwt(headerB64, payloadB64, signature);

    this.currentSession.counter = nextCtr;

    return { id_token, sessionId: this.currentSession.sessionId };
  }
}
