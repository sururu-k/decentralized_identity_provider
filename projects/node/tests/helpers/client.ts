import crypto from "node:crypto";
import { ristretto255 } from "@noble/curves/ed25519";
import {
  FrostCommitment,
  aggregateSignatureShares,
  computeGroupCommitment,
} from "../../src/crypto/frost.js";
import { blind, deriveServerKey, finalize, unblind } from "../../src/crypto/toprf.js";
import { aeadDecrypt, deriveAeadNonce } from "../../src/crypto/aead.js";
import { deriveRefreshKey } from "../../src/crypto/kdf.js";
import {
  assembleJwt,
  base64UrlDecode,
  base64UrlEncode,
  createSigningInput,
} from "../../src/jwt/jwt.js";
import {
  DPoPKeyPair,
  calculateJwkThumbprint,
  createDPoPProof,
  exportDPoPJwk,
  generateDPoPKeyPair,
} from "../../src/client-sdk/dpop.js";
import {
  commitmentFromWire,
  type CommitmentWire,
  type RefreshResponseWire,
  type SignOnRequestWire,
  type SignOnResponseWire,
} from "../../src/wire.js";
import { postJsonOrThrow, type RunningNode } from "./nodes.js";

/**
 * Client-side half of the PASTA flow, rebuilt from `src/client-sdk/client.ts` without its
 * dependency on `PastaOAuthProxy`. The node component is only responsible for the server
 * side, so the test drives the gateway's relay role over plain HTTP itself.
 */

export interface TokenClaims {
  iss: string;
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  nonce?: string;
  cnfJkt: string;
}

export const JWT_HEADER = { alg: "EdDSA", typ: "JWT", kid: "pasta-group-key-1" };

/** Rebuilds the exact bytes every node signed, from claims the client already knows. */
export function buildSigningInput(claims: TokenClaims) {
  const payload = {
    iss: claims.iss,
    sub: claims.sub,
    aud: claims.aud,
    iat: claims.iat,
    exp: claims.exp,
    nonce: claims.nonce,
    cnf: { jkt: claims.cnfJkt },
  };
  return createSigningInput(JWT_HEADER, payload);
}

export function newDPoPKeyPair(): { keyPair: DPoPKeyPair; cnfJkt: string } {
  const keyPair = generateDPoPKeyPair();
  return { keyPair, cnfJkt: calculateJwkThumbprint(exportDPoPJwk(keyPair.publicKey)) };
}

export interface ClientSession {
  id_token: string;
  sessionId: string;
  sub: string;
  cnfJkt: string;
  dpopKeyPair: DPoPKeyPair;
  nodeSecrets: Map<number, Uint8Array>;
  counter: number;
  claims: TokenClaims;
}

export interface SignOnParams {
  nodes: RunningNode[];
  username: string;
  password: string;
  clientId: string;
  issuer: string;
  nonce?: string;
  lifetimeSeconds?: number;
  dpop?: { keyPair: DPoPKeyPair; cnfJkt: string };
  /** Overrides the `sub` the client assumes, to show a spoofed subject cannot decrypt. */
  subOverride?: string;
  /**
   * Reuses a round already opened with `collectCommitments`, so a test can open several
   * rounds first and then finish them in whatever order it likes.
   */
  round?: { roundId: string; commitments: CommitmentWire[] };
}

/** Round 1: ask every participant for a FROST commitment over HTTP. */
export async function collectCommitments(
  nodes: RunningNode[],
  roundId: string
): Promise<CommitmentWire[]> {
  const out: CommitmentWire[] = [];
  for (const n of nodes) {
    const body = await postJsonOrThrow(n.url, "/commit", { roundId });
    out.push({ nodeId: body.nodeId, D: body.D, E: body.E });
  }
  return out;
}

/** Full sign-on: /commit on every node, then /sign-on, then local decrypt + aggregate. */
export async function signOnOverHttp(params: SignOnParams): Promise<ClientSession> {
  const dpop = params.dpop ?? newDPoPKeyPair();
  const now = Math.floor(Date.now() / 1000);
  const exp = now + (params.lifetimeSeconds ?? 3600);
  const roundId = params.round?.roundId ?? crypto.randomUUID();
  const sessionId = crypto.randomUUID();
  const participants = params.nodes.map((n) => n.nodeId);

  const commitments = params.round?.commitments ?? (await collectCommitments(params.nodes, roundId));

  const { blinding, blinded } = blind(params.password);
  const sessionNonce = crypto.randomBytes(16);

  const request: SignOnRequestWire = {
    sessionId,
    username: params.username,
    blinded: base64UrlEncode(blinded.toRawBytes()),
    sessionNonce: base64UrlEncode(sessionNonce),
    cnfJkt: dpop.cnfJkt,
    iat: now,
    exp,
    aud: params.clientId,
    iss: params.issuer,
    commitments,
    allParticipants: participants,
  };
  if (params.nonce !== undefined) {
    request.nonce = params.nonce;
  }

  const responses: SignOnResponseWire[] = [];
  for (const n of params.nodes) {
    responses.push(await postJsonOrThrow(n.url, "/sign-on", { roundId, request }));
  }

  const sub = params.subOverride ?? responses[0].sub;
  const claims: TokenClaims = {
    iss: params.issuer,
    sub,
    aud: params.clientId,
    iat: now,
    exp,
    nonce: params.nonce,
    cnfJkt: dpop.cnfJkt,
  };
  const { signingInput, headerB64, payloadB64 } = buildSigningInput(claims);

  // Unblind the TOPRF partials to recover the master PRF value h.
  const partials = responses.map((r) => ({
    id: r.nodeId,
    point: ristretto255.Point.fromBytes(base64UrlDecode(r.toprfPartial)),
  }));
  const v = unblind(blinding, partials);
  const h = finalize(params.password, v);

  const shares: bigint[] = [];
  const nodeSecrets = new Map<number, Uint8Array>();
  for (const r of responses) {
    const h_i = deriveServerKey(h, r.nodeId);
    const aeadNonce = deriveAeadNonce(sessionNonce, r.nodeId);
    let plaintext: Uint8Array;
    try {
      plaintext = aeadDecrypt(h_i, aeadNonce, base64UrlDecode(r.ct_i), signingInput);
    } catch {
      throw new Error(
        `Failed to decrypt share from node ${r.nodeId}. Invalid password or corrupted share.`
      );
    }
    const parsed = JSON.parse(Buffer.from(plaintext).toString("utf8"));
    shares.push(BigInt(parsed.z_i));
    nodeSecrets.set(r.nodeId, base64UrlDecode(parsed.rs_i));
  }

  const decodedCommitments: FrostCommitment[] = commitments.map((c) => commitmentFromWire(c));
  const R = computeGroupCommitment(signingInput, decodedCommitments);
  const signature = aggregateSignatureShares(R, shares);

  return {
    id_token: assembleJwt(headerB64, payloadB64, signature),
    sessionId,
    sub,
    cnfJkt: dpop.cnfJkt,
    dpopKeyPair: dpop.keyPair,
    nodeSecrets,
    counter: 0,
    claims,
  };
}

export interface RefreshParams {
  nodes: RunningNode[];
  session: ClientSession;
  clientId: string;
  issuer: string;
  refreshEndpointUrl: string;
  nonce?: string;
  lifetimeSeconds?: number;
  /** Signs the DPoP proof for a different URL, to exercise node-side rejection. */
  proofHtuOverride?: string;
}

/** Full refresh: /commit on every node, then /refresh, then local decrypt + aggregate. */
export async function refreshOverHttp(
  params: RefreshParams
): Promise<{ id_token: string; ctr: number }> {
  const session = params.session;
  const nextCtr = session.counter + 1;
  const now = Math.floor(Date.now() / 1000);
  const exp = now + (params.lifetimeSeconds ?? 3600);
  const roundId = crypto.randomUUID();
  const participants = params.nodes.map((n) => n.nodeId);

  const commitments = await collectCommitments(params.nodes, roundId);

  const dpopProof = createDPoPProof(
    session.dpopKeyPair,
    "POST",
    params.proofHtuOverride ?? params.refreshEndpointUrl
  );

  const request: Record<string, unknown> = {
    sessionId: session.sessionId,
    dpopProof,
    expectedHtu: params.refreshEndpointUrl,
    iat: now,
    exp,
    aud: params.clientId,
    iss: params.issuer,
    commitments,
    allParticipants: participants,
  };
  if (params.nonce !== undefined) {
    request.nonce = params.nonce;
  }

  const responses: RefreshResponseWire[] = [];
  for (const n of params.nodes) {
    responses.push(await postJsonOrThrow(n.url, "/refresh", { roundId, request }));
  }

  const claims: TokenClaims = {
    iss: params.issuer,
    sub: session.sub,
    aud: params.clientId,
    iat: now,
    exp,
    nonce: params.nonce,
    cnfJkt: session.cnfJkt,
  };
  const { signingInput, headerB64, payloadB64 } = buildSigningInput(claims);

  const shares: bigint[] = [];
  for (const r of responses) {
    const rs_i = session.nodeSecrets.get(r.nodeId);
    if (!rs_i) {
      throw new Error(`Missing rs_i for node ${r.nodeId} in client session`);
    }
    const rk_i = deriveRefreshKey(rs_i, nextCtr, session.sessionId);
    const refreshNonce = deriveAeadNonce(
      new TextEncoder().encode(`REFRESH:${session.sessionId}:${nextCtr}`),
      r.nodeId
    );
    let plaintext: Uint8Array;
    try {
      plaintext = aeadDecrypt(rk_i, refreshNonce, base64UrlDecode(r.ct_i), signingInput);
    } catch {
      throw new Error(`Failed to decrypt refresh share from node ${r.nodeId}`);
    }
    const parsed = JSON.parse(Buffer.from(plaintext).toString("utf8"));
    shares.push(BigInt(parsed.z_i));
  }

  const decodedCommitments: FrostCommitment[] = commitments.map((c) => commitmentFromWire(c));
  const R = computeGroupCommitment(signingInput, decodedCommitments);
  const signature = aggregateSignatureShares(R, shares);

  session.counter = nextCtr;

  return { id_token: assembleJwt(headerB64, payloadB64, signature), ctr: responses[0].ctr };
}
