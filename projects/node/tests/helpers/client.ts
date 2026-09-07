import crypto from "node:crypto";
import { ristretto255 } from "@noble/curves/ed25519";
import {
  FrostCommitment,
  aggregateSignatureShares,
  computeGroupCommitment,
} from "../../src/crypto/frost.js";
import { blind, deriveServerKey, finalize, unblind } from "../../src/crypto/toprf.js";
import { aeadDecrypt, deriveAeadNonce } from "../../src/crypto/aead.js";
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
  type SignOnRequestWire,
  type SignOnResponseWire,
  type SignRequestWire,
  type SignResponseWire,
} from "../../src/wire.js";
import { postJsonOrThrow, type RunningNode } from "./nodes.js";

/**
 * The two client roles of docs/container-split.md section 14, over real HTTP.
 *
 * The browser half assembles the **assertion**, which is also the authorization code: it
 * decrypts every `ct_i` with the key it derives from the password and aggregates the
 * shares. The rp front-end half holds the DPoP key and presents that assertion back to
 * the nodes, which sign the **access token** against it. The gateway's relay role is
 * played by the test, and the nodes keep no session between the two halves.
 */

export const KEY_ID = "pasta-group-key-1";
export const ASSERTION_HEADER = { alg: "EdDSA", typ: "JWT", kid: KEY_ID };
export const ACCESS_TOKEN_HEADER = { alg: "EdDSA", typ: "at+jwt", kid: KEY_ID };
export const REFRESH_TOKEN_HEADER = { alg: "EdDSA", typ: "refresh+jwt", kid: KEY_ID };

/** The refresh token lifetime the nodes fall back to. */
export const DEFAULT_REFRESH_LIFETIME_SECONDS = 86400 * 30;

/** Longest assertion the nodes will sign, and the window it is spendable in. */
export const ASSERTION_LIFETIME_SECONDS = 30;

/** The assertion payload, exactly as every node builds it. */
export interface AssertionClaims {
  iss: string;
  sub: string;
  aud: string;
  clientId: string;
  scope: string;
  cnfJkt: string;
  nonce?: string;
  iat: number;
  exp: number;
}

/** The access token payload, exactly as every node builds it. */
export interface AccessTokenClaims {
  iss: string;
  sub: string;
  aud: string;
  scope: string;
  cnfJkt: string;
  iat: number;
  exp: number;
  jti: string;
}

/** Rebuilds the exact bytes every node signed for the assertion. */
export function buildAssertionSigningInput(claims: AssertionClaims) {
  const payload = {
    iss: claims.iss,
    sub: claims.sub,
    aud: claims.aud,
    client_id: claims.clientId,
    scope: claims.scope,
    cnf: { jkt: claims.cnfJkt },
    nonce: claims.nonce,
    iat: claims.iat,
    exp: claims.exp,
  };
  return createSigningInput(ASSERTION_HEADER, payload);
}

/** The refresh token payload, exactly as every node builds it. */
export interface RefreshTokenClaims {
  iss: string;
  sub: string;
  clientId: string;
  scope: string;
  cnfJkt: string;
  iat: number;
  exp: number;
}

/** Rebuilds the exact bytes every node signed for the refresh token. */
export function buildRefreshTokenSigningInput(claims: RefreshTokenClaims) {
  const payload = {
    iss: claims.iss,
    sub: claims.sub,
    cnf: { jkt: claims.cnfJkt },
    client_id: claims.clientId,
    scope: claims.scope,
    iat: claims.iat,
    exp: claims.exp,
  };
  return createSigningInput(REFRESH_TOKEN_HEADER, payload);
}

/** Rebuilds the exact bytes every node signed for the access token. */
export function buildAccessTokenSigningInput(claims: AccessTokenClaims) {
  const payload = {
    iss: claims.iss,
    sub: claims.sub,
    aud: claims.aud,
    scope: claims.scope,
    cnf: { jkt: claims.cnfJkt },
    iat: claims.iat,
    exp: claims.exp,
    jti: claims.jti,
  };
  return createSigningInput(ACCESS_TOKEN_HEADER, payload);
}

export function newDPoPKeyPair(): { keyPair: DPoPKeyPair; cnfJkt: string } {
  const keyPair = generateDPoPKeyPair();
  return { keyPair, cnfJkt: calculateJwkThumbprint(exportDPoPJwk(keyPair.publicKey)) };
}

export interface ClientSession {
  assertion: string;
  sessionId: string;
  sub: string;
  cnfJkt: string;
  dpopKeyPair: DPoPKeyPair;
  clientId: string;
  scope: string;
  issuer: string;
  claims: AssertionClaims;
}

export interface SignOnParams {
  nodes: RunningNode[];
  username: string;
  password: string;
  clientId: string;
  issuer: string;
  scope?: string;
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
  const exp = now + (params.lifetimeSeconds ?? ASSERTION_LIFETIME_SECONDS);
  const roundId = params.round?.roundId ?? crypto.randomUUID();
  const sessionId = crypto.randomUUID();
  const participants = params.nodes.map((n) => n.nodeId);
  const scope = params.scope ?? "openid profile";

  const commitments = params.round?.commitments ?? (await collectCommitments(params.nodes, roundId));

  const { blinding, blinded } = blind(params.password);
  const sessionNonce = crypto.randomBytes(16);

  const request: SignOnRequestWire = {
    sessionId,
    username: params.username,
    blinded: base64UrlEncode(blinded.toRawBytes()),
    sessionNonce: base64UrlEncode(sessionNonce),
    cnfJkt: dpop.cnfJkt,
    clientId: params.clientId,
    scope,
    iat: now,
    exp,
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
  const claims: AssertionClaims = {
    iss: params.issuer,
    sub,
    aud: params.issuer,
    clientId: params.clientId,
    scope,
    cnfJkt: dpop.cnfJkt,
    nonce: params.nonce,
    iat: now,
    exp,
  };
  const { signingInput, headerB64, payloadB64 } = buildAssertionSigningInput(claims);

  // Unblind the TOPRF partials to recover the master PRF value h.
  const partials = responses.map((r) => ({
    id: r.nodeId,
    point: ristretto255.Point.fromBytes(base64UrlDecode(r.toprfPartial)),
  }));
  const v = unblind(blinding, partials);
  const h = finalize(params.password, v);

  const shares: bigint[] = [];
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
    shares.push(BigInt(JSON.parse(Buffer.from(plaintext).toString("utf8")).z_i));
  }

  const decodedCommitments: FrostCommitment[] = commitments.map((c) => commitmentFromWire(c));
  const R = computeGroupCommitment(signingInput, decodedCommitments);
  const signature = aggregateSignatureShares(R, shares);

  return {
    assertion: assembleJwt(headerB64, payloadB64, signature),
    sessionId,
    sub,
    cnfJkt: dpop.cnfJkt,
    dpopKeyPair: dpop.keyPair,
    clientId: params.clientId,
    scope,
    issuer: params.issuer,
    claims,
  };
}

export interface SignParams {
  nodes: RunningNode[];
  session: ClientSession;
  /** Which credential to spend. Defaults to the session's assertion. */
  grant?: "authorization_code" | "refresh_token";
  /** The refresh token to spend, for a `refresh_token` grant. */
  refreshToken?: string;
  /** Replaces the credential presented, to exercise the node's verification. */
  assertionOverride?: string;
  lifetimeSeconds?: number;
  jti?: string;
  /** `exp` of the new refresh token. Left off, the node defaults to iat + 30 days. */
  refreshExp?: number;
  /** Signs the DPoP proof for a different URL, to exercise node-side rejection. */
  proofHtuOverride?: string;
  /** Signs the DPoP proof with another key, to exercise the jkt binding. */
  keyPairOverride?: DPoPKeyPair;
  /** Replaces the whole proof, to exercise replay. */
  dpopProofOverride?: string;
  /** Overrides `iat` / `exp` / `jti` of the token claims, for the range checks. */
  claimsOverride?: Partial<{ iat: number; exp: number; jti: string }>;
}

export interface SignAttempt {
  accessRoundId: string;
  refreshRoundId: string;
  commitments: CommitmentWire[];
  refreshCommitments: CommitmentWire[];
  request: SignRequestWire;
  atClaims: AccessTokenClaims;
  rtClaims: RefreshTokenClaims;
}

/** Reads the identity claims out of a credential, the way the nodes do. */
function credentialClaims(credential: string): {
  sub: string;
  client_id: string;
  scope: string;
  jkt: string;
} {
  // A deliberately malformed credential still has to reach the node, so that the test can
  // see the node's own refusal rather than one of its own.
  let payload: any = {};
  try {
    payload = JSON.parse(
      Buffer.from(credential.split(".")[1] ?? "", "base64url").toString("utf8")
    );
  } catch {
    payload = {};
  }
  return {
    sub: payload.sub ?? "",
    client_id: payload.client_id ?? "",
    scope: payload.scope ?? "",
    jkt: payload.cnf?.jkt ?? "",
  };
}

/** Opens both rounds and builds the `/sign` request the rp front-end would send. */
export async function prepareSign(params: SignParams): Promise<SignAttempt> {
  const session = params.session;
  const grant = params.grant ?? "authorization_code";
  const accessRoundId = crypto.randomUUID();
  const refreshRoundId = crypto.randomUUID();
  const commitments = await collectCommitments(params.nodes, accessRoundId);
  const refreshCommitments = await collectCommitments(params.nodes, refreshRoundId);

  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iat: now,
    exp: now + (params.lifetimeSeconds ?? 3600),
    jti: params.jti ?? crypto.randomUUID(),
    ...(params.claimsOverride ?? {}),
  };

  const credential =
    params.assertionOverride ??
    (grant === "refresh_token" ? params.refreshToken ?? "" : session.assertion);

  const dpopProof =
    params.dpopProofOverride ??
    createDPoPProof(
      params.keyPairOverride ?? session.dpopKeyPair,
      "POST",
      params.proofHtuOverride ?? `${session.issuer}/token`
    );

  const request: SignRequestWire = {
    grant,
    dpopProof,
    claims,
    commitments,
    refreshCommitments,
    allParticipants: params.nodes.map((n) => n.nodeId),
  };
  if (grant === "authorization_code") {
    request.assertion = credential;
  } else {
    request.refreshToken = credential;
  }
  if (params.refreshExp !== undefined) {
    request.refreshExp = params.refreshExp;
  }

  // The nodes read these out of the credential, so the client does too rather than
  // assuming what it asked for.
  const identity = credentialClaims(credential);
  return {
    accessRoundId,
    refreshRoundId,
    commitments,
    refreshCommitments,
    request,
    atClaims: {
      iss: session.issuer,
      sub: identity.sub,
      aud: identity.client_id,
      scope: identity.scope,
      cnfJkt: identity.jkt,
      ...claims,
    },
    rtClaims: {
      iss: session.issuer,
      sub: identity.sub,
      clientId: identity.client_id,
      scope: identity.scope,
      cnfJkt: identity.jkt,
      iat: claims.iat,
      exp: params.refreshExp ?? claims.iat + DEFAULT_REFRESH_LIFETIME_SECONDS,
    },
  };
}

/** Aggregates one set of plaintext shares into a finished JWT. */
function assemble(
  parts: { signingInput: Uint8Array; headerB64: string; payloadB64: string },
  commitments: CommitmentWire[],
  shares: string[]
): string {
  const decoded: FrostCommitment[] = commitments.map((c) => commitmentFromWire(c));
  const R = computeGroupCommitment(parts.signingInput, decoded);
  const signature = aggregateSignatureShares(
    R,
    shares.map((z) => BigInt("0x" + z))
  );
  return assembleJwt(parts.headerB64, parts.payloadB64, signature);
}

/** Full issuance: two rounds of /commit, /sign on every node, then aggregate both JWTs. */
export async function signOverHttp(params: SignParams): Promise<{
  access_token: string;
  refresh_token: string;
  claims: AccessTokenClaims;
  refreshClaims: RefreshTokenClaims;
  shares: string[];
  refreshShares: string[];
}> {
  const attempt = await prepareSign(params);

  const responses: SignResponseWire[] = [];
  for (const n of params.nodes) {
    responses.push(
      await postJsonOrThrow(n.url, "/sign", {
        roundId: attempt.accessRoundId,
        refreshRoundId: attempt.refreshRoundId,
        request: attempt.request,
      })
    );
  }

  return {
    access_token: assemble(
      buildAccessTokenSigningInput(attempt.atClaims),
      attempt.commitments,
      responses.map((r) => r.at.z_i)
    ),
    refresh_token: assemble(
      buildRefreshTokenSigningInput(attempt.rtClaims),
      attempt.refreshCommitments,
      responses.map((r) => r.rt.z_i)
    ),
    claims: attempt.atClaims,
    refreshClaims: attempt.rtClaims,
    shares: responses.map((r) => r.at.z_i),
    refreshShares: responses.map((r) => r.rt.z_i),
  };
}
