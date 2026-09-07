import crypto from "node:crypto";
import { ristretto255 } from "@noble/curves/ed25519";
import type { FrostCommitment } from "../../src/crypto/frost.js";
import { aggregateSignatureShares, computeGroupCommitment } from "../../src/crypto/frost.js";
import { blind, deriveServerKey, finalize, unblind } from "../../src/crypto/toprf.js";
import { aeadDecrypt, deriveAeadNonce } from "../../src/crypto/aead.js";
import { assembleJwt, base64UrlDecode, base64UrlEncode } from "../../src/jwt/jwt.js";
import type { IdentityNode, SignOnRequest, SignOnResponse } from "../../src/protocol/node.js";
import {
  ASSERTION_LIFETIME_SECONDS,
  buildAssertionSigningInput,
  newDPoPKeyPair,
  type AssertionClaims,
} from "./client.js";
import { TEST_ISSUER } from "./nodes.js";

/**
 * In-process driver for the node-only protocol tests. It plays the gateway's relay role
 * and the client's aggregation role against `IdentityNode` directly, with no HTTP hop.
 */

export interface InProcRound {
  roundId: string;
  sessionId: string;
  commitments: FrostCommitment[];
  request: SignOnRequest;
  blinding: { r: bigint };
  sessionNonce: Uint8Array;
  claims: Omit<AssertionClaims, "sub">;
  dpop: ReturnType<typeof newDPoPKeyPair>;
}

export interface StartRoundOptions {
  username: string;
  password: string;
  issuer?: string;
  clientId?: string;
  scope?: string;
  nonce?: string;
  cnfJkt?: string;
  dpop?: ReturnType<typeof newDPoPKeyPair>;
  lifetimeSeconds?: number;
  /** Extra fields the client tries to smuggle into the request. */
  extra?: Record<string, unknown>;
}

export function startRound(nodes: IdentityNode[], options: StartRoundOptions): InProcRound {
  const roundId = crypto.randomUUID();
  const sessionId = crypto.randomUUID();
  const commitments: FrostCommitment[] = nodes.map((n) => {
    const { D, E } = n.generateCommitment(roundId);
    return { nodeId: n.nodeId, D, E };
  });

  const { blinding, blinded } = blind(options.password);
  const sessionNonce = crypto.randomBytes(16);
  const now = Math.floor(Date.now() / 1000);
  const exp = now + (options.lifetimeSeconds ?? ASSERTION_LIFETIME_SECONDS);
  const dpop = options.dpop ?? newDPoPKeyPair();
  const cnfJkt = options.cnfJkt ?? dpop.cnfJkt;
  const issuer = options.issuer ?? TEST_ISSUER;
  const clientId = options.clientId ?? "demo_client";
  const scope = options.scope ?? "openid profile";

  const request = {
    sessionId,
    username: options.username,
    blinded: base64UrlEncode(blinded.toRawBytes()),
    sessionNonce: base64UrlEncode(sessionNonce),
    cnfJkt,
    clientId,
    scope,
    nonce: options.nonce,
    iat: now,
    exp,
    iss: issuer,
    commitments,
    allParticipants: nodes.map((n) => n.nodeId),
    ...(options.extra ?? {}),
  } as SignOnRequest;

  return {
    roundId,
    sessionId,
    commitments,
    request,
    blinding,
    sessionNonce,
    claims: {
      iss: issuer,
      aud: issuer,
      clientId,
      scope,
      iat: now,
      exp,
      nonce: options.nonce,
      cnfJkt,
    },
    dpop,
  };
}

/** Runs round 2 on every node, handing each its own commitment. */
export function runSignOn(nodes: IdentityNode[], round: InProcRound): SignOnResponse[] {
  return nodes.map((n) => {
    const mine = round.commitments.find((c) => c.nodeId === n.nodeId)!;
    return n.handleSignOn(round.roundId, round.request, { D: mine.D, E: mine.E });
  });
}

export interface AggregateOptions {
  round: InProcRound;
  responses: SignOnResponse[];
  password: string;
  /** Defaults to the sub the nodes reported. */
  sub?: string;
  /** Defaults to the full commitment set from round 1. */
  commitments?: FrostCommitment[];
  /** Signing input to decrypt against, when deliberately mismatched. */
  signingInputOverride?: Uint8Array;
}

/** Client-side finish: unblind, decrypt every ct_i, aggregate, assemble the assertion. */
export function aggregateSignOn(options: AggregateOptions): {
  assertion: string;
  signature: Uint8Array;
  signingInput: Uint8Array;
  shares: bigint[];
} {
  const { round, responses, password } = options;
  const sub = options.sub ?? responses[0].sub;
  const claims: AssertionClaims = { ...round.claims, sub };
  const { signingInput, headerB64, payloadB64 } = buildAssertionSigningInput(claims);
  const aad = options.signingInputOverride ?? signingInput;

  const partials = responses.map((r) => ({
    id: r.nodeId,
    point: ristretto255.Point.fromBytes(base64UrlDecode(r.toprfPartial)),
  }));
  const v = unblind(round.blinding, partials);
  const h = finalize(password, v);

  const shares: bigint[] = [];
  for (const r of responses) {
    const h_i = deriveServerKey(h, r.nodeId);
    const aeadNonce = deriveAeadNonce(round.sessionNonce, r.nodeId);
    let plaintext: Uint8Array;
    try {
      plaintext = aeadDecrypt(h_i, aeadNonce, base64UrlDecode(r.ct_i), aad);
    } catch {
      throw new Error(
        `Failed to decrypt share from node ${r.nodeId}. Invalid password or corrupted share.`
      );
    }
    shares.push(BigInt(JSON.parse(Buffer.from(plaintext).toString("utf8")).z_i));
  }

  const commitments = options.commitments ?? round.commitments;
  const R = computeGroupCommitment(signingInput, commitments);
  const signature = aggregateSignatureShares(R, shares);

  return { assertion: assembleJwt(headerB64, payloadB64, signature), signature, signingInput, shares };
}

/** Sign-on plus aggregation: the assertion a client walks away from `/sign-on` with. */
export function assertionFor(
  nodes: IdentityNode[],
  options: StartRoundOptions
): { round: InProcRound; assertion: string; sub: string } {
  const round = startRound(nodes, options);
  const responses = runSignOn(nodes, round);
  const { assertion } = aggregateSignOn({ round, responses, password: options.password });
  return { round, assertion, sub: responses[0].sub };
}
