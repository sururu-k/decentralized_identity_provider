import crypto from "node:crypto";
import { Grant, SignOnResponse } from "../protocol/types.js";
import {
  FrostCommitment,
  aggregateSignatureShares,
  computeGroupCommitment,
} from "../crypto/frost.js";
import { assembleJwt, base64UrlDecode, createSigningInput } from "../jwt/jwt.js";
import { DemoLog, ExcludedNode, createDemoLog } from "../demolog.js";
import { NodeClient } from "../nodes/client.js";

/** Group signing key id stamped into every JWT header (dealer contract). */
export const DEFAULT_KEY_ID = "pasta-group-key-1";

/** Access token lifetime the gateway pins, in seconds (section 14: 1 hour). */
export const ACCESS_TOKEN_LIFETIME_SECONDS = 3600;

/** Refresh token lifetime the gateway pins, in seconds (section 14: 30 days). */
export const REFRESH_TOKEN_LIFETIME_SECONDS = 86400 * 30;

export interface ProxySignOnRequestBody {
  username: string;
  blinded: string; // base64url of Ristretto255 blinded point A
  sessionNonce: string; // base64url of session nonce
  cnfJkt: string;
  /** OAuth `client_id`, signed into the assertion. */
  clientId: string;
  /** OAuth `scope`, signed into the assertion. May be empty. */
  scope: string;
  nonce?: string;
  iat: number;
  exp: number;
  iss: string;
  participants?: number[];
}

export interface ProxySignOnResult {
  sessionId: string;
  commitments: FrostCommitment[];
  nodeResponses: SignOnResponse[];
}

/** What `/token` hands back once the two tokens are synthesised. */
export interface ProxyTokenResult {
  accessToken: string;
  refreshToken: string;
  /** Access token lifetime, for the `expires_in` field. */
  expiresIn: number;
  /** Scope carried in the credential, echoed back to the client. */
  scope: string;
  /** `cnf.jkt` the tokens are bound to. For the demo log only. */
  cnfJkt: string;
}

/** The identity fields `/token` reads out of the credential it was handed. */
export interface CredentialClaims {
  sub: string;
  client_id: string;
  scope: string;
  cnf: { jkt: string };
}

/** A credential (an assertion or a refresh token) that will not parse or is malformed. */
export class InvalidCredentialError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidCredentialError";
  }
}

/**
 * OAuth / PASTA Proxy (`docs/container-split.md` section 14).
 *
 * The gateway holds **no user state**: no authorize session, no code store, no refresh
 * token store, no `sub`. It relays the sign-on rounds that mint an assertion, and it
 * relays the `/token` rounds that mint an access token and the next refresh token,
 * synthesising the two group signatures from the plaintext `z_i` shares each node
 * returns. It cannot decrypt a `ct_i` (it holds no `h_i`) and it cannot forge a
 * signature (it holds no key share), so the assertion can only be assembled by a client
 * that knows the password, and a token can only be minted when a threshold of nodes each
 * verify the credential and the DPoP proof for themselves.
 *
 * Every value that flows through here is either public, a blinded / encrypted per-session
 * value, or a finished token bound to a `cnf.jkt` no third party can exercise.
 */
export class QuorumError extends Error {
  constructor(
    message: string,
    /** How many nodes did answer round 1. */
    readonly committed: number,
    readonly threshold: number,
    /** Node ids that did not answer, ascending. */
    readonly unreachable: number[]
  ) {
    super(message);
    this.name = "QuorumError";
  }
}

export class PastaOAuthProxy {
  private nodes: Map<number, NodeClient>;
  private demoLog: DemoLog;
  public readonly threshold: number;
  public readonly issuer: string;
  public readonly keyId: string;

  constructor(
    nodes: NodeClient[],
    threshold: number = 2,
    demoLog?: DemoLog,
    issuer: string = "http://localhost:3000",
    keyId: string = DEFAULT_KEY_ID
  ) {
    this.nodes = new Map(nodes.map((n) => [n.nodeId, n]));
    this.threshold = threshold;
    this.demoLog = demoLog ?? createDemoLog();
    this.issuer = issuer.replace(/\/+$/, "");
    this.keyId = keyId;
  }

  /** Every node the gateway knows about, in ascending node id order. */
  public getNodes(): NodeClient[] {
    return [...this.nodes.values()].sort((a, b) => a.nodeId - b.nodeId);
  }

  /**
   * Round 1 across the requested participants.
   *
   * When the caller named `participants` explicitly, every one of them must answer: the
   * client asked for a specific quorum and silently substituting another one would
   * surprise it. When the caller named none, the gateway is free to choose, so a node
   * that fails to commit is simply left out and the round continues with whoever
   * answered -- as long as that is still at least `threshold` nodes.
   */
  private async collectCommitments(
    roundId: string,
    participantIds: number[],
    explicit: boolean
  ): Promise<{
    commitments: FrostCommitment[];
    participants: number[];
    excluded: ExcludedNode[];
  }> {
    const settled = await Promise.all(
      participantIds.map(
        async (id): Promise<FrostCommitment | { nodeId: number; error: Error }> => {
          const node = this.nodes.get(id);
          if (!node) return { nodeId: id, error: new Error(`Node ${id} not found in proxy`) };
          try {
            const { D, E } = await node.commit(roundId);
            return { nodeId: id, D, E };
          } catch (err) {
            return { nodeId: id, error: err instanceof Error ? err : new Error(String(err)) };
          }
        }
      )
    );

    const isFailure = (
      r: FrostCommitment | { nodeId: number; error: Error }
    ): r is { nodeId: number; error: Error } => "error" in r;

    const failures = settled.filter(isFailure);
    if (explicit && failures.length > 0) {
      throw new Error(
        `Requested participants did not all commit: ` +
          failures.map((f) => f.error.message).join("; ")
      );
    }

    const commitments = settled
      .filter((r): r is FrostCommitment => !isFailure(r))
      .sort((a, b) => a.nodeId - b.nodeId);

    if (commitments.length < this.threshold) {
      const detail = failures.map((f) => f.error.message).join("; ");
      throw new QuorumError(
        `Insufficient nodes for threshold quorum: need at least ${this.threshold}, ` +
          `${commitments.length} committed${detail ? ` (${detail})` : ""}`,
        commitments.length,
        this.threshold,
        failures.map((f) => f.nodeId).sort((a, b) => a - b)
      );
    }

    return {
      commitments,
      participants: commitments.map((c) => c.nodeId),
      excluded: failures
        .map((f) => ({ nodeId: f.nodeId, reason: f.error.message }))
        .sort((a, b) => a.nodeId - b.nodeId),
    };
  }

  /**
   * Relay endpoint for `POST /api/pasta/sign-on`.
   *
   * Orchestrates a two-round FROST threshold signature over the authentication assertion.
   * The gateway receives only the encrypted shares `ct_i` from nodes; because it never
   * holds the password or any `h_i`, it cannot inspect, steal, or forge the assertion.
   * It keeps no session record -- the assertion the client walks away with is the whole
   * artefact (section 14.2).
   */
  public async handleSignOn(body: ProxySignOnRequestBody): Promise<ProxySignOnResult> {
    const explicit = body.participants !== undefined;
    const requested = body.participants || Array.from(this.nodes.keys());
    if (requested.length < this.threshold) {
      throw new QuorumError(
        `Insufficient nodes for threshold quorum: need at least ${this.threshold}`,
        requested.length,
        this.threshold,
        []
      );
    }

    const roundId = crypto.randomUUID();

    // Round 1: gather FROST commitments from participants.
    const { commitments, participants, excluded } = await this.collectCommitments(
      roundId,
      requested,
      explicit
    );

    // Round 2: relay the sign-on request to each node with a common session id. Every
    // participant must succeed: the group commitment R and the Lagrange coefficients are
    // fixed by the commitment set, so a partial answer cannot aggregate.
    const sessionId = crypto.randomUUID();
    const nodeResponses = await Promise.all(
      commitments.map((comm) => {
        const node = this.nodes.get(comm.nodeId)!;
        return node.signOn(
          roundId,
          {
            sessionId,
            username: body.username,
            blinded: body.blinded,
            sessionNonce: body.sessionNonce,
            cnfJkt: body.cnfJkt,
            clientId: body.clientId,
            scope: body.scope,
            nonce: body.nonce,
            iat: body.iat,
            exp: body.exp,
            iss: body.iss,
            commitments,
            allParticipants: participants,
          },
          { D: comm.D, E: comm.E }
        );
      })
    );

    // Both rounds are done, so the whole event is written at once. Nothing here carries a
    // password: only the blinded point the gateway cannot open (section 11).
    this.demoLog.signOn({
      sessionId,
      roundId,
      participants,
      blinded: body.blinded,
      cnfJkt: body.cnfJkt,
      username: body.username,
      nonce: body.nonce ?? "",
      excluded,
    });

    return { sessionId, commitments, nodeResponses };
  }

  /**
   * Relay endpoint for `POST /token`, both grants (section 14).
   *
   * The gateway hands the credential (an assertion for `authorization_code`, a refresh
   * token for `refresh_token`) and the DPoP proof to each node, which verifies both for
   * itself and returns the plaintext `z_i` share of the access token and of the next
   * refresh token. The gateway synthesises the two group signatures and assembles the two
   * JWTs; it keeps no state and mints no signature of its own.
   *
   * Two FROST rounds are consumed, one per signature, so a node's Schnorr nonce pair is
   * never reused across the two messages. The refresh round runs against the exact
   * participant set of the access round, so both signatures share `allParticipants` and
   * the shares aggregate.
   */
  public async handleSign(
    grant: Grant,
    credential: string,
    dpopProof: string
  ): Promise<ProxyTokenResult> {
    const claims = decodeCredentialClaims(credential);

    const requested = Array.from(this.nodes.keys());
    if (requested.length < this.threshold) {
      throw new QuorumError(
        `Insufficient nodes for threshold quorum: need at least ${this.threshold}`,
        requested.length,
        this.threshold,
        []
      );
    }

    const accessRoundId = crypto.randomUUID();
    const refreshRoundId = crypto.randomUUID();

    // Round 1 for the access token, tolerating nodes that fail to commit.
    const access = await this.collectCommitments(accessRoundId, requested, false);
    // Round 1 for the refresh token, against exactly that participant set: all must
    // answer, so the two signatures aggregate over the same nodes.
    const refresh = await this.collectCommitments(refreshRoundId, access.participants, true);
    const participants = access.participants;

    const iat = Math.floor(Date.now() / 1000);
    const accessExp = iat + ACCESS_TOKEN_LIFETIME_SECONDS;
    const refreshExp = iat + REFRESH_TOKEN_LIFETIME_SECONDS;
    const jti = crypto.randomUUID();

    const nodeResponses = await Promise.all(
      access.commitments.map((comm) => {
        const node = this.nodes.get(comm.nodeId)!;
        const rtComm = refresh.commitments.find((c) => c.nodeId === comm.nodeId)!;
        return node.sign(
          accessRoundId,
          refreshRoundId,
          {
            grant,
            assertion: grant === "authorization_code" ? credential : undefined,
            refreshToken: grant === "refresh_token" ? credential : undefined,
            dpopProof,
            claims: { iat, exp: accessExp, jti },
            refreshExp,
            commitments: access.commitments,
            refreshCommitments: refresh.commitments,
            allParticipants: participants,
          },
          { D: comm.D, E: comm.E },
          { D: rtComm.D, E: rtComm.E }
        );
      })
    );

    // Rebuild the byte-identical signing inputs the nodes signed. Every node runs the
    // frozen `createSigningInput` over the same header and payload, so the gateway does
    // too, and the shares aggregate into a signature the published JWKS verifies.
    const accessToken = this.assembleToken(
      { alg: "EdDSA", typ: "at+jwt", kid: this.keyId },
      {
        iss: this.issuer,
        sub: claims.sub,
        aud: claims.client_id,
        scope: claims.scope,
        cnf: { jkt: claims.cnf.jkt },
        iat,
        exp: accessExp,
        jti,
      },
      access.commitments,
      nodeResponses.map((r) => r.at.z_i)
    );

    const refreshToken = this.assembleToken(
      { alg: "EdDSA", typ: "refresh+jwt", kid: this.keyId },
      {
        iss: this.issuer,
        sub: claims.sub,
        cnf: { jkt: claims.cnf.jkt },
        client_id: claims.client_id,
        scope: claims.scope,
        iat,
        exp: refreshExp,
      },
      refresh.commitments,
      nodeResponses.map((r) => r.rt.z_i)
    );

    this.demoLog.token({
      grant,
      credential,
      accessToken,
      cnfJkt: claims.cnf.jkt,
      participants,
      excluded: access.excluded,
    });

    return {
      accessToken,
      refreshToken,
      expiresIn: accessExp - iat,
      scope: claims.scope,
      cnfJkt: claims.cnf.jkt,
    };
  }

  /** Aggregates the shares of one JWT into a group Ed25519 signature and assembles it. */
  private assembleToken(
    header: object,
    payload: object,
    commitments: FrostCommitment[],
    shares: bigint[]
  ): string {
    const { signingInput, headerB64, payloadB64 } = createSigningInput(header, payload);
    const R = computeGroupCommitment(signingInput, commitments);
    const signature = aggregateSignatureShares(R, shares);
    return assembleJwt(headerB64, payloadB64, signature);
  }
}

/**
 * Reads the identity fields a token is built from out of a credential.
 *
 * The gateway does **not** verify the group signature (the nodes do, each for itself);
 * it only needs `sub`, `client_id`, `scope` and `cnf.jkt` to rebuild the byte-identical
 * signing input, and `cnf.jkt` for the "proof key equals credential key" check the caller
 * makes before this runs. A credential that is not a well-formed JWT, or that is missing
 * an identity field, cannot yield a token and is rejected as an invalid grant.
 */
export function decodeCredentialClaims(credential: string): CredentialClaims {
  const parts = credential.split(".");
  if (parts.length !== 3) {
    throw new InvalidCredentialError("credential is not a JWT");
  }
  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(Buffer.from(base64UrlDecode(parts[1])).toString("utf8"));
  } catch {
    throw new InvalidCredentialError("credential payload is not valid JSON");
  }
  if (typeof payload !== "object" || payload === null) {
    throw new InvalidCredentialError("credential payload is not an object");
  }

  const str = (name: string): string => {
    const value = payload[name];
    if (typeof value !== "string" || value.length === 0) {
      throw new InvalidCredentialError(`credential ${name} is missing`);
    }
    return value;
  };

  const cnf = payload.cnf as { jkt?: unknown } | undefined;
  if (!cnf || typeof cnf.jkt !== "string" || cnf.jkt.length === 0) {
    throw new InvalidCredentialError("credential cnf.jkt is missing");
  }

  return {
    sub: str("sub"),
    client_id: str("client_id"),
    // An empty scope is a legitimate authorize request, so it is read as-is.
    scope: typeof payload.scope === "string" ? payload.scope : "",
    cnf: { jkt: cnf.jkt },
  };
}
