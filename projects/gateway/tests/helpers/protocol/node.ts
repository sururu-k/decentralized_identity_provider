import { ristretto255 } from "@noble/curves/ed25519";
import {
  FrostCommitment,
  FrostNonces,
  computeSignatureShare,
  generateFrostNonces,
} from "../crypto/frost.js";
import { aeadEncrypt, deriveAeadNonce } from "../crypto/aead.js";
import { Share } from "../crypto/shamir.js";
import {
  blind,
  deriveServerKey,
  evaluate,
  finalize,
  generateToprfKey,
  unblind,
} from "../crypto/toprf.js";
import { verifyDPoPProof } from "../client-sdk/dpop.js";
import { base64UrlDecode, base64UrlEncode, createSigningInput, verifyJwt } from "../jwt/jwt.js";

/**
 * `IdentityNode` for the OAuth flow of docs/container-split.md section 14.
 *
 * The node does two things with its FROST share, and it decides both on its own:
 *
 * 1. `/sign-on` signs an **authentication assertion**, which is also the authorization
 *    code. The share comes back encrypted under `h_i`, so only a client that knows the
 *    password can decrypt it and assemble the assertion. The node never learns or checks
 *    the password.
 * 2. `/sign` signs an **access token and a refresh token**, in the clear, against that
 *    assertion presented back to it together with a DPoP proof from the key the assertion
 *    is bound to. The refresh token is itself a group-signed JWT (`typ: refresh+jwt`), so
 *    a later refresh grant presents it in place of the assertion and the gateway keeps no
 *    state of its own either.
 *
 * The node keeps **no session state at all**: the only thing it remembers between two
 * requests is the FROST nonce pair of an open round. Everything the access token asserts
 * travels inside the assertion, under the group signature, so nothing the gateway sends
 * alongside it can widen a token. The gateway supplies only `iat`, `exp` and `jti`,
 * because all nodes must sign byte-identical bytes, and the node range-checks those.
 */

/** Group signing key id written into every JWT header. Frozen by the dealer contract. */
export const DEFAULT_KEY_ID = "pasta-group-key-1";

/** `typ` of a refresh token, which is a group-signed JWT like the other two. */
export const REFRESH_TOKEN_TYP = "refresh+jwt";

/**
 * Longest assertion lifetime the node will sign, and therefore the window in which it is
 * spendable at `/sign` (section 14: 30 seconds from issue).
 */
export const MAX_ASSERTION_LIFETIME_SECONDS = 30;

/** Longest access token lifetime the node will sign (section 14: `exp − iat ≤ 3600`). */
export const MAX_ACCESS_TOKEN_LIFETIME_SECONDS = 3600;

/** Refresh token lifetime when the gateway does not pin one. */
export const DEFAULT_REFRESH_LIFETIME_SECONDS = 86400 * 30;

/** Longest refresh token lifetime the node will sign, whatever the gateway asks for. */
export const MAX_REFRESH_LIFETIME_SECONDS = 86400 * 40;

/** How far `iat` may sit from the node's clock, for DPoP proofs and for token claims. */
export const CLOCK_SKEW_SECONDS = 60;

export interface UserRecord {
  sub: string;
  username: string;
  toprfKeyShare: Share; // Share of TOPRF key
  h_i: Uint8Array; // pre-computed / TOPRF derived key for node i
}

export interface SignOnRequest {
  sessionId: string;
  username: string;
  blinded: string; // base64url of Ristretto255 point A = r * H1(password)
  sessionNonce: string; // base64url of 16-byte random session nonce
  cnfJkt: string;
  /** OAuth `client_id`, carried in the assertion as the access token's future `aud`. */
  clientId: string;
  /** OAuth `scope`, carried in the assertion. May be empty. */
  scope: string;
  nonce?: string;
  iat: number;
  exp: number;
  iss: string;
  commitments: FrostCommitment[];
  allParticipants: number[];
}

export interface SignOnResponse {
  nodeId: number;
  commitment: { D: Uint8Array; E: Uint8Array };
  toprfPartial: string; // base64url of Ristretto255 point B_i = k_i * A
  ct_i: string; // base64url of ChaCha20-Poly1305 ciphertext of { z_i }
  sessionId: string;
  sub: string;
}

/** Which credential the caller is spending at `/sign`. */
export type Grant = "authorization_code" | "refresh_token";

/** The token claims the gateway pins so all nodes sign the same bytes. */
export interface AccessTokenClaims {
  iat: number;
  exp: number;
  jti: string;
}

export interface SignRequest {
  grant: Grant;
  /** `authorization_code`: the assertion the client assembled at sign-on. */
  assertion?: string;
  /** `refresh_token`: a refresh token this group signed earlier. */
  refreshToken?: string;
  /** RFC 9449 proof for `POST <ISSUER>/token`, signed by the credential's DPoP key. */
  dpopProof: string;
  claims: AccessTokenClaims;
  /** `exp` of the new refresh token. Defaults to `claims.iat` + 30 days. */
  refreshExp?: number;
  /** Round-1 commitments of the access token round. */
  commitments: FrostCommitment[];
  /** Round-1 commitments of the refresh token round. A different round, necessarily. */
  refreshCommitments: FrostCommitment[];
  allParticipants: number[];
}

/** One signature's half of a `/sign` answer: the node's commitment and its share. */
export interface SignedShare {
  commitment: { D: Uint8Array; E: Uint8Array };
  /** FROST signature share, **plaintext**: 64 lowercase hex digits, big-endian. */
  z_i: string;
}

export interface SignResponse {
  nodeId: number;
  /** The access token. */
  at: SignedShare;
  /** The refresh token, signed in its own FROST round. */
  rt: SignedShare;
}

/** The two FROST rounds one `/sign` consumes. They must not be the same round. */
export interface SignRounds {
  accessRoundId: string;
  refreshRoundId: string;
}

/** This node's own commitment in each of those two rounds. */
export interface SignCommitments {
  access: { D: Uint8Array; E: Uint8Array };
  refresh: { D: Uint8Array; E: Uint8Array };
}

/**
 * What `/sign` reads back out of a verified credential: an assertion, or a refresh token
 * this group signed earlier. Both carry the same identity fields, which is what lets the
 * refresh grant run the same code path.
 */
export interface CredentialClaims {
  iss: string;
  sub: string;
  aud?: string;
  client_id: string;
  scope: string;
  cnf: { jkt: string };
  nonce?: string;
  iat: number;
  exp: number;
}

/** Kept as the old name for the assertion, which is one shape of a credential. */
export type AssertionClaims = CredentialClaims;

/** Encodes a FROST scalar the way section 3 encodes scalars: 64 hex digits, big-endian. */
export function scalarToHex(scalar: bigint): string {
  return scalar.toString(16).padStart(64, "0");
}

export class IdentityNode {
  public readonly nodeId: number;
  private readonly secretKeyShare: bigint;
  public readonly groupPublicKey: Uint8Array;
  /** This node's view of the issuer URL, no trailing slash. Never taken from a request. */
  public readonly issuer: string;
  public readonly keyId: string;
  private readonly users = new Map<string, UserRecord>();

  // Temporary nonces for in-flight FROST rounds. The node's only mutable state.
  private activeNonces = new Map<string, FrostNonces>();

  constructor(
    nodeId: number,
    secretKeyShare: bigint,
    groupPublicKey: Uint8Array,
    issuer: string,
    keyId: string = DEFAULT_KEY_ID
  ) {
    this.nodeId = nodeId;
    this.secretKeyShare = secretKeyShare;
    this.groupPublicKey = groupPublicKey;
    this.issuer = issuer.replace(/\/+$/, "");
    this.keyId = keyId;
  }

  /** The URL a DPoP proof must be bound to. Computed here, never sent by the gateway. */
  public get tokenEndpoint(): string {
    return `${this.issuer}/token`;
  }

  /**
   * Register user with TOPRF key share and server-specific key h_i.
   * Master password and master secret h are NEVER revealed to the node!
   */
  public registerUser(
    username: string,
    sub: string,
    toprfKeyShare: Share,
    h_i: Uint8Array
  ): void {
    this.users.set(username, { username, sub, toprfKeyShare, h_i });
  }

  /**
   * Round 1: Generate FROST commitment for this node
   */
  public generateCommitment(roundId: string): { D: Uint8Array; E: Uint8Array } {
    const { nonces, commitment } = generateFrostNonces();
    this.activeNonces.set(roundId, nonces);
    return commitment;
  }

  /**
   * Round 2 of authorisation: sign the authentication assertion.
   *
   * 1. Evaluates the TOPRF partial B_i = k_i·A without learning the password
   * 2. Signs the byte-identical assertion payload with its FROST share, giving z_i
   * 3. Encrypts { z_i } under h_i with ChaCha20-Poly1305 (AAD = signingInput)
   *
   * The node NEVER knows or verifies the plaintext password: encryption under h_i is what
   * makes the share usable only to a client that can recompute h. It stores nothing about
   * this sign-on -- the assertion the client walks away with is the whole record.
   */
  public handleSignOn(
    roundId: string,
    req: SignOnRequest,
    commitment: { D: Uint8Array; E: Uint8Array }
  ): SignOnResponse {
    const user = this.users.get(req.username);
    if (!user) {
      throw new Error(`User not found on node ${this.nodeId}`);
    }

    // The assertion's `iss` and `aud` are both this node's own issuer. The request still
    // carries `iss` so a gateway pointed at the wrong node is refused here, loudly,
    // instead of producing shares that aggregate into a token nobody accepts.
    if (req.iss !== this.issuer) {
      throw new Error(
        `iss mismatch on node ${this.nodeId}: expected ${this.issuer}, got ${req.iss}`
      );
    }

    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - req.iat) > CLOCK_SKEW_SECONDS) {
      throw new Error(
        `Assertion iat is outside the ±${CLOCK_SKEW_SECONDS}s window on node ${this.nodeId}`
      );
    }
    const lifetime = req.exp - req.iat;
    if (lifetime <= 0 || lifetime > MAX_ASSERTION_LIFETIME_SECONDS) {
      throw new Error(
        `Assertion lifetime ${lifetime}s out of range on node ${this.nodeId}: ` +
          `exp - iat must be 1..${MAX_ASSERTION_LIFETIME_SECONDS}`
      );
    }

    const nonces = this.activeNonces.get(roundId);
    if (!nonces) {
      throw new Error(`Round ${roundId} expired or not found on node ${this.nodeId}`);
    }
    this.activeNonces.delete(roundId);

    // 1. TOPRF partial evaluation B_i = k_i * A
    const blindedPointBytes = base64UrlDecode(req.blinded);
    const blindedPoint = ristretto255.Point.fromBytes(blindedPointBytes);
    const partialPoint = evaluate(user.toprfKeyShare, blindedPoint);

    // 2. Build the byte-identical assertion payload. `sub` comes from this node's own
    // user record; everything else the access token will need rides along here, under
    // the group signature, because the node keeps no session to look it up in later.
    const header = { alg: "EdDSA", typ: "JWT", kid: this.keyId };
    const payload = {
      iss: this.issuer,
      sub: user.sub,
      aud: this.issuer,
      client_id: req.clientId,
      scope: req.scope,
      cnf: { jkt: req.cnfJkt },
      nonce: req.nonce,
      iat: req.iat,
      exp: req.exp,
    };

    const { signingInput } = createSigningInput(header, payload);

    // 3. Compute FROST signature share z_i
    const z_i = computeSignatureShare(
      this.nodeId,
      nonces,
      this.secretKeyShare,
      signingInput,
      req.commitments,
      this.groupPublicKey,
      req.allParticipants
    );

    // 4. Encrypt { z_i } under h_i, AAD = signingInput
    const sessionNonceBytes = base64UrlDecode(req.sessionNonce);
    const aeadNonce = deriveAeadNonce(sessionNonceBytes, this.nodeId);
    const shareBundle = JSON.stringify({ z_i: z_i.toString() });

    const ct_i = aeadEncrypt(
      user.h_i,
      aeadNonce,
      new TextEncoder().encode(shareBundle),
      signingInput
    );

    return {
      nodeId: this.nodeId,
      commitment,
      toprfPartial: base64UrlEncode(partialPoint.toRawBytes()),
      ct_i: base64UrlEncode(ct_i),
      sessionId: req.sessionId,
      sub: user.sub,
    };
  }

  /**
   * Round 2 of issuance: sign the access token and the next refresh token, in the clear.
   *
   * Everything is checked here and now, against the credential presented: no session is
   * consulted, because none is kept. `sub`, `client_id`, `scope` and `cnf.jkt` are read
   * out of the verified assertion (`authorization_code`) or refresh token
   * (`refresh_token`), so the gateway can pick the moment of issue and nothing else.
   *
   * A replayed `/sign` is not tracked: within the credential's window a replay yields the
   * same pair of tokens, bound to the same `cnf.jkt`, which the replayer cannot use
   * without the DPoP private key. Refresh tokens rotate, but the previous one keeps
   * working until it expires -- invalidating it would need exactly the state this design
   * gives up (section 14.3).
   *
   * Two independent FROST rounds are consumed, one per signature. Signing two different
   * messages under one nonce pair would leak the key share, so the two rounds must be
   * different and each is spent here.
   */
  public handleSign(
    rounds: SignRounds,
    req: SignRequest,
    commitments: SignCommitments
  ): SignResponse {
    if (rounds.accessRoundId === rounds.refreshRoundId) {
      throw new Error(
        `Node ${this.nodeId} needs two different rounds for /sign: the access token and ` +
          `the refresh token cannot share a FROST nonce pair`
      );
    }

    const credential =
      req.grant === "authorization_code"
        ? this.verifyAssertion(req.assertion ?? "")
        : this.verifyRefreshToken(req.refreshToken ?? "");

    const verification = verifyDPoPProof(req.dpopProof, {
      expectedHtm: "POST",
      expectedHtu: this.tokenEndpoint,
      expectedJkt: credential.cnf.jkt,
      maxAgeSeconds: CLOCK_SKEW_SECONDS,
    });
    if (!verification.valid) {
      throw new Error(
        `Node ${this.nodeId} rejected DPoP proof: ${verification.error || "invalid"}`
      );
    }

    const now = Math.floor(Date.now() / 1000);
    const claims = req.claims;
    if (Math.abs(now - claims.iat) > CLOCK_SKEW_SECONDS) {
      throw new Error(
        `Access token iat is outside the ±${CLOCK_SKEW_SECONDS}s window on node ${this.nodeId}`
      );
    }
    const lifetime = claims.exp - claims.iat;
    if (lifetime <= 0 || lifetime > MAX_ACCESS_TOKEN_LIFETIME_SECONDS) {
      throw new Error(
        `Access token lifetime ${lifetime}s out of range on node ${this.nodeId}: ` +
          `exp - iat must be 1..${MAX_ACCESS_TOKEN_LIFETIME_SECONDS}`
      );
    }
    if (claims.jti.length === 0) {
      throw new Error(`Access token jti must not be empty on node ${this.nodeId}`);
    }

    // Deterministic either way, so every node signs the same refresh token bytes.
    const refreshExp = req.refreshExp ?? claims.iat + DEFAULT_REFRESH_LIFETIME_SECONDS;
    const refreshLifetime = refreshExp - claims.iat;
    if (refreshLifetime <= 0 || refreshLifetime > MAX_REFRESH_LIFETIME_SECONDS) {
      throw new Error(
        `Refresh token lifetime ${refreshLifetime}s out of range on node ${this.nodeId}: ` +
          `exp - iat must be 1..${MAX_REFRESH_LIFETIME_SECONDS}`
      );
    }

    const accessNonces = this.activeNonces.get(rounds.accessRoundId);
    if (!accessNonces) {
      throw new Error(
        `Round ${rounds.accessRoundId} expired or not found on node ${this.nodeId}`
      );
    }
    const refreshNonces = this.activeNonces.get(rounds.refreshRoundId);
    if (!refreshNonces) {
      throw new Error(
        `Round ${rounds.refreshRoundId} expired or not found on node ${this.nodeId}`
      );
    }
    this.activeNonces.delete(rounds.accessRoundId);
    this.activeNonces.delete(rounds.refreshRoundId);

    const accessToken = {
      header: { alg: "EdDSA", typ: "at+jwt", kid: this.keyId },
      payload: {
        iss: this.issuer,
        sub: credential.sub,
        aud: credential.client_id,
        scope: credential.scope,
        cnf: { jkt: credential.cnf.jkt },
        iat: claims.iat,
        exp: claims.exp,
        jti: claims.jti,
      },
    };
    const refreshToken = {
      header: { alg: "EdDSA", typ: REFRESH_TOKEN_TYP, kid: this.keyId },
      payload: {
        iss: this.issuer,
        sub: credential.sub,
        cnf: { jkt: credential.cnf.jkt },
        client_id: credential.client_id,
        scope: credential.scope,
        iat: claims.iat,
        exp: refreshExp,
      },
    };

    const atZ_i = this.share(accessToken, accessNonces, req.commitments, req.allParticipants);
    const rtZ_i = this.share(
      refreshToken,
      refreshNonces,
      req.refreshCommitments,
      req.allParticipants
    );

    return {
      nodeId: this.nodeId,
      at: { commitment: commitments.access, z_i: atZ_i },
      rt: { commitment: commitments.refresh, z_i: rtZ_i },
    };
  }

  /** One FROST share over one JWT, in the node's own scalar encoding. */
  private share(
    token: { header: object; payload: object },
    nonces: FrostNonces,
    commitments: FrostCommitment[],
    allParticipants: number[]
  ): string {
    const { signingInput } = createSigningInput(token.header, token.payload);
    return scalarToHex(
      computeSignatureShare(
        this.nodeId,
        nonces,
        this.secretKeyShare,
        signingInput,
        commitments,
        this.groupPublicKey,
        allParticipants
      )
    );
  }

  /**
   * Checks an assertion against the group public key and this node's own configuration,
   * and returns the claims it carries.
   *
   * The `typ` check is what keeps an access token or a refresh token from being presented
   * as an assertion: all three are signed by the same group key, and only the header
   * tells them apart.
   */
  public verifyAssertion(assertion: string): CredentialClaims {
    const claims = this.verifyCredential(assertion, "assertion", "JWT");
    if (claims.aud !== this.issuer) {
      throw new Error(
        `Node ${this.nodeId} rejected assertion: aud mismatch, expected ${this.issuer}`
      );
    }
    const lifetime = claims.exp - claims.iat;
    if (lifetime <= 0 || lifetime > MAX_ASSERTION_LIFETIME_SECONDS) {
      throw new Error(
        `Node ${this.nodeId} rejected assertion: lifetime ${lifetime}s is not ` +
          `1..${MAX_ASSERTION_LIFETIME_SECONDS}`
      );
    }
    return claims;
  }

  /** The same, for a refresh token this group signed earlier. */
  public verifyRefreshToken(refreshToken: string): CredentialClaims {
    const claims = this.verifyCredential(refreshToken, "refresh_token", REFRESH_TOKEN_TYP);
    const lifetime = claims.exp - claims.iat;
    if (lifetime <= 0 || lifetime > MAX_REFRESH_LIFETIME_SECONDS) {
      throw new Error(
        `Node ${this.nodeId} rejected refresh_token: lifetime ${lifetime}s is not ` +
          `1..${MAX_REFRESH_LIFETIME_SECONDS}`
      );
    }
    return claims;
  }

  /**
   * The verification both credentials share: the group signature, `alg`, `typ`, `exp` in
   * the future, `iss`, and the identity fields the access token is built from.
   */
  private verifyCredential(token: string, what: string, typ: string): CredentialClaims {
    const verified = verifyJwt(token, this.groupPublicKey);
    if (!verified.valid) {
      throw new Error(`Node ${this.nodeId} rejected ${what}: ${verified.error || "invalid"}`);
    }

    const header = verified.header as { typ?: unknown };
    if (header?.typ !== typ) {
      throw new Error(
        `Node ${this.nodeId} rejected ${what}: typ ${String(header?.typ)} is not ${typ}`
      );
    }

    const payload = verified.payload as Record<string, unknown> & { cnf?: { jkt?: unknown } };
    const claim = (name: string): string => {
      const value = payload[name];
      if (typeof value !== "string" || value.length === 0) {
        throw new Error(`Node ${this.nodeId} rejected ${what}: ${name} is missing`);
      }
      return value;
    };

    if (typeof payload.iat !== "number" || typeof payload.exp !== "number") {
      throw new Error(`Node ${this.nodeId} rejected ${what}: iat or exp is missing`);
    }

    const iss = claim("iss");
    if (iss !== this.issuer) {
      throw new Error(
        `Node ${this.nodeId} rejected ${what}: iss mismatch, expected ${this.issuer}`
      );
    }
    const jkt = payload.cnf?.jkt;
    if (typeof jkt !== "string" || jkt.length === 0) {
      throw new Error(`Node ${this.nodeId} rejected ${what}: cnf.jkt is missing`);
    }

    const claims: CredentialClaims = {
      iss,
      sub: claim("sub"),
      client_id: claim("client_id"),
      // An empty scope is a legitimate authorize request, so this one is read as-is.
      scope: typeof payload.scope === "string" ? payload.scope : "",
      cnf: { jkt },
      iat: payload.iat,
      exp: payload.exp,
    };
    if (typeof payload.aud === "string") {
      claims.aud = payload.aud;
    }
    if (typeof payload.nonce === "string") {
      claims.nonce = payload.nonce;
    }
    return claims;
  }
}

/**
 * Client-side user registration utility:
 * Generates TOPRF key shares via Shamir secret sharing,
 * locally computes master PRF value h and per-node keys h_i,
 * and registers them to nodes.
 * The master password is NEVER revealed to any node!
 */
export function registerUserToNodes(
  nodes: IdentityNode[],
  username: string,
  password: string,
  sub: string,
  threshold: number = 2
): void {
  const total = nodes.length;
  const toprfKeyShares = generateToprfKey(total, threshold);

  const { blinding, blinded } = blind(password);
  const partials = toprfKeyShares.slice(0, threshold).map((s) => ({
    id: s.id,
    point: evaluate(s, blinded),
  }));
  const v = unblind(blinding, partials);
  const h = finalize(password, v);

  for (let i = 0; i < nodes.length; i++) {
    const node = nodes[i];
    const keyShare = toprfKeyShares[i];
    const serverKey = deriveServerKey(h, node.nodeId);
    node.registerUser(username, sub, keyShare, serverKey);
  }
}
