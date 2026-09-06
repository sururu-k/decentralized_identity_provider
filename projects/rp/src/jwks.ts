/**
 * JWKS fetching and caching.
 *
 * The RP knows nothing about how the IdP produces signatures; it only knows the
 * public keys published at `<idp>/jwks.json`. Keys are fetched lazily on the
 * first callback and cached; an unknown `kid` triggers exactly one refetch so a
 * key rotation is picked up without hammering the IdP.
 */

export interface Jwk {
  kty?: string;
  crv?: string;
  x?: string;
  kid?: string;
  alg?: string;
  use?: string;
  [key: string]: unknown;
}

/** Raised when the JWKS document cannot be fetched or parsed. Surfaced as 502. */
export class JwksFetchError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = "JwksFetchError";
  }
}

/** Raised when the JWKS was fetched but holds no key matching the token's `kid`. */
export class JwksKeyNotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JwksKeyNotFoundError";
  }
}

export interface JwksClientOptions {
  /** Base URL of the IdP; `/jwks.json` is appended. */
  idpBaseUrl: string;
  /** Injectable for tests. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
  /** Per-request timeout in milliseconds. */
  timeoutMs?: number;
  /**
   * Called immediately before each network fetch — the initial load and any
   * kid-triggered refetch, but never a cache hit. Used by the demo log; a
   * fetch that fails still counts as an attempt and still fires this.
   */
  onFetch?: () => void;
}

export class JwksClient {
  private readonly jwksUri: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;
  private readonly onFetch?: () => void;
  private cachedKeys: Jwk[] | null = null;
  private inFlight: Promise<Jwk[]> | null = null;

  constructor(options: JwksClientOptions) {
    this.jwksUri = `${options.idpBaseUrl.replace(/\/+$/, "")}/jwks.json`;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.timeoutMs = options.timeoutMs ?? 5000;
    this.onFetch = options.onFetch;
  }

  public get uri(): string {
    return this.jwksUri;
  }

  /**
   * Returns the signing key for `kid`.
   *
   * When `kid` is absent the JWKS must hold exactly one usable key. A miss
   * against a *cached* document causes a single refetch before giving up; a miss
   * against a document that was just fetched is final, so a cold cache never
   * costs two round trips. A refetch replaces the cache only when it succeeds.
   */
  public async getSigningKey(kid: string | undefined): Promise<Jwk> {
    const cached = this.cachedKeys;
    let keys = cached ?? (await this.load());
    let key = selectKey(keys, kid);
    if (!key && cached !== null) {
      // Unknown kid against a cached document: refetch once, then give up. The
      // cached keys are kept until the new document arrives, so a token with a
      // bogus kid cannot evict a working JWKS while the IdP is unreachable.
      keys = await this.load();
      key = selectKey(keys, kid);
    }
    if (!key) {
      throw new JwksKeyNotFoundError(
        kid ? `no key in JWKS matches kid "${kid}"` : "JWKS holds no usable Ed25519 key"
      );
    }
    return key;
  }

  /** Fetches the JWKS, coalescing concurrent calls and caching only on success. */
  private async load(): Promise<Jwk[]> {
    if (this.inFlight) return this.inFlight;
    this.inFlight = this.fetchJwks()
      .then((keys) => {
        this.cachedKeys = keys;
        return keys;
      })
      .finally(() => {
        this.inFlight = null;
      });
    return this.inFlight;
  }

  private async fetchJwks(): Promise<Jwk[]> {
    this.onFetch?.();
    let response: Response;
    try {
      response = await this.fetchImpl(this.jwksUri, {
        signal: AbortSignal.timeout(this.timeoutMs),
        headers: { accept: "application/json" },
      });
    } catch (err) {
      throw new JwksFetchError(`failed to fetch JWKS from ${this.jwksUri}`, err);
    }
    if (!response.ok) {
      throw new JwksFetchError(`JWKS endpoint ${this.jwksUri} returned HTTP ${response.status}`);
    }
    let document: unknown;
    try {
      document = await response.json();
    } catch (err) {
      throw new JwksFetchError(`JWKS document at ${this.jwksUri} is not valid JSON`, err);
    }
    const keys = (document as { keys?: unknown } | null)?.keys;
    if (!Array.isArray(keys)) {
      throw new JwksFetchError(`JWKS document at ${this.jwksUri} has no "keys" array`);
    }
    return keys as Jwk[];
  }
}

/**
 * Picks the Ed25519 key for `kid`, or the only usable key when `kid` is absent.
 *
 * The JWKS is attacker-influenced input as far as this process is concerned, so
 * entries that are not plain objects (`null`, strings, arrays) are skipped
 * rather than dereferenced.
 */
function selectKey(keys: Jwk[], kid: string | undefined): Jwk | undefined {
  const usable = keys.filter(
    (k) =>
      typeof k === "object" &&
      k !== null &&
      !Array.isArray(k) &&
      k.kty === "OKP" &&
      k.crv === "Ed25519" &&
      typeof k.x === "string" &&
      (k.use ?? "sig") === "sig"
  );
  if (kid !== undefined) {
    return usable.find((k) => k.kid === kid);
  }
  return usable.length === 1 ? usable[0] : undefined;
}
