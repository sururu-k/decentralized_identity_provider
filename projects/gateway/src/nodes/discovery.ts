import { base64UrlEncode } from "../jwt/jwt.js";
import { bytesToHex } from "../config.js";
import { DEFAULT_NODE_TIMEOUT_MS, HttpNodeClient } from "./http-node-client.js";

/**
 * Startup node discovery (`docs/container-split.md` section 6).
 *
 * `NODE_URLS` is an unordered list. Position says nothing about identity: the gateway
 * asks each URL `GET /health` and learns the `nodeId` from the answer. That keeps the
 * compose file from having to encode which container holds which share, and it catches a
 * node started with the wrong config file.
 *
 * Each node's `groupPublicKey` is checked against the dealer's `group.json`. A node that
 * belongs to a different key ceremony can never join: its FROST share would not
 * aggregate, and the mismatch is far easier to read here than as a signature that fails
 * verification much later.
 */

export interface DiscoveryOptions {
  urls: string[];
  groupPublicKey: Uint8Array;
  threshold: number;
  /** Attempts per node before giving up. */
  attempts?: number;
  /** Delay between attempts, in milliseconds. */
  retryDelayMs?: number;
  timeoutMs?: number;
  log?: (message: string) => void;
}

export const DEFAULT_DISCOVERY_ATTEMPTS = 30;
export const DEFAULT_DISCOVERY_RETRY_MS = 1_000;

/** Thrown when discovery cannot assemble a usable set of nodes. */
export class DiscoveryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DiscoveryError";
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Resolves every URL to a node client, retrying the ones that are not up yet.
 *
 * Returns once every URL has answered, or throws once the attempts are exhausted --
 * even if a quorum's worth of nodes did answer. Starting half-configured would hide a
 * broken deployment behind a working demo, and the contract says the gateway does not
 * come up below the threshold; coming up below the configured node count is treated the
 * same way, because compose has already waited for every node to be healthy.
 */
export async function discoverNodes(options: DiscoveryOptions): Promise<HttpNodeClient[]> {
  const attempts = options.attempts ?? DEFAULT_DISCOVERY_ATTEMPTS;
  const retryDelayMs = options.retryDelayMs ?? DEFAULT_DISCOVERY_RETRY_MS;
  const timeoutMs = options.timeoutMs ?? DEFAULT_NODE_TIMEOUT_MS;
  const log = options.log ?? (() => {});

  if (options.urls.length === 0) {
    throw new DiscoveryError("NODE_URLS is empty: the gateway needs at least one node URL");
  }
  if (options.urls.length < options.threshold) {
    throw new DiscoveryError(
      `NODE_URLS lists ${options.urls.length} node(s) but the threshold is ${options.threshold}`
    );
  }

  const expectedKeyHex = bytesToHex(options.groupPublicKey);
  const expectedKeyB64 = base64UrlEncode(options.groupPublicKey);

  const resolved = new Map<string, HttpNodeClient>();
  let lastErrors: string[] = [];

  for (let attempt = 1; attempt <= attempts; attempt++) {
    lastErrors = [];

    await Promise.all(
      options.urls.map(async (url) => {
        if (resolved.has(url)) return;
        // nodeId 0 is a placeholder; the real id comes from the /health answer.
        const probe = new HttpNodeClient(0, url, timeoutMs);
        try {
          const health = await probe.health();
          if (health.groupPublicKey !== expectedKeyB64) {
            // A key mismatch is not something a retry can fix.
            throw new DiscoveryError(
              `Node at ${url} serves group public key ${health.groupPublicKey} ` +
                `but group.json holds ${expectedKeyHex}; the node is from a different key ceremony`
            );
          }
          resolved.set(url, new HttpNodeClient(health.nodeId, url, timeoutMs));
          log(`[gateway] discovered node ${health.nodeId} at ${url}`);
        } catch (err) {
          if (err instanceof DiscoveryError) throw err;
          lastErrors.push(err instanceof Error ? err.message : String(err));
        }
      })
    );

    if (resolved.size === options.urls.length) {
      break;
    }

    if (attempt < attempts) {
      log(
        `[gateway] waiting for ${options.urls.length - resolved.size} node(s) ` +
          `(attempt ${attempt}/${attempts})`
      );
      await sleep(retryDelayMs);
    }
  }

  if (resolved.size < options.urls.length) {
    const missing = options.urls.filter((u) => !resolved.has(u));
    throw new DiscoveryError(
      `Node discovery failed after ${attempts} attempt(s). ` +
        `Unreachable: ${missing.join(", ")}. Last errors: ${lastErrors.join("; ") || "none"}`
    );
  }

  const clients = [...resolved.values()].sort((a, b) => a.nodeId - b.nodeId);

  const seen = new Set<number>();
  for (const client of clients) {
    if (client.nodeId < 1) {
      throw new DiscoveryError(`Node at ${client.url} reported an invalid nodeId ${client.nodeId}`);
    }
    if (seen.has(client.nodeId)) {
      throw new DiscoveryError(
        `Two node URLs report the same nodeId ${client.nodeId}: ` +
          clients
            .filter((c) => c.nodeId === client.nodeId)
            .map((c) => c.url)
            .join(" and ")
      );
    }
    seen.add(client.nodeId);
  }

  if (clients.length < options.threshold) {
    throw new DiscoveryError(
      `Only ${clients.length} node(s) available but the threshold is ${options.threshold}`
    );
  }

  return clients;
}

/**
 * Splits the comma-separated `NODE_URLS` value, dropping empty entries.
 *
 * Each entry has to be an absolute `http`/`https` URL. A typo is rejected here rather
 * than left to discovery, which would otherwise spend its full retry budget on a value
 * no amount of waiting can fix.
 */
export function parseNodeUrls(raw: string): string[] {
  const urls = raw
    .split(",")
    .map((s) => s.trim().replace(/\/+$/, ""))
    .filter((s) => s.length > 0);

  for (const candidate of urls) {
    let parsed: URL;
    try {
      parsed = new URL(candidate);
    } catch {
      throw new DiscoveryError(`Invalid NODE_URLS entry ${JSON.stringify(candidate)}: not a URL`);
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new DiscoveryError(
        `Invalid NODE_URLS entry ${JSON.stringify(candidate)}: expected an http or https URL`
      );
    }
  }

  return urls;
}
