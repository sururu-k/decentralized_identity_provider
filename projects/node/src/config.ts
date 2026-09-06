import fs from "node:fs";
import { Share } from "./crypto/shamir.js";

/**
 * Node configuration loader.
 *
 * Reads the `node-<id>.json` file produced by the dealer (docs/container-split.md
 * section 4) and turns it into the values `IdentityNode` needs.
 *
 * Encoding contract (docs/container-split.md section 3): every byte string and every
 * scalar in a secrets file is lowercase hex. A scalar is 64 hex digits, 32 bytes,
 * **big-endian**, zero padded, and is restored with `BigInt("0x" + hex)`. The
 * little-endian `scalarToBytes` in `crypto/frost.js` must never be used for this.
 */

export const NODE_CONFIG_VERSION = 1;

export interface NodeUserConfig {
  username: string;
  sub: string;
  toprfKeyShare: Share;
  h_i: Uint8Array;
}

export interface NodeConfig {
  version: number;
  nodeId: number;
  threshold: number;
  total: number;
  groupPublicKey: Uint8Array;
  secretKeyShare: bigint;
  users: NodeUserConfig[];
}

/** Thrown for any unusable configuration file. The message is meant to be printed as-is. */
export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

const HEX_RE = /^[0-9a-fA-F]+$/;

function fail(path: string, detail: string): never {
  throw new ConfigError(`Invalid node config ${path}: ${detail}`);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireString(path: string, where: string, value: unknown): string {
  if (typeof value !== "string" || value.length === 0) {
    fail(path, `${where} must be a non-empty string`);
  }
  return value;
}

function requireInteger(path: string, where: string, value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    fail(path, `${where} must be an integer, got ${JSON.stringify(value)}`);
  }
  return value;
}

/** Decodes a lowercase/uppercase hex byte string of an exact byte length. */
function decodeBytes(path: string, where: string, value: unknown, byteLength: number): Uint8Array {
  const hex = requireString(path, where, value);
  if (!HEX_RE.test(hex)) {
    fail(path, `${where} is not a hex string`);
  }
  if (hex.length !== byteLength * 2) {
    fail(path, `${where} must be ${byteLength * 2} hex digits (${byteLength} bytes), got ${hex.length}`);
  }
  const out = new Uint8Array(byteLength);
  for (let i = 0; i < byteLength; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Decodes a 64 hex digit scalar written big-endian by the dealer. */
function decodeScalar(path: string, where: string, value: unknown): bigint {
  const hex = requireString(path, where, value);
  if (!HEX_RE.test(hex)) {
    fail(path, `${where} is not a hex string`);
  }
  if (hex.length !== 64) {
    fail(path, `${where} must be 64 hex digits (32 bytes), got ${hex.length}`);
  }
  return BigInt("0x" + hex);
}

function parseUser(path: string, index: number, raw: unknown, nodeId: number): NodeUserConfig {
  const where = `users[${index}]`;
  if (!isPlainObject(raw)) {
    fail(path, `${where} must be an object`);
  }

  const username = requireString(path, `${where}.username`, raw.username);
  const sub = requireString(path, `${where}.sub`, raw.sub);

  const share = raw.toprfKeyShare;
  if (!isPlainObject(share)) {
    fail(path, `${where}.toprfKeyShare must be an object`);
  }
  const shareId = requireInteger(path, `${where}.toprfKeyShare.id`, share.id);
  if (shareId !== nodeId) {
    fail(
      path,
      `${where}.toprfKeyShare.id is ${shareId} but this file is for node ${nodeId}; ` +
        `each node must hold the share matching its own id`
    );
  }
  const shareValue = decodeScalar(path, `${where}.toprfKeyShare.value`, share.value);
  const h_i = decodeBytes(path, `${where}.h_i`, raw.h_i, 32);

  return { username, sub, toprfKeyShare: { id: shareId, value: shareValue }, h_i };
}

/** Parses already-read JSON text. `path` is only used to build error messages. */
export function parseNodeConfig(text: string, path: string): NodeConfig {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    fail(path, `not valid JSON (${err instanceof Error ? err.message : String(err)})`);
  }

  if (!isPlainObject(raw)) {
    fail(path, "top level value must be a JSON object");
  }

  const version = requireInteger(path, "version", raw.version);
  if (version !== NODE_CONFIG_VERSION) {
    fail(path, `unsupported version ${version}, this build understands version ${NODE_CONFIG_VERSION}`);
  }

  const nodeId = requireInteger(path, "nodeId", raw.nodeId);
  if (nodeId < 1) {
    fail(path, `nodeId must be >= 1, got ${nodeId}`);
  }

  const threshold = requireInteger(path, "threshold", raw.threshold);
  const total = requireInteger(path, "total", raw.total);
  if (threshold < 1 || threshold > total) {
    fail(path, `threshold ${threshold} and total ${total} must satisfy 1 <= threshold <= total`);
  }
  if (nodeId > total) {
    fail(path, `nodeId ${nodeId} is larger than total ${total}`);
  }

  const groupPublicKey = decodeBytes(path, "groupPublicKey", raw.groupPublicKey, 32);
  const secretKeyShare = decodeScalar(path, "secretKeyShare", raw.secretKeyShare);

  if (!Array.isArray(raw.users)) {
    fail(path, "users must be an array");
  }
  const users = raw.users.map((user, i) => parseUser(path, i, user, nodeId));

  const names = new Set<string>();
  for (const user of users) {
    if (names.has(user.username)) {
      fail(path, `duplicate username ${JSON.stringify(user.username)} in users`);
    }
    names.add(user.username);
  }

  return { version, nodeId, threshold, total, groupPublicKey, secretKeyShare, users };
}

/** Default listen port when `PORT` is unset or empty. */
export const DEFAULT_PORT = 4000;

/**
 * Reads the `PORT` environment variable, accepting only plain decimal digits naming a
 * real port.
 *
 * `Number()` alone is too generous here: it turns `" "` into 0, `"1e3"` into 1000 and
 * `"0x10"` into 16. Port 0 is rejected too -- it makes the kernel pick an ephemeral port,
 * so the container would come up on an address nobody, the HEALTHCHECK included, can
 * guess. Both cases used to start a server that looked healthy in the log and was
 * unreachable.
 */
export function readPort(raw: string | undefined): number {
  if (raw === undefined || raw === "") {
    return DEFAULT_PORT;
  }
  if (!/^[0-9]+$/.test(raw)) {
    throw new ConfigError(
      `Invalid PORT ${JSON.stringify(raw)}: expected decimal digits naming a port in 1..65535`
    );
  }
  const port = Number(raw);
  if (port < 1 || port > 65535) {
    throw new ConfigError(`Invalid PORT ${JSON.stringify(raw)}: expected a port in 1..65535`);
  }
  return port;
}

/** Reads and validates the node config file at `path`. */
export function loadNodeConfig(path: string): NodeConfig {
  let text: string;
  try {
    text = fs.readFileSync(path, "utf8");
  } catch (err) {
    const reason = (err as NodeJS.ErrnoException)?.code === "ENOENT" ? "file not found" : String(err);
    throw new ConfigError(`Cannot read node config ${path}: ${reason}`);
  }
  return parseNodeConfig(text, path);
}
