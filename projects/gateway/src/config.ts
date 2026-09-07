import fs from "node:fs";

/**
 * Group configuration loader.
 *
 * Reads the dealer's `group.json` (`docs/container-split.md` section 4). The gateway
 * needs only the public half of the key material: the group public key it publishes as
 * JWKS, the `kid` it stamps on tokens, and the threshold the dealer used.
 *
 * Encoding contract (section 3): byte strings in a secrets file are lowercase hex. There
 * is no scalar here -- the gateway never holds a share.
 */

export const GROUP_CONFIG_VERSION = 1;

export interface GroupConfig {
  version: number;
  threshold: number;
  total: number;
  keyId: string;
  groupPublicKey: Uint8Array;
}

/** Thrown for any unusable configuration. The message is meant to be printed as-is. */
export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

const HEX_RE = /^[0-9a-fA-F]+$/;

function fail(path: string, detail: string): never {
  throw new ConfigError(`Invalid group config ${path}: ${detail}`);
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

/** Decodes a hex byte string of an exact byte length. */
export function hexToBytes(path: string, where: string, value: unknown, byteLength: number): Uint8Array {
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

/** Lowercase hex, for logging and for comparing keys across nodes. */
export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

/** Parses already-read JSON text. `path` is only used to build error messages. */
export function parseGroupConfig(text: string, path: string): GroupConfig {
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
  if (version !== GROUP_CONFIG_VERSION) {
    fail(path, `unsupported version ${version}, this build understands version ${GROUP_CONFIG_VERSION}`);
  }

  const threshold = requireInteger(path, "threshold", raw.threshold);
  const total = requireInteger(path, "total", raw.total);
  if (threshold < 1 || threshold > total) {
    fail(path, `threshold ${threshold} and total ${total} must satisfy 1 <= threshold <= total`);
  }

  const keyId = requireString(path, "keyId", raw.keyId);
  const groupPublicKey = hexToBytes(path, "groupPublicKey", raw.groupPublicKey, 32);

  return { version, threshold, total, keyId, groupPublicKey };
}

/** Reads and validates the group config file at `path`. */
export function loadGroupConfig(path: string): GroupConfig {
  let text: string;
  try {
    text = fs.readFileSync(path, "utf8");
  } catch (err) {
    const reason = (err as NodeJS.ErrnoException)?.code === "ENOENT" ? "file not found" : String(err);
    throw new ConfigError(`Cannot read group config ${path}: ${reason}`);
  }
  return parseGroupConfig(text, path);
}
