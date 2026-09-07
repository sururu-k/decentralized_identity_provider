/**
 * Minimal `Buffer` global for the browser.
 *
 * `docs/container-split.md` section 11 freezes `crypto/{frost,shamir,toprf,aead,kdf}.ts`
 * as byte-identical copies, and two of those files reach for the Node global `Buffer`:
 *
 *   frost.ts  computeGroupCommitment  -> Buffer.from(comm.D).toString("hex")
 *   kdf.ts    deriveRefreshKey        -> Buffer.from(sessionId, "utf8")
 *
 * Editing them would break the byte freeze, so the missing global is supplied instead.
 * Only those two shapes are implemented; anything else throws rather than silently
 * returning something subtly different from Node's Buffer. Under Node (the CLI stand-in
 * and vitest) the real `Buffer` already exists and this module does nothing.
 *
 * The result of `from` is a plain `Uint8Array` with its own `toString`, not a subclass:
 * `@noble/hashes` checks `instanceof Uint8Array`, which holds either way, and a subclass
 * cannot keep TypeScript's `Uint8Array.from` signature.
 */

const HEX = "0123456789abcdef";

interface ShimBuffer extends Uint8Array {
  toString(encoding?: string): string;
}

function wrap(bytes: Uint8Array): ShimBuffer {
  const buf = bytes as ShimBuffer;
  buf.toString = function (encoding?: string): string {
    if (encoding === "hex") {
      let out = "";
      for (let i = 0; i < this.length; i++) {
        out += HEX[this[i] >> 4] + HEX[this[i] & 0x0f];
      }
      return out;
    }
    if (encoding === undefined || encoding === "utf8" || encoding === "utf-8") {
      return new TextDecoder().decode(this);
    }
    throw new Error(`Buffer shim: unsupported encoding "${encoding}"`);
  };
  return buf;
}

export const BrowserBuffer = {
  from(value: string | Uint8Array | ArrayLike<number>, encoding?: string): ShimBuffer {
    if (typeof value === "string") {
      if (encoding !== undefined && encoding !== "utf8" && encoding !== "utf-8") {
        throw new Error(`Buffer shim: unsupported string encoding "${encoding}"`);
      }
      return wrap(new TextEncoder().encode(value));
    }
    return wrap(Uint8Array.from(value as ArrayLike<number>));
  },
};

const g = globalThis as unknown as { Buffer?: unknown };
if (typeof g.Buffer === "undefined") {
  g.Buffer = BrowserBuffer;
}

