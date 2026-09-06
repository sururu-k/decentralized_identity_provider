import { expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { Share, combineShares } from "../src/crypto/shamir.js";
import {
  blind,
  deriveServerKey,
  evaluate,
  finalize,
  unblind,
} from "../src/crypto/toprf.js";
import { GroupFile, NodeFile } from "../src/dealer.js";
import { bytesToHex, hexToScalar } from "../src/hex.js";

const B = ed25519.ExtendedPoint.BASE;
const HEX64 = /^[0-9a-f]{64}$/;

/** A user whose password the caller knows, so `h` can be recomputed. */
export interface KnownUser {
  username: string;
  password: string;
  sub?: string;
}

/** Reads back a node file's Shamir share of the FROST master secret. */
export function secretKeyShareOf(node: NodeFile): Share {
  return { id: node.nodeId, value: hexToScalar(node.secretKeyShare) };
}

/** Reads back one user's TOPRF key share from a node file. */
export function toprfShareOf(node: NodeFile, username: string): Share {
  const record = recordOf(node, username);
  return {
    id: record.toprfKeyShare.id,
    value: hexToScalar(record.toprfKeyShare.value),
  };
}

/** The `h_i` a node file stores for a user. */
export function hOf(node: NodeFile, username: string): string {
  return recordOf(node, username).h_i;
}

function recordOf(node: NodeFile, username: string) {
  const record = node.users.find((u) => u.username === username);
  if (!record) {
    throw new Error(`No record for ${username} in node ${node.nodeId}`);
  }
  return record;
}

/** The group public key implied by a set of Shamir shares. */
export function groupPublicKeyFrom(shares: Share[]): string {
  return bytesToHex(B.multiply(combineShares(shares)).toRawBytes());
}

/** Recomputes the master PRF value `h` from `threshold` TOPRF shares. */
export function recomputeH(password: string, shares: Share[]): Uint8Array {
  const { blinding, blinded } = blind(password);
  const partials = shares.map((s) => ({ id: s.id, point: evaluate(s, blinded) }));
  return finalize(password, unblind(blinding, partials));
}

/** Every combination of `size` elements of `items`, in index order. */
function combinations<T>(items: T[], size: number): T[][] {
  if (size === 0) return [[]];
  const out: T[][] = [];
  for (let i = 0; i <= items.length - size; i++) {
    for (const rest of combinations(items.slice(i + 1), size - 1)) {
      out.push([items[i], ...rest]);
    }
  }
  return out;
}

/**
 * Asserts the full contract for a dealer output set: file shape, hex encoding,
 * and the two completion conditions of docs/container-split.md section 4.
 *
 * Used both on freshly generated output and on the committed `sample-output/`
 * fixtures, so a corrupted fixture fails the dealer's own test suite.
 */
export function checkDealerOutput(
  group: GroupFile,
  nodes: NodeFile[],
  users: KnownUser[]
): void {
  // --- shape and encoding (section 3 / section 4) ---
  expect(group.version).toBe(1);
  expect(group.total).toBe(nodes.length);
  expect(group.threshold).toBeGreaterThanOrEqual(1);
  expect(group.threshold).toBeLessThanOrEqual(group.total);
  expect(typeof group.keyId).toBe("string");
  expect(group.keyId.length).toBeGreaterThan(0);
  expect(group.groupPublicKey).toMatch(HEX64);

  expect(nodes.map((n) => n.nodeId)).toEqual(
    Array.from({ length: group.total }, (_, i) => i + 1)
  );
  for (const node of nodes) {
    expect(node.version).toBe(1);
    expect(node.threshold).toBe(group.threshold);
    expect(node.total).toBe(group.total);
    expect(node.groupPublicKey).toBe(group.groupPublicKey);
    expect(node.secretKeyShare).toMatch(HEX64);
    expect(node.users.map((u) => u.username)).toEqual(users.map((u) => u.username));
    for (const user of node.users) {
      expect(user.toprfKeyShare.id).toBe(node.nodeId);
      expect(user.toprfKeyShare.value).toMatch(HEX64);
      expect(user.h_i).toMatch(HEX64);
      expect(typeof user.sub).toBe("string");
      expect(user.sub.length).toBeGreaterThan(0);
      const expected = users.find((u) => u.username === user.username);
      if (expected?.sub !== undefined) {
        expect(user.sub).toBe(expected.sub);
      }
    }
  }

  // No password ever reaches a file.
  const serialized = JSON.stringify({ group, nodes });
  for (const user of users) {
    expect(serialized).not.toContain(user.password);
  }

  // --- completion condition 1: any t secretKeyShares rebuild the group key ---
  const quorums = combinations(nodes, group.threshold);
  expect(quorums.length).toBeGreaterThan(0);
  for (const quorum of quorums) {
    expect(groupPublicKeyFrom(quorum.map(secretKeyShareOf))).toBe(group.groupPublicKey);
  }

  // --- completion condition 2: any t toprfKeyShares + password rebuild every h_i ---
  for (const user of users) {
    for (const quorum of quorums) {
      const h = recomputeH(
        user.password,
        quorum.map((n) => toprfShareOf(n, user.username))
      );
      for (const node of nodes) {
        expect(bytesToHex(deriveServerKey(h, node.nodeId))).toBe(
          hOf(node, user.username)
        );
      }
    }
  }
}
