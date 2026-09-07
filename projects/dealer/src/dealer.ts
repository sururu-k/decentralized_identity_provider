import { generateShamirShares, randomScalar } from "./crypto/frost.js";
import {
  blind,
  deriveServerKey,
  evaluate,
  finalize,
  generateToprfKey,
  unblind,
} from "./crypto/toprf.js";
import { bytesToHex, scalarToHex } from "./hex.js";

/** A user the dealer pre-registers with every node. */
export interface UserSpec {
  username: string;
  password: string;
  sub: string;
}

/** Default users, per docs/container-split.md section 4. */
export const DEFAULT_USERS: UserSpec[] = [
  { username: "alice", password: "password123", sub: "usr_alice_12345" },
  { username: "bob", password: "password456", sub: "usr_bob_67890" },
];

export const DEFAULT_KEY_ID = "pasta-group-key-1";
export const DEFAULT_THRESHOLD = 2;
export const DEFAULT_TOTAL = 3;

/** File format version of every file the dealer writes. */
export const OUTPUT_VERSION = 1;

export interface DealerOptions {
  threshold?: number;
  total?: number;
  keyId?: string;
  users?: UserSpec[];
}

/** `<out>/group.json`, read by gateway and rp. */
export interface GroupFile {
  version: number;
  threshold: number;
  total: number;
  keyId: string;
  groupPublicKey: string;
}

/** One pre-registered user inside a node file. */
export interface NodeUserRecord {
  username: string;
  sub: string;
  toprfKeyShare: { id: number; value: string };
  h_i: string;
}

/** `<out>/node-<id>.json`, read by the node with that id. */
export interface NodeFile {
  version: number;
  nodeId: number;
  threshold: number;
  total: number;
  groupPublicKey: string;
  secretKeyShare: string;
  users: NodeUserRecord[];
}

export interface DealerOutput {
  group: GroupFile;
  nodes: NodeFile[];
}

/**
 * Generates the full set of dealer output files.
 *
 * 1. A FROST master secret is split with Shamir (t-of-n); the group public key
 *    is the Ed25519 point for that secret.
 * 2. Every user gets an independent TOPRF key, split the same way. The master
 *    PRF value h is derived exactly as `registerUserToNodes` does in
 *    `src/protocol/node.ts`, and node i stores `deriveServerKey(h, i)`.
 *
 * Passwords are used only to derive h and never appear in the returned data.
 */
export function generateDealerOutput(options: DealerOptions = {}): DealerOutput {
  const threshold = options.threshold ?? DEFAULT_THRESHOLD;
  const total = options.total ?? DEFAULT_TOTAL;
  const keyId = options.keyId ?? DEFAULT_KEY_ID;
  const users = options.users ?? DEFAULT_USERS;

  if (!Number.isInteger(threshold) || !Number.isInteger(total)) {
    throw new Error("threshold and total must be integers");
  }
  if (total < 1) {
    throw new Error(`total must be at least 1, got ${total}`);
  }
  if (threshold < 1 || threshold > total) {
    throw new Error(
      `Invalid threshold: must satisfy 1 <= threshold (${threshold}) <= total (${total})`
    );
  }
  // The gateway publishes keyId as the JWKS `kid`, so an empty one would ship a
  // key nobody can select.
  if (keyId.length === 0) {
    throw new Error("keyId must not be empty");
  }
  if (users.length === 0) {
    throw new Error("At least one user is required");
  }
  const names = new Set<string>();
  const subs = new Set<string>();
  for (const user of users) {
    if (user.username.length === 0) {
      throw new Error("username must not be empty");
    }
    if (user.sub.length === 0) {
      throw new Error(`sub must not be empty (user ${user.username})`);
    }
    if (names.has(user.username)) {
      throw new Error(`Duplicate username: ${user.username}`);
    }
    // Two usernames sharing a sub would mint tokens for one identity from two
    // accounts, so the dealer refuses it here rather than at the nodes.
    if (subs.has(user.sub)) {
      throw new Error(`Duplicate sub: ${user.sub}`);
    }
    names.add(user.username);
    subs.add(user.sub);
  }

  // 1. FROST group key.
  const masterSecret = randomScalar();
  const { groupPublicKey, shares } = generateShamirShares(masterSecret, threshold, total);
  const groupPublicKeyHex = bytesToHex(groupPublicKey);

  // 2. Per-user TOPRF material, one record per node.
  const recordsByNode = new Map<number, NodeUserRecord[]>();
  for (let id = 1; id <= total; id++) {
    recordsByNode.set(id, []);
  }

  for (const user of users) {
    const toprfKeyShares = generateToprfKey(total, threshold);

    // Reproduce the client-side derivation of h from `registerUserToNodes`.
    const { blinding, blinded } = blind(user.password);
    const partials = toprfKeyShares.slice(0, threshold).map((s) => ({
      id: s.id,
      point: evaluate(s, blinded),
    }));
    const v = unblind(blinding, partials);
    const h = finalize(user.password, v);

    for (let id = 1; id <= total; id++) {
      const keyShare = toprfKeyShares[id - 1];
      recordsByNode.get(id)!.push({
        username: user.username,
        sub: user.sub,
        toprfKeyShare: { id: keyShare.id, value: scalarToHex(keyShare.value) },
        h_i: bytesToHex(deriveServerKey(h, id)),
      });
    }
  }

  const group: GroupFile = {
    version: OUTPUT_VERSION,
    threshold,
    total,
    keyId,
    groupPublicKey: groupPublicKeyHex,
  };

  const nodes: NodeFile[] = [];
  for (let id = 1; id <= total; id++) {
    const share = shares.get(id);
    if (share === undefined) {
      throw new Error(`Missing Shamir share for node ${id}`);
    }
    nodes.push({
      version: OUTPUT_VERSION,
      nodeId: id,
      threshold,
      total,
      groupPublicKey: groupPublicKeyHex,
      secretKeyShare: scalarToHex(share),
      users: recordsByNode.get(id)!,
    });
  }

  return { group, nodes };
}

/** File name a node file gets for the given node id. */
export function nodeFileName(nodeId: number): string {
  return `node-${nodeId}.json`;
}

/** Every file name `generateDealerOutput` produces for the given node count. */
export function outputFileNames(total: number): string[] {
  const names = ["group.json"];
  for (let id = 1; id <= total; id++) {
    names.push(nodeFileName(id));
  }
  return names;
}
