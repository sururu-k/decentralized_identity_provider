import { describe, expect, it } from "vitest";
import { deriveServerKey } from "../src/crypto/toprf.js";
import {
  DEFAULT_KEY_ID,
  DEFAULT_USERS,
  generateDealerOutput,
  outputFileNames,
} from "../src/dealer.js";
import { bytesToHex, hexToBytes, hexToScalar, scalarToHex } from "../src/hex.js";
import {
  checkDealerOutput,
  groupPublicKeyFrom,
  hOf,
  recomputeH,
  secretKeyShareOf,
  toprfShareOf,
} from "./verify.js";

describe("generateDealerOutput", () => {
  it("writes group metadata matching the requested parameters", () => {
    const { group, nodes } = generateDealerOutput();
    expect(group).toMatchObject({
      version: 1,
      threshold: 2,
      total: 3,
      keyId: DEFAULT_KEY_ID,
    });
    expect(group.groupPublicKey).toMatch(/^[0-9a-f]{64}$/);
    expect(nodes.map((n) => n.nodeId)).toEqual([1, 2, 3]);
    for (const node of nodes) {
      expect(node.version).toBe(1);
      expect(node.threshold).toBe(2);
      expect(node.total).toBe(3);
      expect(node.groupPublicKey).toBe(group.groupPublicKey);
      expect(node.secretKeyShare).toMatch(/^[0-9a-f]{64}$/);
      expect(node.users.map((u) => u.username)).toEqual(["alice", "bob"]);
      for (const user of node.users) {
        expect(user.toprfKeyShare.id).toBe(node.nodeId);
        expect(user.toprfKeyShare.value).toMatch(/^[0-9a-f]{64}$/);
        expect(user.h_i).toMatch(/^[0-9a-f]{64}$/);
      }
    }
  });

  it("never writes a password into the output", () => {
    const { group, nodes } = generateDealerOutput();
    const serialized = JSON.stringify({ group, nodes });
    for (const user of DEFAULT_USERS) {
      expect(serialized).not.toContain(user.password);
    }
  });

  // Completion conditions 1 and 2 (docs/container-split.md section 4), run over
  // every 2-of-3 quorum. The same checker runs against sample-output/.
  it("satisfies both completion conditions", () => {
    const { group, nodes } = generateDealerOutput();
    checkDealerOutput(group, nodes, DEFAULT_USERS);
  });

  it("does not reconstruct the group public key from a single share", () => {
    const { group, nodes } = generateDealerOutput();
    expect(groupPublicKeyFrom([secretKeyShareOf(nodes[0])])).not.toBe(
      group.groupPublicKey
    );
  });

  it("derives a different h for the wrong password", () => {
    const { nodes } = generateDealerOutput();
    const shares = [toprfShareOf(nodes[0], "alice"), toprfShareOf(nodes[1], "alice")];
    const h = recomputeH("wrong-password", shares);
    expect(bytesToHex(deriveServerKey(h, 1))).not.toBe(hOf(nodes[0], "alice"));
  });

  it("gives each user an independent TOPRF key", () => {
    const { nodes } = generateDealerOutput();
    const alice = [toprfShareOf(nodes[0], "alice"), toprfShareOf(nodes[1], "alice")];
    // bob's password against alice's key shares must not yield bob's h_i.
    const h = recomputeH(DEFAULT_USERS[1].password, alice);
    expect(bytesToHex(deriveServerKey(h, 1))).not.toBe(hOf(nodes[0], "bob"));
  });

  it("honours custom threshold, total, key id and users", () => {
    const { group, nodes } = generateDealerOutput({
      threshold: 3,
      total: 5,
      keyId: "custom-key",
      users: [{ username: "carol", password: "pw", sub: "usr_carol" }],
    });
    expect(group).toMatchObject({ threshold: 3, total: 5, keyId: "custom-key" });
    expect(nodes).toHaveLength(5);
    expect(nodes[4].users).toHaveLength(1);
    expect(nodes[4].users[0].sub).toBe("usr_carol");

    checkDealerOutput(group, nodes, [
      { username: "carol", password: "pw", sub: "usr_carol" },
    ]);
  });

  it("rejects an invalid threshold", () => {
    expect(() => generateDealerOutput({ threshold: 4, total: 3 })).toThrow(/threshold/);
    expect(() => generateDealerOutput({ threshold: 0, total: 3 })).toThrow(/threshold/);
  });

  // keyId becomes the JWKS `kid` the gateway publishes.
  it("rejects an empty key id", () => {
    expect(() => generateDealerOutput({ keyId: "" })).toThrow(/keyId/);
  });

  it("rejects a malformed user list", () => {
    expect(() =>
      generateDealerOutput({
        users: [
          { username: "a", password: "p", sub: "s1" },
          { username: "a", password: "p", sub: "s2" },
        ],
      })
    ).toThrow(/Duplicate username/);

    // Two accounts minting tokens for one subject is an identity bug.
    expect(() =>
      generateDealerOutput({
        users: [
          { username: "a", password: "p", sub: "s1" },
          { username: "b", password: "p", sub: "s1" },
        ],
      })
    ).toThrow(/Duplicate sub/);

    expect(() =>
      generateDealerOutput({ users: [{ username: "", password: "p", sub: "s" }] })
    ).toThrow(/username/);
    expect(() =>
      generateDealerOutput({ users: [{ username: "a", password: "p", sub: "" }] })
    ).toThrow(/sub/);
    expect(() => generateDealerOutput({ users: [] })).toThrow(/at least one user/i);
  });

  it("lists the file names it produces", () => {
    expect(outputFileNames(3)).toEqual([
      "group.json",
      "node-1.json",
      "node-2.json",
      "node-3.json",
    ]);
  });
});

describe("hex encoding", () => {
  it("zero pads scalars to 64 lowercase hex digits", () => {
    expect(scalarToHex(1n)).toBe("0".repeat(63) + "1");
    expect(scalarToHex(255n)).toMatch(/^0{62}ff$/);
    expect(hexToScalar(scalarToHex(123456789n))).toBe(123456789n);
  });

  it("round trips bytes", () => {
    const bytes = new Uint8Array([0, 1, 254, 255]);
    expect(bytesToHex(bytes)).toBe("0001feff");
    expect(Array.from(hexToBytes("0001feff"))).toEqual([0, 1, 254, 255]);
  });
});
