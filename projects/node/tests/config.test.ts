import { describe, expect, it } from "vitest";
import fs from "node:fs";
import {
  ConfigError,
  DEFAULT_ISSUER,
  DEFAULT_PORT,
  loadNodeConfig,
  parseNodeConfig,
  readIssuer,
  readPort,
} from "../src/config.js";
import { fixturePath, hexToBytes, readFixtureJson } from "./helpers/nodes.js";

const NODE_1 = readFixtureJson("node-1.json");
const GROUP = readFixtureJson("group.json");

function withNode1(mutate: (draft: any) => void): string {
  const draft = JSON.parse(JSON.stringify(NODE_1));
  mutate(draft);
  return JSON.stringify(draft);
}

describe("node config loading", () => {
  it("loads the dealer fixture for node 1", () => {
    const config = loadNodeConfig(fixturePath("node-1.json"));

    expect(config.version).toBe(1);
    expect(config.nodeId).toBe(1);
    expect(config.threshold).toBe(2);
    expect(config.total).toBe(3);
    expect(Array.from(config.groupPublicKey)).toEqual(
      Array.from(hexToBytes(GROUP.groupPublicKey))
    );
    expect(config.groupPublicKey).toHaveLength(32);
    expect(config.users.map((u) => u.username)).toEqual(["alice", "bob"]);
    expect(config.users[0].sub).toBe("usr_alice_12345");
    expect(config.users[0].toprfKeyShare.id).toBe(1);
    expect(config.users[0].h_i).toHaveLength(32);
  });

  it("restores scalars big-endian, not through the little-endian frost helper", () => {
    const config = loadNodeConfig(fixturePath("node-1.json"));

    expect(config.secretKeyShare).toBe(BigInt("0x" + NODE_1.secretKeyShare));
    expect(config.users[0].toprfKeyShare.value).toBe(
      BigInt("0x" + NODE_1.users[0].toprfKeyShare.value)
    );

    // A scalar whose hex ends in 01 is the number 1 when read big-endian, and a huge
    // number when read little-endian. This pins the byte order down.
    const oneBigEndian = withNode1((d) => {
      d.secretKeyShare = "00".repeat(31) + "01";
    });
    expect(parseNodeConfig(oneBigEndian, "test").secretKeyShare).toBe(1n);
  });

  it("agrees on the group public key across all three node files", () => {
    const keys = ["node-1.json", "node-2.json", "node-3.json"].map((f) =>
      Buffer.from(loadNodeConfig(fixturePath(f)).groupPublicKey).toString("hex")
    );
    expect(new Set(keys).size).toBe(1);
    expect(keys[0]).toBe(GROUP.groupPublicKey);
  });

  it("gives every node the share carrying its own id", () => {
    for (const [id, file] of [
      [1, "node-1.json"],
      [2, "node-2.json"],
      [3, "node-3.json"],
    ] as const) {
      const config = loadNodeConfig(fixturePath(file));
      expect(config.nodeId).toBe(id);
      for (const user of config.users) {
        expect(user.toprfKeyShare.id).toBe(id);
      }
    }
  });

  it("rejects an unsupported version", () => {
    const text = withNode1((d) => {
      d.version = 2;
    });
    expect(() => parseNodeConfig(text, "test")).toThrowError(ConfigError);
    expect(() => parseNodeConfig(text, "test")).toThrowError(/unsupported version 2/);
  });

  it("rejects a missing version", () => {
    const text = withNode1((d) => {
      delete d.version;
    });
    expect(() => parseNodeConfig(text, "test")).toThrowError(/version must be an integer/);
  });

  it("rejects malformed hex", () => {
    const nonHex = withNode1((d) => {
      d.secretKeyShare = "z".repeat(64);
    });
    expect(() => parseNodeConfig(nonHex, "test")).toThrowError(/secretKeyShare is not a hex string/);

    const shortScalar = withNode1((d) => {
      d.secretKeyShare = "00ff";
    });
    expect(() => parseNodeConfig(shortScalar, "test")).toThrowError(
      /secretKeyShare must be 64 hex digits/
    );

    const shortKey = withNode1((d) => {
      d.groupPublicKey = "00ff";
    });
    expect(() => parseNodeConfig(shortKey, "test")).toThrowError(
      /groupPublicKey must be 64 hex digits/
    );

    const badHi = withNode1((d) => {
      d.users[1].h_i = "abc";
    });
    expect(() => parseNodeConfig(badHi, "test")).toThrowError(/users\[1\]\.h_i/);
  });

  it("rejects a toprfKeyShare id that does not match nodeId", () => {
    const text = withNode1((d) => {
      d.users[0].toprfKeyShare.id = 2;
    });
    expect(() => parseNodeConfig(text, "test")).toThrowError(
      /users\[0\]\.toprfKeyShare\.id is 2 but this file is for node 1/
    );
  });

  it("rejects an inconsistent threshold, total or nodeId", () => {
    expect(() =>
      parseNodeConfig(
        withNode1((d) => {
          d.threshold = 4;
        }),
        "test"
      )
    ).toThrowError(/1 <= threshold <= total/);

    expect(() =>
      parseNodeConfig(
        withNode1((d) => {
          d.nodeId = 9;
        }),
        "test"
      )
    ).toThrowError(/nodeId 9 is larger than total 3/);
  });

  it("rejects duplicate usernames", () => {
    const text = withNode1((d) => {
      d.users[1].username = "alice";
    });
    expect(() => parseNodeConfig(text, "test")).toThrowError(/duplicate username "alice"/);
  });

  it("rejects text that is not JSON", () => {
    expect(() => parseNodeConfig("not json", "test")).toThrowError(/not valid JSON/);
  });

  it("reports a missing file clearly", () => {
    const missing = fixturePath("node-99.json");
    expect(fs.existsSync(missing)).toBe(false);
    expect(() => loadNodeConfig(missing)).toThrowError(ConfigError);
    expect(() => loadNodeConfig(missing)).toThrowError(/file not found/);
  });
});

describe("PORT parsing", () => {
  it("falls back to the default when PORT is unset or empty", () => {
    expect(readPort(undefined)).toBe(DEFAULT_PORT);
    expect(readPort("")).toBe(DEFAULT_PORT);
  });

  it("accepts a plain decimal port", () => {
    expect(readPort("4001")).toBe(4001);
    expect(readPort("1")).toBe(1);
    expect(readPort("65535")).toBe(65535);
  });

  it("refuses values Number() would silently accept", () => {
    // " " -> 0 and "1e3" -> 1000 used to start a server on a port nobody asked for.
    for (const raw of [" ", " 4001", "4001 ", "1e3", "0x10", "40.5", "-1", "abc", "+4001"]) {
      expect(() => readPort(raw), `PORT=${JSON.stringify(raw)}`).toThrowError(ConfigError);
    }
  });

  it("refuses port 0, which would bind an unguessable ephemeral port", () => {
    expect(() => readPort("0")).toThrowError(/1\.\.65535/);
  });

  it("refuses a port above the 16 bit range", () => {
    expect(() => readPort("65536")).toThrowError(/1\.\.65535/);
  });
});

describe("ISSUER", () => {
  it("defaults when unset or empty", () => {
    expect(readIssuer(undefined)).toBe(DEFAULT_ISSUER);
    expect(readIssuer("")).toBe(DEFAULT_ISSUER);
  });

  it("keeps an absolute http or https origin and trims a trailing slash", () => {
    expect(readIssuer("http://localhost:3000")).toBe("http://localhost:3000");
    expect(readIssuer("http://localhost:3000/")).toBe("http://localhost:3000");
    expect(readIssuer("https://idp.example.com/pasta")).toBe("https://idp.example.com/pasta");
  });

  it("refuses anything that is not a usable issuer URL", () => {
    for (const raw of ["localhost:3000", "/relative", "ftp://host", "http://h/?a=b", "http://h/#f"]) {
      expect(() => readIssuer(raw), `ISSUER=${JSON.stringify(raw)}`).toThrowError(ConfigError);
    }
  });
});
