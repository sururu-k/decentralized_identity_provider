import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import crypto from "node:crypto";
import {
  CONTINUATION_INDENT,
  NEVER_HELD,
  VALUE_PREFIX_LENGTH,
  colorEnabled,
  createDemoLog,
  demoLogEnabled,
  shortValue,
} from "../src/demolog.js";
import {
  RunningNode,
  postJson,
  readFixtureJson,
  startNodeFromFixture,
  stopAll,
} from "./helpers/nodes.js";
import { signOnOverHttp, signOverHttp } from "./helpers/client.js";

/**
 * The demo log of docs/container-split.md section 10: the shape of the lines, the switches
 * that turn them on and off, and -- the point of the whole exercise -- that a node's own
 * secrets never appear in them.
 */

/** Collects lines instead of printing them. */
function capture(): { lines: string[]; write: (line: string) => void } {
  const lines: string[] = [];
  return { lines, write: (line) => lines.push(line) };
}

describe("demo log switches", () => {
  it("is on by default and off with DEMO_LOG=0", () => {
    expect(demoLogEnabled({})).toBe(true);
    expect(demoLogEnabled({ DEMO_LOG: "1" })).toBe(true);
    expect(demoLogEnabled({ DEMO_LOG: "0" })).toBe(false);
  });

  it("writes nothing at all when disabled", () => {
    const sink = capture();
    const log = createDemoLog({
      nodeId: 1,
      total: 3,
      env: { DEMO_LOG: "0" },
      isTty: true,
      write: sink.write,
    });
    log.startup({ threshold: 2, total: 3, usernames: ["alice"] });
    log.commit({ roundId: "r", D: "DDDDDDDDDD", E: "EEEEEEEEEE" });
    log.reject("sign-on", "boom");
    expect(log.enabled).toBe(false);
    expect(sink.lines).toEqual([]);
  });

  it("colours on a TTY or with FORCE_COLOR, never with NO_COLOR", () => {
    expect(colorEnabled({}, true)).toBe(true);
    expect(colorEnabled({}, false)).toBe(false);
    expect(colorEnabled({ FORCE_COLOR: "1" }, false)).toBe(true);
    expect(colorEnabled({ FORCE_COLOR: "0" }, true)).toBe(false);
    expect(colorEnabled({ NO_COLOR: "1" }, true)).toBe(false);
    expect(colorEnabled({ NO_COLOR: "1", FORCE_COLOR: "1" }, true)).toBe(false);
  });

  it("emits ANSI escapes only when colour is on", () => {
    const plain = capture();
    createDemoLog({ nodeId: 1, total: 3, env: {}, isTty: false, write: plain.write }).commit({
      roundId: "round-1",
      D: "AAAAAAAAAA",
      E: "BBBBBBBBBB",
    });
    expect(plain.lines.every((l) => !l.includes("\x1b["))).toBe(true);
    expect(plain.lines[0]).toBe("[node1]   commit    round=round-1  → D_1,E_1 AAAAAAAA BBBBBBBB");

    const colored = capture();
    createDemoLog({
      nodeId: 1,
      total: 3,
      env: { FORCE_COLOR: "1" },
      isTty: false,
      write: colored.write,
    }).commit({ roundId: "round-1", D: "AAAAAAAAAA", E: "BBBBBBBBBB" });
    expect(colored.lines.every((l) => l.includes("\x1b[") && l.endsWith("\x1b[0m"))).toBe(true);
    // Same text underneath: colour only wraps it.
    expect(colored.lines.map((l) => l.replaceAll(/\x1b\[[0-9;]*m/g, ""))).toEqual(plain.lines);
  });

  it("shades the blue by node id", () => {
    const shades = [1, 2, 3].map((nodeId) => {
      const sink = capture();
      createDemoLog({
        nodeId,
        total: 3,
        env: { FORCE_COLOR: "1" },
        isTty: false,
        write: sink.write,
      }).reject("sign-on", "no");
      return /\x1b\[38;5;(\d+)m/.exec(sink.lines[0])?.[1];
    });
    expect(new Set(shades).size).toBe(3);
    expect(shades.every((s) => s !== undefined)).toBe(true);
  });
});

describe("demo log values", () => {
  it("cuts a value to its first 8 characters, with no ellipsis", () => {
    expect(shortValue("k5Qx8vL2abcdef")).toBe("k5Qx8vL2");
    expect(shortValue("k5Qx8vL2abcdef")).toHaveLength(VALUE_PREFIX_LENGTH);
    expect(shortValue("short")).toBe("short");
    expect(shortValue("")).toBe("-");
    expect(shortValue(undefined)).toBe("-");
  });

  it("truncates every value it prints", () => {
    const sink = capture();
    const log = createDemoLog({ nodeId: 2, total: 3, env: {}, isTty: false, write: sink.write });
    const long = "0123456789abcdefghij";
    log.signOn({
      roundId: long,
      sessionId: long,
      username: "alice",
      blinded: long,
      sessionNonce: long,
      cnfJkt: long,
      participants: 3,
      toprfPartial: long,
      ct: long,
    });
    for (const line of sink.lines) {
      expect(line).not.toContain(long);
    }
    expect(sink.lines.join("\n")).toContain("01234567");
    expect(sink.lines.join("\n")).not.toContain("…");
  });

  it("prints a sign-on as one line plus one aligned continuation", () => {
    const sink = capture();
    const log = createDemoLog({ nodeId: 2, total: 3, env: {}, isTty: false, write: sink.write });
    log.signOn({
      roundId: "7be1",
      sessionId: "3f9a12c0",
      username: "alice",
      blinded: "k5Qx8vL2xxxx",
      sessionNonce: "nonce1234567",
      cnfJkt: "jkt1234567",
      participants: 3,
      toprfPartial: "9mZpQw3exxx",
      ct: "Qw3eRt5yxxx",
    });
    expect(sink.lines).toEqual([
      "[node2]   sign-on   sess=3f9a12c0 round=7be1 user=alice  ← A k5Qx8vL2  (D,E)×3  " +
        "nonce_s nonce123  jkt jkt12345",
      `${CONTINUATION_INDENT}→ B_2=k_2·A 9mZpQw3e  ct_2=AEAD_h2(z_2) Qw3eRt5y`,
    ]);
    // The continuation starts exactly under the first line's event column.
    expect(CONTINUATION_INDENT).toHaveLength("[node2]   sign-on   ".length);
  });

  it("never prints the value of z_i, only the ciphertext it went into", () => {
    const sink = capture();
    const log = createDemoLog({ nodeId: 1, total: 3, env: {}, isTty: false, write: sink.write });
    log.signOn({
      roundId: "r",
      sessionId: "s",
      username: "alice",
      blinded: "b",
      sessionNonce: "n",
      cnfJkt: "j",
      participants: 3,
      toprfPartial: "p",
      ct: "c",
    });
    expect(sink.lines[1]).toContain("ct_1=AEAD_h1(z_1) c");
    expect(sink.lines.join("\n")).not.toMatch(/z_1 [0-9a-zA-Z_-]/);
  });

  it("states never: on the startup line only, never on a later event", () => {
    const sink = capture();
    const log = createDemoLog({ nodeId: 3, total: 3, env: {}, isTty: false, write: sink.write });
    log.startup({ threshold: 2, total: 3, usernames: ["alice", "bob"] });
    log.signOn({
      roundId: "r1",
      sessionId: "s1",
      username: "alice",
      blinded: "b1",
      sessionNonce: "n1",
      cnfJkt: "j1",
      participants: 3,
      toprfPartial: "p1",
      ct: "c1",
    });
    log.commit({ roundId: "r2", D: "d2", E: "e2" });
    log.sign({
      roundId: "r3",
      grant: "authorization_code",
      signature: "sig12345678",
      jti: "jti12345678",
      participants: 3,
      atZ: "at_value_123",
      rtZ: "rt_value_123",
    });

    const never = sink.lines.filter((l) => l.includes("never:"));
    expect(never).toHaveLength(1);
    expect(never[0]).toContain(`never: ${NEVER_HELD}`);
    expect(sink.lines[0]).toBe(never[0]);
  });

  it("prints the startup, commit and sign events in the contract's shape", () => {
    const sink = capture();
    const log = createDemoLog({ nodeId: 1, total: 3, env: {}, isTty: false, write: sink.write });

    log.startup({ threshold: 2, total: 3, usernames: ["alice", "bob"] });
    expect(sink.lines).toEqual([
      "[node1]   ● up      id=1 t=2/3 users=alice,bob   holds: s_1, k_1, h_1(alice,bob)   " +
        `never: ${NEVER_HELD}`,
    ]);

    sink.lines.length = 0;
    log.commit({ roundId: "7be1abcd90", D: "DDDDDDDDDD", E: "EEEEEEEEEE" });
    expect(sink.lines).toEqual([
      "[node1]   commit    round=7be1abcd  → D_1,E_1 DDDDDDDD EEEEEEEE",
    ]);

    sink.lines.length = 0;
    log.sign({
      roundId: "8837fc27aa",
      grant: "authorization_code",
      signature: "SiGnAtUrExx",
      jti: "JtIvAlUexx",
      participants: 3,
      atZ: "0a1b2c3d4e5f",
      rtZ: "9f8e7d6c5b4a",
    });
    expect(sink.lines).toEqual([
      "[node1]   sign      round=8837fc27 grant=authz  ← assertion σ SiGnAtUr ✓  " +
        "DPoP ✓ jti JtIvAlUe  (D,E)×3  → at z_1 0a1b2c3d + rt(refresh+jwt) z_1 9f8e7d6c",
    ]);

    sink.lines.length = 0;
    log.sign({
      roundId: "8837fc27aa",
      grant: "refresh_token",
      signature: "SiGnAtUrExx",
      jti: "JtIvAlUexx",
      participants: 3,
      atZ: "0a1b2c3d4e5f",
      rtZ: "9f8e7d6c5b4a",
    });
    expect(sink.lines).toEqual([
      "[node1]   sign      round=8837fc27 grant=refresh  ← refresh_token σ SiGnAtUr ✓ " +
        "(typ=refresh+jwt)  DPoP ✓ jti JtIvAlUe  (D,E)×3  " +
        "→ at z_1 0a1b2c3d + rt z_1 9f8e7d6c",
    ]);
  });

  it("prints a refusal as one ✖ line carrying the reason verbatim", () => {
    const sink = capture();
    const log = createDemoLog({ nodeId: 2, total: 3, env: {}, isTty: false, write: sink.write });
    log.reject("sign-on", "Round abc expired or not found on node 2");
    expect(sink.lines).toEqual([
      "[node2]   ✖ sign-on rejected: Round abc expired or not found on node 2",
    ]);
  });
});

describe("demo log over HTTP", () => {
  const ISSUER = "http://localhost:3000";
  const CLIENT_ID = "demo_client";
  const NODE_1 = readFixtureJson("node-1.json");

  let nodes: RunningNode[];
  let logged: string[];
  let spy: ReturnType<typeof vi.spyOn>;

  beforeAll(async () => {
    // Only node 1 traces, so the assertions below can attribute every line to it. Its log
    // goes through the real `console.log` default, exactly as in the container.
    nodes = [
      await startNodeFromFixture(
        "node-1.json",
        createDemoLog({ nodeId: 1, total: 3, env: {}, isTty: false })
      ),
      await startNodeFromFixture("node-2.json"),
      await startNodeFromFixture("node-3.json"),
    ];
  });

  afterAll(async () => {
    await stopAll(nodes);
  });

  afterEach(() => {
    spy?.mockRestore();
  });

  function spyOnConsole(): void {
    logged = [];
    spy = vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      logged.push(args.join(" "));
    });
  }

  it("traces a real sign-on without leaking anything the node holds", async () => {
    spyOnConsole();
    const session = await signOnOverHttp({
      nodes,
      username: "alice",
      password: "password123",
      clientId: CLIENT_ID,
      issuer: ISSUER,
      nonce: "n1",
    });
    spy.mockRestore();

    expect(session.assertion.split(".")).toHaveLength(3);

    const heading = logged.findIndex((l) => l.startsWith("[node1]   sign-on   sess="));
    expect(heading).toBeGreaterThanOrEqual(0);
    const event = logged.slice(heading, heading + 2);
    expect(event[0]).toContain("← A ");
    expect(event[0]).toContain("(D,E)×3");
    expect(event[0]).toContain("user=alice");
    expect(event[1]).toContain(`${CONTINUATION_INDENT}→ B_1=k_1·A `);
    expect(event[1]).toContain("ct_1=AEAD_h1(z_1)");

    // The commit event of round 1 is there too, and node 2 and 3 stay silent.
    expect(logged.some((l) => l.startsWith("[node1]   commit  "))).toBe(true);
    expect(logged.some((l) => l.startsWith("[node2]") || l.startsWith("[node3]"))).toBe(false);

    const all = logged.join("\n");
    expect(all).not.toContain("password123");
    expect(all).not.toContain(NODE_1.secretKeyShare);
    expect(all).not.toContain(NODE_1.users[0].toprfKeyShare.value);
    expect(all).not.toContain(NODE_1.users[0].h_i);
    // Not even a prefix of a long-term secret.
    expect(all).not.toContain(NODE_1.secretKeyShare.slice(0, 8));
    expect(all).not.toContain(NODE_1.users[0].h_i.slice(0, 8));
  });

  it("traces a refusal from the node with the reason it gave the caller", async () => {
    spyOnConsole();
    const res = await postJson(nodes[0].url, "/sign-on", {
      roundId: crypto.randomUUID(),
      request: {
        sessionId: "s",
        username: "alice",
        blinded: "AAAA",
        sessionNonce: "AAAA",
        cnfJkt: "jkt",
        clientId: CLIENT_ID,
        scope: "openid",
        nonce: "c",
        iat: 1,
        exp: 2,
        iss: ISSUER,
        commitments: [],
        allParticipants: [1],
      },
    });
    spy.mockRestore();

    expect(res.status).toBe(400);
    const line = logged.find((l) => l.includes("✖"));
    expect(line).toBe(`[node1]   ✖ sign-on rejected: ${res.body.error}`);
    expect(line).toContain("commitments contains no entry for node 1");
  });

  it("traces sign, without the assembled access token", async () => {
    const session = await signOnOverHttp({
      nodes,
      username: "alice",
      password: "password123",
      clientId: CLIENT_ID,
      issuer: ISSUER,
      nonce: "c-demolog",
    });

    spyOnConsole();
    const { access_token, refresh_token } = await signOverHttp({ nodes, session });
    spy.mockRestore();

    const sign = logged.find((l) => l.startsWith("[node1]   sign      "));
    expect(sign).toContain("grant=authz");
    expect(sign).toContain("← assertion σ ");
    expect(sign).toContain("DPoP ✓ jti ");
    expect(sign).toContain("(D,E)×3");
    expect(sign).toContain("→ at z_1 ");
    expect(sign).toContain("+ rt(refresh+jwt) z_1 ");

    // The node never sees an assembled token, and never prints a whole value.
    const all = logged.join("\n");
    expect(all).not.toContain(access_token);
    expect(all).not.toContain(refresh_token);
    expect(all).not.toContain(session.assertion);
    expect(all).not.toContain("password123");
  });
});
