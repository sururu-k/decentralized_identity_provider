import { describe, expect, it } from "vitest";
import {
  CONTINUATION_INDENT,
  NEVER_HELD,
  VALUE_PREFIX_LENGTH,
  colorEnabled,
  createDemoLog,
  demoLogEnabled,
  shortId,
  shortValue,
  type DemoLogEnv,
} from "../src/demolog.js";

/**
 * Unit tests for the gateway's demo log (`docs/container-split.md` section 10).
 *
 * Three things matter here and are asserted directly rather than through the server:
 * the switch (`DEMO_LOG`), the colour precedence, and the exact text. The text is the
 * point of the whole feature -- an audience reads the node, gateway, rp and browser
 * columns side by side -- so the column widths and the `never:` line are compared
 * literally.
 */

/** Collects lines instead of printing them. */
function capture(env: DemoLogEnv = {}, isTty = false) {
  const lines: string[] = [];
  const log = createDemoLog({ env, isTty, write: (line) => lines.push(line) });
  return { log, lines };
}

const SIGN_ON = {
  sessionId: "2b4e8c32-1111-4222-8333-444455556666",
  roundId: "c1b3762a-7777-4888-8999-aaaabbbbcccc",
  participants: [1, 2, 3],
  blinded: "1u0pm07KabcdefghXYZ",
  cnfJkt: "vfiOlS-Fabcdefgh",
  username: "alice",
  nonce: "gw-demolog-1",
  excluded: [],
};

/** A real RFC 7638 thumbprint: SHA-256, base64url, 43 characters (section 13). */
const RP_JKT = "b0JFnFHOoQOqFk3sGvEnW6tC8VOBT9NIXtYjIrhAHTA";

describe("DEMO_LOG", () => {
  it("is on unless the value is exactly 0", () => {
    expect(demoLogEnabled({})).toBe(true);
    expect(demoLogEnabled({ DEMO_LOG: "1" })).toBe(true);
    expect(demoLogEnabled({ DEMO_LOG: "" })).toBe(true);
    expect(demoLogEnabled({ DEMO_LOG: "yes" })).toBe(true);
    expect(demoLogEnabled({ DEMO_LOG: "0" })).toBe(false);
  });

  it("silences every event when off, while keeping the same shape", () => {
    const { log, lines } = capture({ DEMO_LOG: "0" });
    expect(log.enabled).toBe(false);

    log.startup({
      issuer: "http://localhost:3000",
      threshold: 2,
      total: 3,
      keyId: "pasta-group-key-1",
      nodeUrls: ["http://node1:4001"],
    });
    log.authorize({
      clientId: "demo_client",
      redirectUri: "http://rp/cb",
      nonce: "n",
      state: "s",
      dpopJkt: RP_JKT,
    });
    log.signOn(SIGN_ON);
    log.refresh({
      sessionId: SIGN_ON.sessionId,
      roundId: SIGN_ON.roundId,
      participants: [1, 2],
      dpopProof: "eyJhbGciOi",
      excluded: [],
    });
    log.jwks();
    log.discovery();
    log.demoRpCallback({ idToken: "eyJhbGciOi", verified: true });
    log.reject("sign-on", "nope");

    expect(lines).toEqual([]);
  });
});

describe("colour precedence", () => {
  it("follows NO_COLOR, then FORCE_COLOR=0, then FORCE_COLOR, then the TTY", () => {
    // NO_COLOR wins over everything, including an explicit FORCE_COLOR=1.
    expect(colorEnabled({ NO_COLOR: "1", FORCE_COLOR: "1" }, true)).toBe(false);
    // FORCE_COLOR=0 is the documented way to turn colour off for the demo, because
    // NO_COLOR makes Node itself print a warning.
    expect(colorEnabled({ FORCE_COLOR: "0" }, true)).toBe(false);
    // A set FORCE_COLOR beats the TTY check, which is what makes the image's
    // `ENV FORCE_COLOR=1` work under `docker compose logs` (never a TTY).
    expect(colorEnabled({ FORCE_COLOR: "1" }, false)).toBe(true);
    expect(colorEnabled({}, true)).toBe(true);
    expect(colorEnabled({}, false)).toBe(false);
    // An empty NO_COLOR is not "set" for this purpose; an empty FORCE_COLOR falls through.
    expect(colorEnabled({ NO_COLOR: "" }, true)).toBe(true);
    expect(colorEnabled({ FORCE_COLOR: "" }, false)).toBe(false);
  });

  it("wraps gateway lines in magenta and nothing else", () => {
    const { log, lines } = capture({ FORCE_COLOR: "1" }, false);
    log.jwks();
    log.signOn(SIGN_ON);

    // Magenta (35) for the continuation, bold magenta for an event's first line.
    expect(lines[0]).toBe("\x1b[1m\x1b[35m[gateway] jwks      public only\x1b[0m");
    expect(lines[2].startsWith(`\x1b[35m${CONTINUATION_INDENT}round1 `)).toBe(true);
    for (const line of lines) {
      expect(line.endsWith("\x1b[0m")).toBe(true);
    }
  });

  it("emits no escape sequences at all when colour is off", () => {
    const { log, lines } = capture({ FORCE_COLOR: "0" }, true);
    log.signOn(SIGN_ON);
    expect(lines.join("\n")).not.toContain("\x1b[");
  });
});

describe("truncation", () => {
  it("shows the first 8 characters and no ellipsis", () => {
    expect(VALUE_PREFIX_LENGTH).toBe(8);
    expect(shortValue("1u0pm07KabcdefXYZ")).toBe("1u0pm07K");
    expect(shortValue("12345678")).toBe("12345678");
    expect(shortValue("1234567")).toBe("1234567");
    expect(shortValue("")).toBe("-");
    expect(shortValue(undefined)).toBe("-");
  });

  it("cuts session and round ids the same way", () => {
    expect(shortId("2b4e8c32-1111-4222")).toBe("2b4e8c32");
    expect(shortId("abc")).toBe("abc");
    expect(shortId(undefined)).toBe("-");
  });
});

describe("event wording", () => {
  it("states holds: and never: on the startup line, and only there", () => {
    const { log, lines } = capture();
    log.startup({
      issuer: "http://localhost:3000",
      threshold: 2,
      total: 3,
      keyId: "pasta-group-key-1",
      nodeUrls: ["http://node1:4001", "http://node2:4002", "http://node3:4003"],
    });
    log.signOn(SIGN_ON);

    expect(lines[0]).toBe(
      "[gateway] ● up      t=2/3 nodes=3 issuer=http://localhost:3000   " +
        `holds: group pubkey, kid=pasta-group-key-1   never: ${NEVER_HELD}`
    );
    expect(lines.filter((l) => l.includes("never:"))).toHaveLength(1);
  });

  it("prints a sign-on as one line plus one aligned continuation", () => {
    const { log, lines } = capture();
    log.signOn(SIGN_ON);

    expect(lines).toEqual([
      "[gateway] sign-on   sess=2b4e8c32 round=c1b3762a user=alice nonce=gw-demolog-1  " +
        "← A 1u0pm07K  jkt vfiOlS-F  (no pw)",
      `${CONTINUATION_INDENT}round1 (D,E)×3 → round2 ← B_i×3 ct_i×3 ` +
        "(no h_i, cannot decrypt) → relayed as-is",
    ]);
    expect(CONTINUATION_INDENT).toHaveLength("[gateway] sign-on   ".length);
  });

  it("names every dropped node on the round1 line and counts only the survivors", () => {
    const { log, lines } = capture();
    log.signOn({
      ...SIGN_ON,
      participants: [1, 2],
      excluded: [{ nodeId: 3, reason: "Node 3 at http://node3:4003/commit unreachable" }],
    });

    expect(lines[1]).toContain("round1 (D,E)×2 (node3 unreachable, excluded) → round2");
    expect(lines[1]).toContain("B_i×2");
    expect(lines[1]).toContain("ct_i×2");
    // The reason text stays out of the line: it names hosts and ports, which the audience
    // does not need and which would push the line off screen.
    expect(lines.join("\n")).not.toContain("http://node3:4003/commit");
  });

  it("prints a refresh on one line", () => {
    const { log, lines } = capture();
    log.refresh({
      sessionId: SIGN_ON.sessionId,
      roundId: SIGN_ON.roundId,
      participants: [1, 2],
      dpopProof: "eyJhbGciOiJFZERTQSJ9.abc",
      excluded: [],
    });

    expect(lines).toEqual([
      "[gateway] refresh   sess=2b4e8c32 round=c1b3762a  ← DPoP eyJhbGci (verified by nodes)  " +
        "→ ct_i×2 relayed",
    ]);
  });

  it("prints authorize, the public endpoints and the demo callback", () => {
    const { log, lines } = capture();
    log.authorize({
      clientId: "demo_client",
      redirectUri: "http://localhost:3001/callback",
      nonce: "n-abcdefghijkl",
      state: "st-1",
      dpopJkt: RP_JKT,
    });
    log.jwks();
    log.discovery();
    log.demoRpCallback({ idToken: "eyJhbGciOiJFZERTQSJ9.e30.AAAA", verified: false });

    expect(lines).toEqual([
      "[gateway] authorize client_id=demo_client nonce=n-abcdefghijkl state=st-1 " +
        `dpop_jkt=${RP_JKT.slice(0, 8)}  → redirect /demo`,
      "[gateway] jwks      public only",
      "[gateway] discovery public only",
      "[gateway] rp-demo   ← id_token eyJhbGci  → Ed25519 ✗  (demo-only callback page)",
    ]);
  });

  it("shows a missing state as - rather than as an empty field", () => {
    const { log, lines } = capture();
    log.authorize({
      clientId: "c",
      redirectUri: "http://rp/cb",
      nonce: "n",
      state: undefined,
      dpopJkt: RP_JKT,
    });
    expect(lines[0]).toContain("state=-");
  });

  it("cuts dpop_jkt to eight characters like every other cryptographic value", () => {
    const { log, lines } = capture();
    log.authorize({
      clientId: "c",
      redirectUri: "http://rp/cb",
      nonce: "n",
      state: "s",
      dpopJkt: RP_JKT,
    });
    expect(lines[0]).toContain(`dpop_jkt=${RP_JKT.slice(0, 8)}`);
    expect(lines[0]).not.toContain(RP_JKT);
  });

  it("prints a refusal as one ✖ line", () => {
    const { log, lines } = capture();
    log.reject("sign-on", "quorum 1 < 2 (node2, node3 unreachable)");

    expect(lines).toEqual([
      "[gateway] ✖ sign-on rejected: quorum 1 < 2 (node2, node3 unreachable)",
    ]);
  });

  it("never repeats the never: claim on a relayed event", () => {
    // Section 10's reason: the claim belongs on the startup line, and the audience reads
    // it once per column instead of on every event.
    const { log, lines } = capture();
    log.signOn(SIGN_ON);
    log.refresh({
      sessionId: SIGN_ON.sessionId,
      roundId: SIGN_ON.roundId,
      participants: [1, 2, 3],
      dpopProof: "proof",
      excluded: [],
    });
    log.demoRpCallback({ idToken: "tok", verified: true });

    expect(lines.filter((l) => l.includes("never:"))).toHaveLength(0);
    expect(NEVER_HELD).toBe("s_i, k_i, h_i, pw, id_token");
  });

  it("keeps every event's first line in the same two columns", () => {
    const { log, lines } = capture();
    log.startup({
      issuer: "http://i",
      threshold: 2,
      total: 3,
      keyId: "kid",
      nodeUrls: ["http://node1:4001"],
    });
    log.authorize({
      clientId: "c",
      redirectUri: "http://rp/cb",
      nonce: "n",
      state: "s",
      dpopJkt: RP_JKT,
    });
    log.signOn(SIGN_ON);
    log.jwks();
    log.discovery();
    log.demoRpCallback({ idToken: "tok", verified: true });

    for (const line of lines.filter((l) => l.startsWith("[gateway]"))) {
      expect(line.slice(0, CONTINUATION_INDENT.length)).toMatch(/^\[gateway\] \S.{0,8} *$/);
    }
  });
});
