import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  CONTINUATION_INDENT,
  NEVER_HELD,
  logCallback,
  logJwksFetch,
  logLanding,
  logStartup,
  truncate8,
} from "../src/demolog.js";

/**
 * Unit tests for the demo-log formatter itself (docs/container-split.md section 10).
 * The HTTP-level behaviour (which outcome each `/callback` path logs) is covered by the
 * component e2e in `tests/rp.test.ts`; this file only checks the formatting rules:
 * disabling, truncation, the column widths, and the fixed `never:` wording.
 */

let logSpy: ReturnType<typeof vi.spyOn>;
const ORIGINAL_ENV = { ...process.env };

beforeEach(() => {
  logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
});

afterEach(() => {
  logSpy.mockRestore();
  process.env = { ...ORIGINAL_ENV };
});

describe("truncate8", () => {
  it("passes short values through unchanged", () => {
    expect(truncate8("abc")).toBe("abc");
    expect(truncate8("12345678")).toBe("12345678");
  });

  it("cuts to the first 8 characters, with no ellipsis", () => {
    expect(truncate8("123456789")).toBe("12345678");
    expect(truncate8("a".repeat(100))).toBe("aaaaaaaa");
  });

  it("handles the empty string", () => {
    expect(truncate8("")).toBe("");
  });
});

describe("DEMO_LOG toggle", () => {
  it("logs by default (unset)", () => {
    delete process.env.DEMO_LOG;
    logLanding({ nonce: "n1", state: "s1" });
    expect(logSpy).toHaveBeenCalled();
  });

  it("logs when DEMO_LOG is any value other than the literal '0'", () => {
    process.env.DEMO_LOG = "1";
    logLanding({ nonce: "n1", state: "s1" });
    expect(logSpy).toHaveBeenCalled();
  });

  it("suppresses every event when DEMO_LOG=0", () => {
    process.env.DEMO_LOG = "0";
    logStartup({ issuer: "http://localhost:3000" });
    logLanding({ nonce: "n1", state: "s1" });
    logCallback({
      idToken: "abc.def.ghi",
      state: "s1",
      idpInternalUrl: "http://gateway:3000",
      outcome: { kind: "parse_failed", reason: "bad" },
    });
    logJwksFetch();
    expect(logSpy).not.toHaveBeenCalled();
  });
});

describe("logStartup", () => {
  it("is the only line that carries holds: and never:", () => {
    process.env.DEMO_LOG = "1";
    process.env.NO_COLOR = "1";
    logStartup({ issuer: "http://localhost:3000" });
    logLanding({ nonce: "n1", state: "s1" });
    logCallback({
      idToken: "header.payload.sig",
      state: "s1",
      idpInternalUrl: "http://gateway:3000",
      outcome: {
        kind: "verified",
        kid: "pasta-group-key-1",
        iss: "http://localhost:3000",
        aud: "demo_client",
        expRemainingSeconds: 10,
        sub: "usr_alice_12345",
      },
    });

    const lines = logSpy.mock.calls.map((call) => call[0] as string);
    expect(lines[0]).toBe(
      `[rp]      ● up      issuer=http://localhost:3000   holds: JWKS(kid) only   never: ${NEVER_HELD}`
    );
    expect(lines.filter((l) => l.includes("never:"))).toHaveLength(1);
    expect(lines.filter((l) => l.includes("holds:"))).toHaveLength(1);
  });
});

describe("logLanding", () => {
  it("emits one line, prefixed [rp] and padded into the event column", () => {
    process.env.DEMO_LOG = "1";
    process.env.NO_COLOR = "1"; // keep the raw text easy to assert on
    logLanding({ nonce: "nonceValueLongerThan8", state: "state-abc" });

    const lines = logSpy.mock.calls.map((call) => call[0] as string);
    expect(lines).toHaveLength(1);
    // OIDC nonce/state are public correlation ids (section 10): never truncated.
    expect(lines[0]).toBe(
      "[rp]      landing   nonce=nonceValueLongerThan8 state=state-abc  → authorize URL"
    );
  });
});

describe("logCallback", () => {
  beforeEach(() => {
    process.env.DEMO_LOG = "1";
    process.env.NO_COLOR = "1";
  });

  it("verified outcome: two lines, no ✖, claims shown in full", () => {
    logCallback({
      idToken: "header.payload.signaturevalue",
      state: "rp-demo",
      idpInternalUrl: "http://gateway:3000",
      outcome: {
        kind: "verified",
        kid: "pasta-group-key-1",
        iss: "http://localhost:3000",
        aud: "demo_client",
        expRemainingSeconds: 3599,
        sub: "usr_alice_12345",
      },
    });

    const lines = logSpy.mock.calls.map((call) => call[0] as string);
    expect(lines).toEqual([
      "[rp]      callback  state=rp-demo  ← id_token header.p (direct from browser, not via gateway)",
      `${CONTINUATION_INDENT}JWKS kid=pasta-group-key-1 → Ed25519 ✓  iss ✓  aud ✓  ` +
        "exp 3599s  sub=usr_alice_12345",
    ]);
    expect(lines.some((l) => l.includes("✖"))).toBe(false);
  });

  it("verification_failed outcome: the arrival line plus one ✖ line", () => {
    logCallback({
      idToken: "header.payload.signaturevalue",
      state: undefined,
      idpInternalUrl: "http://gateway:3000",
      outcome: { kind: "verification_failed", kid: "pasta-group-key-1", reason: "iss mismatch" },
    });

    const lines = logSpy.mock.calls.map((call) => call[0] as string);
    expect(lines).toHaveLength(2);
    expect(lines[0]).toContain("state=-  ← id_token header.p");
    expect(lines[1]).toBe("[rp]      ✖ callback rejected: iss mismatch");
    expect(lines.some((l) => l.includes("Ed25519 ✓"))).toBe(false);
  });

  it("jwks_unreachable outcome: same refusal shape, reason names the JWKS source", () => {
    logCallback({
      idToken: "header.payload.signaturevalue",
      state: "s",
      idpInternalUrl: "http://gateway:3000",
      outcome: { kind: "jwks_unreachable", kid: "pasta-group-key-1", reason: "ECONNREFUSED" },
    });

    const lines = logSpy.mock.calls.map((call) => call[0] as string);
    expect(lines).toHaveLength(2);
    expect(lines[1]).toBe(
      "[rp]      ✖ callback rejected: JWKS(kid=pasta-group-key-1) unreachable at " +
        "http://gateway:3000: ECONNREFUSED"
    );
  });

  it("parse_failed outcome: same refusal shape, no kid to show yet", () => {
    logCallback({
      idToken: "not-a-jwt",
      state: "s",
      idpInternalUrl: "http://gateway:3000",
      outcome: { kind: "parse_failed", reason: "Malformed JWT: expected 3 dot-separated parts" },
    });

    const lines = logSpy.mock.calls.map((call) => call[0] as string);
    expect(lines).toHaveLength(2);
    expect(lines[1]).toBe(
      "[rp]      ✖ callback rejected: JWT parse failed before JWKS lookup: " +
        "Malformed JWT: expected 3 dot-separated parts"
    );
  });

  it("keeps the refusal format identical across calls", () => {
    for (let i = 0; i < 3; i++) {
      logCallback({
        idToken: `token-${i}`,
        state: "s",
        idpInternalUrl: "http://gateway:3000",
        outcome: { kind: "parse_failed", reason: "x" },
      });
    }
    const rejectLines = logSpy.mock.calls
      .map((call) => call[0] as string)
      .filter((l) => l.includes("✖"));
    expect(rejectLines).toHaveLength(3);
    expect(new Set(rejectLines).size).toBe(1);
    expect(rejectLines[0]).toBe(
      "[rp]      ✖ callback rejected: JWT parse failed before JWKS lookup: x"
    );
  });
});

describe("logJwksFetch", () => {
  it("emits exactly one line noting it is public information only", () => {
    process.env.DEMO_LOG = "1";
    process.env.NO_COLOR = "1";
    logJwksFetch();
    expect(logSpy).toHaveBeenCalledTimes(1);
    expect(logSpy.mock.calls[0][0]).toBe("[rp]      jwks      public only");
  });
});

describe("color handling", () => {
  it("wraps lines in ANSI green when FORCE_COLOR=1 and NO_COLOR is unset", () => {
    process.env.DEMO_LOG = "1";
    process.env.FORCE_COLOR = "1";
    delete process.env.NO_COLOR;
    logJwksFetch();
    const line = logSpy.mock.calls[0][0] as string;
    expect(line.startsWith("\x1b[1m\x1b[32m")).toBe(true);
    expect(line.endsWith("\x1b[0m")).toBe(true);
    expect(line).toContain("[rp]      jwks      public only");
  });

  it("NO_COLOR overrides FORCE_COLOR", () => {
    process.env.DEMO_LOG = "1";
    process.env.FORCE_COLOR = "1";
    process.env.NO_COLOR = "1";
    logJwksFetch();
    const line = logSpy.mock.calls[0][0] as string;
    expect(line).toBe("[rp]      jwks      public only");
  });

  it("FORCE_COLOR=0 turns colour back off, the documented way for the demo since NO_COLOR warns", () => {
    process.env.DEMO_LOG = "1";
    process.env.FORCE_COLOR = "0";
    delete process.env.NO_COLOR;
    logJwksFetch();
    const line = logSpy.mock.calls[0][0] as string;
    expect(line).toBe("[rp]      jwks      public only");
  });
});
