import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  HELD,
  NEVER_HELD,
  logCallback,
  logCallbackRejected,
  logLanding,
  logStartup,
  truncate8,
} from "../src/demolog.js";

/**
 * Unit tests for the demo-log formatter itself (docs/container-split.md section 10).
 * Which event each route emits is covered by `tests/rp.test.ts`; this file only checks
 * the formatting rules: disabling, truncation, the column widths, and the fixed
 * `holds:` / `never:` wording.
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

function lines(): string[] {
  return logSpy.mock.calls.map((call) => call[0] as string);
}

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
    logLanding({ state: "s1" });
    expect(logSpy).toHaveBeenCalled();
  });

  it("logs when DEMO_LOG is any value other than the literal '0'", () => {
    process.env.DEMO_LOG = "1";
    logLanding({ state: "s1" });
    expect(logSpy).toHaveBeenCalled();
  });

  it("suppresses every event when DEMO_LOG=0", () => {
    process.env.DEMO_LOG = "0";
    logStartup({ issuer: "http://localhost:3000" });
    logLanding({ state: "s1" });
    logCallback({ code: "abcdefghij", state: "s1" });
    logCallbackRejected("no code in the redirect query string");
    expect(logSpy).not.toHaveBeenCalled();
  });
});

describe("logStartup", () => {
  it("is the only line that carries holds: and never:", () => {
    process.env.DEMO_LOG = "1";
    process.env.NO_COLOR = "1";
    logStartup({ issuer: "http://localhost:3000" });
    logLanding({ state: "s1" });
    logCallback({ code: "code_abcdefgh", state: "s1" });

    expect(lines()[0]).toBe(
      `[rp]      ● up      issuer=http://localhost:3000   holds: ${HELD}   never: ${NEVER_HELD}`
    );
    expect(lines().filter((l) => l.includes("never:"))).toHaveLength(1);
    expect(lines().filter((l) => l.includes("holds:"))).toHaveLength(1);
  });

  it("names the access token among what the rp server can never hold", () => {
    // Section 14: the browser posts to /token itself, so the token never reaches this
    // process — not even as something it relays.
    expect(NEVER_HELD).toContain("access_token (handled in browser only)");
    expect(NEVER_HELD).toContain("pw");
    expect(HELD).toBe("nothing (HTML only)");
  });
});

describe("logLanding", () => {
  it("emits one line, prefixed [rp] and padded into the event column", () => {
    process.env.DEMO_LOG = "1";
    process.env.NO_COLOR = "1"; // keep the raw text easy to assert on
    logLanding({ state: "stateValueLongerThan8" });

    expect(lines()).toHaveLength(1);
    // state is a public correlation id (section 10): never truncated.
    expect(lines()[0]).toBe("[rp]      landing   state=stateValueLongerThan8  → authorize URL");
    expect(lines()[0]).not.toContain("nonce");
  });
});

describe("logCallback", () => {
  beforeEach(() => {
    process.env.DEMO_LOG = "1";
    process.env.NO_COLOR = "1";
  });

  it("emits one line: the code truncated to 8, and where the flow continues", () => {
    logCallback({ code: "code_abcdefghijklmnop", state: "rp-demo" });

    expect(lines()).toEqual([
      "[rp]      callback  state=rp-demo  ← code(assertion) code_abc " +
        "(query, via browser redirect)  → page with token script",
    ]);
  });

  it("names the code as the assertion, and truncates the long JWT to 8 chars", () => {
    // Section 14 (revised): the code is the group-signed assertion JWT. Only its first 8
    // characters go in the log, like every other session-scoped byte string (section 10).
    const assertion = `${"e".repeat(200)}.${"p".repeat(300)}.${"s".repeat(86)}`;
    logCallback({ code: assertion, state: "rp-demo" });

    expect(lines()[0]).toContain("← code(assertion) eeeeeeee ");
    expect(lines()[0].length).toBeLessThan(120);
  });

  it("renders a missing state as '-'", () => {
    logCallback({ code: "abc", state: undefined });
    expect(lines()[0]).toContain("state=-  ← code(assertion) abc");
  });

  it("keeps the refusal format identical across calls", () => {
    for (let i = 0; i < 3; i++) {
      logCallbackRejected("no code in the redirect query string");
    }
    expect(new Set(lines()).size).toBe(1);
    expect(lines()[0]).toBe(
      "[rp]      ✖ callback rejected: no code in the redirect query string"
    );
  });
});

describe("color handling", () => {
  it("wraps lines in ANSI green when FORCE_COLOR=1 and NO_COLOR is unset", () => {
    process.env.DEMO_LOG = "1";
    process.env.FORCE_COLOR = "1";
    delete process.env.NO_COLOR;
    logLanding({ state: "s1" });
    const line = lines()[0];
    expect(line.startsWith("\x1b[1m\x1b[32m")).toBe(true);
    expect(line.endsWith("\x1b[0m")).toBe(true);
    expect(line).toContain("[rp]      landing   state=s1");
  });

  it("NO_COLOR overrides FORCE_COLOR", () => {
    process.env.DEMO_LOG = "1";
    process.env.FORCE_COLOR = "1";
    process.env.NO_COLOR = "1";
    logLanding({ state: "s1" });
    expect(lines()[0]).toBe("[rp]      landing   state=s1  → authorize URL");
  });

  it("FORCE_COLOR=0 turns colour back off, the documented way for the demo since NO_COLOR warns", () => {
    process.env.DEMO_LOG = "1";
    process.env.FORCE_COLOR = "0";
    delete process.env.NO_COLOR;
    logLanding({ state: "s1" });
    expect(lines()[0]).toBe("[rp]      landing   state=s1  → authorize URL");
  });
});
