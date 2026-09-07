import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { contentTypeFor, lookupStatic } from "../src/static.js";

/**
 * Direct tests of the static lookup.
 *
 * The HTTP-level test in `e2e.test.ts` cannot reach these cases: a client normalises
 * `..` out of the path before the request leaves, so the containment check is exercised
 * here with the raw paths a hand-written request could still deliver.
 */

let root: string;
let outside: string;

beforeAll(() => {
  outside = fs.mkdtempSync(path.join(os.tmpdir(), "gateway-static-outside-"));
  fs.writeFileSync(path.join(outside, "secret.txt"), "top secret\n");

  root = fs.mkdtempSync(path.join(os.tmpdir(), "gateway-static-root-"));
  fs.mkdirSync(path.join(root, "assets"));
  fs.writeFileSync(path.join(root, "index.html"), "<!doctype html>hello");
  fs.writeFileSync(path.join(root, "assets", "app.js"), "console.log(1)");
  fs.writeFileSync(path.join(root, "assets", "style.css"), "body{}");
});

afterAll(() => {
  fs.rmSync(root, { recursive: true, force: true });
  fs.rmSync(outside, { recursive: true, force: true });
});

describe("lookupStatic", () => {
  it("serves index.html for / and /demo", () => {
    for (const p of ["/", "/demo"]) {
      const result = lookupStatic(root, p);
      expect(result.kind).toBe("file");
      if (result.kind !== "file") return;
      expect(result.file.content.toString("utf8")).toContain("hello");
      expect(result.file.contentType).toContain("text/html");
    }
  });

  it("serves files under /assets with a matching content type", () => {
    const js = lookupStatic(root, "/assets/app.js");
    expect(js.kind).toBe("file");
    if (js.kind === "file") {
      expect(js.file.contentType).toBe("application/javascript");
    }

    const css = lookupStatic(root, "/assets/style.css");
    expect(css.kind).toBe("file");
    if (css.kind === "file") {
      expect(css.file.contentType).toBe("text/css");
    }
  });

  it("refuses paths that resolve outside the dist directory", () => {
    const relative = path.relative(path.join(root, "assets"), path.join(outside, "secret.txt"));
    const attempt = `/assets/${relative.split(path.sep).join("/")}`;
    expect(lookupStatic(root, attempt).kind).toBe("forbidden");

    expect(lookupStatic(root, "/assets/../../../../etc/passwd").kind).toBe("forbidden");
    expect(lookupStatic(root, "/assets/\0secret").kind).toBe("forbidden");
    // `/assets/..` lands on the dist root itself, which is contained but is a directory.
    expect(lookupStatic(root, "/assets/..").kind).toBe("none");
  });

  it("reports paths it does not own, and missing files, as none", () => {
    expect(lookupStatic(root, "/jwks.json").kind).toBe("none");
    expect(lookupStatic(root, "/api/pasta/sign-on").kind).toBe("none");
    expect(lookupStatic(root, "/assets/missing.js").kind).toBe("none");
    // A directory is not a file.
    expect(lookupStatic(root, "/assets/").kind).toBe("none");
  });

  it("falls back to a generic content type for unknown extensions", () => {
    expect(contentTypeFor("/x/y.bin")).toBe("application/octet-stream");
    expect(contentTypeFor("/x/y.WOFF2")).toBe("font/woff2");
  });
});
