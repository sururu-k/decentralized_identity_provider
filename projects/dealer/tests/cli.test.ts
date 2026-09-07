import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { NodeFile } from "../src/dealer.js";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const entry = path.join(projectRoot, "src", "index.ts");

/** Runs the CLI in a child process, through tsx so no build step is needed. */
function runCli(args: string[]) {
  return spawnSync(process.execPath, ["--import", "tsx", entry, ...args], {
    cwd: projectRoot,
    encoding: "utf8",
  });
}

let outDir: string;

beforeEach(() => {
  outDir = mkdtempSync(path.join(os.tmpdir(), "dealer-cli-"));
});

afterEach(() => {
  rmSync(outDir, { recursive: true, force: true });
});

describe("dealer CLI", () => {
  it("writes group.json and one file per node", () => {
    const result = runCli(["--out", outDir]);
    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);

    for (const name of ["group.json", "node-1.json", "node-2.json", "node-3.json"]) {
      expect(existsSync(path.join(outDir, name))).toBe(true);
    }

    const group = JSON.parse(readFileSync(path.join(outDir, "group.json"), "utf8"));
    expect(group).toMatchObject({
      version: 1,
      threshold: 2,
      total: 3,
      keyId: "pasta-group-key-1",
    });
    expect(group.groupPublicKey).toMatch(/^[0-9a-f]{64}$/);

    const node2: NodeFile = JSON.parse(readFileSync(path.join(outDir, "node-2.json"), "utf8"));
    expect(node2.nodeId).toBe(2);
    expect(node2.groupPublicKey).toBe(group.groupPublicKey);
    expect(node2.users.map((u) => u.username)).toEqual(["alice", "bob"]);
    expect(node2.users[0].sub).toBe("usr_alice_12345");
    expect(node2.users[1].sub).toBe("usr_bob_67890");
  });

  it("does not write passwords to disk", () => {
    expect(runCli(["--out", outDir]).status).toBe(0);
    for (const name of ["group.json", "node-1.json", "node-2.json", "node-3.json"]) {
      const contents = readFileSync(path.join(outDir, name), "utf8");
      expect(contents).not.toContain("password123");
      expect(contents).not.toContain("password456");
    }
  });

  it("exits 1 without overwriting when an output file already exists", () => {
    writeFileSync(path.join(outDir, "node-2.json"), "sentinel");

    const result = runCli(["--out", outDir]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("node-2.json");
    expect(readFileSync(path.join(outDir, "node-2.json"), "utf8")).toBe("sentinel");
    // Nothing else was written either.
    expect(existsSync(path.join(outDir, "group.json"))).toBe(false);
  });

  it("overwrites existing files with --force", () => {
    writeFileSync(path.join(outDir, "node-2.json"), "sentinel");

    const result = runCli(["--out", outDir, "--force"]);
    expect(result.status).toBe(0);

    const node2: NodeFile = JSON.parse(readFileSync(path.join(outDir, "node-2.json"), "utf8"));
    expect(node2.nodeId).toBe(2);
    expect(existsSync(path.join(outDir, "group.json"))).toBe(true);
  });

  it("--if-missing keeps an existing complete output set and exits 0", () => {
    expect(runCli(["--out", outDir]).status).toBe(0);
    const before = ["group.json", "node-1.json", "node-2.json", "node-3.json"].map(
      (name) => readFileSync(path.join(outDir, name), "utf8")
    );

    const result = runCli(["--out", outDir, "--if-missing"]);
    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");

    const after = ["group.json", "node-1.json", "node-2.json", "node-3.json"].map(
      (name) => readFileSync(path.join(outDir, name), "utf8")
    );
    // Byte identical: a compose restart must not rotate the keys.
    expect(after).toEqual(before);
  });

  it("--if-missing generates the set when the directory is empty", () => {
    const result = runCli(["--out", outDir, "--if-missing"]);
    expect(result.status).toBe(0);
    for (const name of ["group.json", "node-1.json", "node-2.json", "node-3.json"]) {
      expect(existsSync(path.join(outDir, name))).toBe(true);
    }
  });

  it("--if-missing creates the output directory when it does not exist", () => {
    const nested = path.join(outDir, "fresh");
    expect(runCli(["--out", nested, "--if-missing"]).status).toBe(0);
    expect(existsSync(path.join(nested, "group.json"))).toBe(true);
  });

  it("--if-missing exits 1 on a partial output set without touching it", () => {
    expect(runCli(["--out", outDir]).status).toBe(0);
    const group = readFileSync(path.join(outDir, "group.json"), "utf8");
    rmSync(path.join(outDir, "node-3.json"));

    const result = runCli(["--out", outDir, "--if-missing"]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("group.json");
    expect(readFileSync(path.join(outDir, "group.json"), "utf8")).toBe(group);
    expect(existsSync(path.join(outDir, "node-3.json"))).toBe(false);
  });

  it("--if-missing with --force rewrites a partial output set", () => {
    expect(runCli(["--out", outDir]).status).toBe(0);
    const first = JSON.parse(readFileSync(path.join(outDir, "group.json"), "utf8"));
    rmSync(path.join(outDir, "node-3.json"));

    const result = runCli(["--out", outDir, "--if-missing", "--force"]);
    expect(result.status).toBe(0);
    const second = JSON.parse(readFileSync(path.join(outDir, "group.json"), "utf8"));
    expect(second.groupPublicKey).not.toBe(first.groupPublicKey);
    expect(existsSync(path.join(outDir, "node-3.json"))).toBe(true);
  });

  it("--if-missing counts the files --total asks for, not the ones present", () => {
    expect(runCli(["--out", outDir]).status).toBe(0);
    // 3 files present, 5 wanted: not a complete set, so this must not exit 0.
    const result = runCli(["--out", outDir, "--total", "5", "--if-missing"]);
    expect(result.status).toBe(1);
    expect(existsSync(path.join(outDir, "node-5.json"))).toBe(false);
  });

  it("mentions --if-missing in the usage text", () => {
    expect(runCli(["--help"]).stdout).toContain("--if-missing");
  });

  it("regenerates fresh key material on every run", () => {
    expect(runCli(["--out", outDir]).status).toBe(0);
    const first = JSON.parse(readFileSync(path.join(outDir, "group.json"), "utf8"));
    expect(runCli(["--out", outDir, "--force"]).status).toBe(0);
    const second = JSON.parse(readFileSync(path.join(outDir, "group.json"), "utf8"));
    expect(second.groupPublicKey).not.toBe(first.groupPublicKey);
  });

  it("honours --threshold, --total, --key-id and --users", () => {
    const result = runCli([
      "--out",
      outDir,
      "--threshold",
      "2",
      "--total",
      "4",
      "--key-id",
      "my-key",
      "--users",
      "carol:pw:usr_carol,dave:pw2:usr_dave",
    ]);
    expect(result.status).toBe(0);

    const group = JSON.parse(readFileSync(path.join(outDir, "group.json"), "utf8"));
    expect(group).toMatchObject({ threshold: 2, total: 4, keyId: "my-key" });
    expect(existsSync(path.join(outDir, "node-4.json"))).toBe(true);

    const node4: NodeFile = JSON.parse(readFileSync(path.join(outDir, "node-4.json"), "utf8"));
    expect(node4.users.map((u) => u.username)).toEqual(["carol", "dave"]);
  });

  it("creates the output directory when it does not exist", () => {
    const nested = path.join(outDir, "a", "b");
    expect(runCli(["--out", nested]).status).toBe(0);
    expect(existsSync(path.join(nested, "group.json"))).toBe(true);
  });

  it("exits 1 when --out is missing", () => {
    const result = runCli([]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("--out");
  });

  it("exits 1 on an unknown option and on a malformed --users entry", () => {
    expect(runCli(["--out", outDir, "--nope"]).status).toBe(1);
    expect(runCli(["--out", outDir, "--users", "alice:password123"]).status).toBe(1);
    expect(runCli(["--out", outDir, "--threshold", "5", "--total", "3"]).status).toBe(1);
  });

  it("rejects an empty, doubled-comma or duplicated --users entry", () => {
    // A blank entry is a typo, not a user: it must not be silently skipped.
    const doubled = runCli(["--out", outDir, "--users", "alice:p:s1,,bob:p:s2"]);
    expect(doubled.status).toBe(1);
    expect(doubled.stderr).toContain("empty entry");

    expect(runCli(["--out", outDir, "--users", "alice:p:s1,"]).status).toBe(1);
    expect(runCli(["--out", outDir, "--users", ""]).status).toBe(1);

    const dupName = runCli(["--out", outDir, "--users", "alice:p:s1,alice:p:s2"]);
    expect(dupName.status).toBe(1);
    expect(dupName.stderr).toContain("Duplicate username");

    const dupSub = runCli(["--out", outDir, "--users", "alice:p:s1,bob:p:s1"]);
    expect(dupSub.status).toBe(1);
    expect(dupSub.stderr).toContain("Duplicate sub");

    expect(existsSync(path.join(outDir, "group.json"))).toBe(false);
  });

  it("rejects a threshold below 1 and a non-numeric count", () => {
    const zero = runCli(["--out", outDir, "--threshold", "0"]);
    expect(zero.status).toBe(1);
    expect(zero.stderr).toContain("--threshold");

    const word = runCli(["--out", outDir, "--total", "three"]);
    expect(word.status).toBe(1);
    expect(word.stderr).toContain("--total");

    const emptyKeyId = runCli(["--out", outDir, "--key-id", ""]);
    expect(emptyKeyId.status).toBe(1);
    expect(emptyKeyId.stderr).toContain("keyId");

    // Nothing was written by any rejected invocation.
    expect(existsSync(path.join(outDir, "group.json"))).toBe(false);
  });

  it("explains a threshold larger than total", () => {
    const result = runCli(["--out", outDir, "--threshold", "5", "--total", "3"]);
    expect(result.stderr).toMatch(/threshold/i);
    expect(result.stderr).toContain("3");
  });

  it("prints usage and exits 0 for --help", () => {
    const result = runCli(["--help"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("--out");
  });
});
