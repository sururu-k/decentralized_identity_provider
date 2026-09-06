import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import {
  DEFAULT_KEY_ID,
  DEFAULT_THRESHOLD,
  DEFAULT_TOTAL,
  DEFAULT_USERS,
  UserSpec,
  generateDealerOutput,
  nodeFileName,
  outputFileNames,
} from "./dealer.js";

const USAGE = `pasta-dealer - generates FROST key shares and pre-registered user records

Usage:
  node dist/index.js --out <dir> [options]

Options:
  --out <dir>        Output directory (required). Created if missing.
  --threshold <t>    Signing threshold t. Default ${DEFAULT_THRESHOLD}.
  --total <n>        Number of nodes n. Default ${DEFAULT_TOTAL}.
  --key-id <id>      Group key id written to group.json. Default ${DEFAULT_KEY_ID}.
  --users <list>     Comma separated user list, each entry
                     <username>:<password>:<sub>.
                     Default ${DEFAULT_USERS.map((u) => `${u.username}:<password>:${u.sub}`).join(",")}
  --force            Overwrite existing output files.
  --if-missing       Exit 0 without writing when every output file already
                     exists. If only some of them exist, behave as usual:
                     exit 1, or overwrite when --force is also given.
  -h, --help         Show this help.

Writes <out>/group.json and <out>/node-<id>.json for id 1..n.
Passwords are never written to disk.
`;

/**
 * Parses one `--users` entry of the form <username>:<password>:<sub>.
 * The first and last colon are the separators, so a password may contain
 * colons. A password may not contain a comma, which separates entries.
 */
export function parseUserSpec(entry: string): UserSpec {
  const first = entry.indexOf(":");
  const last = entry.lastIndexOf(":");
  if (first === -1 || last === first) {
    throw new Error(
      `Invalid --users entry "${entry}": expected <username>:<password>:<sub>`
    );
  }
  const username = entry.slice(0, first);
  const password = entry.slice(first + 1, last);
  const sub = entry.slice(last + 1);
  if (username.length === 0 || password.length === 0 || sub.length === 0) {
    throw new Error(
      `Invalid --users entry "${entry}": username, password and sub must be non-empty`
    );
  }
  return { username, password, sub };
}

/**
 * Parses the whole `--users` value. Empty entries are rejected rather than
 * skipped: a doubled or trailing comma is far more likely a typo than an
 * intentionally blank user, and silently dropping it would hide the mistake.
 */
export function parseUsers(value: string): UserSpec[] {
  if (value.length === 0) {
    throw new Error("--users must list at least one user");
  }
  const entries = value.split(",");
  if (entries.some((e) => e.length === 0)) {
    throw new Error(
      `Invalid --users value "${value}": empty entry (check for a doubled or trailing comma)`
    );
  }
  return entries.map(parseUserSpec);
}

function parsePositiveInt(name: string, value: string): number {
  if (!/^[0-9]+$/.test(value)) {
    throw new Error(`${name} must be a positive integer, got "${value}"`);
  }
  const parsed = Number.parseInt(value, 10);
  if (parsed < 1) {
    throw new Error(`${name} must be at least 1, got ${parsed}`);
  }
  return parsed;
}

/** Runs the CLI and returns the process exit code. */
export function main(argv: string[]): number {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      options: {
        out: { type: "string" },
        threshold: { type: "string" },
        total: { type: "string" },
        "key-id": { type: "string" },
        users: { type: "string" },
        force: { type: "boolean", default: false },
        "if-missing": { type: "boolean", default: false },
        help: { type: "boolean", short: "h", default: false },
      },
      allowPositionals: false,
    });
  } catch (err) {
    process.stderr.write(`${(err as Error).message}\n\n${USAGE}`);
    return 1;
  }

  const values = parsed.values;
  if (values.help) {
    process.stdout.write(USAGE);
    return 0;
  }

  if (!values.out) {
    process.stderr.write(`error: --out <dir> is required\n\n${USAGE}`);
    return 1;
  }

  let threshold = DEFAULT_THRESHOLD;
  let total = DEFAULT_TOTAL;
  let users = DEFAULT_USERS;
  try {
    if (values.threshold !== undefined) {
      threshold = parsePositiveInt("--threshold", values.threshold);
    }
    if (values.total !== undefined) {
      total = parsePositiveInt("--total", values.total);
    }
    if (values.users !== undefined) {
      users = parseUsers(values.users);
    }
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n`);
    return 1;
  }

  const keyId = values["key-id"] ?? DEFAULT_KEY_ID;
  const outDir = path.resolve(values.out);
  const fileNames = outputFileNames(total);

  const existing = fileNames.filter((name) => existsSync(path.join(outDir, name)));

  // --if-missing keeps a compose restart from rotating the keys: when the whole
  // set is already there, do nothing and succeed. A partial set is not a usable
  // key set, so it falls through to the normal refuse-to-overwrite check.
  if (values["if-missing"] && existing.length === fileNames.length) {
    process.stdout.write(
      `dealer: ${fileNames.length} output file(s) already present in ${outDir}, keeping them\n`
    );
    return 0;
  }

  if (!values.force && existing.length > 0) {
    process.stderr.write(
      `error: refusing to overwrite existing file(s) in ${outDir}: ${existing.join(", ")}\n` +
        `Expected ${fileNames.join(", ")}. Pass --force to overwrite.\n`
    );
    return 1;
  }

  let output;
  try {
    output = generateDealerOutput({ threshold, total, keyId, users });
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n`);
    return 1;
  }

  try {
    mkdirSync(outDir, { recursive: true });
    writeFileSync(
      path.join(outDir, "group.json"),
      JSON.stringify(output.group, null, 2) + "\n"
    );
    for (const node of output.nodes) {
      writeFileSync(
        path.join(outDir, nodeFileName(node.nodeId)),
        JSON.stringify(node, null, 2) + "\n"
      );
    }
  } catch (err) {
    process.stderr.write(`error: failed to write to ${outDir}: ${(err as Error).message}\n`);
    return 1;
  }

  process.stdout.write(
    `dealer: wrote ${fileNames.length} file(s) to ${outDir}\n` +
      `  threshold=${threshold} total=${total} keyId=${keyId}\n` +
      `  groupPublicKey=${output.group.groupPublicKey}\n` +
      `  users=${users.map((u) => u.username).join(", ")}\n` +
      fileNames.map((n) => `  ${path.join(outDir, n)}\n`).join("")
  );
  return 0;
}

