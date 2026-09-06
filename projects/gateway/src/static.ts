import fs from "node:fs";
import path from "node:path";

/**
 * Static serving of the built demo UI.
 *
 * Only three shapes of path are served (`docs/container-split.md` section 6): `/` and
 * `/demo` return the SPA entry point, and `/assets/...` returns a build artefact. Every
 * other path falls through to the router's 404.
 *
 * The monolith joined the request path onto the dist directory and trusted the result.
 * Here the resolved path is required to stay inside the root, so `/assets/../../etc/...`
 * and any percent-encoded spelling of it are refused rather than served.
 */

const CONTENT_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript",
  ".mjs": "application/javascript",
  ".css": "text/css",
  ".svg": "image/svg+xml",
  ".json": "application/json",
  ".map": "application/json",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".ttf": "font/ttf",
  ".txt": "text/plain; charset=utf-8",
};

export interface StaticFile {
  content: Buffer;
  contentType: string;
}

/** Result of a static lookup: a file, a refusal, or "not a static path at all". */
export type StaticLookup =
  | { kind: "file"; file: StaticFile }
  | { kind: "forbidden" }
  | { kind: "none" };

export function contentTypeFor(filePath: string): string {
  return CONTENT_TYPES[path.extname(filePath).toLowerCase()] ?? "application/octet-stream";
}

/**
 * Maps a request path to a file under `root`.
 *
 * `pathname` comes from `URL`, which resolves `.` and `..` segments but leaves percent
 * escapes alone. So `/assets/../../etc/passwd` has already collapsed to `/etc/passwd` and
 * no longer looks like an asset path, while `/assets/%2e%2e/...` arrives with the escapes
 * intact and names a directory that does not exist. Neither is decoded here: the path is
 * used exactly as received, and the containment check below is what makes that safe for
 * any spelling a hand-written request could still deliver.
 *
 * Containment is checked twice. Once on the resolved path, which catches literal `..`
 * segments, and once on the real path, which catches a symlink inside the dist directory
 * that points out of it.
 */
export function lookupStatic(root: string, pathname: string): StaticLookup {
  const resolvedRoot = path.resolve(root);

  let target: string;
  if (pathname === "/" || pathname === "/demo") {
    target = path.join(resolvedRoot, "index.html");
  } else if (pathname.startsWith("/assets/")) {
    if (pathname.includes("\0")) {
      return { kind: "forbidden" };
    }
    target = path.resolve(resolvedRoot, "." + pathname);
  } else {
    return { kind: "none" };
  }

  if (!isInside(resolvedRoot, target)) {
    return { kind: "forbidden" };
  }

  let real: string;
  try {
    real = fs.realpathSync(target);
  } catch {
    return { kind: "none" };
  }
  // `realpathSync` follows symlinks, so a link planted inside the dist directory could
  // otherwise hand out any file the process can read.
  if (!isInside(fs.realpathSync(resolvedRoot), real)) {
    return { kind: "forbidden" };
  }

  let stat: fs.Stats;
  try {
    stat = fs.statSync(real);
  } catch {
    return { kind: "none" };
  }
  if (!stat.isFile()) {
    return { kind: "none" };
  }

  return {
    kind: "file",
    file: { content: fs.readFileSync(real), contentType: contentTypeFor(real) },
  };
}

/** True when `target` is `root` itself or sits somewhere beneath it. */
function isInside(root: string, target: string): boolean {
  const relative = path.relative(root, target);
  return !relative.startsWith("..") && !path.isAbsolute(relative);
}
