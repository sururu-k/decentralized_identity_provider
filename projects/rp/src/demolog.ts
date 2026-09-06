/**
 * Demo-log output for the RP.
 *
 * `docs/container-split.md` section 10: every component in the demo emits the same
 * compact one-or-two-line shape to stdout, in English, so an audience watching the
 * node / gateway / rp / browser columns side by side can see who can assemble what.
 *
 * Since the OAuth step (section 14) the rp *server* is the thinnest column of all. It
 * builds an `/authorize` URL, and it serves the callback HTML. It never sees the
 * authorization code turn into a token: the browser posts to `/token` itself, with a DPoP
 * proof made from a key the server has never held. That is what the `never:` line on
 * `● up` says, and no later event repeats it.
 *
 * This module owns formatting only. `server.ts` decides what values go where; it never
 * has to duplicate the column widths, the truncation rule, or the `never:` wording.
 */

/** Width of the `[rp]` column, including the space that follows it. */
export const TAG_WIDTH = 9;
/** Width of the event-name column, including the space that follows it. */
export const EVENT_WIDTH = 9;
/** What a continuation line is indented by: tag column + event column. */
export const CONTINUATION_INDENT = " ".repeat(TAG_WIDTH + 1 + EVENT_WIDTH + 1);

const TAG = "[rp]".padEnd(TAG_WIDTH);

/** ANSI green — the color the container-split contract assigns to rp. */
const GREEN = "\x1b[32m";
const BOLD = "\x1b[1m";
const RESET = "\x1b[0m";

/** `DEMO_LOG` defaults to enabled; only the literal `"0"` turns it off. */
function demoLogEnabled(): boolean {
  return (process.env.DEMO_LOG ?? "1") !== "0";
}

/**
 * Colour when the terminal is a TTY or `FORCE_COLOR` is set to anything but `0`, never
 * when `NO_COLOR` is set (section 10). `docker compose logs` is not a TTY and the image
 * sets `FORCE_COLOR=1`, which is why the environment variable has to win over the TTY
 * check; `FORCE_COLOR=0` is the documented way to turn colour back off for the demo,
 * because `NO_COLOR` makes Node itself print a warning.
 */
function colorEnabled(): boolean {
  const noColor = process.env.NO_COLOR;
  if (noColor !== undefined && noColor !== "") return false;
  const force = process.env.FORCE_COLOR;
  if (force === "0" || force === "false") return false;
  if (force !== undefined && force !== "") return true;
  return Boolean(process.stdout.isTTY);
}

function colorize(line: string, bold: boolean): string {
  if (!colorEnabled()) return line;
  return `${bold ? BOLD : ""}${GREEN}${line}${RESET}`;
}

/**
 * Truncates a value to its first 8 characters, with no ellipsis (section 10).
 * The authorization code is a session-scoped, single-use value and is shown this way;
 * long-term secrets are never passed to this function in the first place — there is
 * nothing in this process that qualifies (rp holds no keys at all).
 */
export function truncate8(value: string): string {
  return value.slice(0, 8);
}

/**
 * The `holds:` text of the `● up` line. Public configuration and nothing else: since the
 * token exchange moved into the browser, the rp server keeps no key material and no
 * cache.
 */
export const HELD = "nothing (HTML only)";

/**
 * The `never:` text of the `● up` line. A constant (section 10): the audience compares it
 * across columns, and it is the only place the rp makes the claim. `access_token` is on
 * the list because the browser calls `/token` directly — the token never reaches this
 * process, not even in a request it proxies.
 */
export const NEVER_HELD =
  "pw, A, B_i, ct_i, any node traffic, access_token (handled in browser only)";

/** First line of an event: tag, event name in its own column, then the content. */
function head(event: string, text: string): void {
  if (!demoLogEnabled()) return;
  console.log(colorize(`${TAG} ${event.padEnd(EVENT_WIDTH)} ${text}`, true));
}

/** A refusal: one line, the reason verbatim. */
function reject(event: string, reason: string): void {
  if (!demoLogEnabled()) return;
  console.log(colorize(`${TAG} ✖ ${event} rejected: ${reason}`, true));
}

export interface StartupLogParams {
  /** The authorization server this RP points the browser at. Public configuration. */
  issuer: string;
}

/** Process start: the one place the `holds:` / `never:` claim is made. */
export function logStartup(params: StartupLogParams): void {
  head("● up", `issuer=${params.issuer}   holds: ${HELD}   never: ${NEVER_HELD}`);
}

export interface LandingLogParams {
  /**
   * The `state` just generated for the outgoing `/authorize` URL. Shown in full (section
   * 10): it is a public correlation id, not cryptographic byte material, and truncating
   * it would make it useless for tracing one login across the log columns.
   */
  state: string;
}

/** `GET /`: the landing page hands the browser a fresh `state` for the code flow. */
export function logLanding(params: LandingLogParams): void {
  head("landing", `state=${params.state}  → authorize URL`);
}

export interface CallbackLogParams {
  /**
   * The authorization code from the query string, truncated to 8 chars for display.
   *
   * Since the section 14 revision this is not an opaque handle but the authentication
   * assertion itself — the group-signed JWT the browser assembled at the IdP front end.
   * The log says `code(assertion)` so the audience can see that what travels through the
   * rp is a signed statement the rp cannot have produced, not a database key.
   */
  code: string;
  /** The `state` echoed by the authorization server. Shown in full; the browser checks it. */
  state: string | undefined;
}

/**
 * `GET /callback`: the browser comes back from the authorization server with a code.
 *
 * One line, because that is the whole of the server's involvement. It hands out a page
 * whose inline script does the `/token` call; the code is spent in the browser, not here.
 */
export function logCallback(params: CallbackLogParams): void {
  head(
    "callback",
    `state=${params.state ?? "-"}  ← code(assertion) ${truncate8(params.code)} ` +
      `(query, via browser redirect)  → page with token script`
  );
}

/** `GET /callback` with no usable code: the authorization server's error, or a bad URL. */
export function logCallbackRejected(reason: string): void {
  reject("callback", reason);
}
