/**
 * Demo-log output for the RP.
 *
 * `docs/container-split.md` section 10: every component in the demo emits the same
 * compact one-or-two-line shape to stdout, in English, so an audience watching the
 * node / gateway / rp / browser columns side by side can see that only the browser ever
 * assembles a full `id_token` — the rp only ever sees the finished token over form_post
 * and the IdP's *public* signing key. What the rp cannot hold is stated once, on the
 * `● up` line, as `never:`; no later event repeats it.
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
 * Session-scoped, single-use values (`id_token`, …) are shown this way; long-term secrets
 * are never passed to this function in the first place — there is nothing in this process
 * that qualifies (rp holds no keys at all).
 */
export function truncate8(value: string): string {
  return value.slice(0, 8);
}

/**
 * The `never:` text of the `● up` line. A constant (section 10): the audience compares it
 * across columns, and it is the only place the rp makes the claim.
 */
export const NEVER_HELD = "pw, A, B_i, ct_i, any node traffic";

/** First line of an event: tag, event name in its own column, then the content. */
function head(event: string, text: string): void {
  if (!demoLogEnabled()) return;
  console.log(colorize(`${TAG} ${event.padEnd(EVENT_WIDTH)} ${text}`, true));
}

/** Continuation line: the same width of blanks, so the columns line up. */
function cont(text: string): void {
  if (!demoLogEnabled()) return;
  console.log(colorize(`${CONTINUATION_INDENT}${text}`, false));
}

/** A refusal: one line, the reason verbatim. */
function reject(event: string, reason: string): void {
  if (!demoLogEnabled()) return;
  console.log(colorize(`${TAG} ✖ ${event} rejected: ${reason}`, true));
}

export interface StartupLogParams {
  /** The IdP this RP trusts. Public configuration. */
  issuer: string;
}

/** Process start: the one place the `holds:` / `never:` claim is made. */
export function logStartup(params: StartupLogParams): void {
  head(
    "● up",
    `issuer=${params.issuer}   holds: JWKS(kid) only   never: ${NEVER_HELD}`
  );
}

export interface LandingLogParams {
  /**
   * The nonce just generated for the outgoing `/authorize` URL. Shown in full (section
   * 10): the OIDC `nonce` is a public correlation id, not cryptographic byte material,
   * and truncating it would make it useless for tracing one login across the log columns.
   */
  nonce: string;
  /** The state just generated for the outgoing `/authorize` URL. Shown in full: it is not a secret. */
  state: string;
}

/** `GET /`: the landing page hands the browser a fresh nonce/state pair. */
export function logLanding(params: LandingLogParams): void {
  head("landing", `nonce=${params.nonce} state=${params.state}  → authorize URL`);
}

/**
 * How `/callback` ended up, in enough detail to render the second line and, on anything
 * but success, the `✖` line instead of it.
 */
export type CallbackOutcome =
  | {
      kind: "verified";
      kid: string;
      iss: string;
      aud: string;
      expRemainingSeconds: number;
      sub: string;
    }
  | { kind: "verification_failed"; kid: string | undefined; reason: string }
  | { kind: "jwks_unreachable"; kid: string | undefined; reason: string }
  | { kind: "parse_failed"; reason: string };

export interface CallbackLogParams {
  /** The raw `id_token` from the form_post body, truncated to 8 chars for display. */
  idToken: string;
  /** The `state` echoed by the form_post body, shown in full (display-only, never a secret). */
  state: string | undefined;
  /** Where the JWKS was (or would have been) fetched from. */
  idpInternalUrl: string;
  outcome: CallbackOutcome;
}

function formatKid(kid: string | undefined): string {
  return kid ?? "?";
}

/**
 * `POST /callback`: the browser's finished `id_token` arrives over form_post.
 *
 * Success is two lines: what arrived, then what the RP checked with the IdP's public key.
 * A refusal keeps the first line — the audience still sees what arrived — and replaces
 * the second with the shared `✖ <event> rejected: <reason>` line (section 10).
 */
export function logCallback(params: CallbackLogParams): void {
  head(
    "callback",
    `state=${params.state ?? "-"}  ← id_token ${truncate8(params.idToken)} ` +
      `(direct from browser, not via gateway)`
  );

  const outcome = params.outcome;
  switch (outcome.kind) {
    case "parse_failed":
      reject("callback", `JWT parse failed before JWKS lookup: ${outcome.reason}`);
      return;
    case "jwks_unreachable":
      reject(
        "callback",
        `JWKS(kid=${formatKid(outcome.kid)}) unreachable at ${params.idpInternalUrl}: ${outcome.reason}`
      );
      return;
    case "verification_failed":
      reject("callback", outcome.reason);
      return;
    case "verified":
      cont(
        `JWKS kid=${outcome.kid} → Ed25519 ✓  iss ✓  aud ✓  ` +
          `exp ${outcome.expRemainingSeconds}s  sub=${outcome.sub}`
      );
  }
}

/**
 * JWKS fetch (first request or a kid-triggered refetch). Public information only, so a
 * single line.
 */
export function logJwksFetch(): void {
  head("jwks", "public only");
}
