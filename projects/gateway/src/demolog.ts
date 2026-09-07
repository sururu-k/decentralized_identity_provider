/**
 * Demo logging for the gateway (`docs/container-split.md` section 10).
 *
 * One event is one or two lines, in English, printed in the same shape the node, rp and
 * browser columns use, so a `tmux` screen showing all five columns can be read across.
 * What the gateway cannot hold is stated once, on the `● up` line, as `never:`; later
 * events never repeat it.
 *
 * The gateway's own claim is the strongest one in the demo: it relays. It never receives
 * a password (`/api/pasta/browser-sign-on` was removed, section 11), it cannot unblind
 * `A` because it does not know `r`, and it cannot open any `ct_i` because it holds no
 * `h_i`. Every value that reaches this module is therefore either public or a blinded /
 * encrypted per-session value, cut to its first 8 characters.
 *
 * None of the `*Info` shapes below has a `password` field, and each declares
 * `password?: never` so that a caller which tries to pass one fails to compile. There is
 * nothing to redact at runtime because nothing that carries a password can be handed in.
 */

/** Where a line goes. Injectable so tests can capture instead of printing. */
export type LogSink = (line: string) => void;

/** The subset of `process.env` this module reads. */
export interface DemoLogEnv {
  DEMO_LOG?: string | undefined;
  NO_COLOR?: string | undefined;
  FORCE_COLOR?: string | undefined;
}

export interface DemoLogOptions {
  env?: DemoLogEnv;
  /** Whether stdout is a terminal. Defaults to `process.stdout.isTTY`. */
  isTty?: boolean | undefined;
  write?: LogSink;
}

/**
 * The `never:` text of the `● up` line. A constant on purpose (section 10): the audience
 * compares it across columns, and it is the only place the claim is made.
 */
export const NEVER_HELD = "s_i, k_i, h_i, pw";

/** How many characters of a per-session value are shown. */
export const VALUE_PREFIX_LENGTH = 8;

/** Width of the `[gateway]` column, including the space that follows it. */
export const TAG_WIDTH = 9;
/** Width of the event-name column, including the space that follows it. */
export const EVENT_WIDTH = 9;
/** What a continuation line is indented by: tag column + event column. */
export const CONTINUATION_INDENT = " ".repeat(TAG_WIDTH + 1 + EVENT_WIDTH + 1);

/**
 * Cuts a base64url value to its first 8 characters, with no ellipsis (section 10).
 *
 * Only ever called on values that are safe to show in part: the blinded point `A`, a
 * `cnf.jkt` thumbprint, a credential or token bound to `cnf.jkt`, an id. The gateway holds
 * no long-term secret of its own, so nothing that would be unsafe even truncated can reach
 * this function.
 */
export function shortValue(value: string | undefined): string {
  if (value === undefined || value === "") return "-";
  return value.slice(0, VALUE_PREFIX_LENGTH);
}

/** Ids (`sess=`, `round=`) are shown the same way: a bare 8-character prefix. */
export const shortId = shortValue;

/**
 * `DEMO_LOG` gates the whole thing. Default on (section 10); `0` turns it off and leaves
 * only the operational log lines.
 */
export function demoLogEnabled(env: DemoLogEnv): boolean {
  return env.DEMO_LOG !== "0";
}

/**
 * Colour when the terminal is a TTY or `FORCE_COLOR` is set to anything but `0`, never
 * when `NO_COLOR` is set (section 10). `docker compose logs` is not a TTY and the image
 * sets `FORCE_COLOR=1`, which is why the environment variable has to win over the TTY
 * check; `FORCE_COLOR=0` is the documented way to turn colour back off for the demo,
 * because `NO_COLOR` makes Node itself print a warning.
 */
export function colorEnabled(env: DemoLogEnv, isTty: boolean): boolean {
  if (env.NO_COLOR !== undefined && env.NO_COLOR !== "") return false;
  const force = env.FORCE_COLOR;
  if (force === "0" || force === "false") return false;
  if (force !== undefined && force !== "") return true;
  return isTty;
}

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
/** Magenta — the colour section 10 assigns to the gateway. */
const MAGENTA = "\x1b[35m";

const TAG = "[gateway]".padEnd(TAG_WIDTH);

export interface StartupInfo {
  issuer: string;
  threshold: number;
  /** Number of nodes the gateway discovered. */
  total: number;
  keyId: string;
  nodeUrls: string[];
  password?: never;
}

export interface AuthorizeInfo {
  clientId: string;
  redirectUri: string;
  nonce: string;
  state: string | undefined;
  /** The RP front end's DPoP thumbprint, carried through to the demo UI (section 13). */
  dpopJkt: string;
  password?: never;
}

/** A node the gateway dropped from the round because it did not answer round 1. */
export interface ExcludedNode {
  nodeId: number;
  reason: string;
}

export interface SignOnInfo {
  sessionId: string;
  roundId: string;
  /** Node ids that actually committed, in ascending order. */
  participants: number[];
  /** base64url of A = r·H1(password), as received. The gateway cannot unblind it. */
  blinded: string;
  cnfJkt: string;
  username: string;
  /** The OIDC nonce, shown in full: it is the client's own public correlation id. */
  nonce: string;
  excluded: ExcludedNode[];
  password?: never;
}

export interface TokenInfo {
  /** Which credential the client spent. */
  grant: "authorization_code" | "refresh_token";
  /** The credential (assertion or refresh token). Shown as its first 8 characters. */
  credential: string;
  /** The synthesised access token. Bound to `cnf.jkt`, so shown as its first 16. */
  accessToken: string;
  cnfJkt: string;
  participants: number[];
  excluded: ExcludedNode[];
  password?: never;
}

export interface DemoLog {
  readonly enabled: boolean;
  readonly colored: boolean;
  startup(info: StartupInfo): void;
  authorize(info: AuthorizeInfo): void;
  signOn(info: SignOnInfo): void;
  /** `POST /token` — synthesises the access token and next refresh token (section 14). */
  token(info: TokenInfo): void;
  /** `GET /jwks.json` — public key material only, so a single line. */
  jwks(): void;
  /** `GET /.well-known/openid-configuration` — public metadata only. */
  discovery(): void;
  /** A refusal, printed as a single `✖` line carrying the reason verbatim. */
  reject(event: string, reason: string): void;
}

/** ` (node3 unreachable, excluded)` — the phrase the demo grep looks for. */
export function excludedPhrase(excluded: ExcludedNode[]): string {
  if (excluded.length === 0) return "";
  const names = excluded.map((e) => `node${e.nodeId}`).join(", ");
  return ` (${names} unreachable, excluded)`;
}

/**
 * Builds the gateway's demo logger.
 *
 * Disabled loggers keep the same shape and do nothing, so callers never branch.
 */
export function createDemoLog(options: DemoLogOptions = {}): DemoLog {
  const env: DemoLogEnv = options.env ?? (process.env as DemoLogEnv);
  const write: LogSink = options.write ?? ((line) => console.log(line));
  const isTty = options.isTty ?? Boolean(process.stdout.isTTY);

  const enabled = demoLogEnabled(env);
  const colored = enabled && colorEnabled(env, isTty);

  /** The first line of an event: tag, event name in its own column, then the content. */
  const head = (event: string, text: string): void => {
    const line = `${TAG} ${event.padEnd(EVENT_WIDTH)} ${text}`;
    write(colored ? `${BOLD}${MAGENTA}${line}${RESET}` : line);
  };
  /** A continuation line: the same width of blanks, so the columns line up. */
  const cont = (text: string): void => {
    const line = `${CONTINUATION_INDENT}${text}`;
    write(colored ? `${MAGENTA}${line}${RESET}` : line);
  };

  const noop: DemoLog = {
    enabled: false,
    colored: false,
    startup: () => {},
    authorize: () => {},
    signOn: () => {},
    token: () => {},
    jwks: () => {},
    discovery: () => {},
    reject: () => {},
  };
  if (!enabled) return noop;

  return {
    enabled,
    colored,

    startup(info) {
      head(
        "● up",
        `t=${info.threshold}/${info.total} nodes=${info.nodeUrls.length} issuer=${info.issuer}   ` +
          `holds: group pubkey, kid=${info.keyId}   never: ${NEVER_HELD}`
      );
    },

    authorize(info) {
      // nonce/state are public correlation ids (section 10), never truncated. dpop_jkt is
      // a cryptographic value, so it is cut to 8 characters like every other one.
      head(
        "authorize",
        `client_id=${info.clientId} nonce=${info.nonce} state=${info.state ?? "-"} ` +
          `dpop_jkt=${shortValue(info.dpopJkt)}  → redirect /demo`
      );
    },

    signOn(info) {
      const n = info.participants.length;
      head(
        "sign-on",
        `sess=${shortId(info.sessionId)} round=${shortId(info.roundId)} user=${info.username} ` +
          `nonce=${info.nonce}  ← A ${shortValue(info.blinded)}  jkt ${shortValue(info.cnfJkt)}  (no pw)`
      );
      cont(
        `round1 (D,E)×${n}${excludedPhrase(info.excluded)} → round2 ` +
          `← B_i×${n} ct_i×${n} (no h_i, cannot decrypt) → relayed as-is`
      );
    },

    token(info) {
      const grantLabel = info.grant === "authorization_code" ? "authz" : "refresh";
      const credLabel = info.grant === "authorization_code" ? "code(assertion)" : "refresh_token";
      const n = info.participants.length;
      // Both synthesised tokens are bound to cnf.jkt, so the access token is safe to show
      // in part (section 14.2). The credential is a single-use signed value, cut to 8.
      head(
        "token",
        `grant=${grantLabel}  ← ${credLabel} ${shortValue(info.credential)} + DPoP ✓` +
          `${excludedPhrase(info.excluded)}  → 2×/commit ×${n} → /sign → ` +
          `access_token ${info.accessToken.slice(0, 16)} (cnf.jkt=${shortValue(info.cnfJkt)}) + refresh_token`
      );
    },

    jwks() {
      head("jwks", "public only");
    },

    discovery() {
      head("discovery", "public only");
    },

    reject(event, reason) {
      const line = `${TAG} ✖ ${event} rejected: ${reason}`;
      write(colored ? `${BOLD}${MAGENTA}${line}${RESET}` : line);
    },
  };
}
