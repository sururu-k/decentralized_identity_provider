/**
 * Demo logging (docs/container-split.md section 10).
 *
 * One event is one or two lines, in English, so the node, gateway, rp and browser columns
 * of a `tmux` screen can be read side by side. The point of the exercise is what each
 * component does *not* have, and that is stated once, on the `● up` line, as `never:`;
 * later events never repeat it.
 *
 * Nothing here reaches into `IdentityNode`. The HTTP handler passes in the values it
 * already has on the wire, and only those: long-lived secrets (`secretKeyShare`, the TOPRF
 * key share, `h_i`) and the password never appear, not even truncated. Per-session values
 * (`A`, `B_i`, `ct_i`, `D`, `E`, `sessionNonce`, `z_i`, a DPoP `jti`, an assertion
 * signature) are cut to their first 8 characters, with no ellipsis.
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
  nodeId: number;
  /** `n` of the `n` nodes, used for the `t=` wording at startup. */
  total?: number | undefined;
  env?: DemoLogEnv;
  /** Whether stdout is a terminal. Defaults to `process.stdout.isTTY`. */
  isTty?: boolean | undefined;
  write?: LogSink;
}

/**
 * The `never:` text of the `● up` line. A constant on purpose (section 10): the audience
 * compares this against the other columns, so it must not move, and it is the only place
 * the claim is made — no later event repeats it.
 *
 * `access tokens` is on the list because of section 14: the node signs a share of one and
 * never sees the assembled token. `sessions` is on it because the node keeps none: the
 * assertion the client presents at `/sign` is the whole record.
 */
export const NEVER_HELD = "pw, h, other s_i/k_i, sessions, access tokens";

/** How many characters of a per-session value are shown. */
export const VALUE_PREFIX_LENGTH = 8;

/** Width of the `[nodeN]` column, including the space that follows it. */
export const TAG_WIDTH = 9;
/** Width of the event-name column, including the space that follows it. */
export const EVENT_WIDTH = 9;
/** What a continuation line is indented by: tag column + event column. */
export const CONTINUATION_INDENT = " ".repeat(TAG_WIDTH + 1 + EVENT_WIDTH + 1);

/**
 * Cuts a base64url value to its first 8 characters, with no ellipsis (section 10).
 *
 * Only ever called on values that are safe to show in part: a blinded point, a TOPRF
 * partial, a ciphertext, a commitment, a session nonce, a masked signature share, an id.
 * Long-term secrets are not passed to this function at all, since a prefix of a key is
 * still key material.
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
 * Colour when the terminal is a TTY or `FORCE_COLOR=1`, never when `NO_COLOR` is set
 * (section 10). `FORCE_COLOR=0` is the usual way to say "no colour" and is honoured too,
 * which matters because `docker compose logs` is not a TTY and the image sets
 * `FORCE_COLOR=1` so the demo stays readable there.
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

/** Blue, getting deeper with the node id (section 10: node = blue, shaded by nodeId). */
const NODE_SHADES = [117, 75, 33];

function nodeColor(nodeId: number): string {
  const index = ((Math.trunc(nodeId) - 1) % NODE_SHADES.length + NODE_SHADES.length) % NODE_SHADES.length;
  return `\x1b[38;5;${NODE_SHADES[index]}m`;
}

export interface StartupInfo {
  threshold: number;
  total: number;
  usernames: string[];
}

export interface CommitInfo {
  roundId: string;
  /** base64url, as sent back on the wire. */
  D: string;
  E: string;
}

export interface SignOnInfo {
  roundId: string;
  sessionId: string;
  username: string;
  /** base64url of A = r·H1(password), as received. */
  blinded: string;
  sessionNonce: string;
  cnfJkt: string;
  /** Number of nodes in this round, from `allParticipants`. */
  participants: number;
  /** base64url of B_i = k_i·A, from the response. */
  toprfPartial: string;
  /** base64url of ct_i, from the response. */
  ct: string;
}

export interface SignInfo {
  /** The access token's round. The refresh token's round is a different one. */
  roundId: string;
  /** Which credential was spent. */
  grant: "authorization_code" | "refresh_token";
  /** base64url of the credential's group signature, its third JWT segment. */
  signature: string;
  /** `jti` of the DPoP proof the node just accepted. */
  jti: string;
  /** Number of nodes in this round, from `allParticipants`. */
  participants: number;
  /** hex of the access token share. Masked by the round nonce, so a prefix is safe. */
  atZ: string;
  /** hex of the refresh token share. */
  rtZ: string;
}

export interface DemoLog {
  readonly enabled: boolean;
  readonly colored: boolean;
  startup(info: StartupInfo): void;
  commit(info: CommitInfo): void;
  signOn(info: SignOnInfo): void;
  sign(info: SignInfo): void;
  /** A refusal, printed as a single `✖` line carrying the reason verbatim. */
  reject(event: string, reason: string): void;
}

/**
 * Builds the demo logger for one node.
 *
 * Disabled loggers keep the same shape and do nothing, so callers never branch.
 */
export function createDemoLog(options: DemoLogOptions): DemoLog {
  const env: DemoLogEnv = options.env ?? (process.env as DemoLogEnv);
  const write: LogSink = options.write ?? ((line) => console.log(line));
  const isTty = options.isTty ?? Boolean(process.stdout.isTTY);

  const enabled = demoLogEnabled(env);
  const colored = enabled && colorEnabled(env, isTty);
  const color = colored ? nodeColor(options.nodeId) : "";
  const tag = `[node${options.nodeId}]`.padEnd(TAG_WIDTH);
  const id = options.nodeId;

  /** The first line of an event: tag, event name in its own column, then the content. */
  const head = (event: string, text: string): void => {
    const line = `${tag} ${event.padEnd(EVENT_WIDTH)} ${text}`;
    write(colored ? `${BOLD}${color}${line}${RESET}` : line);
  };
  /** A continuation line: the same width of blanks, so the columns line up. */
  const cont = (text: string): void => {
    const line = `${CONTINUATION_INDENT}${text}`;
    write(colored ? `${color}${line}${RESET}` : line);
  };

  const noop: DemoLog = {
    enabled: false,
    colored: false,
    startup: () => {},
    commit: () => {},
    signOn: () => {},
    sign: () => {},
    reject: () => {},
  };
  if (!enabled) return noop;

  return {
    enabled,
    colored,

    startup(info) {
      const users = info.usernames.join(",") || "-";
      head(
        "● up",
        `id=${id} t=${info.threshold}/${info.total} users=${users}   ` +
          `holds: s_${id}, k_${id}, h_${id}(${users})   never: ${NEVER_HELD}`
      );
    },

    commit(info) {
      head(
        "commit",
        `round=${shortId(info.roundId)}  → D_${id},E_${id} ${shortValue(info.D)} ${shortValue(info.E)}`
      );
    },

    signOn(info) {
      head(
        "sign-on",
        `sess=${shortId(info.sessionId)} round=${shortId(info.roundId)} user=${info.username}  ` +
          `← A ${shortValue(info.blinded)}  (D,E)×${info.participants}  ` +
          `nonce_s ${shortValue(info.sessionNonce)}  jkt ${shortValue(info.cnfJkt)}`
      );
      cont(
        `→ B_${id}=k_${id}·A ${shortValue(info.toprfPartial)}  ` +
          `ct_${id}=AEAD_h${id}(z_${id}) ${shortValue(info.ct)}`
      );
    },

    sign(info) {
      const received =
        info.grant === "authorization_code"
          ? `← assertion σ ${shortValue(info.signature)} ✓`
          : `← refresh_token σ ${shortValue(info.signature)} ✓ (typ=refresh+jwt)`;
      head(
        "sign",
        `round=${shortId(info.roundId)} grant=${info.grant === "authorization_code" ? "authz" : "refresh"}  ` +
          `${received}  DPoP ✓ jti ${shortValue(info.jti)}  (D,E)×${info.participants}  ` +
          `→ at z_${id} ${shortValue(info.atZ)} + ` +
          `rt${info.grant === "authorization_code" ? "(refresh+jwt)" : ""} z_${id} ${shortValue(info.rtZ)}`
      );
    },

    reject(event, reason) {
      const line = `${tag} ✖ ${event} rejected: ${reason}`;
      write(colored ? `${BOLD}${color}${line}${RESET}` : line);
    },
  };
}
