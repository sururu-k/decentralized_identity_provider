/**
 * Demo log events for the browser / CLI column of docs/container-split.md section 10.
 *
 * This module is an addition to the port, not part of the reference SDK. The SDK calls
 * `onEvent` at each protocol step; the demo UI pushes the lines into its log tab and
 * `console.log`, and the CLI stand-in writes them to stderr. Sign-on is one event of
 * three lines — blind, response, aggregate — in the same column widths the node, gateway
 * and rp components print, so the terminals can be read side by side. Since section 14 the
 * IdP front end no longer refreshes (the rp front end does, at `/token`), so there is no
 * refresh event here.
 *
 * Nothing secret reaches a line. The password, the master PRF value `h` and the derived
 * `h_i` are never passed in. Per-session values (`r`, `A`, `B_i`, `ct_i`, `z_i`, `R`,
 * `sessionNonce`) are cut to their first 8 characters, with no ellipsis.
 */

export const DEMO_PREFIX = "[browser]";

/** Width of the `[browser]` column, including the space that follows it. */
export const TAG_WIDTH = 9;
/** Width of the event-name column, including the space that follows it. */
export const EVENT_WIDTH = 9;
/** What a continuation line is indented by: tag column + event column. */
export const CONTINUATION_INDENT = " ".repeat(TAG_WIDTH + 1 + EVENT_WIDTH + 1);

/**
 * Stable identifier of the protocol step an event belongs to. The UI keys its node
 * animation off this instead of parsing the line text.
 */
export type DemoStep =
  | "signon-blind"
  | "signon-response"
  | "signon-aggregate"
  | "signon-reject";

export interface DemoEvent {
  kind: "step" | "reject";
  step: DemoStep;
  /** Ready to print, `[browser]` prefixed, uncolored. */
  lines: string[];
}

export type DemoEventSink = (event: DemoEvent) => void;

/** First 8 characters of a base64url value, as section 10 requires. No ellipsis. */
export function trunc(value: string): string {
  return value.slice(0, 8);
}

/** First 8 hex characters of a scalar (z_i, r). Never used for h or h_i. */
export function truncScalar(value: bigint): string {
  return trunc(value.toString(16).padStart(64, "0"));
}

/** The opening line of an event: prefix, event name in its own column, then content. */
export function headLine(event: string, text: string): string {
  return `${DEMO_PREFIX.padEnd(TAG_WIDTH)} ${event.padEnd(EVENT_WIDTH)} ${text}`;
}

/** A continuation line of the event above it. */
export function contLine(text: string): string {
  return `${CONTINUATION_INDENT}${text}`;
}

/** One step of a multi-line event. `event` is `undefined` on a continuation. */
export function stepEvent(step: DemoStep, event: string | undefined, text: string): DemoEvent {
  return {
    kind: "step",
    step,
    lines: [event === undefined ? contLine(text) : headLine(event, text)],
  };
}

/**
 * A failure. The browser says `failed:` rather than `rejected:` (section 10): nothing
 * refused it — the AEAD tag did not match here, and no node can tell.
 */
export function rejectEvent(step: DemoStep, event: string, reason: string): DemoEvent {
  return {
    kind: "reject",
    step,
    lines: [`${DEMO_PREFIX.padEnd(TAG_WIDTH)} ✖ ${event} failed: ${reason}`],
  };
}

/**
 * ANSI yellow for the browser / CLI column (section 10). Callers decide whether colour is
 * wanted; this only wraps.
 */
export function colorizeDemoLine(line: string): string {
  return `\u001b[33m${line}\u001b[0m`;
}
