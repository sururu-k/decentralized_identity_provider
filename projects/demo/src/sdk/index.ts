/**
 * Browser client SDK for the decentralized IdP (docs/container-split.md section 11).
 *
 * `import "./buffer-shim.js"` comes first: the frozen crypto copies use the Node global
 * `Buffer` and the browser has none.
 */
import "./buffer-shim.js";

export {
  ASSERTION_LIFETIME_SECONDS,
  DecentralizedClientSdk,
  type ClientAuthConfig,
  type ClientSignOnOptions,
  type StoredSession,
} from "./client.js";
export {
  CONTINUATION_INDENT,
  DEMO_PREFIX,
  EVENT_WIDTH,
  TAG_WIDTH,
  colorizeDemoLine,
  contLine,
  headLine,
  rejectEvent,
  stepEvent,
  trunc,
  truncScalar,
  type DemoEvent,
  type DemoEventSink,
  type DemoStep,
} from "./events.js";
export {
  assembleJwt,
  base64UrlDecode,
  base64UrlEncode,
  createSigningInput,
  deterministicJsonStringify,
  verifyJwt,
  type VerifyJwtResult,
} from "./jwt.js";
export {
  calculateJwkThumbprint,
  createDPoPProof,
  exportDPoPJwk,
  generateDPoPKeyPair,
  type DPoPJwk,
  type DPoPKeyPair,
} from "./dpop.js";
export { signOnResultFromWire } from "./wire.js";
export type {
  ProxySignOnRequestBody,
  ProxySignOnResult,
  SignOnResponse,
} from "./types.js";
