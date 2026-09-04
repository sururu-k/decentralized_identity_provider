// Crypto primitives
export {
  ED25519_ORDER,
  type ParticipantId,
  type Share,
  mod,
  invert,
  modPow,
  bytesToBigIntLE,
  bigIntToBytesLE,
  bytesToScalar,
  scalarToBytes,
  randomScalar,
  splitSecret,
  lagrangeCoeff,
  combineShares,
} from './crypto/shamir.js';

export {
  type RistrettoPoint,
  type Blinding,
  type PartialEvaluation,
  hashToGroup,
  blind,
  evaluate,
  unblind,
  finalize,
  deriveServerKey,
  deriveServerKeyHkdf,
  generateToprfKey,
} from './crypto/toprf.js';

export {
  type ExtendedPoint,
  type Nonces,
  type Commitment,
  generateKey as generateSigningKey,
  commit,
  encodeCommitments,
  bindingFactor,
  computeGroupCommitment,
  computeChallenge,
  signShare,
  aggregateSignatures,
  verifySignature,
} from './crypto/tsign.js';

export {
  deriveAeadNonce,
  aeadEncrypt,
  aeadDecrypt,
} from './crypto/aead.js';

// JWT handling
export {
  TIME_QUANTUM,
  TOKEN_LIFETIME,
  type JwtClaims,
  quantizeTime,
  base64urlEncode,
  base64urlDecode,
  deriveJti,
  claimsToJson,
  buildHeader,
  buildSigningInput,
  assembleJwt,
} from './jwt/builder.js';

export {
  type DecodedJwt,
  decodeJwt,
  verifyJwt,
} from './jwt/verifier.js';

// Distributed IdP Protocol
export {
  type IdpMetadata,
  type UserRecord,
  type SignOnRequest,
  type SignOnResponse,
  type PendingSignOn,
  type ProtocolErrorCode,
  ProtocolError,
} from './protocol/types.js';

export {
  IdpServer,
  now,
  buildIdpSigningInput,
} from './protocol/server.js';

export {
  registerUser,
  beginSignOn,
  finishSignOn,
  verifyIdpToken,
  IdpClient,
} from './protocol/client.js';

export {
  IdentityNode,
  registerUserToNodes,
  type UserRecord as NodeUserRecord,
  type SignOnRequest as NodeSignOnRequest,
  type SignOnResponse as NodeSignOnResponse,
  type RefreshRequest as NodeRefreshRequest,
  type RefreshResponse as NodeRefreshResponse,
} from './protocol/node.js';

// OAuth 2.0 / OIDC Client SDK & DPoP (Holes 2, 4, 7)
export {
  type DPoPKeyPair,
  type DPoPJwk,
  type DPoPProofHeader,
  type DPoPProofPayload,
  generateDPoPKeyPair,
  exportDPoPJwk,
  calculateJwkThumbprint,
  createDPoPProof,
  verifyDPoPProof,
} from './client-sdk/dpop.js';

export {
  type FormPostParams,
  escapeHtml,
  generateFormPostHtml,
  submitFormPost,
} from './client-sdk/form-post.js';

export {
  DecentralizedClientSdk,
  type ClientAuthConfig,
  type ClientSignOnOptions,
  type ClientRefreshOptions,
  type StoredSession,
} from './client-sdk/client.js';

// OAuth Proxy & OIDC Gateway (Holes 2 & 5)
export {
  PastaOAuthProxy,
  type ProxySignOnRequestBody,
  type ProxySignOnResult,
  type ProxyRefreshRequestBody,
  type ProxyRefreshResult,
} from './gateway/proxy.js';

export {
  GatewaySessionManager,
  type ProxySessionInfo,
  type NodeSessionAudit,
} from './gateway/session.js';

export {
  OidcEndpointHandler,
  type OidcConfigOptions,
  type AuthorizeQueryParams,
  type AuthorizeValidationResult,
} from './gateway/oidc.js';

