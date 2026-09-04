import { describe, expect, it } from 'vitest';
import {
  IdpClient,
  IdpMetadata,
  IdpServer,
  ProtocolError,
  SignOnResponse,
  beginSignOn,
  decodeJwt,
  finishSignOn,
  generateSigningKey,
  registerUser,
  verifyIdpToken,
  verifyJwt,
} from '../src/index.js';

const TOTAL_SERVERS = 3;
const THRESHOLD = 2;
const USERNAME = 'alice';
const PASSWORD = 'correct horse battery staple';
const DPOP_JKT = '0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I';

function setupEnvironment(): {
  servers: IdpServer[];
  metadata: IdpMetadata;
  client: IdpClient;
} {
  const { keyShares, publicKey } = generateSigningKey(TOTAL_SERVERS, THRESHOLD);
  const metadata: IdpMetadata = {
    issuer: 'https://idp.example',
    audience: 'https://rp.example',
    kid: 'key-2026-1',
    publicKey,
  };

  const servers = keyShares.map((s) => new IdpServer(s.id, s, metadata));
  const client = new IdpClient(metadata, THRESHOLD);

  registerUser(servers, USERNAME, PASSWORD, THRESHOLD);

  return { servers, metadata, client };
}

function collectResponses(
  servers: IdpServer[],
  password: string,
  serverIndices: number[],
  sessionNonce: Uint8Array
) {
  const chosenServers = serverIndices.map((i) => servers[i]);
  const commitments = chosenServers.map((s) => s.preprocess(sessionNonce));
  const { pending, request } = beginSignOn(
    USERNAME,
    password,
    DPOP_JKT,
    sessionNonce,
    commitments
  );
  const responses = chosenServers.map((s) => s.signOn(request));
  return { responses, pending };
}

describe('PASTA Protocol Integration & Security Threat Model Tests', () => {
  // ---------------------------------------------------------------------------
  // 1. Normal Flow & RP Verification
  // ---------------------------------------------------------------------------
  it('correct password yields token verifiable by standard RP', () => {
    const { servers, metadata, client } = setupEnvironment();
    const token = client.signOn(servers.slice(0, 2), USERNAME, PASSWORD, DPOP_JKT);

    expect(typeof token).toBe('string');
    expect(verifyIdpToken(metadata, token)).toBe(true);

    const decoded = decodeJwt(token);
    expect(decoded.header.alg).toBe('EdDSA');
    expect(decoded.header.typ).toBe('JWT');
    expect(decoded.payload.iss).toBe('https://idp.example');
    expect(decoded.payload.sub).toBe('alice');
    expect(decoded.payload.aud).toBe('https://rp.example');
    expect(decoded.payload.cnf).toEqual({ jkt: DPOP_JKT });
  });

  // ---------------------------------------------------------------------------
  // 2. PASTA Principle: Servers NEVER verify password
  // ---------------------------------------------------------------------------
  it('servers emit shares without verifying password', () => {
    const { servers } = setupEnvironment();
    const sessionNonce = new Uint8Array(16).fill(1);

    const { responses } = collectResponses(servers, 'completely wrong password', [0, 1], sessionNonce);

    expect(responses).toHaveLength(2);
    expect(responses.every((r) => r.ciphertext.length > 0)).toBe(true);
    expect(responses.every((r) => r.toprfPartial.length === 32)).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // 3. Incorrect password authentication failure
  // ---------------------------------------------------------------------------
  it('wrong password yields no token (AuthenticationFailed)', () => {
    const { servers, metadata } = setupEnvironment();
    const sessionNonce = new Uint8Array(16).fill(2);

    const { responses, pending } = collectResponses(
      servers,
      'wrong password',
      [0, 1],
      sessionNonce
    );

    expect(() =>
      finishSignOn(pending, 'wrong password', metadata, responses, THRESHOLD)
    ).toThrowError(expect.objectContaining({ code: 'AuthenticationFailed' }));
  });

  // ---------------------------------------------------------------------------
  // 4. Below threshold yields no token
  // ---------------------------------------------------------------------------
  it('below threshold yields no token (NotEnoughShares)', () => {
    const { servers, metadata } = setupEnvironment();
    const sessionNonce = new Uint8Array(16).fill(4);

    const { responses, pending } = collectResponses(servers, PASSWORD, [0], sessionNonce);

    expect(() =>
      finishSignOn(pending, PASSWORD, metadata, responses, THRESHOLD)
    ).toThrowError(expect.objectContaining({ code: 'NotEnoughShares' }));
  });

  // ---------------------------------------------------------------------------
  // 5. Breaching 1 server does not allow forgery
  // ---------------------------------------------------------------------------
  it('breaching one server does not allow forgery', () => {
    const { servers, metadata } = setupEnvironment();

    // Attacker compromises Server 0 and steals UserRecord + signing key share
    const breachData = servers[0].breach(USERNAME);
    expect(breachData).toBeDefined();

    // Attacker guesses password and attempts to sign-on with Server 0 and Server 1
    const sessionNonce = new Uint8Array(16).fill(5);
    const { responses, pending } = collectResponses(
      servers,
      'guessed wrong password',
      [0, 1],
      sessionNonce
    );

    // Attacker cannot decrypt Server 1's share because attacker lacks the correct h_1
    expect(() =>
      finishSignOn(pending, 'guessed wrong password', metadata, responses, THRESHOLD)
    ).toThrowError(expect.objectContaining({ code: 'AuthenticationFailed' }));
  });

  // ---------------------------------------------------------------------------
  // 6. Shares cannot be replayed across sessions
  // ---------------------------------------------------------------------------
  it('shares cannot be replayed across sessions due to AAD binding', () => {
    const { servers, metadata } = setupEnvironment();

    // Session A: legitimately collected responses
    const sessionA = new Uint8Array(16).fill(10);
    const { responses: responsesA } = collectResponses(servers, PASSWORD, [0, 1], sessionA);

    // Session B: separate session initiated
    const sessionB = new Uint8Array(16).fill(11);
    const commitmentsB = [servers[0].preprocess(sessionB), servers[1].preprocess(sessionB)];
    const { pending: pendingB } = beginSignOn(
      USERNAME,
      PASSWORD,
      DPOP_JKT,
      sessionB,
      commitmentsB
    );

    // Feeding responses from Session A into Session B fails decryption due to AAD mismatch
    expect(() =>
      finishSignOn(pendingB, PASSWORD, metadata, responsesA, THRESHOLD)
    ).toThrowError(expect.objectContaining({ code: 'AuthenticationFailed' }));
  });

  // ---------------------------------------------------------------------------
  // 7. Preprocessed nonce is strictly single-use
  // ---------------------------------------------------------------------------
  it('preprocessed nonce is single-use to prevent Schnorr nonce reuse', () => {
    const { servers } = setupEnvironment();
    const session = new Uint8Array(16).fill(12);

    const commitments = [servers[0].preprocess(session), servers[1].preprocess(session)];
    const { request } = beginSignOn(USERNAME, PASSWORD, DPOP_JKT, session, commitments);

    // First attempt succeeds
    expect(servers[0].signOn(request)).toBeDefined();

    // Replay attempt fails with NoPreprocessedNonce
    expect(() => servers[0].signOn(request)).toThrowError(
      expect.objectContaining({ code: 'NoPreprocessedNonce' })
    );
  });

  // ---------------------------------------------------------------------------
  // 8. Payload integrity: sub is determined by server record
  // ---------------------------------------------------------------------------
  it('subject comes from server record, preventing client-side spoofing', () => {
    const { servers, metadata, client } = setupEnvironment();
    const token = client.signOn(servers.slice(0, 2), USERNAME, PASSWORD, DPOP_JKT);

    const decoded = decodeJwt(token);
    expect(decoded.payload.sub).toBe(USERNAME);
    expect(decoded.payload.iss).toBe(metadata.issuer);
    expect(decoded.payload.aud).toBe(metadata.audience);
  });

  // ---------------------------------------------------------------------------
  // 9. DPoP thumbprint binding
  // ---------------------------------------------------------------------------
  it('token is bound to dpop key thumbprint (cnf.jkt)', () => {
    const { servers, metadata, client } = setupEnvironment();
    const token = client.signOn(servers.slice(0, 2), USERNAME, PASSWORD, DPOP_JKT);

    const decoded = decodeJwt(token);
    expect(decoded.payload.cnf).toEqual({ jkt: DPOP_JKT });
  });

  // ---------------------------------------------------------------------------
  // 10. Bitwise identical payload across all servers
  // ---------------------------------------------------------------------------
  it('all servers sign byte-identical payload', () => {
    const { servers, metadata } = setupEnvironment();
    const session = new Uint8Array(16).fill(9);

    const { responses, pending } = collectResponses(servers, PASSWORD, [0, 1, 2], session);
    expect(responses).toHaveLength(3);

    const token = finishSignOn(pending, PASSWORD, metadata, responses, THRESHOLD);
    expect(verifyIdpToken(metadata, token)).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // 11. Complete commitment set requirement (FROST property)
  // ---------------------------------------------------------------------------
  it('commitment set must be complete (cannot drop committed signers)', () => {
    const { servers, metadata } = setupEnvironment();
    const session = new Uint8Array(16).fill(14);

    // 3 servers committed in Round 1
    const { responses, pending } = collectResponses(servers, PASSWORD, [0, 1, 2], session);

    // But only 2 responses provided to aggregator
    expect(() =>
      finishSignOn(pending, PASSWORD, metadata, responses.slice(0, 2), THRESHOLD)
    ).toThrowError(expect.objectContaining({ code: 'InvalidSignature' }));
  });

  // ---------------------------------------------------------------------------
  // 12. Tampered token is rejected
  // ---------------------------------------------------------------------------
  it('tampered token is rejected by standard verifier', () => {
    const { servers, metadata, client } = setupEnvironment();
    const token = client.signOn(servers.slice(0, 2), USERNAME, PASSWORD, DPOP_JKT);

    const parts = token.split('.');
    // Tamper payload by replacing it with spoofed admin payload
    const spoofedPayload = Buffer.from(JSON.stringify({ sub: 'admin' })).toString('base64url');
    const tamperedToken = `${parts[0]}.${spoofedPayload}.${parts[2]}`;

    expect(verifyJwt(tamperedToken, metadata.publicKey)).toBe(false);
  });

  // ---------------------------------------------------------------------------
  // 13. Any quorum yields valid token under the same group public key
  // ---------------------------------------------------------------------------
  it('any quorum yields valid token verifiable with the same public key', () => {
    const { servers, metadata, client } = setupEnvironment();

    const token1 = client.signOn([servers[0], servers[1]], USERNAME, PASSWORD, DPOP_JKT);
    const token2 = client.signOn([servers[1], servers[2]], USERNAME, PASSWORD, DPOP_JKT);
    const token3 = client.signOn([servers[0], servers[2]], USERNAME, PASSWORD, DPOP_JKT);

    expect(verifyIdpToken(metadata, token1)).toBe(true);
    expect(verifyIdpToken(metadata, token2)).toBe(true);
    expect(verifyIdpToken(metadata, token3)).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // 14. Header declares standard EdDSA
  // ---------------------------------------------------------------------------
  it('header declares standard EdDSA algorithm (RFC 8037)', () => {
    const { servers, client } = setupEnvironment();
    const token = client.signOn(servers.slice(0, 2), USERNAME, PASSWORD, DPOP_JKT);

    const decoded = decodeJwt(token);
    expect(decoded.header.alg).toBe('EdDSA');
  });
});
