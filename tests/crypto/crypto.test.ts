import { describe, expect, it } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import {
  combineShares,
  lagrangeCoeff,
  randomScalar,
  splitSecret,
} from '../../src/crypto/shamir.js';
import {
  blind,
  deriveServerKey,
  evaluate,
  finalize,
  generateToprfKey,
  unblind,
} from '../../src/crypto/toprf.js';
import {
  aggregateSignatures,
  commit,
  generateKey as generateSigningKey,
  signShare,
  verifySignature,
} from '../../src/crypto/tsign.js';
import { aeadDecrypt, aeadEncrypt, deriveAeadNonce } from '../../src/crypto/aead.js';
import {
  assembleJwt,
  buildHeader,
  buildSigningInput,
  claimsToJson,
  deriveJti,
  quantizeTime,
  TIME_QUANTUM,
} from '../../src/jwt/builder.js';
import { decodeJwt, verifyJwt } from '../../src/jwt/verifier.js';

describe('Shamir Secret Sharing (src/crypto/shamir.ts)', () => {
  it('t-of-n reconstructs original secret for any t shares', () => {
    const secret = randomScalar();
    const shares = splitSecret(secret, 3, 5);

    // Any subset of 3 shares can reconstruct
    expect(combineShares(shares.slice(0, 3))).toBe(secret);
    expect(combineShares([shares[0], shares[2], shares[4]])).toBe(secret);
    expect(combineShares([shares[1], shares[3], shares[4]])).toBe(secret);
  });

  it('fewer than t shares cannot reconstruct original secret', () => {
    const secret = randomScalar();
    const shares = splitSecret(secret, 3, 5);

    expect(combineShares(shares.slice(0, 2))).not.toBe(secret);
  });
});

describe('2HashTDH Threshold OPRF (src/crypto/toprf.ts)', () => {
  it('any quorum of t servers yields identical PRF output h', () => {
    const total = 5;
    const threshold = 3;
    const keyShares = generateToprfKey(total, threshold);
    const password = 'correct horse battery staple';

    const evaluateSubset = (subsetIndices: number[]) => {
      const { blinding, blinded } = blind(password);
      const partials = subsetIndices.map((i) => ({
        id: keyShares[i].id,
        point: evaluate(keyShares[i], blinded),
      }));
      const v = unblind(blinding, partials);
      return finalize(password, v);
    };

    const h1 = evaluateSubset([0, 1, 2]);
    const h2 = evaluateSubset([2, 3, 4]);
    const h3 = evaluateSubset([1, 2, 4]);

    expect(Buffer.from(h1).toString('hex')).toBe(Buffer.from(h2).toString('hex'));
    expect(Buffer.from(h1).toString('hex')).toBe(Buffer.from(h3).toString('hex'));
  });

  it('different password yields different output', () => {
    const keyShares = generateToprfKey(3, 2);

    const run = (pw: string) => {
      const { blinding, blinded } = blind(pw);
      const partials = keyShares.slice(0, 2).map((s) => ({
        id: s.id,
        point: evaluate(s, blinded),
      }));
      return finalize(pw, unblind(blinding, partials));
    };

    expect(Buffer.from(run('hunter2')).toString('hex')).not.toBe(
      Buffer.from(run('hunter3')).toString('hex')
    );
  });

  it('below threshold fails to reconstruct PRF output', () => {
    const keyShares = generateToprfKey(5, 3);
    const password = 'my-secret-password';

    const { blinding, blinded } = blind(password);
    const fullPartials = keyShares.slice(0, 3).map((s) => ({
      id: s.id,
      point: evaluate(s, blinded),
    }));
    const shortPartials = keyShares.slice(0, 2).map((s) => ({
      id: s.id,
      point: evaluate(s, blinded),
    }));

    const hFull = finalize(password, unblind(blinding, fullPartials));
    const hShort = finalize(password, unblind(blinding, shortPartials));

    expect(Buffer.from(hFull).toString('hex')).not.toBe(Buffer.from(hShort).toString('hex'));
  });

  it('deriveServerKey derives distinct keys per server id', () => {
    const h = new Uint8Array(32).fill(7);
    const k1 = deriveServerKey(h, 1);
    const k2 = deriveServerKey(h, 2);
    expect(k1).toHaveLength(32);
    expect(k2).toHaveLength(32);
    expect(Buffer.from(k1).toString('hex')).not.toBe(Buffer.from(k2).toString('hex'));
  });
});

describe('FROST Threshold Signatures on Ed25519 (src/crypto/tsign.ts)', () => {
  it('generates standard RFC 8032 Ed25519 signature verifiable with noble ed25519.verify', () => {
    const { keyShares, publicKey } = generateSigningKey(5, 3);
    const message = new TextEncoder().encode('threshold signature payload test');

    const signers = [0, 1, 2];
    const prepared = signers.map((i) => commit(keyShares[i].id));
    const commitments = prepared.map((p) => p.commitment);

    const shares = signers.map((idx, i) =>
      signShare(keyShares[idx], prepared[i].nonces, message, commitments, publicKey)
    );

    const sig = aggregateSignatures(message, commitments, shares);
    expect(sig).toHaveLength(64);

    // Verify with our module's verifySignature
    expect(verifySignature(publicKey, message, sig)).toBe(true);
    // Verify directly with @noble/curves standard Ed25519 verifier
    expect(ed25519.verify(sig, message, publicKey)).toBe(true);
  });

  it('any quorum produces valid signature for the same public key', () => {
    const { keyShares, publicKey } = generateSigningKey(5, 3);
    const message = new TextEncoder().encode('any quorum test');

    const runQuorum = (indices: number[]) => {
      const prepared = indices.map((i) => commit(keyShares[i].id));
      const commitments = prepared.map((p) => p.commitment);
      const shares = indices.map((idx, i) =>
        signShare(keyShares[idx], prepared[i].nonces, message, commitments, publicKey)
      );
      return aggregateSignatures(message, commitments, shares);
    };

    const sig1 = runQuorum([0, 1, 2]);
    const sig2 = runQuorum([1, 3, 4]);

    expect(verifySignature(publicKey, message, sig1)).toBe(true);
    expect(verifySignature(publicKey, message, sig2)).toBe(true);
  });

  it('below threshold produces invalid signature', () => {
    const { keyShares, publicKey } = generateSigningKey(5, 3);
    const message = new TextEncoder().encode('below threshold test');

    const indices = [0, 1]; // 2 of 3
    const prepared = indices.map((i) => commit(keyShares[i].id));
    const commitments = prepared.map((p) => p.commitment);
    const shares = indices.map((idx, i) =>
      signShare(keyShares[idx], prepared[i].nonces, message, commitments, publicKey)
    );

    const sig = aggregateSignatures(message, commitments, shares);
    expect(verifySignature(publicKey, message, sig)).toBe(false);
  });
});

describe('AEAD ChaCha20-Poly1305 with AAD (src/crypto/aead.ts)', () => {
  it('encrypts and decrypts with matching key, nonce, and AAD', () => {
    const key = new Uint8Array(32).fill(0xaa);
    const nonce = deriveAeadNonce(new Uint8Array(16).fill(1), 1);
    const plaintext = new Uint8Array([10, 20, 30, 40]);
    const aad = new TextEncoder().encode('session-bound-aad');

    const ct = aeadEncrypt(key, nonce, plaintext, aad);
    expect(ct.length).toBe(plaintext.length + 16);

    const decrypted = aeadDecrypt(key, nonce, ct, aad);
    expect(decrypted).toEqual(plaintext);
  });

  it('fails decryption if AAD is mismatched or tampered', () => {
    const key = new Uint8Array(32).fill(0xaa);
    const nonce = deriveAeadNonce(new Uint8Array(16).fill(1), 1);
    const plaintext = new Uint8Array([10, 20, 30, 40]);
    const aad1 = new TextEncoder().encode('aad-session-1');
    const aad2 = new TextEncoder().encode('aad-session-2');

    const ct = aeadEncrypt(key, nonce, plaintext, aad1);
    expect(() => aeadDecrypt(key, nonce, ct, aad2)).toThrow();
  });
});

describe('Deterministic JWT (src/jwt/builder.ts & src/jwt/verifier.ts)', () => {
  it('serializes claims deterministically with fixed key order', () => {
    const claims = {
      iss: 'https://idp.example',
      sub: 'alice',
      aud: 'https://rp.example',
      iat: 1700000010,
      exp: 1700000310,
      jti: 'abc123',
      cnfJkt: 'thumbprint',
    };
    const json = claimsToJson(claims);
    expect(json).toBe(
      '{"iss":"https://idp.example","sub":"alice","aud":"https://rp.example","iat":1700000010,"exp":1700000310,"jti":"abc123","cnf":{"jkt":"thumbprint"}}'
    );
  });

  it('assembles and verifies standard JWT', () => {
    const { publicKey, keyShares } = generateSigningKey(3, 2);
    const headerJson = buildHeader('key-1');
    const claimsJson = claimsToJson({
      iss: 'https://idp.example',
      sub: 'alice',
      aud: 'https://rp.example',
      iat: 1700000000,
      exp: 1700000300,
      jti: 'jti-123',
      cnfJkt: 'jkt-456',
    });

    const signingInput = buildSigningInput(headerJson, claimsJson);
    const inputBytes = new TextEncoder().encode(signingInput);

    const signers = [0, 1];
    const prepared = signers.map((i) => commit(keyShares[i].id));
    const commitments = prepared.map((p) => p.commitment);
    const shares = signers.map((idx, i) =>
      signShare(keyShares[idx], prepared[i].nonces, inputBytes, commitments, publicKey)
    );
    const sig = aggregateSignatures(inputBytes, commitments, shares);

    const token = assembleJwt(signingInput, sig);

    expect(verifyJwt(token, publicKey)).toBe(true);

    const decoded = decodeJwt(token);
    expect(decoded.header.alg).toBe('EdDSA');
    expect(decoded.payload.sub).toBe('alice');
  });

  it('quantizeTime rounds down to quantum multiples', () => {
    expect(quantizeTime(1700000000)).toBe(quantizeTime(1700000005));
    expect(quantizeTime(1700000000)).not.toBe(quantizeTime(1700000029));
    expect(quantizeTime(1700000029) % TIME_QUANTUM).toBe(0);
  });
});
