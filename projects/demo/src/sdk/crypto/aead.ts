import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { sha512 } from '@noble/hashes/sha512';
import { ParticipantId } from './shamir.js';

function u16ToBytesLE(n: number): Uint8Array {
  const buf = new Uint8Array(2);
  const view = new DataView(buf.buffer);
  view.setUint16(0, n, true);
  return buf;
}

/**
 * Deterministically derives a 12-byte AEAD nonce from the session nonce and server participant ID:
 * nonce = SHA-512("PASTA-AEAD-NONCE" || sessionNonce || id_le)[0..12]
 *
 * No need to transmit the nonce over the wire since both client and server compute it identically.
 */
export function deriveAeadNonce(sessionNonce: Uint8Array, id: ParticipantId): Uint8Array {
  const prefix = new TextEncoder().encode('PASTA-AEAD-NONCE');
  const idBytes = u16ToBytesLE(id);

  const input = new Uint8Array(prefix.length + sessionNonce.length + idBytes.length);
  input.set(prefix, 0);
  input.set(sessionNonce, prefix.length);
  input.set(idBytes, prefix.length + sessionNonce.length);

  const digest = sha512(input);
  return digest.slice(0, 12);
}

/**
 * Encrypts plaintext using ChaCha20-Poly1305 authenticated encryption with AAD.
 * AAD binds the exact signing input payload and session parameters, preventing replay across sessions.
 *
 * @param key 32-byte secret key (e.g. h_i)
 * @param nonce 12-byte AEAD nonce
 * @param plaintext Data to encrypt (e.g. signature share z_i)
 * @param aad Additional authenticated data (e.g. JWT signing input)
 * @returns Ciphertext with appended 16-byte Poly1305 authentication tag
 */
export function aeadEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array
): Uint8Array {
  if (key.length !== 32) {
    throw new Error(`Invalid key length: expected 32 bytes, got ${key.length}`);
  }
  if (nonce.length !== 12) {
    throw new Error(`Invalid nonce length: expected 12 bytes, got ${nonce.length}`);
  }
  const cipher = chacha20poly1305(key, nonce, aad);
  return cipher.encrypt(plaintext);
}

/**
 * Decrypts ciphertext using ChaCha20-Poly1305 and verifies authentication tag with AAD.
 * Throws an Error if tag verification fails (e.g., incorrect password, manipulated payload, or replayed share).
 *
 * @param key 32-byte secret key (e.g. h_i)
 * @param nonce 12-byte AEAD nonce
 * @param ciphertext Ciphertext with appended 16-byte Poly1305 authentication tag
 * @param aad Additional authenticated data
 * @returns Decrypted plaintext
 */
export function aeadDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array
): Uint8Array {
  if (key.length !== 32) {
    throw new Error(`Invalid key length: expected 32 bytes, got ${key.length}`);
  }
  if (nonce.length !== 12) {
    throw new Error(`Invalid nonce length: expected 12 bytes, got ${nonce.length}`);
  }
  const cipher = chacha20poly1305(key, nonce, aad);
  return cipher.decrypt(ciphertext);
}
