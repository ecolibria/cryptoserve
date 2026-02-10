/**
 * Local cryptographic operations for the CryptoServe SDK.
 *
 * Port of sdk/python/cryptoserve/_local_crypto.py.
 * Cross-SDK compatible blob format — data encrypted by Python can be
 * decrypted by Node.js and vice versa.
 *
 * Zero dependencies — uses only node:crypto.
 */

import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
  pbkdf2Sync,
  createHash,
} from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const FORMAT_VERSION = 4;
const AES_GCM_NONCE_SIZE = 12;
const CHACHA_NONCE_SIZE = 12;
const AUTH_TAG_LENGTH = 16;

const ALGORITHMS = {
  'AES-256-GCM':       { cipher: 'aes-256-gcm',       keySize: 32, nonceSize: AES_GCM_NONCE_SIZE },
  'AES-128-GCM':       { cipher: 'aes-128-gcm',       keySize: 16, nonceSize: AES_GCM_NONCE_SIZE },
  'ChaCha20-Poly1305': { cipher: 'chacha20-poly1305',  keySize: 32, nonceSize: CHACHA_NONCE_SIZE },
};

// ---------------------------------------------------------------------------
// Core encrypt/decrypt (cross-SDK blob format)
// ---------------------------------------------------------------------------

export function encrypt(plaintext, key, keyId, context, algorithm = 'AES-256-GCM', associatedData = null) {
  const spec = ALGORITHMS[algorithm];
  if (!spec) throw new Error(`Unsupported algorithm: ${algorithm}`);
  if (key.length !== spec.keySize) {
    throw new Error(`Invalid key size: expected ${spec.keySize}, got ${key.length}`);
  }

  const nonce = randomBytes(spec.nonceSize);
  const cipher = createCipheriv(spec.cipher, key, nonce, { authTagLength: AUTH_TAG_LENGTH });

  if (associatedData) cipher.setAAD(associatedData);

  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const header = {
    v: FORMAT_VERSION,
    ctx: context,
    kid: keyId,
    alg: algorithm,
    nonce: nonce.toString('base64'),
    local: true,
  };
  if (associatedData) header.aad_len = associatedData.length;

  const headerBytes = Buffer.from(JSON.stringify(header));
  const headerLen = Buffer.alloc(2);
  headerLen.writeUInt16BE(headerBytes.length);

  // ciphertext includes auth tag appended (matches Python cryptography library behavior)
  return Buffer.concat([headerLen, headerBytes, encrypted, authTag]);
}

export function decrypt(ciphertext, key, associatedData = null) {
  const { header, rawCiphertext } = parseCiphertext(ciphertext);

  const algorithm = header.alg || 'AES-256-GCM';
  const spec = ALGORITHMS[algorithm];
  if (!spec) throw new Error(`Unsupported algorithm: ${algorithm}`);
  if (key.length !== spec.keySize) {
    throw new Error(`Invalid key size: expected ${spec.keySize}, got ${key.length}`);
  }

  const nonce = Buffer.from(header.nonce, 'base64');

  // Separate ciphertext from auth tag (last 16 bytes)
  const encData = rawCiphertext.subarray(0, rawCiphertext.length - AUTH_TAG_LENGTH);
  const authTag = rawCiphertext.subarray(rawCiphertext.length - AUTH_TAG_LENGTH);

  const decipher = createDecipheriv(spec.cipher, key, nonce, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAuthTag(authTag);

  if (associatedData) decipher.setAAD(associatedData);

  return Buffer.concat([decipher.update(encData), decipher.final()]);
}

export function parseCiphertext(ciphertext) {
  if (ciphertext.length < 3) throw new Error('Ciphertext too short');

  const headerLen = ciphertext.readUInt16BE(0);
  if (ciphertext.length < 2 + headerLen) throw new Error('Invalid ciphertext format');

  const headerBytes = ciphertext.subarray(2, 2 + headerLen);
  const rawCiphertext = ciphertext.subarray(2 + headerLen);
  const header = JSON.parse(headerBytes.toString('utf-8'));

  return { header, rawCiphertext };
}

export function getKeyIdFromCiphertext(ciphertext) {
  try {
    return parseCiphertext(ciphertext).header.kid || null;
  } catch { return null; }
}

export function getContextFromCiphertext(ciphertext) {
  try {
    return parseCiphertext(ciphertext).header.ctx || null;
  } catch { return null; }
}

// ---------------------------------------------------------------------------
// Password-based encryption (for CLI encrypt/decrypt commands)
// ---------------------------------------------------------------------------

const SCRYPT_N = 2 ** 15;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SALT_SIZE = 16;

function deriveKeyFromPassword(password, salt, keySize = 32) {
  return scryptSync(password, salt, keySize, {
    N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: 64 * 1024 * 1024,
  });
}

export function encryptString(text, password, algorithm = 'AES-256-GCM', context = 'cli') {
  const salt = randomBytes(SALT_SIZE);
  const spec = ALGORITHMS[algorithm];
  if (!spec) throw new Error(`Unsupported algorithm: ${algorithm}`);

  const key = deriveKeyFromPassword(password, salt, spec.keySize);
  const blob = encrypt(Buffer.from(text, 'utf-8'), key, 'password-derived', context, algorithm);

  // Format: [16-byte salt][encrypted blob] → base64
  return Buffer.concat([salt, blob]).toString('base64');
}

export function decryptString(base64Text, password) {
  const packed = Buffer.from(base64Text, 'base64');
  if (packed.length < SALT_SIZE + 3) throw new Error('Invalid encrypted data');

  const salt = packed.subarray(0, SALT_SIZE);
  const blob = packed.subarray(SALT_SIZE);

  // Parse header to get algorithm and determine key size
  const { header } = parseCiphertext(blob);
  const algorithm = header.alg || 'AES-256-GCM';
  const spec = ALGORITHMS[algorithm];
  if (!spec) throw new Error(`Unsupported algorithm: ${algorithm}`);

  const key = deriveKeyFromPassword(password, salt, spec.keySize);
  return decrypt(blob, key).toString('utf-8');
}

export function encryptFile(inPath, outPath, password, algorithm = 'AES-256-GCM', context = 'file') {
  const plaintext = readFileSync(inPath);
  const salt = randomBytes(SALT_SIZE);
  const spec = ALGORITHMS[algorithm];
  if (!spec) throw new Error(`Unsupported algorithm: ${algorithm}`);

  const key = deriveKeyFromPassword(password, salt, spec.keySize);
  const blob = encrypt(plaintext, key, 'password-derived', context, algorithm);

  writeFileSync(outPath, Buffer.concat([salt, blob]), { mode: 0o600 });
}

export function decryptFile(inPath, outPath, password) {
  const packed = readFileSync(inPath);
  if (packed.length < SALT_SIZE + 3) throw new Error('Invalid encrypted file');

  const salt = packed.subarray(0, SALT_SIZE);
  const blob = packed.subarray(SALT_SIZE);

  const { header } = parseCiphertext(blob);
  const algorithm = header.alg || 'AES-256-GCM';
  const spec = ALGORITHMS[algorithm];
  if (!spec) throw new Error(`Unsupported algorithm: ${algorithm}`);

  const key = deriveKeyFromPassword(password, salt, spec.keySize);
  const plaintext = decrypt(blob, key);

  writeFileSync(outPath, plaintext);
}

// ---------------------------------------------------------------------------
// Password hashing
// ---------------------------------------------------------------------------

export function hashPassword(password, algorithm = 'scrypt') {
  const salt = randomBytes(SALT_SIZE);
  if (algorithm === 'scrypt') {
    const hash = scryptSync(password, salt, 64, {
      N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: 64 * 1024 * 1024,
    });
    return `$scrypt$N=${SCRYPT_N}$r=${SCRYPT_R}$p=${SCRYPT_P}$${salt.toString('base64')}$${hash.toString('base64')}`;
  }
  if (algorithm === 'pbkdf2') {
    const iterations = 600000;
    const hash = pbkdf2Sync(password, salt, iterations, 64, 'sha256');
    return `$pbkdf2-sha256$${iterations}$${salt.toString('base64')}$${hash.toString('base64')}`;
  }
  throw new Error(`Unsupported hash algorithm: ${algorithm}`);
}

// ---------------------------------------------------------------------------
// Utility: SHA-256 digest
// ---------------------------------------------------------------------------

export function sha256(data) {
  return createHash('sha256').update(data).digest();
}
