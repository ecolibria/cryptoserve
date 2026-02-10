import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { writeFileSync, readFileSync, unlinkSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  encrypt, decrypt, parseCiphertext,
  getKeyIdFromCiphertext, getContextFromCiphertext,
  encryptString, decryptString,
  encryptFile, decryptFile,
  hashPassword,
} from '../lib/local-crypto.mjs';

describe('encrypt/decrypt (raw key)', () => {
  it('AES-256-GCM round-trip', () => {
    const key = randomBytes(32);
    const plaintext = Buffer.from('hello world');
    const ct = encrypt(plaintext, key, 'kid1', 'test-ctx', 'AES-256-GCM');
    const result = decrypt(ct, key);
    assert.deepEqual(result, plaintext);
  });

  it('AES-128-GCM round-trip', () => {
    const key = randomBytes(16);
    const plaintext = Buffer.from('short text');
    const ct = encrypt(plaintext, key, 'kid2', 'ctx2', 'AES-128-GCM');
    const result = decrypt(ct, key);
    assert.deepEqual(result, plaintext);
  });

  it('ChaCha20-Poly1305 round-trip', () => {
    const key = randomBytes(32);
    const plaintext = Buffer.from('chacha test');
    const ct = encrypt(plaintext, key, 'kid3', 'ctx3', 'ChaCha20-Poly1305');
    const result = decrypt(ct, key);
    assert.deepEqual(result, plaintext);
  });

  it('wrong key fails', () => {
    const key1 = randomBytes(32);
    const key2 = randomBytes(32);
    const ct = encrypt(Buffer.from('secret'), key1, 'k', 'c');
    assert.throws(() => decrypt(ct, key2));
  });

  it('preserves header metadata', () => {
    const key = randomBytes(32);
    const ct = encrypt(Buffer.from('data'), key, 'mykey', 'myctx');
    assert.equal(getKeyIdFromCiphertext(ct), 'mykey');
    assert.equal(getContextFromCiphertext(ct), 'myctx');
  });

  it('handles empty plaintext', () => {
    const key = randomBytes(32);
    const ct = encrypt(Buffer.from(''), key, 'k', 'c');
    const result = decrypt(ct, key);
    assert.deepEqual(result, Buffer.from(''));
  });

  it('handles large plaintext', () => {
    const key = randomBytes(32);
    const plaintext = randomBytes(100000);
    const ct = encrypt(plaintext, key, 'k', 'c');
    const result = decrypt(ct, key);
    assert.deepEqual(result, plaintext);
  });

  it('rejects invalid key size', () => {
    assert.throws(() => encrypt(Buffer.from('x'), randomBytes(10), 'k', 'c'));
  });

  it('rejects unsupported algorithm', () => {
    assert.throws(() => encrypt(Buffer.from('x'), randomBytes(32), 'k', 'c', 'AES-512-GCM'));
  });

  it('with associated data', () => {
    const key = randomBytes(32);
    const aad = Buffer.from('context-data');
    const ct = encrypt(Buffer.from('payload'), key, 'k', 'c', 'AES-256-GCM', aad);
    const result = decrypt(ct, key, aad);
    assert.deepEqual(result, Buffer.from('payload'));
  });

  it('wrong AAD fails', () => {
    const key = randomBytes(32);
    const aad = Buffer.from('correct');
    const ct = encrypt(Buffer.from('x'), key, 'k', 'c', 'AES-256-GCM', aad);
    assert.throws(() => decrypt(ct, key, Buffer.from('wrong')));
  });
});

describe('parseCiphertext', () => {
  it('parses header correctly', () => {
    const key = randomBytes(32);
    const ct = encrypt(Buffer.from('test'), key, 'kid', 'ctx');
    const { header } = parseCiphertext(ct);
    assert.equal(header.v, 4);
    assert.equal(header.kid, 'kid');
    assert.equal(header.ctx, 'ctx');
    assert.equal(header.alg, 'AES-256-GCM');
    assert.equal(header.local, true);
  });

  it('throws on too-short data', () => {
    assert.throws(() => parseCiphertext(Buffer.from([0, 1])));
  });
});

describe('encryptString/decryptString (password-based)', () => {
  it('round-trip with correct password', () => {
    const encrypted = encryptString('hello world', 'mypassword');
    const decrypted = decryptString(encrypted, 'mypassword');
    assert.equal(decrypted, 'hello world');
  });

  it('wrong password fails', () => {
    const encrypted = encryptString('secret', 'correct');
    assert.throws(() => decryptString(encrypted, 'wrong'));
  });

  it('different encryptions produce different output', () => {
    const e1 = encryptString('same text', 'pw');
    const e2 = encryptString('same text', 'pw');
    assert.notEqual(e1, e2); // Random salt + nonce
  });

  it('handles unicode text', () => {
    const text = 'Hello\nAES-256-GCM encryption test';
    const encrypted = encryptString(text, 'pw');
    assert.equal(decryptString(encrypted, 'pw'), text);
  });
});

describe('encryptFile/decryptFile', () => {
  const tmpDir = tmpdir();
  const inFile = join(tmpDir, 'cryptoserve-test-in.txt');
  const encFile = join(tmpDir, 'cryptoserve-test.enc');
  const outFile = join(tmpDir, 'cryptoserve-test-out.txt');

  it('round-trip file encryption', () => {
    writeFileSync(inFile, 'file content here');
    encryptFile(inFile, encFile, 'filepassword');
    decryptFile(encFile, outFile, 'filepassword');
    assert.equal(readFileSync(outFile, 'utf-8'), 'file content here');

    // Cleanup
    for (const f of [inFile, encFile, outFile]) {
      if (existsSync(f)) unlinkSync(f);
    }
  });
});

describe('hashPassword', () => {
  it('scrypt hash format', () => {
    const hash = hashPassword('testpassword', 'scrypt');
    assert.ok(hash.startsWith('$scrypt$'));
    assert.ok(hash.includes('$N='));
  });

  it('pbkdf2 hash format', () => {
    const hash = hashPassword('testpassword', 'pbkdf2');
    assert.ok(hash.startsWith('$pbkdf2-sha256$'));
  });

  it('different salts produce different hashes', () => {
    const h1 = hashPassword('same', 'scrypt');
    const h2 = hashPassword('same', 'scrypt');
    assert.notEqual(h1, h2);
  });

  it('rejects unsupported algorithm', () => {
    assert.throws(() => hashPassword('pw', 'bcrypt'));
  });
});
