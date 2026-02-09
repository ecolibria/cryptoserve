import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { encrypt, decrypt, parseCiphertext } from '../lib/local-crypto.mjs';

describe('cross-SDK blob format', () => {
  it('blob starts with 2-byte header length', () => {
    const key = randomBytes(32);
    const ct = encrypt(Buffer.from('test'), key, 'kid', 'ctx');
    const headerLen = ct.readUInt16BE(0);
    assert.ok(headerLen > 0);
    assert.ok(headerLen < 1000);
  });

  it('header is valid JSON with expected fields', () => {
    const key = randomBytes(32);
    const ct = encrypt(Buffer.from('test'), key, 'my-key', 'my-ctx', 'AES-256-GCM');
    const { header } = parseCiphertext(ct);

    assert.equal(header.v, 4);
    assert.equal(header.kid, 'my-key');
    assert.equal(header.ctx, 'my-ctx');
    assert.equal(header.alg, 'AES-256-GCM');
    assert.equal(header.local, true);
    assert.ok(header.nonce); // base64 nonce
  });

  it('nonce is 12 bytes (16 chars base64)', () => {
    const key = randomBytes(32);
    const ct = encrypt(Buffer.from('test'), key, 'k', 'c');
    const { header } = parseCiphertext(ct);
    const nonceBytes = Buffer.from(header.nonce, 'base64');
    assert.equal(nonceBytes.length, 12);
  });

  it('format version 4 matches Python SDK', () => {
    // Python's FORMAT_VERSION = 4 (SDK local crypto)
    const key = randomBytes(32);
    const ct = encrypt(Buffer.from('x'), key, 'k', 'c');
    const { header } = parseCiphertext(ct);
    assert.equal(header.v, 4);
  });

  it('ChaCha20-Poly1305 header contains correct algorithm', () => {
    const key = randomBytes(32);
    const ct = encrypt(Buffer.from('test'), key, 'k', 'c', 'ChaCha20-Poly1305');
    const { header } = parseCiphertext(ct);
    assert.equal(header.alg, 'ChaCha20-Poly1305');
  });

  it('AAD length recorded in header when provided', () => {
    const key = randomBytes(32);
    const aad = Buffer.from('associated data');
    const ct = encrypt(Buffer.from('test'), key, 'k', 'c', 'AES-256-GCM', aad);
    const { header } = parseCiphertext(ct);
    assert.equal(header.aad_len, aad.length);
  });

  it('all three algorithms produce cross-decryptable blobs', () => {
    const algorithms = ['AES-256-GCM', 'AES-128-GCM', 'ChaCha20-Poly1305'];
    const keySizes = [32, 16, 32];
    const plaintext = Buffer.from('cross-algorithm test');

    for (let i = 0; i < algorithms.length; i++) {
      const key = randomBytes(keySizes[i]);
      const ct = encrypt(plaintext, key, `key-${i}`, 'ctx', algorithms[i]);
      const result = decrypt(ct, key);
      assert.deepEqual(result, plaintext, `${algorithms[i]} round-trip failed`);

      // Verify header
      const { header } = parseCiphertext(ct);
      assert.equal(header.alg, algorithms[i]);
    }
  });
});
