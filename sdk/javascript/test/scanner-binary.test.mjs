import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { scanBinary, scanBinaries, BINARY_SIGNATURES } from '../lib/scanner-binary.mjs';

const TEST_DIR = join(tmpdir(), 'cryptoserve-binary-test-' + Date.now());

function setup() { mkdirSync(TEST_DIR, { recursive: true }); }
function cleanup() { if (existsSync(TEST_DIR)) rmSync(TEST_DIR, { recursive: true, force: true }); }

describe('BINARY_SIGNATURES', () => {
  it('has at least 10 signatures', () => {
    assert.ok(BINARY_SIGNATURES.length >= 10);
  });

  it('each signature has required fields', () => {
    for (const sig of BINARY_SIGNATURES) {
      assert.ok(sig.name, 'missing name');
      assert.ok(sig.algorithm, 'missing algorithm');
      assert.ok(sig.severity, 'missing severity');
      assert.ok(Buffer.isBuffer(sig.bytes), 'bytes should be Buffer');
    }
  });
});

describe('scanBinary', () => {
  beforeEach(setup);
  afterEach(cleanup);

  it('detects AES S-box in binary', () => {
    // Create a binary file with AES S-box bytes embedded
    const sbox = BINARY_SIGNATURES.find(s => s.name === 'AES S-box');
    const buf = Buffer.concat([Buffer.alloc(100), sbox.bytes, Buffer.alloc(100)]);
    const filePath = join(TEST_DIR, 'test.so');
    writeFileSync(filePath, buf);

    const matches = scanBinary(filePath);
    assert.ok(matches.some(m => m.algorithm === 'aes'));
    assert.equal(matches.find(m => m.algorithm === 'aes').offset, 100);
  });

  it('detects ChaCha20 sigma constant', () => {
    const sigma = BINARY_SIGNATURES.find(s => s.name === 'ChaCha20 sigma constant');
    const buf = Buffer.concat([Buffer.alloc(50), sigma.bytes, Buffer.alloc(50)]);
    const filePath = join(TEST_DIR, 'test.wasm');
    writeFileSync(filePath, buf);

    const matches = scanBinary(filePath);
    assert.ok(matches.some(m => m.algorithm === 'chacha20'));
  });

  it('detects MD5 initial values', () => {
    const md5 = BINARY_SIGNATURES.find(s => s.name === 'MD5 initial values');
    const buf = Buffer.concat([Buffer.alloc(20), md5.bytes]);
    const filePath = join(TEST_DIR, 'legacy.dll');
    writeFileSync(filePath, buf);

    const matches = scanBinary(filePath);
    assert.ok(matches.some(m => m.algorithm === 'md5'));
    assert.equal(matches.find(m => m.algorithm === 'md5').severity, 'critical');
  });

  it('returns empty for file without signatures', () => {
    const buf = Buffer.alloc(1000, 0xFF);
    const filePath = join(TEST_DIR, 'empty.so');
    writeFileSync(filePath, buf);

    const matches = scanBinary(filePath);
    assert.equal(matches.length, 0);
  });

  it('returns empty for missing file', () => {
    const matches = scanBinary(join(TEST_DIR, 'nonexistent.so'));
    assert.equal(matches.length, 0);
  });
});

describe('scanBinaries', () => {
  beforeEach(setup);
  afterEach(cleanup);

  it('walks project directory for binary files', () => {
    const sbox = BINARY_SIGNATURES.find(s => s.name === 'AES S-box');
    const buf = Buffer.concat([Buffer.alloc(50), sbox.bytes]);
    writeFileSync(join(TEST_DIR, 'app.wasm'), buf);

    const results = scanBinaries(TEST_DIR);
    assert.ok(results.some(r => r.algorithm === 'aes'));
    assert.ok(results.some(r => r.file === 'app.wasm'));
  });

  it('returns empty for project without binaries', () => {
    writeFileSync(join(TEST_DIR, 'README.md'), 'hello');
    const results = scanBinaries(TEST_DIR);
    assert.equal(results.length, 0);
  });
});
