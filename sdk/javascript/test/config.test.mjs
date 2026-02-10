import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadConfig, loadScannerConfig } from '../lib/config.mjs';

const TEST_DIR = join(tmpdir(), 'cryptoserve-config-test-' + Date.now());

function setup() { mkdirSync(TEST_DIR, { recursive: true }); }
function cleanup() { if (existsSync(TEST_DIR)) rmSync(TEST_DIR, { recursive: true, force: true }); }

describe('loadConfig', () => {
  beforeEach(setup);
  afterEach(cleanup);

  it('returns null when no config file', () => {
    assert.equal(loadConfig(TEST_DIR), null);
  });

  it('loads valid .cryptoserve.json', () => {
    writeFileSync(join(TEST_DIR, '.cryptoserve.json'), JSON.stringify({
      contexts: { medical: { sensitivity: 'critical' } },
    }));

    const config = loadConfig(TEST_DIR);
    assert.ok(config);
    assert.ok(config.contexts.medical);
  });

  it('returns null for invalid JSON', () => {
    writeFileSync(join(TEST_DIR, '.cryptoserve.json'), 'not json');
    assert.equal(loadConfig(TEST_DIR), null);
  });
});

describe('loadScannerConfig', () => {
  beforeEach(setup);
  afterEach(cleanup);

  it('returns defaults when no config', () => {
    const config = loadScannerConfig(TEST_DIR);
    assert.equal(config.maxFiles, 10000);
    assert.equal(config.maxFileSize, 1024 * 1024);
    assert.equal(config.binary.maxFiles, 50);
    assert.deepEqual(config.skipDirs, []);
    assert.deepEqual(config.includeExtensions, []);
  });

  it('returns defaults when config has no scanner section', () => {
    writeFileSync(join(TEST_DIR, '.cryptoserve.json'), JSON.stringify({
      contexts: {},
    }));

    const config = loadScannerConfig(TEST_DIR);
    assert.equal(config.maxFiles, 10000);
  });

  it('merges scanner overrides with defaults', () => {
    writeFileSync(join(TEST_DIR, '.cryptoserve.json'), JSON.stringify({
      scanner: {
        skipDirs: ['my-vendor', 'generated'],
        maxFiles: 20000,
        binary: { maxFiles: 100 },
      },
    }));

    const config = loadScannerConfig(TEST_DIR);
    assert.deepEqual(config.skipDirs, ['my-vendor', 'generated']);
    assert.equal(config.maxFiles, 20000);
    assert.equal(config.binary.maxFiles, 100);
    // Unset values use defaults
    assert.equal(config.maxFileSize, 1024 * 1024);
    assert.equal(config.binary.maxFileSize, 10 * 1024 * 1024);
  });

  it('includes extension overrides', () => {
    writeFileSync(join(TEST_DIR, '.cryptoserve.json'), JSON.stringify({
      scanner: {
        includeExtensions: ['.sol', '.move'],
      },
    }));

    const config = loadScannerConfig(TEST_DIR);
    assert.deepEqual(config.includeExtensions, ['.sol', '.move']);
  });

  it('handles invalid scanner field types gracefully', () => {
    writeFileSync(join(TEST_DIR, '.cryptoserve.json'), JSON.stringify({
      scanner: {
        skipDirs: 'not-an-array',
        maxFiles: 'not-a-number',
      },
    }));

    const config = loadScannerConfig(TEST_DIR);
    assert.deepEqual(config.skipDirs, []);
    assert.equal(config.maxFiles, 10000); // falls back to default
  });
});
