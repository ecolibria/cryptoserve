import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  initVault, setSecret, getSecret, listSecrets,
  deleteSecret, resetVault, vaultExists, importEnvFile,
  exportVault, importVaultBundle,
  _encryptData, _decryptData,
} from '../lib/vault.mjs';

const TEST_DIR = join(tmpdir(), 'cryptoserve-vault-test-' + Date.now());
const VAULT_PATH = join(TEST_DIR, 'vault.enc');
const PW = 'test-password-123';

function setup() {
  mkdirSync(TEST_DIR, { recursive: true });
}

function cleanup() {
  if (existsSync(TEST_DIR)) rmSync(TEST_DIR, { recursive: true, force: true });
}

describe('vault init', () => {
  beforeEach(setup);
  afterEach(cleanup);

  it('creates vault file', () => {
    initVault(PW, VAULT_PATH);
    assert.ok(existsSync(VAULT_PATH));
  });

  it('throws if vault already exists', () => {
    initVault(PW, VAULT_PATH);
    assert.throws(() => initVault(PW, VAULT_PATH), /already exists/);
  });
});

describe('vault set/get', () => {
  beforeEach(() => { setup(); initVault(PW, VAULT_PATH); });
  afterEach(cleanup);

  it('stores and retrieves a secret', () => {
    setSecret(PW, 'API_KEY', 'sk-test-123', VAULT_PATH);
    assert.equal(getSecret(PW, 'API_KEY', VAULT_PATH), 'sk-test-123');
  });

  it('returns null for missing key', () => {
    assert.equal(getSecret(PW, 'NOPE', VAULT_PATH), null);
  });

  it('overwrites existing key', () => {
    setSecret(PW, 'K', 'v1', VAULT_PATH);
    setSecret(PW, 'K', 'v2', VAULT_PATH);
    assert.equal(getSecret(PW, 'K', VAULT_PATH), 'v2');
  });

  it('wrong password fails', () => {
    setSecret(PW, 'K', 'V', VAULT_PATH);
    assert.throws(() => getSecret('wrong-pw', 'K', VAULT_PATH));
  });

  it('handles special characters in values', () => {
    const value = 'pa$$w0rd!@#$%^&*()_+{}:"<>?\n\ttab';
    setSecret(PW, 'SPECIAL', value, VAULT_PATH);
    assert.equal(getSecret(PW, 'SPECIAL', VAULT_PATH), value);
  });
});

describe('vault list', () => {
  beforeEach(() => { setup(); initVault(PW, VAULT_PATH); });
  afterEach(cleanup);

  it('lists all secrets without values', () => {
    setSecret(PW, 'A', '1', VAULT_PATH);
    setSecret(PW, 'B', '2', VAULT_PATH);
    const list = listSecrets(PW, VAULT_PATH);
    assert.equal(list.length, 2);
    assert.ok(list.some(s => s.key === 'A'));
    assert.ok(list.some(s => s.key === 'B'));
    // Should not expose values
    assert.ok(!list.some(s => s.value));
  });
});

describe('vault delete', () => {
  beforeEach(() => { setup(); initVault(PW, VAULT_PATH); });
  afterEach(cleanup);

  it('deletes a secret', () => {
    setSecret(PW, 'K', 'V', VAULT_PATH);
    assert.ok(deleteSecret(PW, 'K', VAULT_PATH));
    assert.equal(getSecret(PW, 'K', VAULT_PATH), null);
  });

  it('returns false for missing key', () => {
    assert.equal(deleteSecret(PW, 'NOPE', VAULT_PATH), false);
  });
});

describe('vault reset', () => {
  beforeEach(() => { setup(); initVault(PW, VAULT_PATH); });
  afterEach(cleanup);

  it('deletes vault file', () => {
    resetVault(VAULT_PATH);
    assert.ok(!existsSync(VAULT_PATH));
  });
});

describe('vault import .env', () => {
  beforeEach(() => { setup(); initVault(PW, VAULT_PATH); });
  afterEach(cleanup);

  it('imports .env file', () => {
    const envPath = join(TEST_DIR, '.env');
    writeFileSync(envPath, [
      '# Comment',
      'DB_HOST=localhost',
      'DB_PASS="secret123"',
      "API_KEY='sk-test'",
      'export EXPORTED_VAR=value',
      '',
      'EMPTY=',
    ].join('\n'));

    const count = importEnvFile(PW, envPath, VAULT_PATH);
    assert.equal(count, 5);
    assert.equal(getSecret(PW, 'DB_HOST', VAULT_PATH), 'localhost');
    assert.equal(getSecret(PW, 'DB_PASS', VAULT_PATH), 'secret123');
    assert.equal(getSecret(PW, 'API_KEY', VAULT_PATH), 'sk-test');
    assert.equal(getSecret(PW, 'EXPORTED_VAR', VAULT_PATH), 'value');
    assert.equal(getSecret(PW, 'EMPTY', VAULT_PATH), '');
  });
});

describe('vault export/import bundle', () => {
  beforeEach(() => { setup(); initVault(PW, VAULT_PATH); });
  afterEach(cleanup);

  it('export and re-import', () => {
    setSecret(PW, 'A', '1', VAULT_PATH);
    setSecret(PW, 'B', '2', VAULT_PATH);

    const bundle = exportVault(PW, null, VAULT_PATH);
    assert.ok(typeof bundle === 'string');
    assert.ok(bundle.length > 0);

    // Import into a new vault
    const newVaultPath = join(TEST_DIR, 'vault2.enc');
    initVault(PW, newVaultPath);
    const count = importVaultBundle(PW, bundle, null, newVaultPath);
    assert.equal(count, 2);
    assert.equal(getSecret(PW, 'A', newVaultPath), '1');
    assert.equal(getSecret(PW, 'B', newVaultPath), '2');
  });
});

describe('internal encrypt/decrypt', () => {
  it('round-trip', () => {
    const data = 'test data';
    const encrypted = _encryptData(data, PW);
    const decrypted = _decryptData(encrypted, PW);
    assert.equal(decrypted, data);
  });

  it('wrong password fails', () => {
    const encrypted = _encryptData('data', PW);
    assert.throws(() => _decryptData(encrypted, 'wrong'));
  });
});
