import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  initVault, setSecret, getSecret, listSecrets,
  deleteSecret, resetVault, vaultExists, importEnvFile,
  exportVault, importVaultBundle, vaultRun,
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

  it('deletes the vault file when given the right password', () => {
    assert.equal(resetVault(PW, VAULT_PATH), true);
    assert.ok(!existsSync(VAULT_PATH));
  });

  it('refuses a wrong password and leaves the vault intact', () => {
    // This test used to call resetVault(VAULT_PATH) with no password at all and
    // assert the file was gone. It restated the code rather than judging it:
    // deleting ONE secret was authenticated and deleting ALL of them was not.
    assert.throws(() => resetVault('wrong-password', VAULT_PATH));
    assert.ok(existsSync(VAULT_PATH), 'the vault was destroyed by a wrong password');
  });

  it('reports rather than throws when there is no vault to delete', () => {
    resetVault(PW, VAULT_PATH);
    assert.equal(resetVault(PW, VAULT_PATH), false);
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

describe('vault secret names inherited from Object.prototype', () => {
  // The secrets table was a plain object read with `data.secrets[key]` and
  // `key in data.secrets`, so these names behaved as existing entries:
  // getSecret('constructor') returned undefined instead of null,
  // deleteSecret('constructor') returned true, and setSecret('__proto__')
  // replaced the table's prototype, so the value was never saved.
  const INHERITED = ['constructor', 'toString', 'hasOwnProperty', '__proto__'];
  const sorted = list => list.map(s => s.key).sort();

  beforeEach(() => {
    setup();
    initVault(PW, VAULT_PATH);
    setSecret(PW, 'REAL_NAME', 'v1', VAULT_PATH);
  });
  afterEach(cleanup);

  it('get finds no secret under an inherited name', () => {
    for (const name of INHERITED) {
      assert.equal(getSecret(PW, name, VAULT_PATH), null, name);
    }
  });

  it('delete reports an inherited name as missing', () => {
    for (const name of INHERITED) {
      assert.equal(deleteSecret(PW, name, VAULT_PATH), false, name);
    }
    assert.deepEqual(sorted(listSecrets(PW, VAULT_PATH)), ['REAL_NAME']);
  });

  it('stores, lists, reads and deletes them as ordinary names', () => {
    for (const name of INHERITED) setSecret(PW, name, `value of ${name}`, VAULT_PATH);
    assert.deepEqual(sorted(listSecrets(PW, VAULT_PATH)), ['REAL_NAME', ...INHERITED].sort());
    for (const name of INHERITED) {
      assert.equal(getSecret(PW, name, VAULT_PATH), `value of ${name}`, name);
    }
    assert.equal(getSecret(PW, 'REAL_NAME', VAULT_PATH), 'v1');
    for (const name of INHERITED) {
      assert.equal(deleteSecret(PW, name, VAULT_PATH), true, name);
      assert.equal(getSecret(PW, name, VAULT_PATH), null, name);
    }
    assert.deepEqual(sorted(listSecrets(PW, VAULT_PATH)), ['REAL_NAME']);
  });

  it('carries them through export and import', () => {
    for (const name of INHERITED) setSecret(PW, name, `value of ${name}`, VAULT_PATH);
    const bundle = exportVault(PW, null, VAULT_PATH);
    const newVaultPath = join(TEST_DIR, 'vault2.enc');
    initVault(PW, newVaultPath);
    assert.equal(importVaultBundle(PW, bundle, null, newVaultPath), INHERITED.length + 1);
    assert.deepEqual(sorted(listSecrets(PW, newVaultPath)), ['REAL_NAME', ...INHERITED].sort());
    for (const name of INHERITED) {
      assert.equal(getSecret(PW, name, newVaultPath), `value of ${name}`, name);
    }
  });

  it('imports a bundle entry named __proto__ as a secret', () => {
    // Written as JSON text: in an object literal, `__proto__:` sets the prototype.
    const json = '{"__proto__":{"value":"p","updatedAt":"2026-01-01T00:00:00.000Z"},"constructor":"c"}';
    const bundle = _encryptData(json, PW).toString('base64');
    assert.equal(importVaultBundle(PW, bundle, null, VAULT_PATH), 2);
    assert.equal(getSecret(PW, '__proto__', VAULT_PATH), 'p');
    assert.equal(getSecret(PW, 'constructor', VAULT_PATH), 'c');
    assert.deepEqual(sorted(listSecrets(PW, VAULT_PATH)), ['REAL_NAME', '__proto__', 'constructor'].sort());
  });

  it('vault run gives the command a secret named __proto__', async () => {
    setSecret(PW, '__proto__', 'p', VAULT_PATH);
    setSecret(PW, 'constructor', 'c', VAULT_PATH);
    const check = [
      'const has = (k, v) => Object.entries(process.env).some(([n, x]) => n === k && x === v);',
      'process.exit(has("__proto__", "p") && has("constructor", "c") && has("REAL_NAME", "v1") ? 0 : 3);',
    ].join(' ');
    assert.equal(await vaultRun(PW, process.execPath, ['-e', check], VAULT_PATH), 0);
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
