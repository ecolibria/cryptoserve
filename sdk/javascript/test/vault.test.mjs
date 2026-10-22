import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
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

describe('vault import of a bundle entry that is not a secret', () => {
  // importVaultBundle stored every entry whose typeof was 'object' as it was.
  // After a null entry, listSecrets and vaultRun threw "Cannot read properties
  // of null" for the whole vault, and an array or an object without a `value`
  // read back from getSecret as undefined.
  const bundleOf = json => _encryptData(json, PW).toString('base64');
  const names = () => listSecrets(PW, VAULT_PATH).map(s => s.key).sort();

  beforeEach(() => {
    setup();
    initVault(PW, VAULT_PATH);
    setSecret(PW, 'KEPT', 'k', VAULT_PATH);
  });
  afterEach(cleanup);

  it('refuses a null entry, and list, get and run keep working', async () => {
    const before = readFileSync(VAULT_PATH);
    assert.throws(() => importVaultBundle(PW, bundleOf('{"NEW":"n","A":null}'), null, VAULT_PATH),
      /^Error: Bundle not imported: "A" is null\. .*The vault was not changed\.$/);
    assert.deepEqual(readFileSync(VAULT_PATH), before, 'the vault file was rewritten');
    assert.deepEqual(names(), ['KEPT']);
    assert.equal(getSecret(PW, 'NEW', VAULT_PATH), null);
    assert.equal(getSecret(PW, 'A', VAULT_PATH), null);
    const check = 'process.exit(process.env.KEPT === "k" ? 0 : 3)';
    assert.equal(await vaultRun(PW, process.execPath, ['-e', check], VAULT_PATH), 0);
  });

  it('refuses an array, a number, a boolean and an object without a string value', () => {
    const cases = [
      ['["x"]', /"BAD" is an array/],
      ['{}', /"BAD" has no string "value"/],
      ['{"value":7}', /"BAD" has no string "value"/],
      ['{"value":null}', /"BAD" has no string "value"/],
      ['{"value":["x"]}', /"BAD" has no string "value"/],
      ['42', /"BAD" is a number/],
      ['true', /"BAD" is a boolean/],
    ];
    const before = readFileSync(VAULT_PATH);
    for (const [entry, reason] of cases) {
      assert.throws(() => importVaultBundle(PW, bundleOf(`{"NEW":"n","BAD":${entry}}`), null, VAULT_PATH),
        reason, entry);
      assert.deepEqual(readFileSync(VAULT_PATH), before, entry);
    }
    assert.deepEqual(names(), ['KEPT']);
  });

  it('names the first five refused entries and counts the rest', () => {
    const json = '{"B1":null,"OK":"v","B2":[],"B3":{},"B4":1,"B5":false,"B6":null,"B7":null}';
    assert.throws(() => importVaultBundle(PW, bundleOf(json), null, VAULT_PATH), {
      message: 'Bundle not imported: "B1" is null, "B2" is an array, "B3" has no string "value", '
        + '"B4" is a number, "B5" is a boolean, and 2 more. Each entry must be a string or an '
        + 'object with a string "value". The vault was not changed.',
    });
    assert.deepEqual(names(), ['KEPT']);
  });

  it('refuses a bundle that is not a table of secrets', () => {
    // A bundle holding the string "str" was imported as the secrets 0, 1 and 2.
    const cases = [['"str"', 'a string'], ['["x"]', 'an array'], ['null', 'null'], ['42', 'a number']];
    const before = readFileSync(VAULT_PATH);
    for (const [json, kind] of cases) {
      assert.throws(() => importVaultBundle(PW, bundleOf(json), null, VAULT_PATH), {
        message: `Bundle not imported: it holds ${kind}, not a table of secrets. `
          + 'The vault was not changed.',
      }, json);
      assert.deepEqual(readFileSync(VAULT_PATH), before, json);
    }
    assert.deepEqual(names(), ['KEPT']);
  });

  it('creates no vault when it refuses a bundle', () => {
    const newVaultPath = join(TEST_DIR, 'vault2.enc');
    for (const json of ['{"A":null}', '"str"']) {
      assert.throws(() => importVaultBundle(PW, bundleOf(json), null, newVaultPath),
        /^Error: Bundle not imported/, json);
      assert.ok(!existsSync(newVaultPath), `the refused bundle ${json} created a vault`);
    }
  });

  it('stores each accepted entry as a string value and an update time', () => {
    const kept = '2026-01-02T03:04:05.000Z';
    const json = JSON.stringify({
      S: 'plain',
      O: { value: 'v', updatedAt: kept, note: 'x' },
      M: { value: 'm' },
      T: { value: 't', updatedAt: 'not a date' },
      N: { value: 'n', updatedAt: 0 },
      E: { value: '' },
    });
    const start = Date.now();
    assert.equal(importVaultBundle(PW, bundleOf(json), null, VAULT_PATH), 6);
    const end = Date.now();
    assert.deepEqual(names(), ['E', 'KEPT', 'M', 'N', 'O', 'S', 'T']);
    const values = { S: 'plain', O: 'v', M: 'm', T: 't', N: 'n', E: '' };
    for (const [name, value] of Object.entries(values)) {
      assert.equal(getSecret(PW, name, VAULT_PATH), value, name);
    }
    // `vault list` printed "NaNd ago" for M and T, whose update time was missing
    // or not a date. They now carry the time of the import, as does N, whose
    // update time is not a string.
    const updated = Object.fromEntries(listSecrets(PW, VAULT_PATH).map(s => [s.key, s.updatedAt]));
    assert.equal(updated.O, kept);
    for (const name of ['S', 'M', 'T', 'N', 'E']) {
      const at = Date.parse(updated[name]);
      assert.ok(at >= start && at <= end, `${name} was not dated at the import: ${updated[name]}`);
    }
    const exported = JSON.parse(_decryptData(Buffer.from(exportVault(PW, null, VAULT_PATH), 'base64'), PW));
    assert.deepEqual(exported.O, { value: 'v', updatedAt: kept });
  });
});

describe('vault already holding an entry that is not a secret', () => {
  // importVaultBundle now refuses such an entry, but it used to store one as it
  // was, and a vault it wrote then still holds it. listSecrets threw
  // "Cannot read properties of null (reading 'updatedAt')" for a null entry and
  // vaultRun the same for 'value', so one entry stopped list and run for every
  // secret, and neither named it.
  const KEPT = { value: 'k', updatedAt: '2026-01-01T00:00:00.000Z' };
  const writeVault = secrets => writeFileSync(VAULT_PATH,
    _encryptData(JSON.stringify({ version: 1, secrets }), PW));
  const absent = names => `process.exit(process.env.KEPT === "k" && ${JSON.stringify(names)}`
    + '.every(n => !(n in process.env)) ? 0 : 3)';

  beforeEach(setup);
  afterEach(cleanup);

  it('lists every name and marks the null entry', () => {
    writeVault({ KEPT, A: null });
    assert.deepEqual(listSecrets(PW, VAULT_PATH), [
      { key: 'KEPT', updatedAt: KEPT.updatedAt },
      { key: 'A', updatedAt: null, problem: 'is null' },
    ]);
  });

  it('says what each entry that is not a secret is', () => {
    const cases = [
      ['null', 'is null'],
      ['["x"]', 'is an array'],
      ['42', 'is a number'],
      ['true', 'is a boolean'],
      ['"bare"', 'is a string'],
      ['{}', 'has no string "value"'],
      ['{"value":7}', 'has no string "value"'],
      ['{"value":null}', 'has no string "value"'],
      ['{"value":["a","b"]}', 'has no string "value"'],
      ['{"value":{"toString":1}}', 'has no string "value"'],
    ];
    for (const [entry, problem] of cases) {
      writeVault({ KEPT, BAD: JSON.parse(entry) });
      assert.deepEqual(listSecrets(PW, VAULT_PATH), [
        { key: 'KEPT', updatedAt: KEPT.updatedAt },
        { key: 'BAD', updatedAt: null, problem },
      ], entry);
    }
  });

  it('vault run passes the secrets, leaves out the null entry and reports it', async () => {
    writeVault({ KEPT, A: null });
    const skipped = [];
    const onSkip = s => skipped.push(s);
    assert.equal(await vaultRun(PW, process.execPath, ['-e', absent(['A'])], VAULT_PATH, { onSkip }), 0);
    assert.deepEqual(skipped, [{ key: 'A', problem: 'is null' }]);
    // Without onSkip as well.
    assert.equal(await vaultRun(PW, process.execPath, ['-e', absent(['A'])], VAULT_PATH), 0);
  });

  it('vault run leaves out a value that is not a string', async () => {
    // A value of null reached the command as "null" and an array as "a,b", and
    // an object without a usable toString threw before the command started.
    writeVault({ KEPT, N: { value: null }, ARR: { value: ['a', 'b'] }, OBJ: { value: { toString: 1 } } });
    const skipped = [];
    const code = await vaultRun(PW, process.execPath, ['-e', absent(['N', 'ARR', 'OBJ'])], VAULT_PATH,
      { onSkip: s => skipped.push(s) });
    assert.equal(code, 0);
    assert.deepEqual(skipped.map(s => s.key), ['N', 'ARR', 'OBJ']);
    assert.ok(skipped.every(s => s.problem === 'has no string "value"'));
  });

  it('delete removes the entry, after which list and run report nothing', async () => {
    writeVault({ KEPT, A: null });
    assert.equal(deleteSecret(PW, 'A', VAULT_PATH), true);
    assert.deepEqual(listSecrets(PW, VAULT_PATH), [{ key: 'KEPT', updatedAt: KEPT.updatedAt }]);
    const skipped = [];
    assert.equal(await vaultRun(PW, process.execPath, ['-e', absent(['A'])], VAULT_PATH,
      { onSkip: s => skipped.push(s) }), 0);
    assert.deepEqual(skipped, []);
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
