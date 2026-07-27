import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir, homedir } from 'node:os';
import { configDir, configPath, ensureConfigDir, displayPath } from '../lib/paths.mjs';

const ORIGINAL_HOME = process.env.CRYPTOSERVE_HOME;
const ORIGINAL_XDG = process.env.XDG_CONFIG_HOME;

function restoreEnv() {
  if (ORIGINAL_HOME === undefined) delete process.env.CRYPTOSERVE_HOME;
  else process.env.CRYPTOSERVE_HOME = ORIGINAL_HOME;
  if (ORIGINAL_XDG === undefined) delete process.env.XDG_CONFIG_HOME;
  else process.env.XDG_CONFIG_HOME = ORIGINAL_XDG;
}

describe('configDir', () => {
  beforeEach(restoreEnv);
  afterEach(restoreEnv);

  it('defaults to ~/.cryptoserve', () => {
    delete process.env.CRYPTOSERVE_HOME;
    delete process.env.XDG_CONFIG_HOME;
    assert.equal(configDir(), join(homedir(), '.cryptoserve'));
  });

  it('honors CRYPTOSERVE_HOME', () => {
    process.env.CRYPTOSERVE_HOME = '/tmp/cs-test-home';
    assert.equal(configDir(), '/tmp/cs-test-home');
  });

  it('honors XDG_CONFIG_HOME when CRYPTOSERVE_HOME is unset', () => {
    delete process.env.CRYPTOSERVE_HOME;
    process.env.XDG_CONFIG_HOME = '/tmp/xdg';
    assert.equal(configDir(), join('/tmp/xdg', 'cryptoserve'));
  });

  it('lets CRYPTOSERVE_HOME win over XDG_CONFIG_HOME', () => {
    process.env.CRYPTOSERVE_HOME = '/tmp/explicit';
    process.env.XDG_CONFIG_HOME = '/tmp/xdg';
    assert.equal(configDir(), '/tmp/explicit');
  });

  it('ignores an empty override', () => {
    process.env.CRYPTOSERVE_HOME = '   ';
    delete process.env.XDG_CONFIG_HOME;
    assert.equal(configDir(), join(homedir(), '.cryptoserve'));
  });

  it('is re-read per call, not frozen at import', () => {
    process.env.CRYPTOSERVE_HOME = '/tmp/first';
    assert.equal(configDir(), '/tmp/first');
    process.env.CRYPTOSERVE_HOME = '/tmp/second';
    assert.equal(configDir(), '/tmp/second');
  });
});

describe('ensureConfigDir', () => {
  let dir;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'cs-paths-')); });
  afterEach(() => { restoreEnv(); rmSync(dir, { recursive: true, force: true }); });

  it('creates the directory with 0700 and never touches the real home', () => {
    process.env.CRYPTOSERVE_HOME = join(dir, 'state');
    const created = ensureConfigDir();
    assert.equal(created, join(dir, 'state'));
    assert.ok(existsSync(created));
    assert.equal(statSync(created).mode & 0o777, 0o700);
  });
});

describe('vault under CRYPTOSERVE_HOME', () => {
  let dir;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'cs-vault-')); });
  afterEach(() => { restoreEnv(); rmSync(dir, { recursive: true, force: true }); });

  it('writes the vault inside the override, not the user home', async () => {
    process.env.CRYPTOSERVE_HOME = dir;
    const vault = await import('../lib/vault.mjs');
    assert.equal(vault.defaultVaultPath(), join(dir, 'vault.enc'));

    vault.initVault('correct horse battery staple');
    assert.ok(existsSync(join(dir, 'vault.enc')), 'vault must land in the override');
    assert.ok(!existsSync(join(homedir(), '.cryptoserve', 'vault-should-not-exist')));

    vault.setSecret('correct horse battery staple', 'API_KEY', 'value-123');
    assert.equal(vault.getSecret('correct horse battery staple', 'API_KEY'), 'value-123');
  });

  it('refuses to overwrite an existing vault', async () => {
    process.env.CRYPTOSERVE_HOME = dir;
    const vault = await import('../lib/vault.mjs');
    vault.initVault('pw');
    assert.throws(() => vault.initVault('pw'), /already exists/);
  });
});

describe('displayPath', () => {
  it('collapses the home directory to ~', () => {
    assert.equal(displayPath(join(homedir(), '.cryptoserve', 'vault.enc')), '~/.cryptoserve/vault.enc');
  });

  it('leaves paths outside home untouched', () => {
    assert.equal(displayPath('/var/lib/cryptoserve/vault.enc'), '/var/lib/cryptoserve/vault.enc');
  });
});

describe('configPath', () => {
  beforeEach(restoreEnv);
  afterEach(restoreEnv);

  it('joins segments onto the state directory', () => {
    process.env.CRYPTOSERVE_HOME = '/tmp/state';
    assert.equal(configPath('vault.enc'), '/tmp/state/vault.enc');
    assert.equal(configPath('sub', 'file.json'), '/tmp/state/sub/file.json');
  });
});
