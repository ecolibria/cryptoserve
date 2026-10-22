/**
 * Encrypted local vault for secret management.
 *
 * Stores secrets in an AES-256-GCM encrypted JSON file at
 * ~/.cryptoserve/vault.enc. Master password is used to derive the
 * encryption key via scrypt.
 *
 * Zero dependencies — uses only node:crypto and node:fs.
 *
 * Commands:
 *   vault init       — Create a new vault
 *   vault set K V    — Store a secret
 *   vault get K      — Retrieve a secret
 *   vault list       — List secret names (not values)
 *   vault delete K   — Remove a secret
 *   vault run -- CMD — Inject secrets as env vars, run command
 *   vault import F   — Import .env file into vault
 *   vault export     — Export as encrypted bundle
 */

import { existsSync, readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { randomBytes, scryptSync, createCipheriv, createDecipheriv } from 'node:crypto';
import { spawn } from 'node:child_process';
import { configPath, ensureConfigDir } from './paths.mjs';

const SALT_SIZE = 32;
const IV_SIZE = 12;
const TAG_SIZE = 16;
const SCRYPT_OPTS = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

/**
 * Default vault path. Resolved per call rather than frozen at import time, so
 * a CRYPTOSERVE_HOME set by the caller takes effect. Default parameters are
 * evaluated at call time in JS, which is what makes `path = defaultVaultPath()`
 * behave correctly on every exported function below.
 */
export function defaultVaultPath() {
  return configPath('vault.enc');
}

function deriveKey(password, salt) {
  return scryptSync(password, salt, 32, SCRYPT_OPTS);
}

function encryptData(plaintext, password) {
  const salt = randomBytes(SALT_SIZE);
  const key = deriveKey(password, salt);
  const iv = randomBytes(IV_SIZE);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf-8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([salt, iv, tag, enc]);
}

function decryptData(packed, password) {
  if (packed.length < SALT_SIZE + IV_SIZE + TAG_SIZE + 1) {
    throw new Error('Vault file is corrupted or empty');
  }
  const salt = packed.subarray(0, SALT_SIZE);
  const iv = packed.subarray(SALT_SIZE, SALT_SIZE + IV_SIZE);
  const tag = packed.subarray(SALT_SIZE + IV_SIZE, SALT_SIZE + IV_SIZE + TAG_SIZE);
  const enc = packed.subarray(SALT_SIZE + IV_SIZE + TAG_SIZE);
  const key = deriveKey(password, salt);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf-8');
}

/**
 * The secrets table, keyed by the names users give. It has no prototype, so a
 * lookup finds only the names the vault holds. It was a plain object, on which
 * `constructor` and `toString` read as existing secrets and assigning
 * `__proto__` replaced the object's prototype instead of storing a secret.
 */
function secretTable(entries) {
  return Object.assign(Object.create(null), entries);
}

/** What a value is, as an error message names it. */
function kindOf(value) {
  if (value === null) return 'null';
  if (value === undefined) return 'undefined';
  if (Array.isArray(value)) return 'an array';
  return typeof value === 'object' ? 'an object' : `a ${typeof value}`;
}

function loadVault(password, path = defaultVaultPath()) {
  if (!existsSync(path)) return null;
  const packed = readFileSync(path);
  const json = decryptData(packed, password);
  const data = JSON.parse(json);
  data.secrets = secretTable(data.secrets);
  return data;
}

function saveVault(data, password, path = defaultVaultPath()) {
  ensureConfigDir();
  const json = JSON.stringify(data, null, 2);
  const encrypted = encryptData(json, password);
  writeFileSync(path, encrypted, { mode: 0o600 });
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function vaultExists(path = defaultVaultPath()) {
  return existsSync(path);
}

export function initVault(password, path = defaultVaultPath()) {
  if (existsSync(path)) {
    throw new Error('Vault already exists. Use "vault reset" to recreate.');
  }
  const data = {
    version: 1,
    createdAt: new Date().toISOString(),
    secrets: secretTable(),
  };
  saveVault(data, password, path);
  return data;
}

/**
 * Store a secret, whose value must be a string. A value such as 8080, true or
 * null used to be stored, and exportVault then wrote a bundle that
 * importVaultBundle refuses.
 */
export function setSecret(password, key, value, path = defaultVaultPath()) {
  if (typeof value !== 'string') {
    throw new TypeError(`Secret ${JSON.stringify(String(key))} not stored: its value is `
      + `${kindOf(value)}, not a string.`);
  }
  const data = loadVault(password, path);
  if (!data) throw new Error('Vault not found. Run "cryptoserve vault init" first.');
  data.secrets[key] = {
    value,
    updatedAt: new Date().toISOString(),
  };
  saveVault(data, password, path);
}

export function getSecret(password, key, path = defaultVaultPath()) {
  const data = loadVault(password, path);
  if (!data) throw new Error('Vault not found. Run "cryptoserve vault init" first.');
  const entry = data.secrets[key];
  if (!entry) return null;
  return entry.value;
}

/**
 * The name and update time of every entry, never a value. An entry that is not
 * a secret is listed with `updatedAt: null` and a `problem` saying what it is,
 * so it can be found and removed with deleteSecret. This used to read
 * `updatedAt` of every entry, which threw for a null entry, so one such entry
 * stopped the listing of every secret.
 */
export function listSecrets(password, path = defaultVaultPath()) {
  const data = loadVault(password, path);
  if (!data) throw new Error('Vault not found. Run "cryptoserve vault init" first.');
  return Object.entries(data.secrets).map(([key, entry]) => {
    const problem = entryProblem(entry);
    return problem ? { key, updatedAt: null, problem } : { key, updatedAt: entry.updatedAt };
  });
}

export function deleteSecret(password, key, path = defaultVaultPath()) {
  const data = loadVault(password, path);
  if (!data) throw new Error('Vault not found. Run "cryptoserve vault init" first.');
  if (!(key in data.secrets)) return false;
  delete data.secrets[key];
  saveVault(data, password, path);
  return true;
}

/**
 * Delete the vault, after proving the caller can open it.
 *
 * This used to unlink unconditionally, so `vault reset --password wrong` and
 * `vault reset` with no password both printed "Vault deleted." and exited 0.
 * Deleting ONE secret was authenticated and deleting ALL of them was not, which
 * is the wrong way round: an attacker with filesystem access could already
 * remove the file, but a CLI that answers a wrong password by destroying the
 * data is a footgun pointed at its owner.
 */
export function resetVault(password, path = defaultVaultPath()) {
  if (!existsSync(path)) return false;
  // Throws on a wrong password, exactly as every other vault read does.
  loadVault(password, path);
  unlinkSync(path);
  return true;
}

// ---------------------------------------------------------------------------
// vault run — inject secrets as env vars into a child process
// ---------------------------------------------------------------------------

/**
 * Run a command with each secret as an environment variable and resolve with
 * its exit code. An entry that is not a secret is left out, and `onSkip` is
 * called with its { key, problem } before the command starts. This used to read
 * `value` of every entry: a null entry threw before the command started, as
 * did a value that does not convert to a string, and a value of null or an
 * array reached the command as the text "null" or "a,b".
 */
export function vaultRun(password, command, args = [], path = defaultVaultPath(), { onSkip } = {}) {
  const data = loadVault(password, path);
  if (!data) throw new Error('Vault not found. Run "cryptoserve vault init" first.');

  // No prototype, as in secretTable: on a plain object, assigning a secret
  // named __proto__ set no variable.
  const secretEnv = Object.create(null);
  for (const [key, entry] of Object.entries(data.secrets)) {
    const problem = entryProblem(entry);
    if (problem) onSkip?.({ key, problem });
    else secretEnv[key] = entry.value;
  }

  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: 'inherit',
      env: { ...process.env, ...secretEnv },
    });

    child.on('close', code => resolve(code));
    child.on('error', reject);
  });
}

// ---------------------------------------------------------------------------
// vault import — read .env file, store each key in vault
// ---------------------------------------------------------------------------

export function importEnvFile(password, envPath, path = defaultVaultPath()) {
  if (!existsSync(envPath)) throw new Error(`File not found: ${envPath}`);

  const content = readFileSync(envPath, 'utf-8');
  const lines = content.split('\n');
  let imported = 0;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    // Parse KEY=VALUE (supports optional quotes)
    const match = trimmed.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (!match) continue;

    const [, key, rawValue] = match;
    // Strip surrounding quotes
    let value = rawValue;
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }

    setSecret(password, key, value, path);
    imported++;
  }

  return imported;
}

// ---------------------------------------------------------------------------
// vault export — create encrypted bundle
// ---------------------------------------------------------------------------

/**
 * The vault's secrets as an encrypted bundle. A vault holding an entry that
 * importVaultBundle refuses, such as a number setSecret stored before it
 * refused one, is not exported, because the bundle would not import.
 */
export function exportVault(password, exportPassword = null, path = defaultVaultPath()) {
  const data = loadVault(password, path);
  if (!data) throw new Error('Vault not found.');

  const refused = refusedEntries(data.secrets);
  if (refused) {
    throw new Error(`Vault not exported: ${refused}. The bundle would not import. `
      + 'Store each such secret again as a string, or delete it.');
  }

  const json = JSON.stringify(data.secrets);
  const pw = exportPassword || password;
  return encryptData(json, pw).toString('base64');
}

/**
 * The entries of a secrets table that importVaultBundle refuses, as its error
 * message names them: the first five and a count of the rest, or '' when there
 * are none. The import takes an entry that is a string, or an object with a
 * string `value` as exportVault writes it. exportVault applies the same check
 * before it writes a bundle.
 */
function refusedEntries(secrets) {
  const refused = [];
  for (const [key, entry] of Object.entries(secrets)) {
    const name = JSON.stringify(key);
    if (typeof entry === 'string') continue;
    if (kindOf(entry) !== 'an object') {
      refused.push(`${name} is ${kindOf(entry)}`);
    } else if (typeof entry.value !== 'string') {
      refused.push(`${name} has no string "value"`);
    }
  }
  const more = refused.length > 5 ? `, and ${refused.length - 5} more` : '';
  return refused.length > 0 ? `${refused.slice(0, 5).join(', ')}${more}` : '';
}

/**
 * What keeps an entry from being a secret, such as 'is null' or 'has no string
 * "value"', or null when it is one: an object with a string `value`, the shape
 * setSecret writes. importVaultBundle stores nothing else, but it used to store
 * a bundle's object entries as they were, and a vault it wrote then still holds
 * them, so listSecrets and vaultRun check each entry too.
 */
function entryProblem(entry) {
  const kind = kindOf(entry);
  if (kind !== 'an object') return `is ${kind}`;
  if (typeof entry.value !== 'string') return 'has no string "value"';
  return null;
}

/**
 * The [name, entry] pairs a bundle holds, each entry in the shape setSecret
 * writes, { value, updatedAt }. A bundle entry is a string, or an object with a
 * string `value` as exportVault writes it, whose `updatedAt` is kept when it is
 * a string Date.parse reads. Any other entry refuses the whole bundle before
 * the vault is read, so nothing from it is stored.
 *
 * Every entry whose typeof was 'object' used to be stored as it was. After a
 * null one, listSecrets and vaultRun threw for the whole vault until that name
 * was deleted, and an array or an object without a `value` read back from
 * getSecret as undefined.
 */
function bundleEntries(secrets) {
  const kind = kindOf(secrets);
  if (kind !== 'an object') {
    throw new Error(`Bundle not imported: it holds ${kind}, not a table of secrets. `
      + 'The vault was not changed.');
  }
  const refused = refusedEntries(secrets);
  if (refused) {
    throw new Error(`Bundle not imported: ${refused}. Each entry must be a string or an object `
      + 'with a string "value". The vault was not changed.');
  }
  const now = new Date().toISOString();
  return Object.entries(secrets).map(([key, entry]) => {
    if (typeof entry === 'string') return [key, { value: entry, updatedAt: now }];
    const { updatedAt } = entry;
    const dated = typeof updatedAt === 'string' && !Number.isNaN(Date.parse(updatedAt));
    return [key, { value: entry.value, updatedAt: dated ? updatedAt : now }];
  });
}

export function importVaultBundle(password, bundle, importPassword = null, path = defaultVaultPath()) {
  const packed = Buffer.from(bundle, 'base64');
  const pw = importPassword || password;
  const json = decryptData(packed, pw);
  const entries = bundleEntries(JSON.parse(json));

  const data = loadVault(password, path) || {
    version: 1,
    createdAt: new Date().toISOString(),
    secrets: secretTable(),
  };

  for (const [key, entry] of entries) {
    data.secrets[key] = entry;
  }

  saveVault(data, password, path);
  return entries.length;
}

// Re-export for testing
export { encryptData as _encryptData, decryptData as _decryptData };
