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

import { existsSync, readFileSync, writeFileSync, unlinkSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { randomBytes, scryptSync, createCipheriv, createDecipheriv } from 'node:crypto';
import { spawn } from 'node:child_process';

const CONFIG_DIR = join(homedir(), '.cryptoserve');
const VAULT_PATH = join(CONFIG_DIR, 'vault.enc');
const SALT_SIZE = 32;
const IV_SIZE = 12;
const TAG_SIZE = 16;
const SCRYPT_OPTS = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function ensureConfigDir() {
  if (!existsSync(CONFIG_DIR)) {
    mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  }
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

function loadVault(password, path = VAULT_PATH) {
  if (!existsSync(path)) return null;
  const packed = readFileSync(path);
  const json = decryptData(packed, password);
  return JSON.parse(json);
}

function saveVault(data, password, path = VAULT_PATH) {
  ensureConfigDir();
  const json = JSON.stringify(data, null, 2);
  const encrypted = encryptData(json, password);
  writeFileSync(path, encrypted, { mode: 0o600 });
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function vaultExists(path = VAULT_PATH) {
  return existsSync(path);
}

export function initVault(password, path = VAULT_PATH) {
  if (existsSync(path)) {
    throw new Error('Vault already exists. Use "vault reset" to recreate.');
  }
  const data = {
    version: 1,
    createdAt: new Date().toISOString(),
    secrets: {},
  };
  saveVault(data, password, path);
  return data;
}

export function setSecret(password, key, value, path = VAULT_PATH) {
  const data = loadVault(password, path);
  if (!data) throw new Error('Vault not found. Run "cryptoserve vault init" first.');
  data.secrets[key] = {
    value,
    updatedAt: new Date().toISOString(),
  };
  saveVault(data, password, path);
}

export function getSecret(password, key, path = VAULT_PATH) {
  const data = loadVault(password, path);
  if (!data) throw new Error('Vault not found. Run "cryptoserve vault init" first.');
  const entry = data.secrets[key];
  if (!entry) return null;
  return entry.value;
}

export function listSecrets(password, path = VAULT_PATH) {
  const data = loadVault(password, path);
  if (!data) throw new Error('Vault not found. Run "cryptoserve vault init" first.');
  return Object.entries(data.secrets).map(([key, entry]) => ({
    key,
    updatedAt: entry.updatedAt,
  }));
}

export function deleteSecret(password, key, path = VAULT_PATH) {
  const data = loadVault(password, path);
  if (!data) throw new Error('Vault not found. Run "cryptoserve vault init" first.');
  if (!(key in data.secrets)) return false;
  delete data.secrets[key];
  saveVault(data, password, path);
  return true;
}

export function resetVault(path = VAULT_PATH) {
  if (existsSync(path)) unlinkSync(path);
}

// ---------------------------------------------------------------------------
// vault run — inject secrets as env vars into a child process
// ---------------------------------------------------------------------------

export function vaultRun(password, command, args = [], path = VAULT_PATH) {
  const data = loadVault(password, path);
  if (!data) throw new Error('Vault not found. Run "cryptoserve vault init" first.');

  const secretEnv = {};
  for (const [key, entry] of Object.entries(data.secrets)) {
    secretEnv[key] = entry.value;
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

export function importEnvFile(password, envPath, path = VAULT_PATH) {
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

export function exportVault(password, exportPassword = null, path = VAULT_PATH) {
  const data = loadVault(password, path);
  if (!data) throw new Error('Vault not found.');

  const json = JSON.stringify(data.secrets);
  const pw = exportPassword || password;
  return encryptData(json, pw).toString('base64');
}

export function importVaultBundle(password, bundle, importPassword = null, path = VAULT_PATH) {
  const packed = Buffer.from(bundle, 'base64');
  const pw = importPassword || password;
  const json = decryptData(packed, pw);
  const secrets = JSON.parse(json);

  const data = loadVault(password, path) || {
    version: 1,
    createdAt: new Date().toISOString(),
    secrets: {},
  };

  for (const [key, entry] of Object.entries(secrets)) {
    data.secrets[key] = typeof entry === 'object' ? entry : {
      value: entry,
      updatedAt: new Date().toISOString(),
    };
  }

  saveVault(data, password, path);
  return Object.keys(secrets).length;
}

// Re-export for testing
export { encryptData as _encryptData, decryptData as _decryptData };
