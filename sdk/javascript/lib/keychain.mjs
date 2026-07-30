/**
 * OS keychain integration for secure local key storage.
 *
 * Uses native OS keychain via child_process (zero dependencies):
 * - macOS: /usr/bin/security (Keychain.app)
 * - Linux: secret-tool (freedesktop.org Secret Service / GNOME Keyring)
 * - Windows: cmdkey.exe + PowerShell (Credential Manager)
 *
 * Fallback: encrypted JSON file at ~/.cryptoserve/keystore.enc
 */

import { execFile, spawn } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { platform } from 'node:os';
import { configPath, ensureConfigDir } from './paths.mjs';
import { randomBytes, scryptSync, createCipheriv, createDecipheriv, hkdfSync } from 'node:crypto';
import { createInterface } from 'node:readline';

const SERVICE_NAME = 'cryptoserve';
const ACCOUNT_NAME = 'master-key';
// Resolved per call (CRYPTOSERVE_HOME aware), never frozen at import time.
// See lib/paths.mjs.
function keystorePath() {
  return configPath('keystore.enc');
}

// ---------------------------------------------------------------------------
// Platform-specific keychain backends
// ---------------------------------------------------------------------------

function execPromise(cmd, args) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { timeout: 10000 }, (err, stdout, stderr) => {
      if (err) return reject(Object.assign(err, { stderr }));
      resolve({ stdout, stderr });
    });
  });
}

function spawnWrite(cmd, args, stdin) {
  return new Promise((resolve, reject) => {
    const proc = spawn(cmd, args, { timeout: 10000 });
    let stderr = '';
    proc.stderr.on('data', d => { stderr += d; });
    proc.stdin.write(stdin);
    proc.stdin.end();
    proc.on('close', code => {
      if (code !== 0) return reject(new Error(`${cmd} exited ${code}: ${stderr}`));
      resolve();
    });
    proc.on('error', reject);
  });
}

const backends = {
  darwin: {
    async set(value) {
      // Delete existing (ignore error if not found)
      try {
        await execPromise('/usr/bin/security', [
          'delete-generic-password', '-a', ACCOUNT_NAME, '-s', SERVICE_NAME,
        ]);
      } catch { /* not found — OK */ }
      await execPromise('/usr/bin/security', [
        'add-generic-password', '-a', ACCOUNT_NAME, '-s', SERVICE_NAME,
        '-w', value, '-U',
      ]);
    },
    async get() {
      const { stderr } = await execPromise('/usr/bin/security', [
        'find-generic-password', '-a', ACCOUNT_NAME, '-s', SERVICE_NAME, '-g',
      ]);
      const match = stderr.match(/password:\s*"(.+)"/);
      if (match) return match[1];
      const hexMatch = stderr.match(/password:\s*0x([0-9A-Fa-f]+)/);
      if (hexMatch) return Buffer.from(hexMatch[1], 'hex').toString();
      throw new Error('Could not parse keychain response');
    },
    async delete() {
      await execPromise('/usr/bin/security', [
        'delete-generic-password', '-a', ACCOUNT_NAME, '-s', SERVICE_NAME,
      ]);
    },
  },

  linux: {
    async set(value) {
      await spawnWrite('secret-tool', [
        'store', '--label', 'CryptoServe Master Key',
        'service', SERVICE_NAME, 'account', ACCOUNT_NAME,
      ], value);
    },
    async get() {
      const { stdout } = await execPromise('secret-tool', [
        'lookup', 'service', SERVICE_NAME, 'account', ACCOUNT_NAME,
      ]);
      return stdout.trim();
    },
    async delete() {
      await execPromise('secret-tool', [
        'clear', 'service', SERVICE_NAME, 'account', ACCOUNT_NAME,
      ]);
    },
  },

  win32: {
    async set(value) {
      await execPromise('cmdkey.exe', [
        `/generic:${SERVICE_NAME}`, `/user:${ACCOUNT_NAME}`, `/pass:${value}`,
      ]);
    },
    async get() {
      const { stdout } = await execPromise('powershell', [
        '-Command',
        `(New-Object System.Net.NetworkCredential("","$(cmdkey /list:${SERVICE_NAME} | Out-Null; [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((Get-StoredCredential -Target '${SERVICE_NAME}').Password)))")).Password`,
      ]);
      return stdout.trim();
    },
    async delete() {
      await execPromise('cmdkey.exe', [`/delete:${SERVICE_NAME}`]);
    },
  },
};

// ---------------------------------------------------------------------------
// Encrypted file fallback
// ---------------------------------------------------------------------------

const FALLBACK_SALT_SIZE = 32;
const FALLBACK_IV_SIZE = 12;
const FALLBACK_TAG_SIZE = 16;

function encryptForStorage(data, password) {
  const salt = randomBytes(FALLBACK_SALT_SIZE);
  const key = scryptSync(password, salt, 32, { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  const iv = randomBytes(FALLBACK_IV_SIZE);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(data, 'utf-8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([salt, iv, tag, encrypted]);
}

function decryptFromStorage(packed, password) {
  const salt = packed.subarray(0, FALLBACK_SALT_SIZE);
  const iv = packed.subarray(FALLBACK_SALT_SIZE, FALLBACK_SALT_SIZE + FALLBACK_IV_SIZE);
  const tag = packed.subarray(FALLBACK_SALT_SIZE + FALLBACK_IV_SIZE, FALLBACK_SALT_SIZE + FALLBACK_IV_SIZE + FALLBACK_TAG_SIZE);
  const encrypted = packed.subarray(FALLBACK_SALT_SIZE + FALLBACK_IV_SIZE + FALLBACK_TAG_SIZE);
  const key = scryptSync(password, salt, 32, { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf-8');
}

// ---------------------------------------------------------------------------
// Password prompting
// ---------------------------------------------------------------------------

/**
 * Raised when a password is needed and there is no terminal to ask on.
 *
 * The bin turns this into a plain message and exit 2. It carries a code rather
 * than being matched on its text so an intermediate catch can re-throw it
 * without having to recognise the wording.
 */
export class NonInteractiveError extends Error {
  constructor(message) {
    super(message);
    this.name = 'NonInteractiveError';
    this.code = 'ERR_NO_TTY';
  }
}

/**
 * Ask for a password on the terminal.
 *
 * With stdin redirected — `</dev/null`, a pipe, any CI runner — the old
 * implementation registered a `data` listener that would never fire, so the
 * promise never settled. Node eventually printed its own internals at the user
 * ("Detected unsettled top-level await at .../bin/cryptoserve.mjs:1287", with
 * installed file paths) and exited 13. That is a diagnostic about our code, not
 * an answer to the operator's question, which is "what should I have passed?".
 *
 * `hint` names the non-interactive form for the calling command, because the
 * answer differs: most commands take `--password`, but `init` takes
 * `--insecure-storage` and `vault set` takes the value as an argument.
 */
export function promptPassword(prompt = 'Password: ', { hint = 'Pass --password <value>.' } = {}) {
  if (!process.stdin.isTTY) {
    return Promise.reject(new NonInteractiveError(
      `Cannot prompt for a password: stdin is not a terminal.\n${hint}`
    ));
  }

  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stderr });
    // Hide input
    process.stderr.write(prompt);
    const originalWrite = process.stdout.write;
    process.stdout.write = () => true;

    let password = '';
    process.stdin.setRawMode?.(true);
    process.stdin.resume();
    process.stdin.on('data', function handler(ch) {
      const c = ch.toString();
      if (c === '\n' || c === '\r') {
        process.stdin.setRawMode?.(false);
        process.stdin.removeListener('data', handler);
        process.stdout.write = originalWrite;
        process.stderr.write('\n');
        rl.close();
        resolve(password);
      } else if (c === '\x7f' || c === '\b') {
        password = password.slice(0, -1);
      } else if (c === '\x03') {
        // Ctrl+C
        process.stdout.write = originalWrite;
        rl.close();
        process.exit(1);
      } else {
        password += c;
      }
    });
  });
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Whether this process is allowed to touch the OS keychain at all.
 *
 * `CRYPTOSERVE_NO_KEYCHAIN=1` turns every keychain path off. Containers and CI
 * runners have no keychain service, and probing for one there costs a
 * subprocess and can hang; declaring its absence is better than discovering it.
 *
 * It also makes the `--insecure-storage` path reachable on demand. That branch
 * only executes when no master key is found, so on a developer machine where
 * `cryptoserve init` has ever run, a regression test for it silently exercises
 * nothing -- which is how a ReferenceError on that exact branch shipped.
 */
function keychainDisabled() {
  const v = process.env.CRYPTOSERVE_NO_KEYCHAIN;
  return v !== undefined && v !== '' && v !== '0' && v.toLowerCase() !== 'false';
}

export async function isKeychainAvailable() {
  if (keychainDisabled()) return false;
  const os = platform();
  const backend = backends[os];
  if (!backend) return false;

  try {
    if (os === 'darwin') {
      await execPromise('/usr/bin/security', ['list-keychains']);
      return true;
    }
    if (os === 'linux') {
      await execPromise('which', ['secret-tool']);
      return true;
    }
    if (os === 'win32') {
      await execPromise('where', ['cmdkey.exe']);
      return true;
    }
  } catch {
    return false;
  }
  return false;
}

export async function generateMasterKey() {
  return randomBytes(32).toString('base64');
}

export async function storeMasterKey(keyBase64, { useKeychain = true, fallbackPassword = null } = {}) {
  ensureConfigDir();

  if (useKeychain && !keychainDisabled()) {
    const backend = backends[platform()];
    if (backend) {
      try {
        await backend.set(keyBase64);
        return { storage: 'keychain', platform: platform() };
      } catch {
        // Keychain failed, fall through to file fallback
      }
    }
  }

  // Encrypted file fallback
  if (!fallbackPassword) {
    throw new Error(
      'No keychain available. Use --insecure-storage or provide a password for encrypted file storage.'
    );
  }

  const encrypted = encryptForStorage(keyBase64, fallbackPassword);
  const path = keystorePath();
  writeFileSync(path, encrypted, { mode: 0o600 });
  return { storage: 'encrypted-file', path };
}

export async function loadMasterKey({ fallbackPassword = null } = {}) {
  // Try OS keychain first
  const backend = keychainDisabled() ? null : backends[platform()];
  if (backend) {
    try {
      return await backend.get();
    } catch {
      // Not in keychain, try file fallback
    }
  }

  // Try encrypted file
  if (existsSync(keystorePath())) {
    if (!fallbackPassword) {
      throw new Error(
        'Master key is stored in encrypted file. Provide password or use OS keychain.'
      );
    }
    return decryptFromStorage(readFileSync(keystorePath()), fallbackPassword);
  }

  return null;
}

export async function deleteMasterKey() {
  const backend = keychainDisabled() ? null : backends[platform()];
  if (backend) {
    try { await backend.delete(); } catch { /* OK */ }
  }
  // Also remove file fallback if exists
  if (existsSync(keystorePath())) {
    const { unlinkSync } = await import('node:fs');
    unlinkSync(keystorePath());
  }
}

// ---------------------------------------------------------------------------
// Key derivation (HKDF) for per-context/per-project keys
// ---------------------------------------------------------------------------

export function deriveKey(masterKeyBase64, context, keySize = 32) {
  const masterKey = Buffer.from(masterKeyBase64, 'base64');
  return Buffer.from(
    hkdfSync('sha256', masterKey, 'cryptoserve-v1', context, keySize)
  );
}

export function deriveProjectKey(masterKeyBase64, projectName, environment = 'development') {
  return deriveKey(masterKeyBase64, `project:${projectName}:${environment}`);
}
