/**
 * Credential storage for CryptoServe platform integration.
 *
 * Stores/reads tokens at ~/.cryptoserve/credentials.json with 0o600 permissions.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

const CONFIG_DIR = join(homedir(), '.cryptoserve');
const CREDENTIALS_PATH = join(CONFIG_DIR, 'credentials.json');

function ensureDir() {
  if (!existsSync(CONFIG_DIR)) {
    mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  }
}

export function saveToken(token, server = 'https://localhost:8003') {
  ensureDir();
  const data = {
    token,
    server,
    savedAt: new Date().toISOString(),
  };
  writeFileSync(CREDENTIALS_PATH, JSON.stringify(data, null, 2), { mode: 0o600 });
}

export function loadToken() {
  if (!existsSync(CREDENTIALS_PATH)) return null;
  try {
    return JSON.parse(readFileSync(CREDENTIALS_PATH, 'utf-8'));
  } catch {
    return null;
  }
}

export function clearToken() {
  if (existsSync(CREDENTIALS_PATH)) {
    unlinkSync(CREDENTIALS_PATH);
  }
}

export function maskToken(token) {
  if (!token || token.length < 12) return '***';
  return token.slice(0, 8) + '...' + token.slice(-4);
}

export function parseJwtExpiry(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    if (!payload.exp) return null;
    const expiresAt = new Date(payload.exp * 1000);
    const remaining = expiresAt - Date.now();
    return {
      expiresAt,
      remainingMs: remaining,
      expired: remaining <= 0,
      subject: payload.sub || null,
    };
  } catch {
    return null;
  }
}
