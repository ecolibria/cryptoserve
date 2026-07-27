/**
 * Credential storage for CryptoServe platform integration.
 *
 * Stores/reads tokens at `<state dir>/credentials.json` with 0o600 permissions.
 * The state directory is resolved by lib/paths.mjs, so CRYPTOSERVE_HOME moves
 * it wholesale (tests, CI, containers).
 */

import { existsSync, readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { configPath, ensureConfigDir } from './paths.mjs';

/** Resolved per call so a CRYPTOSERVE_HOME change takes effect immediately. */
export function tokenStorePath() {
  return configPath('credentials.json');
}

export function saveToken(token, server = 'https://localhost:8003') {
  ensureConfigDir();
  const data = {
    token,
    server,
    savedAt: new Date().toISOString(),
  };
  writeFileSync(tokenStorePath(), JSON.stringify(data, null, 2), { mode: 0o600 });
}

export function loadToken() {
  const path = tokenStorePath();
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, 'utf-8'));
  } catch {
    return null;
  }
}

export function clearToken() {
  const path = tokenStorePath();
  if (existsSync(path)) {
    unlinkSync(path);
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
