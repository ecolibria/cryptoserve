/**
 * Resolution of the CryptoServe state directory.
 *
 * State (master key, vault, credentials, census cache) lived at a hardcoded
 * `~/.cryptoserve` in five separate modules. That made the CLI impossible to
 * sandbox: a test, a CI job or a container had no way to keep its keys and
 * vault out of the invoking user's home directory.
 *
 * Resolution order:
 *   1. $CRYPTOSERVE_HOME          - explicit override, wins outright
 *   2. $XDG_CONFIG_HOME/cryptoserve - honored when set (Linux convention)
 *   3. ~/.cryptoserve             - the historical default
 *
 * Zero dependencies.
 */

import { existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

/**
 * Absolute path to the state directory. Read from the environment on each call
 * so a process that changes CRYPTOSERVE_HOME (tests do) sees the new value.
 */
export function configDir() {
  const override = process.env.CRYPTOSERVE_HOME;
  if (override && override.trim().length > 0) return override;

  const xdg = process.env.XDG_CONFIG_HOME;
  if (xdg && xdg.trim().length > 0) return join(xdg, 'cryptoserve');

  return join(homedir(), '.cryptoserve');
}

/** Path to a file inside the state directory. */
export function configPath(...segments) {
  return join(configDir(), ...segments);
}

/**
 * Create the state directory if absent. Mode 0700 because it holds key
 * material; the caller is responsible for per-file modes.
 */
export function ensureConfigDir() {
  const dir = configDir();
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

/**
 * Render a path for display, collapsing the user's home directory to `~`.
 * Used so messages quote the path actually written rather than a literal.
 */
export function displayPath(absolutePath) {
  const home = homedir();
  return absolutePath.startsWith(home + '/') ? '~' + absolutePath.slice(home.length) : absolutePath;
}
