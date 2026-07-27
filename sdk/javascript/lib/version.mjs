/**
 * Single source of truth for the CLI version.
 *
 * Read from package.json at runtime rather than duplicated as a literal.
 * CBOM and SARIF documents record the producing tool's version as provenance,
 * and a hardcoded copy drifts silently: cbom.mjs claimed 0.2.0 through the
 * entire 0.3.x line, so every CBOM ever emitted named the wrong producer.
 *
 * Zero dependencies.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));

function readVersion() {
  try {
    const pkg = JSON.parse(readFileSync(join(HERE, '..', 'package.json'), 'utf-8'));
    if (typeof pkg.version === 'string' && pkg.version.length > 0) return pkg.version;
  } catch {
    // Fall through: a published tarball always ships package.json, so this is
    // only reachable in an unusual install layout.
  }
  return '0.0.0-unknown';
}

export const VERSION = readVersion();

export const TOOL_NAME = 'CryptoServe';
export const TOOL_URI = 'https://cryptoserve.dev';
