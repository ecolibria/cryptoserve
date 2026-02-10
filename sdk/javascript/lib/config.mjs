/**
 * Scanner configuration loader.
 *
 * Reads optional `scanner` section from `.cryptoserve.json` and merges
 * with hard-coded defaults so users can override limits and skip directories.
 * Zero dependencies — uses only node:fs and node:path.
 *
 * .cryptoserve.json format:
 * {
 *   "contexts": { ... },        // existing encryption contexts
 *   "scanner": {
 *     "skipDirs": ["my-vendor", "generated"],
 *     "includeExtensions": [".sol"],
 *     "maxFiles": 20000,
 *     "maxFileSize": 2097152,
 *     "binary": {
 *       "maxFiles": 100,
 *       "maxFileSize": 20971520
 *     }
 *   }
 * }
 *
 * All fields optional. Extra values extend defaults, never replace.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const SCANNER_DEFAULTS = {
  skipDirs: [],
  includeExtensions: [],
  maxFiles: 10000,
  maxBytes: 500 * 1024 * 1024,
  maxFileSize: 1024 * 1024,
  binary: {
    maxFiles: 50,
    maxFileSize: 10 * 1024 * 1024,
  },
};

// ---------------------------------------------------------------------------
// Loaders
// ---------------------------------------------------------------------------

/**
 * Load raw .cryptoserve.json from the given directory.
 * Returns the parsed object, or null if not found or invalid.
 */
export function loadConfig(dir = process.cwd()) {
  try {
    const configPath = resolve(dir, '.cryptoserve.json');
    return JSON.parse(readFileSync(configPath, 'utf-8'));
  } catch {
    return null;
  }
}

/**
 * Load scanner configuration, merging .cryptoserve.json scanner section
 * with defaults. Extra skipDirs and includeExtensions extend the defaults.
 *
 * @param {string} [dir] - Directory to look for .cryptoserve.json
 * @returns {object} Merged scanner configuration
 */
export function loadScannerConfig(dir = process.cwd()) {
  const config = loadConfig(dir);
  const scanner = config?.scanner;
  if (!scanner) return { ...SCANNER_DEFAULTS, binary: { ...SCANNER_DEFAULTS.binary } };

  const result = {
    skipDirs: Array.isArray(scanner.skipDirs) ? scanner.skipDirs : [],
    includeExtensions: Array.isArray(scanner.includeExtensions) ? scanner.includeExtensions : [],
    maxFiles: typeof scanner.maxFiles === 'number' ? scanner.maxFiles : SCANNER_DEFAULTS.maxFiles,
    maxBytes: typeof scanner.maxBytes === 'number' ? scanner.maxBytes : SCANNER_DEFAULTS.maxBytes,
    maxFileSize: typeof scanner.maxFileSize === 'number' ? scanner.maxFileSize : SCANNER_DEFAULTS.maxFileSize,
    binary: {
      maxFiles: typeof scanner.binary?.maxFiles === 'number' ? scanner.binary.maxFiles : SCANNER_DEFAULTS.binary.maxFiles,
      maxFileSize: typeof scanner.binary?.maxFileSize === 'number' ? scanner.binary.maxFileSize : SCANNER_DEFAULTS.binary.maxFileSize,
    },
  };

  return result;
}
