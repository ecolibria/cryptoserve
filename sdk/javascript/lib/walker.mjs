/**
 * Unified single-pass file walker.
 *
 * Replaces three independent walkers (scanner.mjs, scanner-tls.mjs,
 * scanner-binary.mjs) with a single directory traversal that classifies
 * files into buckets by extension.
 * Zero dependencies — uses only node:fs and node:path.
 */

import { readdirSync, statSync, openSync, readSync, closeSync } from 'node:fs';
import { join, extname } from 'node:path';

// ---------------------------------------------------------------------------
// Default skip directories (union of all three previous walkers)
// ---------------------------------------------------------------------------

export const DEFAULT_SKIP_DIRS = new Set([
  'node_modules', '.git', '.next', 'dist', 'build', 'coverage',
  '.cache', '.nuxt', '.output', '.svelte-kit', '__pycache__',
  'vendor', '.venv', 'venv',
]);

// ---------------------------------------------------------------------------
// File classification by extension
// ---------------------------------------------------------------------------

const SOURCE_EXTENSIONS = new Set([
  '.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx',
  '.go', '.py',
  '.java', '.kt', '.scala',
  '.rs',
  '.c', '.h', '.cpp', '.hpp', '.cc', '.cxx',
]);

const CONFIG_EXTENSIONS = new Set([
  '.conf', '.cfg', '.ini', '.toml', '.yaml', '.yml', '.json', '.xml',
]);

const CONFIG_NAMES = new Set([
  'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
  'nginx.conf', 'httpd.conf', 'apache2.conf', 'ssl.conf',
  '.env',
]);

/**
 * Whether a filename is a dotenv file.
 *
 * `.env` alone was the only name recognised, so `.env.local` and
 * `.env.production` -- the ones a developer is most likely to have on disk with
 * live credentials in them -- were not collected at all.
 *
 * Templates (`.env.example` and friends) are INCLUDED. Excluding them by name
 * was the wrong instinct: a template is the file that actually gets committed,
 * while `.env` is usually gitignored, so a real key pasted into `.env.example`
 * is the higher-risk case rather than the lower-risk one. Placeholders are
 * filtered by their VALUE instead, where the evidence is.
 */
/**
 * Whether a file begins with a PEM private-key header.
 *
 * Reads only the first line. A public `-----BEGIN CERTIFICATE-----` is
 * deliberately not a match: publishing a certificate is routine, publishing the
 * key that signs it is the incident.
 */
/** A PEM private key is small; anything large is not worth opening to check. */
function isSmallEnoughToSniff(filePath) {
  try {
    const { size } = statSync(filePath);
    return size > 0 && size <= 64 * 1024;
  } catch {
    return false;
  }
}

function looksLikePemPrivateKey(filePath) {
  let fd;
  try {
    fd = openSync(filePath, 'r');
    const buf = Buffer.alloc(64);
    const read = readSync(fd, buf, 0, 64, 0);
    return /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/.test(buf.subarray(0, read).toString('latin1'));
  } catch {
    return false;
  } finally {
    if (fd !== undefined) { try { closeSync(fd); } catch { /* already closed */ } }
  }
}

export function isDotenvFile(name) {
  return name === '.env' || (name.startsWith('.env.') && name.length > '.env.'.length);
}

const BINARY_EXTENSIONS = new Set([
  '.exe', '.dll', '.so', '.dylib', '.wasm',
  '.class', '.jar', '.war',
  '.o', '.a', '.lib',
  '.pyc', '.pyd',
]);

const CERT_EXTENSIONS = new Set(['.pem', '.key', '.crt', '.p12', '.pfx', '.jks', '.keystore']);

// ---------------------------------------------------------------------------
// Walker
// ---------------------------------------------------------------------------

/**
 * Walk a project directory once, classifying files into buckets.
 *
 * @param {string} dir - Root directory to walk
 * @param {object} options
 * @param {Set<string>} [options.skipDirs] - Extra directory names to skip (merged with defaults)
 * @param {Set<string>} [options.includeExtensions] - Extra source extensions to include
 * @param {number} [options.maxFiles=10000] - Max total files to collect
 * @param {number} [options.maxBytes=524288000] - Max total bytes (500MB)
 * @param {number} [options.maxFileSize=1048576] - Max single file size (1MB) for source/config
 * @param {number} [options.maxBinaryFiles=50] - Max binary files
 * @param {number} [options.maxBinaryFileSize=10485760] - Max binary file size (10MB)
 * @returns {{ sourceFiles: string[], configFiles: string[], binaryFiles: string[], certFiles: string[], totalBytes: number, totalFiles: number }}
 */
export function walkProject(dir, options = {}) {
  const skipDirs = options.skipDirs
    ? new Set([...DEFAULT_SKIP_DIRS, ...options.skipDirs])
    : DEFAULT_SKIP_DIRS;
  const extraSourceExts = options.includeExtensions
    ? new Set([...SOURCE_EXTENSIONS, ...options.includeExtensions])
    : SOURCE_EXTENSIONS;
  const maxFiles = options.maxFiles || 10000;
  const maxBytes = options.maxBytes || 500 * 1024 * 1024;
  const maxFileSize = options.maxFileSize || 1024 * 1024;
  const maxBinaryFiles = options.maxBinaryFiles || 50;
  const maxBinaryFileSize = options.maxBinaryFileSize || 10 * 1024 * 1024;

  const sourceFiles = [];
  const configFiles = [];
  const binaryFiles = [];
  const certFiles = [];
  let totalBytes = 0;
  let totalFiles = 0;

  function walk(currentDir) {
    if (totalFiles >= maxFiles || totalBytes >= maxBytes) return;

    let entries;
    try { entries = readdirSync(currentDir, { withFileTypes: true }); }
    catch { return; }

    for (const entry of entries) {
      if (totalFiles >= maxFiles || totalBytes >= maxBytes) return;

      if (entry.isDirectory()) {
        if (!skipDirs.has(entry.name) && !entry.name.startsWith('.')) {
          walk(join(currentDir, entry.name));
        }
        continue;
      }

      if (!entry.isFile()) continue;

      const filePath = join(currentDir, entry.name);
      const ext = extname(entry.name).toLowerCase();
      const name = entry.name;

      // Classify cert files (no size check needed — just record path)
      // A private key's evidence is its first line, not its filename. Gating
      // on the extension found `server.key` and missed a byte-identical
      // `id_rsa`, which is the most common name a committed key actually has.
      // Only small unclassified files are sniffed, and only their first line:
      // PEM keys are tiny, so this costs one short read per candidate.
      if (!CERT_EXTENSIONS.has(ext) && !BINARY_EXTENSIONS.has(ext)
          && !extraSourceExts.has(ext) && !CONFIG_EXTENSIONS.has(ext)
          && !CONFIG_NAMES.has(name) && !isDotenvFile(name)
          && isSmallEnoughToSniff(filePath) && looksLikePemPrivateKey(filePath)) {
        certFiles.push(filePath);
        totalFiles++;
        continue;
      }

      if (CERT_EXTENSIONS.has(ext)) {
        certFiles.push(filePath);
        totalFiles++;
        continue;
      }

      // Classify binary files (separate limit)
      if (BINARY_EXTENSIONS.has(ext)) {
        if (binaryFiles.length < maxBinaryFiles) {
          try {
            const stat = statSync(filePath);
            if (stat.size <= maxBinaryFileSize) {
              binaryFiles.push(filePath);
              totalFiles++;
            }
          } catch { /* skip */ }
        }
        continue;
      }

      // Check size for source/config files
      let fileSize;
      try {
        const stat = statSync(filePath);
        if (stat.size > maxFileSize) continue;
        fileSize = stat.size;
      } catch { continue; }

      totalBytes += fileSize;
      totalFiles++;

      // Classify source files
      if (extraSourceExts.has(ext)) {
        sourceFiles.push(filePath);
        continue;
      }

      // Classify config files
      if (CONFIG_EXTENSIONS.has(ext) || CONFIG_NAMES.has(name) || isDotenvFile(name)) {
        configFiles.push(filePath);
        continue;
      }

      // Other files are walked but not bucketed
    }
  }

  walk(dir);

  return { sourceFiles, configFiles, binaryFiles, certFiles, totalBytes, totalFiles };
}
