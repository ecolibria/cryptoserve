/**
 * JavaScript/TypeScript crypto dependency and secret scanner.
 *
 * Scans projects for:
 * 1. Cryptographic dependencies (package.json, imports, algorithm strings)
 * 2. Hardcoded secrets (API keys, passwords — patterns from secretless-ai)
 * 3. Certificate/key files (.pem, .key, .crt, .p12)
 *
 * Output matches the library inventory format used by pqc-engine.mjs.
 * Zero dependencies — uses only node:fs and node:path.
 */

import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, extname, basename } from 'node:path';

// ---------------------------------------------------------------------------
// Known crypto packages → algorithm mappings
// ---------------------------------------------------------------------------

const CRYPTO_PACKAGES = {
  'crypto-js':                { algorithms: ['AES', 'DES', '3DES', 'MD5', 'SHA-256', 'SHA-512', 'HMAC'], quantumRisk: 'low', category: 'symmetric' },
  'bcrypt':                   { algorithms: ['bcrypt'], quantumRisk: 'none', category: 'kdf' },
  'bcryptjs':                 { algorithms: ['bcrypt'], quantumRisk: 'none', category: 'kdf' },
  'jsonwebtoken':             { algorithms: ['RS256', 'HS256', 'ES256'], quantumRisk: 'high', category: 'token' },
  'jose':                     { algorithms: ['RS256', 'ES256', 'EdDSA', 'AES-GCM'], quantumRisk: 'high', category: 'token' },
  'node-forge':               { algorithms: ['RSA', 'AES', 'SHA-256', 'HMAC', 'TLS'], quantumRisk: 'high', category: 'tls' },
  'tweetnacl':                { algorithms: ['X25519', 'Ed25519', 'XSalsa20'], quantumRisk: 'high', category: 'asymmetric' },
  'libsodium-wrappers':       { algorithms: ['X25519', 'Ed25519', 'ChaCha20', 'AES-256-GCM'], quantumRisk: 'high', category: 'asymmetric' },
  '@noble/curves':            { algorithms: ['ECDSA', 'Ed25519', 'X25519'], quantumRisk: 'high', category: 'asymmetric' },
  '@noble/hashes':            { algorithms: ['SHA-256', 'SHA-512', 'SHA3', 'Blake2'], quantumRisk: 'low', category: 'hash' },
  '@noble/post-quantum':      { algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA'], quantumRisk: 'none', category: 'pqc' },
  'openpgp':                  { algorithms: ['RSA', 'ECDSA', 'AES', 'SHA-256'], quantumRisk: 'high', category: 'asymmetric' },
  'elliptic':                 { algorithms: ['ECDSA', 'ECDHE', 'Ed25519'], quantumRisk: 'high', category: 'asymmetric' },
  'secp256k1':                { algorithms: ['ECDSA'], quantumRisk: 'high', category: 'asymmetric' },
  'argon2':                   { algorithms: ['Argon2'], quantumRisk: 'none', category: 'kdf' },
  'scrypt':                   { algorithms: ['scrypt'], quantumRisk: 'none', category: 'kdf' },
  'pbkdf2':                   { algorithms: ['PBKDF2'], quantumRisk: 'none', category: 'kdf' },
  'tls':                      { algorithms: ['TLS', 'RSA', 'ECDSA'], quantumRisk: 'high', category: 'tls' },
  'ssh2':                     { algorithms: ['RSA', 'Ed25519', 'ECDSA', 'AES'], quantumRisk: 'high', category: 'asymmetric' },
  'node-rsa':                 { algorithms: ['RSA'], quantumRisk: 'high', category: 'asymmetric' },
};

// ---------------------------------------------------------------------------
// Import/require patterns to detect in source code
// ---------------------------------------------------------------------------

const IMPORT_PATTERNS = [
  { pattern: /(?:require|from)\s*[('"`]node:crypto[)'"`]/g, lib: 'node:crypto' },
  { pattern: /(?:require|from)\s*[('"`]crypto[)'"`]/g, lib: 'node:crypto' },
  { pattern: /createCipheriv\s*\(/g, lib: 'node:crypto', detail: 'cipher' },
  { pattern: /createDecipheriv\s*\(/g, lib: 'node:crypto', detail: 'cipher' },
  { pattern: /createSign\s*\(/g, lib: 'node:crypto', detail: 'signature' },
  { pattern: /createVerify\s*\(/g, lib: 'node:crypto', detail: 'signature' },
  { pattern: /generateKeyPair(?:Sync)?\s*\(/g, lib: 'node:crypto', detail: 'keygen' },
  { pattern: /scrypt(?:Sync)?\s*\(/g, lib: 'node:crypto', detail: 'kdf' },
  { pattern: /pbkdf2(?:Sync)?\s*\(/g, lib: 'node:crypto', detail: 'kdf' },
  { pattern: /createCipher\s*\(/g, lib: 'node:crypto', detail: 'DEPRECATED-no-iv' },
  { pattern: /CryptoJS\./g, lib: 'crypto-js' },
  { pattern: /forge\.\w+/g, lib: 'node-forge' },
  { pattern: /nacl\.\w+/g, lib: 'tweetnacl' },
  { pattern: /jwt\.(?:sign|verify|decode)\s*\(/g, lib: 'jsonwebtoken' },
];

// Algorithm string literals to detect
const ALGO_LITERALS = [
  { pattern: /['"`]aes-(?:256|128|192)-(?:gcm|cbc|ctr|ecb)['"`]/gi, algo: 'AES' },
  { pattern: /['"`]chacha20-poly1305['"`]/gi, algo: 'ChaCha20' },
  { pattern: /['"`]rsa-sha(?:256|384|512)['"`]/gi, algo: 'RSA' },
  { pattern: /['"`]sha(?:256|384|512|1)['"`]/gi, algo: 'SHA-256' },
  { pattern: /['"`](?:HS|RS|ES|PS)(?:256|384|512)['"`]/gi, algo: 'RS256' },
  { pattern: /['"`]ed25519['"`]/gi, algo: 'Ed25519' },
  { pattern: /minVersion:\s*['"`]TLSv1\.[0-3]['"`]/g, algo: 'TLS' },
  { pattern: /['"`](?:md5|MD5)['"`]/g, algo: 'MD5' },
  { pattern: /['"`](?:des|DES|3des|3DES|des-ede3)['"`]/gi, algo: 'DES' },
  { pattern: /['"`](?:rc4|RC4)['"`]/gi, algo: 'RC4' },
];

// Deprecated/weak patterns
const WEAK_PATTERNS = [
  { pattern: /createCipher\s*\(\s*['"`]/g, issue: 'createCipher without IV (use createCipheriv)', severity: 'critical' },
  { pattern: /['"`](?:md5|MD5)['"`]/g, issue: 'MD5 is cryptographically broken', severity: 'high' },
  { pattern: /['"`](?:des|DES)['"`]/g, issue: 'DES has 56-bit keys (use AES)', severity: 'critical' },
  { pattern: /['"`](?:rc4|RC4)['"`]/g, issue: 'RC4 is broken (use AES-GCM or ChaCha20)', severity: 'critical' },
  { pattern: /['"`]aes-\d+-ecb['"`]/gi, issue: 'ECB mode leaks patterns (use GCM or CTR)', severity: 'high' },
  { pattern: /['"`]aes-\d+-cbc['"`]/gi, issue: 'CBC mode is vulnerable to padding oracles (use GCM)', severity: 'medium' },
];

// ---------------------------------------------------------------------------
// Hardcoded secret detection (borrowed from secretless-ai patterns)
// ---------------------------------------------------------------------------

const SECRET_PATTERNS = [
  { id: 'anthropic',     regex: /sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/g,                      name: 'Anthropic API Key',     envVar: 'ANTHROPIC_API_KEY' },
  { id: 'openai-proj',   regex: /sk-proj-[a-zA-Z0-9]{20,}/g,                                 name: 'OpenAI Project Key',    envVar: 'OPENAI_API_KEY' },
  { id: 'openai-legacy', regex: /sk-[a-zA-Z0-9]{48,}/g,                                       name: 'OpenAI Legacy Key',     envVar: 'OPENAI_API_KEY' },
  { id: 'aws-access',    regex: /AKIA[0-9A-Z]{16}/g,                                          name: 'AWS Access Key',        envVar: 'AWS_ACCESS_KEY_ID' },
  { id: 'github-pat',    regex: /ghp_[a-zA-Z0-9]{36}/g,                                       name: 'GitHub PAT',            envVar: 'GITHUB_TOKEN' },
  { id: 'github-fine',   regex: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/g,                name: 'GitHub Fine-grained',   envVar: 'GITHUB_TOKEN' },
  { id: 'slack',         regex: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/g,      name: 'Slack Token',           envVar: 'SLACK_TOKEN' },
  { id: 'google',        regex: /AIza[0-9A-Za-z_-]{35}/g,                                     name: 'Google API Key',        envVar: 'GOOGLE_API_KEY' },
  { id: 'stripe',        regex: /sk_live_[0-9a-zA-Z]{24,}/g,                                  name: 'Stripe Secret Key',     envVar: 'STRIPE_SECRET_KEY' },
  { id: 'sendgrid',      regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,                 name: 'SendGrid Key',          envVar: 'SENDGRID_API_KEY' },
  { id: 'npm',           regex: /npm_[a-zA-Z0-9]{36}/g,                                       name: 'npm Token',             envVar: 'NPM_TOKEN' },
  { id: 'private-key',   regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,    name: 'Private Key',           envVar: null },
];

// File patterns for cert/key discovery
const CERT_EXTENSIONS = new Set(['.pem', '.key', '.crt', '.p12', '.pfx', '.jks', '.keystore']);

// ---------------------------------------------------------------------------
// File walker
// ---------------------------------------------------------------------------

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.next', 'dist', 'build', 'coverage',
  '.cache', '.nuxt', '.output', '.svelte-kit', '__pycache__',
  'vendor', '.venv', 'venv',
]);

const SOURCE_EXTENSIONS = new Set(['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx']);

function walkFiles(dir, maxFiles = 10000, maxBytes = 500 * 1024 * 1024) {
  const files = [];
  let totalBytes = 0;

  function walk(currentDir) {
    if (files.length >= maxFiles || totalBytes >= maxBytes) return;

    let entries;
    try { entries = readdirSync(currentDir, { withFileTypes: true }); }
    catch { return; }

    for (const entry of entries) {
      if (files.length >= maxFiles || totalBytes >= maxBytes) return;

      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
          walk(join(currentDir, entry.name));
        }
        continue;
      }

      if (!entry.isFile()) continue;

      const filePath = join(currentDir, entry.name);
      try {
        const stat = statSync(filePath);
        if (stat.size > 1024 * 1024) continue; // Skip files >1MB
        totalBytes += stat.size;
        files.push(filePath);
      } catch { continue; }
    }
  }

  walk(dir);
  return files;
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

export function scanProject(projectDir) {
  const results = {
    libraries: [],
    secrets: [],
    weakPatterns: [],
    certFiles: [],
    filesScanned: 0,
  };

  // 1. Scan package.json for crypto dependencies
  const pkgPath = join(projectDir, 'package.json');
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
      const allDeps = {
        ...(pkg.dependencies || {}),
        ...(pkg.devDependencies || {}),
      };

      for (const [name, version] of Object.entries(allDeps)) {
        if (name in CRYPTO_PACKAGES) {
          const info = CRYPTO_PACKAGES[name];
          results.libraries.push({
            name,
            version: version.replace(/^[\^~]/, ''),
            algorithms: info.algorithms,
            quantumRisk: info.quantumRisk,
            category: info.category,
            source: 'package.json',
          });
        }
      }
    } catch { /* invalid package.json */ }
  }

  // 2. Walk source files
  const files = walkFiles(projectDir);
  const seenImports = new Set();
  const seenAlgos = new Set();

  for (const filePath of files) {
    const ext = extname(filePath);

    // Check for cert/key files
    if (CERT_EXTENSIONS.has(ext)) {
      results.certFiles.push(relative(projectDir, filePath));
      continue;
    }

    // Only scan source files for code patterns
    if (!SOURCE_EXTENSIONS.has(ext)) continue;

    results.filesScanned++;

    let content;
    try { content = readFileSync(filePath, 'utf-8'); }
    catch { continue; }

    const relPath = relative(projectDir, filePath);

    // Detect imports/requires
    for (const { pattern, lib, detail } of IMPORT_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(content)) {
        const key = `${lib}:${detail || ''}`;
        if (!seenImports.has(key)) {
          seenImports.add(key);
          if (detail === 'DEPRECATED-no-iv') {
            results.weakPatterns.push({
              file: relPath,
              issue: 'createCipher without IV (use createCipheriv)',
              severity: 'critical',
            });
          }
        }
      }
    }

    // Detect algorithm string literals
    for (const { pattern, algo } of ALGO_LITERALS) {
      pattern.lastIndex = 0;
      if (pattern.test(content) && !seenAlgos.has(algo)) {
        seenAlgos.add(algo);
      }
    }

    // Detect weak/deprecated patterns
    for (const { pattern, issue, severity } of WEAK_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(content)) {
        results.weakPatterns.push({ file: relPath, issue, severity });
      }
    }

    // Detect hardcoded secrets
    for (const line of content.split('\n')) {
      if (line.length > 4096) continue; // ReDoS protection
      // Skip env var references
      if (/\$\{[A-Z_]+\}/.test(line) || /process\.env\.[A-Z_]+/.test(line)) continue;

      for (const { id, regex, name, envVar } of SECRET_PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          results.secrets.push({
            type: id,
            name,
            file: relPath,
            envVar,
            severity: 'critical',
          });
        }
      }
    }
  }

  // Add node:crypto as a library if imports were detected
  if (seenImports.size > 0 || seenAlgos.size > 0) {
    const nodeCryptoAlgos = [...seenAlgos];
    if (seenImports.has('node:crypto:') || seenImports.has('node:crypto:cipher')) {
      if (!nodeCryptoAlgos.includes('AES')) nodeCryptoAlgos.push('AES');
    }
    if (seenImports.has('node:crypto:signature')) {
      if (!nodeCryptoAlgos.includes('RSA')) nodeCryptoAlgos.push('RSA');
    }
    if (seenImports.has('node:crypto:kdf')) {
      nodeCryptoAlgos.push('scrypt');
    }

    if (nodeCryptoAlgos.length > 0) {
      // Determine quantum risk based on detected algorithms
      const hasAsymmetric = nodeCryptoAlgos.some(a =>
        ['RSA', 'ECDSA', 'Ed25519', 'RS256', 'ES256', 'DH'].includes(a)
      );
      results.libraries.push({
        name: 'node:crypto',
        version: 'builtin',
        algorithms: nodeCryptoAlgos,
        quantumRisk: hasAsymmetric ? 'high' : 'low',
        category: hasAsymmetric ? 'asymmetric' : 'symmetric',
        source: 'source-code',
      });
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// Format results as library inventory (for PQC engine input)
// ---------------------------------------------------------------------------

export function toLibraryInventory(scanResults) {
  return scanResults.libraries.map(lib => ({
    name: lib.name,
    version: lib.version,
    algorithms: lib.algorithms,
    quantumRisk: lib.quantumRisk,
    category: lib.category,
    isDeprecated: false,
  }));
}
