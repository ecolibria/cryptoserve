/**
 * Multi-ecosystem manifest parser and crypto package detector.
 *
 * Parses go.mod, requirements.txt, pyproject.toml, Cargo.toml, pom.xml
 * and identifies known crypto packages.
 * Ported from backend/app/core/dependency_scanner.py.
 * Zero dependencies.
 */

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, basename } from 'node:path';

// ---------------------------------------------------------------------------
// Known crypto packages per ecosystem
// ---------------------------------------------------------------------------

export const CRYPTO_PACKAGES = {
  npm: {
    'crypto-js':           { category: 'general', algorithms: ['aes', 'des', '3des', 'rc4', 'sha1', 'sha256', 'md5', 'hmac'], quantumRisk: 'low' },
    'jsonwebtoken':        { category: 'signing', algorithms: ['rsa', 'ecdsa', 'hmac'], quantumRisk: 'high' },
    'jose':                { category: 'signing', algorithms: ['rsa', 'ecdsa', 'ed25519', 'aes-gcm'], quantumRisk: 'high' },
    'node-forge':          { category: 'general', algorithms: ['rsa', 'aes', 'sha256', 'hmac'], quantumRisk: 'high' },
    'tweetnacl':           { category: 'asymmetric', algorithms: ['x25519', 'ed25519', 'xsalsa20'], quantumRisk: 'high' },
    'libsodium-wrappers':  { category: 'asymmetric', algorithms: ['x25519', 'ed25519', 'chacha20', 'aes-256-gcm'], quantumRisk: 'high' },
    '@noble/curves':       { category: 'asymmetric', algorithms: ['ecdsa', 'ed25519', 'x25519'], quantumRisk: 'high' },
    '@noble/hashes':       { category: 'hashing', algorithms: ['sha256', 'sha512', 'sha3-256', 'blake2b'], quantumRisk: 'low' },
    '@noble/post-quantum': { category: 'pqc', algorithms: ['ml-kem', 'ml-dsa', 'slh-dsa'], quantumRisk: 'none' },
    'openpgp':             { category: 'asymmetric', algorithms: ['rsa', 'ecdsa', 'aes', 'sha256'], quantumRisk: 'high' },
    'elliptic':            { category: 'asymmetric', algorithms: ['ecdsa', 'ecdh', 'ed25519'], quantumRisk: 'high' },
    'secp256k1':           { category: 'asymmetric', algorithms: ['ecdsa'], quantumRisk: 'high' },
    'argon2':              { category: 'kdf', algorithms: ['argon2'], quantumRisk: 'none' },
    'scrypt':              { category: 'kdf', algorithms: ['scrypt'], quantumRisk: 'none' },
    'pbkdf2':              { category: 'kdf', algorithms: ['pbkdf2'], quantumRisk: 'none' },
    'bcrypt':              { category: 'kdf', algorithms: ['bcrypt'], quantumRisk: 'none' },
    'bcryptjs':            { category: 'kdf', algorithms: ['bcrypt'], quantumRisk: 'none' },
    'tls':                 { category: 'protocol', algorithms: ['tls', 'rsa', 'ecdsa'], quantumRisk: 'high' },
    'ssh2':                { category: 'asymmetric', algorithms: ['rsa', 'ed25519', 'ecdsa', 'aes'], quantumRisk: 'high' },
    'node-rsa':            { category: 'asymmetric', algorithms: ['rsa'], quantumRisk: 'high' },
    'jsrsasign':           { category: 'asymmetric', algorithms: ['rsa', 'ecdsa', 'sha256'], quantumRisk: 'high' },
    'ethers':              { category: 'asymmetric', algorithms: ['ecdsa', 'sha256'], quantumRisk: 'high' },
  },
  go: {
    'crypto/aes':            { category: 'encryption', algorithms: ['aes'], quantumRisk: 'none' },
    'crypto/des':            { category: 'encryption', algorithms: ['des', '3des'], quantumRisk: 'critical', isDeprecated: true },
    'crypto/rsa':            { category: 'encryption', algorithms: ['rsa'], quantumRisk: 'high' },
    'crypto/ecdsa':          { category: 'signing', algorithms: ['ecdsa'], quantumRisk: 'high' },
    'crypto/ed25519':        { category: 'signing', algorithms: ['ed25519'], quantumRisk: 'high' },
    'crypto/ecdh':           { category: 'key_exchange', algorithms: ['ecdh', 'x25519'], quantumRisk: 'high' },
    'crypto/sha256':         { category: 'hashing', algorithms: ['sha256'], quantumRisk: 'low' },
    'crypto/sha512':         { category: 'hashing', algorithms: ['sha512'], quantumRisk: 'low' },
    'crypto/sha1':           { category: 'hashing', algorithms: ['sha1'], quantumRisk: 'critical', isDeprecated: true },
    'crypto/md5':            { category: 'hashing', algorithms: ['md5'], quantumRisk: 'critical', isDeprecated: true },
    'crypto/hmac':           { category: 'mac', algorithms: ['hmac'], quantumRisk: 'low' },
    'crypto/tls':            { category: 'protocol', algorithms: ['tls'], quantumRisk: 'high' },
    'golang.org/x/crypto':   { category: 'general', algorithms: ['chacha20-poly1305', 'argon2', 'bcrypt', 'scrypt', 'hkdf'], quantumRisk: 'none' },
    'golang.org/x/crypto/chacha20poly1305': { category: 'encryption', algorithms: ['chacha20-poly1305'], quantumRisk: 'none' },
    'golang.org/x/crypto/argon2':           { category: 'kdf', algorithms: ['argon2'], quantumRisk: 'none' },
    'golang.org/x/crypto/bcrypt':           { category: 'kdf', algorithms: ['bcrypt'], quantumRisk: 'none' },
    'golang.org/x/crypto/scrypt':           { category: 'kdf', algorithms: ['scrypt'], quantumRisk: 'none' },
    'github.com/cloudflare/circl':          { category: 'pqc', algorithms: ['kyber', 'dilithium', 'x25519'], quantumRisk: 'none' },
  },
  pypi: {
    'cryptography':    { category: 'general', algorithms: ['aes', 'rsa', 'ecdsa', 'ed25519', 'x25519', 'sha256'], quantumRisk: 'high' },
    'pycryptodome':    { category: 'general', algorithms: ['aes', 'des', 'rsa', 'sha256', 'md5'], quantumRisk: 'high' },
    'pycryptodomex':   { category: 'general', algorithms: ['aes', 'des', 'rsa', 'sha256', 'md5'], quantumRisk: 'high' },
    'bcrypt':          { category: 'kdf', algorithms: ['bcrypt'], quantumRisk: 'none' },
    'argon2-cffi':     { category: 'kdf', algorithms: ['argon2'], quantumRisk: 'none' },
    'pynacl':          { category: 'general', algorithms: ['xchacha20', 'ed25519', 'x25519'], quantumRisk: 'high' },
    'pyopenssl':       { category: 'general', algorithms: ['rsa', 'aes', 'sha256', 'tls'], quantumRisk: 'high' },
    'paramiko':        { category: 'asymmetric', algorithms: ['rsa', 'ed25519', 'ecdsa', 'aes'], quantumRisk: 'high' },
    'pyjwt':           { category: 'signing', algorithms: ['rsa', 'ecdsa', 'hmac'], quantumRisk: 'high' },
    'hashlib':         { category: 'hashing', algorithms: ['sha256', 'sha512', 'md5', 'sha1'], quantumRisk: 'low' },
    'hmac':            { category: 'mac', algorithms: ['hmac'], quantumRisk: 'low' },
    'passlib':         { category: 'kdf', algorithms: ['bcrypt', 'argon2', 'pbkdf2', 'scrypt'], quantumRisk: 'none' },
    'scrypt':          { category: 'kdf', algorithms: ['scrypt'], quantumRisk: 'none' },
    'ecdsa':           { category: 'signing', algorithms: ['ecdsa'], quantumRisk: 'high' },
    'rsa':             { category: 'asymmetric', algorithms: ['rsa'], quantumRisk: 'high' },
    'liboqs-python':   { category: 'pqc', algorithms: ['kyber', 'dilithium', 'sphincs'], quantumRisk: 'none' },
    'pqcrypto':        { category: 'pqc', algorithms: ['kyber', 'dilithium'], quantumRisk: 'none' },
    'pyca-cryptography': { category: 'general', algorithms: ['aes', 'rsa', 'ecdsa'], quantumRisk: 'high' },
  },
  cargo: {
    'aes-gcm':           { category: 'encryption', algorithms: ['aes-gcm'], quantumRisk: 'none' },
    'aes':               { category: 'encryption', algorithms: ['aes'], quantumRisk: 'none' },
    'chacha20poly1305':  { category: 'encryption', algorithms: ['chacha20-poly1305'], quantumRisk: 'none' },
    'chacha20':          { category: 'encryption', algorithms: ['chacha20'], quantumRisk: 'none' },
    'rsa':               { category: 'encryption', algorithms: ['rsa'], quantumRisk: 'high' },
    'ed25519-dalek':     { category: 'signing', algorithms: ['ed25519'], quantumRisk: 'high' },
    'ed25519':           { category: 'signing', algorithms: ['ed25519'], quantumRisk: 'high' },
    'ring':              { category: 'general', algorithms: ['aes-gcm', 'sha256', 'ecdsa', 'ed25519'], quantumRisk: 'high' },
    'pqcrypto':          { category: 'pqc', algorithms: ['kyber', 'dilithium', 'sphincs'], quantumRisk: 'none' },
    'sha2':              { category: 'hashing', algorithms: ['sha256', 'sha512'], quantumRisk: 'low' },
    'sha1':              { category: 'hashing', algorithms: ['sha1'], quantumRisk: 'critical', isDeprecated: true },
    'md-5':              { category: 'hashing', algorithms: ['md5'], quantumRisk: 'critical', isDeprecated: true },
    'blake2':            { category: 'hashing', algorithms: ['blake2b'], quantumRisk: 'low' },
    'argon2':            { category: 'kdf', algorithms: ['argon2'], quantumRisk: 'none' },
    'bcrypt':            { category: 'kdf', algorithms: ['bcrypt'], quantumRisk: 'none' },
    'scrypt':            { category: 'kdf', algorithms: ['scrypt'], quantumRisk: 'none' },
    'pbkdf2':            { category: 'kdf', algorithms: ['pbkdf2'], quantumRisk: 'none' },
    'x25519-dalek':      { category: 'key_exchange', algorithms: ['x25519'], quantumRisk: 'high' },
    'p256':              { category: 'signing', algorithms: ['ecdsa'], quantumRisk: 'high' },
    'hmac':              { category: 'mac', algorithms: ['hmac'], quantumRisk: 'low' },
    'hkdf':              { category: 'kdf', algorithms: ['hkdf'], quantumRisk: 'none' },
    'rustls':            { category: 'protocol', algorithms: ['tls', 'aes-gcm', 'chacha20-poly1305'], quantumRisk: 'high' },
  },
  maven: {
    'org.bouncycastle':  { category: 'general', algorithms: ['aes', 'rsa', 'ecdsa', 'ed25519', 'sha256'], quantumRisk: 'high' },
    'com.google.crypto.tink': { category: 'general', algorithms: ['aes-gcm', 'ecdsa', 'ed25519'], quantumRisk: 'high' },
    'io.jsonwebtoken':   { category: 'signing', algorithms: ['rsa', 'ecdsa', 'hmac'], quantumRisk: 'high' },
    'com.nimbusds':      { category: 'signing', algorithms: ['rsa', 'ecdsa', 'ed25519'], quantumRisk: 'high' },
    'org.signal':        { category: 'asymmetric', algorithms: ['x25519', 'ed25519', 'aes-gcm'], quantumRisk: 'high' },
  },
};

// ---------------------------------------------------------------------------
// Manifest parsers
// ---------------------------------------------------------------------------

/**
 * Parse go.mod — extract module dependencies.
 */
export function parseGoMod(content) {
  const deps = [];
  // Match require block
  const requireBlock = content.match(/require\s*\(([\s\S]*?)\)/);
  const lines = requireBlock ? requireBlock[1].split('\n') : content.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('//') || trimmed === 'require') continue;
    const match = trimmed.match(/^([a-zA-Z0-9.\/_-]+)\s+(v[\d.]+[a-zA-Z0-9._-]*)/);
    if (match) {
      deps.push({ name: match[1], version: match[2] });
    }
  }

  // Also match single-line require directives
  const singleReqs = content.matchAll(/^require\s+([a-zA-Z0-9.\/_-]+)\s+(v[\d.]+[a-zA-Z0-9._-]*)/gm);
  for (const m of singleReqs) {
    if (!deps.some(d => d.name === m[1])) {
      deps.push({ name: m[1], version: m[2] });
    }
  }

  return deps;
}

/**
 * Parse requirements.txt — extract package==version lines.
 */
export function parseRequirementsTxt(content) {
  const deps = [];
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;
    const match = trimmed.match(/^([a-zA-Z0-9._-]+)(?:\[.*?\])?\s*(?:([<>=!~]+)\s*(.*))?$/);
    if (match) {
      deps.push({
        name: match[1].toLowerCase(),
        version: match[3] || null,
      });
    }
  }
  return deps;
}

/**
 * Parse pyproject.toml — extract [project.dependencies] section.
 */
export function parsePyprojectToml(content) {
  const deps = [];
  // Match dependencies array
  const depsMatch = content.match(/\[project\]\s*[\s\S]*?dependencies\s*=\s*\[([\s\S]*?)\]/);
  if (depsMatch) {
    const lines = depsMatch[1].split('\n');
    for (const line of lines) {
      const match = line.match(/["']([a-zA-Z0-9._-]+)(?:\[.*?\])?(?:([<>=!~]+)([\d.]+))?/);
      if (match) {
        deps.push({ name: match[1].toLowerCase(), version: match[3] || null });
      }
    }
  }

  // Also check [tool.poetry.dependencies]
  const poetryMatch = content.match(/\[tool\.poetry\.dependencies\]([\s\S]*?)(?:\[|$)/);
  if (poetryMatch) {
    const lines = poetryMatch[1].split('\n');
    for (const line of lines) {
      const match = line.match(/^([a-zA-Z0-9._-]+)\s*=\s*(?:"([^"]+)"|{.*?version\s*=\s*"([^"]+)")/);
      if (match && match[1] !== 'python') {
        const name = match[1].toLowerCase();
        if (!deps.some(d => d.name === name)) {
          deps.push({ name, version: match[2] || match[3] || null });
        }
      }
    }
  }

  return deps;
}

/**
 * Parse Cargo.toml — extract [dependencies] section.
 */
export function parseCargoToml(content) {
  const deps = [];
  const depsMatch = content.match(/\[dependencies\]([\s\S]*?)(?:\[|$)/);
  if (!depsMatch) return deps;

  for (const line of depsMatch[1].split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    // name = "version" or name = { version = "x.y.z" }
    const simpleMatch = trimmed.match(/^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"/);
    if (simpleMatch) {
      deps.push({ name: simpleMatch[1], version: simpleMatch[2] });
      continue;
    }
    const complexMatch = trimmed.match(/^([a-zA-Z0-9_-]+)\s*=\s*\{.*?version\s*=\s*"([^"]+)"/);
    if (complexMatch) {
      deps.push({ name: complexMatch[1], version: complexMatch[2] });
    }
  }
  return deps;
}

/**
 * Parse pom.xml — extract <dependency> blocks.
 */
export function parsePomXml(content) {
  const deps = [];
  const depRegex = /<dependency>\s*<groupId>(.*?)<\/groupId>\s*<artifactId>(.*?)<\/artifactId>(?:\s*<version>(.*?)<\/version>)?/g;
  let match;
  while ((match = depRegex.exec(content)) !== null) {
    deps.push({
      name: `${match[1]}:${match[2]}`,
      version: match[3] || null,
      groupId: match[1],
      artifactId: match[2],
    });
  }
  return deps;
}

// ---------------------------------------------------------------------------
// Manifest detection and scanning
// ---------------------------------------------------------------------------

const MANIFEST_FILES = [
  { file: 'package.json', ecosystem: 'npm', parser: null }, // npm handled by main scanner
  { file: 'go.mod', ecosystem: 'go', parser: parseGoMod },
  { file: 'go.sum', ecosystem: 'go', parser: null },
  { file: 'requirements.txt', ecosystem: 'pypi', parser: parseRequirementsTxt },
  { file: 'pyproject.toml', ecosystem: 'pypi', parser: parsePyprojectToml },
  { file: 'Cargo.toml', ecosystem: 'cargo', parser: parseCargoToml },
  { file: 'pom.xml', ecosystem: 'maven', parser: parsePomXml },
];

/**
 * Look up a dependency in the crypto packages database.
 * For Go imports, also checks subpackage paths.
 */
function lookupPackage(name, ecosystem) {
  const db = CRYPTO_PACKAGES[ecosystem];
  if (!db) return null;

  // Direct match
  if (db[name]) return { ...db[name], name };

  // For Go, check if it's a subpackage of a known package
  if (ecosystem === 'go') {
    for (const [pkgName, info] of Object.entries(db)) {
      if (name.startsWith(pkgName + '/') || name === pkgName) {
        return { ...info, name: pkgName };
      }
    }
  }

  // For Maven, check groupId
  if (ecosystem === 'maven') {
    const groupId = name.split(':')[0];
    for (const [pkgName, info] of Object.entries(db)) {
      if (groupId.startsWith(pkgName)) {
        return { ...info, name: pkgName };
      }
    }
  }

  return null;
}

/**
 * Scan a project directory for manifests and identify crypto dependencies.
 * Returns array of library entries compatible with scanner.mjs output.
 */
export function scanManifests(projectDir) {
  const results = [];
  const seen = new Set();

  for (const { file, ecosystem, parser } of MANIFEST_FILES) {
    if (!parser) continue; // npm handled by main scanner

    const manifestPath = join(projectDir, file);
    if (!existsSync(manifestPath)) continue;

    let content;
    try { content = readFileSync(manifestPath, 'utf-8'); }
    catch { continue; }

    const deps = parser(content);

    for (const dep of deps) {
      const pkg = lookupPackage(dep.name, ecosystem);
      if (pkg && !seen.has(`${ecosystem}:${pkg.name}`)) {
        seen.add(`${ecosystem}:${pkg.name}`);
        results.push({
          name: pkg.name,
          version: dep.version || 'unknown',
          algorithms: pkg.algorithms,
          quantumRisk: pkg.quantumRisk,
          category: pkg.category,
          ecosystem,
          source: file,
          isDeprecated: pkg.isDeprecated || false,
        });
      }
    }
  }

  return results;
}
