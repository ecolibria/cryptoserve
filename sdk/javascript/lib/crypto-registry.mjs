/**
 * Centralized crypto package registry — single source of truth for all ecosystems.
 *
 * Consolidates package metadata previously duplicated across scanner.mjs (npm only,
 * uppercase algorithms) and scanner-manifests.mjs (all ecosystems, lowercase).
 * Algorithms are stored in lowercase, matching algorithm-db.mjs canonical form.
 * Zero dependencies.
 */

// ---------------------------------------------------------------------------
// Known crypto packages per ecosystem
// ---------------------------------------------------------------------------

export const CRYPTO_PACKAGES = {
  // npm uses display-name algorithms for backward compat with scanner.mjs output.
  // The manifest scanner skips npm (parser is null), so only lookupNpmPackage reads this.
  npm: {
    'crypto-js':           { category: 'symmetric', algorithms: ['AES', 'DES', '3DES', 'MD5', 'SHA-256', 'SHA-512', 'HMAC'], quantumRisk: 'low' },
    'jsonwebtoken':        { category: 'token', algorithms: ['RS256', 'HS256', 'ES256'], quantumRisk: 'high' },
    'jose':                { category: 'token', algorithms: ['RS256', 'ES256', 'EdDSA', 'AES-GCM'], quantumRisk: 'high' },
    'node-forge':          { category: 'tls', algorithms: ['RSA', 'AES', 'SHA-256', 'HMAC', 'TLS'], quantumRisk: 'high' },
    'tweetnacl':           { category: 'asymmetric', algorithms: ['X25519', 'Ed25519', 'XSalsa20'], quantumRisk: 'high' },
    'libsodium-wrappers':  { category: 'asymmetric', algorithms: ['X25519', 'Ed25519', 'ChaCha20', 'AES-256-GCM'], quantumRisk: 'high' },
    '@noble/curves':       { category: 'asymmetric', algorithms: ['ECDSA', 'Ed25519', 'X25519'], quantumRisk: 'high' },
    '@noble/hashes':       { category: 'hash', algorithms: ['SHA-256', 'SHA-512', 'SHA3', 'Blake2'], quantumRisk: 'low' },
    '@noble/post-quantum': { category: 'pqc', algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA'], quantumRisk: 'none' },
    'openpgp':             { category: 'asymmetric', algorithms: ['RSA', 'ECDSA', 'AES', 'SHA-256'], quantumRisk: 'high' },
    'elliptic':            { category: 'asymmetric', algorithms: ['ECDSA', 'ECDHE', 'Ed25519'], quantumRisk: 'high' },
    'secp256k1':           { category: 'asymmetric', algorithms: ['ECDSA'], quantumRisk: 'high' },
    'argon2':              { category: 'kdf', algorithms: ['Argon2'], quantumRisk: 'none' },
    'scrypt':              { category: 'kdf', algorithms: ['scrypt'], quantumRisk: 'none' },
    'pbkdf2':              { category: 'kdf', algorithms: ['PBKDF2'], quantumRisk: 'none' },
    'bcrypt':              { category: 'kdf', algorithms: ['bcrypt'], quantumRisk: 'none' },
    'bcryptjs':            { category: 'kdf', algorithms: ['bcrypt'], quantumRisk: 'none' },
    'tls':                 { category: 'tls', algorithms: ['TLS', 'RSA', 'ECDSA'], quantumRisk: 'high' },
    'ssh2':                { category: 'asymmetric', algorithms: ['RSA', 'Ed25519', 'ECDSA', 'AES'], quantumRisk: 'high' },
    'node-rsa':            { category: 'asymmetric', algorithms: ['RSA'], quantumRisk: 'high' },
    'jsrsasign':           { category: 'asymmetric', algorithms: ['RSA', 'ECDSA', 'SHA-256'], quantumRisk: 'high' },
    'ethers':              { category: 'asymmetric', algorithms: ['ECDSA', 'SHA-256'], quantumRisk: 'high' },
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
// Lookup helpers
// ---------------------------------------------------------------------------

/**
 * Look up a dependency in the crypto packages database.
 * For Go imports, also checks subpackage paths.
 * For Maven, checks groupId prefix.
 */
export function lookupPackage(name, ecosystem) {
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
 * Shorthand for npm package lookup.
 * Returns the package info directly — npm section already uses display-name
 * algorithms and scanner.mjs-compatible categories.
 */
export function lookupNpmPackage(name) {
  const pkg = CRYPTO_PACKAGES.npm[name];
  if (!pkg) return null;
  return { algorithms: pkg.algorithms, quantumRisk: pkg.quantumRisk, category: pkg.category };
}
