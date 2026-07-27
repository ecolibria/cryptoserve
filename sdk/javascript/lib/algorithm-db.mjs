/**
 * Centralized algorithm database — single source of truth for all crypto classification.
 *
 * Ported from backend/app/core/code_scanner.py ALGORITHM_DB.
 * Each entry maps a lowercase algorithm name to its metadata.
 * Zero dependencies.
 */

// ---------------------------------------------------------------------------
// Algorithm Database
// ---------------------------------------------------------------------------

export const ALGORITHM_DB = {
  // Symmetric — quantum-safe (Grover halves effective key length)
  'aes':                { category: 'encryption', quantumRisk: 'none', isWeak: false },
  'aes-128':            { category: 'encryption', quantumRisk: 'none', isWeak: false },
  'aes-192':            { category: 'encryption', quantumRisk: 'none', isWeak: false },
  'aes-256':            { category: 'encryption', quantumRisk: 'none', isWeak: false },
  'aes-gcm':            { category: 'encryption', quantumRisk: 'none', isWeak: false },
  'aes-128-gcm':        { category: 'encryption', quantumRisk: 'none', isWeak: false },
  'aes-256-gcm':        { category: 'encryption', quantumRisk: 'none', isWeak: false },
  'aes-cbc':            { category: 'encryption', quantumRisk: 'none', isWeak: false },
  'aes-128-cbc':        { category: 'encryption', quantumRisk: 'none', isWeak: false },
  'aes-256-cbc':        { category: 'encryption', quantumRisk: 'none', isWeak: false },
  'aes-ctr':            { category: 'encryption', quantumRisk: 'none', isWeak: false },
  'aes-ecb':            { category: 'encryption', quantumRisk: 'none', isWeak: true, weaknessReason: 'ECB mode leaks patterns', cwe: 'CWE-327', replacement: 'AES-256-GCM (any authenticated mode)' },
  'aes-128-ecb':        { category: 'encryption', quantumRisk: 'none', isWeak: true, weaknessReason: 'ECB mode leaks patterns', cwe: 'CWE-327', replacement: 'AES-256-GCM (any authenticated mode)' },
  'aes-256-ecb':        { category: 'encryption', quantumRisk: 'none', isWeak: true, weaknessReason: 'ECB mode leaks patterns', cwe: 'CWE-327', replacement: 'AES-256-GCM (any authenticated mode)' },
  'chacha20':           { category: 'encryption', quantumRisk: 'none', isWeak: false },
  'chacha20-poly1305':  { category: 'encryption', quantumRisk: 'none', isWeak: false },
  'xchacha20':          { category: 'encryption', quantumRisk: 'none', isWeak: false },
  'xchacha20-poly1305': { category: 'encryption', quantumRisk: 'none', isWeak: false },
  'xsalsa20':           { category: 'encryption', quantumRisk: 'none', isWeak: false },
  'salsa20':            { category: 'encryption', quantumRisk: 'none', isWeak: false },
  'camellia':           { category: 'encryption', quantumRisk: 'none', isWeak: false },
  'twofish':            { category: 'encryption', quantumRisk: 'none', isWeak: false },
  'serpent':            { category: 'encryption', quantumRisk: 'none', isWeak: false },
  'aria':               { category: 'encryption', quantumRisk: 'none', isWeak: false },
  'sm4':                { category: 'encryption', quantumRisk: 'none', isWeak: false },

  // Weak symmetric
  'des':      { category: 'encryption', quantumRisk: 'critical', isWeak: true, weaknessReason: '56-bit key is trivially brutable', cwe: 'CWE-327', replacement: 'AES-256-GCM' },
  '3des':     { category: 'encryption', quantumRisk: 'low', isWeak: true, weaknessReason: 'Deprecated, Sweet32 attack', cwe: 'CWE-327', replacement: 'AES-256-GCM' },
  'des-ede3': { category: 'encryption', quantumRisk: 'low', isWeak: true, weaknessReason: 'Deprecated, Sweet32 attack', cwe: 'CWE-327', replacement: 'AES-256-GCM' },
  'rc4':      { category: 'encryption', quantumRisk: 'critical', isWeak: true, weaknessReason: 'Biased keystream, RFC 7465', cwe: 'CWE-327', replacement: 'AES-256-GCM or ChaCha20-Poly1305' },
  'rc2':      { category: 'encryption', quantumRisk: 'critical', isWeak: true, weaknessReason: 'Weak with known attacks', cwe: 'CWE-327', replacement: 'AES-256-GCM' },
  'blowfish': { category: 'encryption', quantumRisk: 'low', isWeak: true, weaknessReason: '64-bit block, birthday attacks', cwe: 'CWE-327', replacement: 'AES-256-GCM' },
  'idea':     { category: 'encryption', quantumRisk: 'low', isWeak: true, weaknessReason: 'Deprecated, limited analysis', cwe: 'CWE-327', replacement: 'AES-256-GCM' },
  'cast5':    { category: 'encryption', quantumRisk: 'low', isWeak: true, weaknessReason: '64-bit block, deprecated', cwe: 'CWE-327', replacement: 'AES-256-GCM' },

  // Asymmetric — quantum-vulnerable (Shor's algorithm)
  'rsa':      { category: 'encryption', quantumRisk: 'high', isWeak: false },
  'rsa-1024': { category: 'encryption', quantumRisk: 'critical', isWeak: true, weaknessReason: 'Key too small', cwe: 'CWE-326', replacement: 'RSA-3072 now, ML-KEM-768 / ML-DSA-65 for the quantum horizon' },
  'rsa-2048': { category: 'encryption', quantumRisk: 'high', isWeak: false },
  'rsa-4096': { category: 'encryption', quantumRisk: 'high', isWeak: false },
  'rsa-pss':  { category: 'signing', quantumRisk: 'high', isWeak: false },
  'rsa-oaep': { category: 'encryption', quantumRisk: 'high', isWeak: false },

  // Signatures — quantum-vulnerable
  'ecdsa':    { category: 'signing', quantumRisk: 'high', isWeak: false },
  'ed25519':  { category: 'signing', quantumRisk: 'high', isWeak: false },
  'ed448':    { category: 'signing', quantumRisk: 'high', isWeak: false },
  'eddsa':    { category: 'signing', quantumRisk: 'high', isWeak: false },
  'dsa':      { category: 'signing', quantumRisk: 'high', isWeak: true, weaknessReason: 'Deprecated', cwe: 'CWE-327', replacement: 'Ed25519, or ML-DSA-65 for the quantum horizon' },
  'secp256k1':{ category: 'signing', quantumRisk: 'high', isWeak: false },
  'secp384r1':{ category: 'signing', quantumRisk: 'high', isWeak: false },
  'secp256r1':{ category: 'signing', quantumRisk: 'high', isWeak: false },
  'prime256v1':{ category: 'signing', quantumRisk: 'high', isWeak: false },
  'p-256':    { category: 'signing', quantumRisk: 'high', isWeak: false },
  'p-384':    { category: 'signing', quantumRisk: 'high', isWeak: false },
  'p-521':    { category: 'signing', quantumRisk: 'high', isWeak: false },

  // Key exchange — quantum-vulnerable
  'ecdh':     { category: 'key_exchange', quantumRisk: 'high', isWeak: false },
  'ecdhe':    { category: 'key_exchange', quantumRisk: 'high', isWeak: false },
  'x25519':   { category: 'key_exchange', quantumRisk: 'high', isWeak: false },
  'x448':     { category: 'key_exchange', quantumRisk: 'high', isWeak: false },
  'dh':       { category: 'key_exchange', quantumRisk: 'high', isWeak: false },
  'diffie-hellman': { category: 'key_exchange', quantumRisk: 'high', isWeak: false },
  'curve25519': { category: 'key_exchange', quantumRisk: 'high', isWeak: false },

  // PQC — quantum-safe
  'kyber':      { category: 'key_exchange', quantumRisk: 'none', isWeak: false },
  'kyber-512':  { category: 'key_exchange', quantumRisk: 'none', isWeak: false },
  'kyber-768':  { category: 'key_exchange', quantumRisk: 'none', isWeak: false },
  'kyber-1024': { category: 'key_exchange', quantumRisk: 'none', isWeak: false },
  'ml-kem':     { category: 'key_exchange', quantumRisk: 'none', isWeak: false },
  'ml-kem-512': { category: 'key_exchange', quantumRisk: 'none', isWeak: false },
  'ml-kem-768': { category: 'key_exchange', quantumRisk: 'none', isWeak: false },
  'ml-kem-1024':{ category: 'key_exchange', quantumRisk: 'none', isWeak: false },
  'dilithium':  { category: 'signing', quantumRisk: 'none', isWeak: false },
  'ml-dsa':     { category: 'signing', quantumRisk: 'none', isWeak: false },
  'ml-dsa-44':  { category: 'signing', quantumRisk: 'none', isWeak: false },
  'ml-dsa-65':  { category: 'signing', quantumRisk: 'none', isWeak: false },
  'ml-dsa-87':  { category: 'signing', quantumRisk: 'none', isWeak: false },
  'falcon':     { category: 'signing', quantumRisk: 'none', isWeak: false },
  'falcon-512': { category: 'signing', quantumRisk: 'none', isWeak: false },
  'falcon-1024':{ category: 'signing', quantumRisk: 'none', isWeak: false },
  'sphincs':    { category: 'signing', quantumRisk: 'none', isWeak: false },
  'sphincs+':   { category: 'signing', quantumRisk: 'none', isWeak: false },
  'slh-dsa':    { category: 'signing', quantumRisk: 'none', isWeak: false },
  'slh-dsa-128f': { category: 'signing', quantumRisk: 'none', isWeak: false },
  'ntru':       { category: 'key_exchange', quantumRisk: 'none', isWeak: false },
  'bike':       { category: 'key_exchange', quantumRisk: 'none', isWeak: false },
  'hqc':        { category: 'key_exchange', quantumRisk: 'none', isWeak: false },
  'frodokem':   { category: 'key_exchange', quantumRisk: 'none', isWeak: false },
  'sike':       { category: 'key_exchange', quantumRisk: 'none', isWeak: true, weaknessReason: 'Broken by Castryck-Decru attack', cwe: 'CWE-327', replacement: 'ML-KEM-768 (FIPS 203)' },

  // Hashes — quantum-safe (Grover halving)
  'sha256':     { category: 'hashing', quantumRisk: 'low', isWeak: false },
  'sha-256':    { category: 'hashing', quantumRisk: 'low', isWeak: false },
  'sha384':     { category: 'hashing', quantumRisk: 'low', isWeak: false },
  'sha-384':    { category: 'hashing', quantumRisk: 'low', isWeak: false },
  'sha512':     { category: 'hashing', quantumRisk: 'low', isWeak: false },
  'sha-512':    { category: 'hashing', quantumRisk: 'low', isWeak: false },
  'sha3-256':   { category: 'hashing', quantumRisk: 'low', isWeak: false },
  'sha3-384':   { category: 'hashing', quantumRisk: 'low', isWeak: false },
  'sha3-512':   { category: 'hashing', quantumRisk: 'low', isWeak: false },
  'blake2b':    { category: 'hashing', quantumRisk: 'low', isWeak: false },
  'blake2s':    { category: 'hashing', quantumRisk: 'low', isWeak: false },
  'blake3':     { category: 'hashing', quantumRisk: 'low', isWeak: false },
  'sha224':     { category: 'hashing', quantumRisk: 'low', isWeak: false },
  'ripemd160':  { category: 'hashing', quantumRisk: 'low', isWeak: false },

  // Weak hashes
  'md5':  { category: 'hashing', quantumRisk: 'critical', isWeak: true, weaknessReason: 'Collision attacks', cwe: 'CWE-328', replacement: 'SHA-256' },
  'md4':  { category: 'hashing', quantumRisk: 'critical', isWeak: true, weaknessReason: 'Completely broken', cwe: 'CWE-328', replacement: 'SHA-256' },
  'sha1': { category: 'hashing', quantumRisk: 'critical', isWeak: true, weaknessReason: 'SHAttered collision', cwe: 'CWE-328', replacement: 'SHA-256' },
  'sha-1':{ category: 'hashing', quantumRisk: 'critical', isWeak: true, weaknessReason: 'SHAttered collision', cwe: 'CWE-328', replacement: 'SHA-256' },

  // KDFs — quantum-safe
  'argon2':   { category: 'kdf', quantumRisk: 'none', isWeak: false },
  'argon2id': { category: 'kdf', quantumRisk: 'none', isWeak: false },
  'argon2i':  { category: 'kdf', quantumRisk: 'none', isWeak: false },
  'argon2d':  { category: 'kdf', quantumRisk: 'none', isWeak: false },
  'bcrypt':   { category: 'kdf', quantumRisk: 'none', isWeak: false },
  'scrypt':   { category: 'kdf', quantumRisk: 'none', isWeak: false },
  'pbkdf2':   { category: 'kdf', quantumRisk: 'none', isWeak: false },
  'hkdf':     { category: 'kdf', quantumRisk: 'none', isWeak: false },

  // MACs
  'hmac':     { category: 'mac', quantumRisk: 'low', isWeak: false },
  'poly1305': { category: 'mac', quantumRisk: 'none', isWeak: false },
  'cmac':     { category: 'mac', quantumRisk: 'none', isWeak: false },
  'gmac':     { category: 'mac', quantumRisk: 'none', isWeak: false },

  // Token / TLS wrappers
  'rs256': { category: 'signing', quantumRisk: 'high', isWeak: false },
  'rs384': { category: 'signing', quantumRisk: 'high', isWeak: false },
  'rs512': { category: 'signing', quantumRisk: 'high', isWeak: false },
  'ps256': { category: 'signing', quantumRisk: 'high', isWeak: false },
  'ps384': { category: 'signing', quantumRisk: 'high', isWeak: false },
  'ps512': { category: 'signing', quantumRisk: 'high', isWeak: false },
  'es256': { category: 'signing', quantumRisk: 'high', isWeak: false },
  'es384': { category: 'signing', quantumRisk: 'high', isWeak: false },
  'es512': { category: 'signing', quantumRisk: 'high', isWeak: false },
  'hs256': { category: 'mac', quantumRisk: 'low', isWeak: false },
  'hs384': { category: 'mac', quantumRisk: 'low', isWeak: false },
  'hs512': { category: 'mac', quantumRisk: 'low', isWeak: false },

  // Random
  'csprng': { category: 'random', quantumRisk: 'none', isWeak: false },

  // TLS protocols
  'tls':     { category: 'protocol', quantumRisk: 'high', isWeak: false },
  'tls-1.0': { category: 'protocol', quantumRisk: 'critical', isWeak: true, weaknessReason: 'Deprecated, POODLE/BEAST', cwe: 'CWE-326', replacement: 'TLS 1.3' },
  'tls-1.1': { category: 'protocol', quantumRisk: 'critical', isWeak: true, weaknessReason: 'Deprecated', cwe: 'CWE-326', replacement: 'TLS 1.3' },
  'tls-1.2': { category: 'protocol', quantumRisk: 'high', isWeak: false },
  'tls-1.3': { category: 'protocol', quantumRisk: 'low', isWeak: false },
  'ssl-3.0': { category: 'protocol', quantumRisk: 'critical', isWeak: true, weaknessReason: 'POODLE attack', cwe: 'CWE-326', replacement: 'TLS 1.3' },
  'ssl-2.0': { category: 'protocol', quantumRisk: 'critical', isWeak: true, weaknessReason: 'Completely broken', cwe: 'CWE-326', replacement: 'TLS 1.3' },
};

// ---------------------------------------------------------------------------
// Common aliases: maps alternate names to canonical names in ALGORITHM_DB
// ---------------------------------------------------------------------------

const ALIASES = {
  'triple-des': '3des',
  'tripledes': '3des',
  'des3': '3des',
  'des-ede': '3des',
  'arcfour': 'rc4',
  'arc4': 'rc4',
  'aes128': 'aes-128',
  'aes192': 'aes-192',
  'aes256': 'aes-256',
  'aes-128-ctr': 'aes-ctr',
  'aes-256-ctr': 'aes-ctr',
  'aes-192-cbc': 'aes-cbc',
  'aes-192-gcm': 'aes-gcm',
  'sha2': 'sha256',
  'sha2-256': 'sha256',
  'sha-2': 'sha256',
  'sha': 'sha1',
  'md-5': 'md5',
  'rsa2048': 'rsa-2048',
  'rsa4096': 'rsa-4096',
  'rsa1024': 'rsa-1024',
  'ec': 'ecdsa',
  'ecc': 'ecdsa',
  // WebCrypto registry identifiers
  'rsassa-pkcs1-v1_5': 'rsa',
  'rsassa-pkcs1-v15': 'rsa',
  'rsa-oaep': 'rsa-oaep',
  'aes-kw': 'aes',
  // OpenSSL signature suite names (createSign/createVerify take these)
  'rsa-sha1': 'sha1',
  'rsa-sha256': 'rsa',
  'rsa-sha384': 'rsa',
  'rsa-sha512': 'rsa',
  'ecdsa-with-sha256': 'ecdsa',
  'sha256withrsa': 'rsa',
  'sha1withrsa': 'sha1',
  'curve-25519': 'curve25519',
  'dh-2048': 'dh',
  'diffie_hellman': 'diffie-hellman',
  'x25519kyber768': 'kyber-768',
  'kyber768': 'kyber-768',
  'kyber512': 'kyber-512',
  'kyber1024': 'kyber-1024',
  'sslv2': 'ssl-2.0',
  'sslv3': 'ssl-3.0',
  'tlsv1': 'tls-1.0',
  'tlsv1.0': 'tls-1.0',
  'tlsv1.1': 'tls-1.1',
  'tlsv1.2': 'tls-1.2',
  'tlsv1.3': 'tls-1.3',
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Normalize an algorithm name: trim, lowercase, strip spaces, try aliases.
 * Returns the canonical key in ALGORITHM_DB or null if not found.
 */
function normalize(name) {
  if (!name || typeof name !== 'string') return null;
  let key = name.trim().toLowerCase().replace(/\s+/g, '-');
  if (key in ALGORITHM_DB) return key;
  if (key in ALIASES) return ALIASES[key];
  // Try without hyphens
  const nohyphen = key.replace(/-/g, '');
  if (nohyphen in ALGORITHM_DB) return nohyphen;
  if (nohyphen in ALIASES) return ALIASES[nohyphen];
  return null;
}

/**
 * Case-insensitive lookup with alias normalization.
 * Returns the ALGORITHM_DB entry or null.
 */
export function lookupAlgorithm(name) {
  const key = normalize(name);
  return key ? { ...ALGORITHM_DB[key], name: key } : null;
}

// ---------------------------------------------------------------------------
// Cipher/digest token canonicalization
// ---------------------------------------------------------------------------

// OpenSSL and Node name a cipher by family, key length and mode in one token
// ("des-ede3-cbc", "bf-cbc", "rc2-40-cbc"). Longest prefix wins, so "des-ede3"
// must be tried before "des-ede" and "des".
const CIPHER_FAMILY_PREFIXES = [
  ['chacha20-poly1305', 'chacha20-poly1305'],
  ['xchacha20-poly1305', 'xchacha20-poly1305'],
  ['chacha20', 'chacha20'],
  ['des-ede3', '3des'],
  ['des-ede', '3des'],
  ['des3', '3des'],
  ['tripledes', '3des'],
  ['desx', 'des'],
  ['des', 'des'],
  ['blowfish', 'blowfish'],
  ['bf', 'blowfish'],
  ['rc2', 'rc2'],
  ['rc4', 'rc4'],
  ['arcfour', 'rc4'],
  ['cast5', 'cast5'],
  ['cast', 'cast5'],
  ['idea', 'idea'],
  ['camellia', 'camellia'],
  ['aria', 'aria'],
  ['sm4', 'sm4'],
];

// AES tokens keep their mode because ECB is weak and GCM/CBC/CTR are not.
const AES_MODES = new Set(['gcm', 'cbc', 'ctr', 'ecb', 'ccm', 'ocb', 'xts', 'cfb', 'ofb', 'wrap']);

const DIGEST_TOKENS = {
  'md4': 'md4', 'md5': 'md5', 'md5-sha1': 'md5',
  'sha': 'sha1', 'sha1': 'sha1', 'sha-1': 'sha1',
  'sha224': 'sha224', 'sha-224': 'sha224',
  'sha256': 'sha256', 'sha-256': 'sha256',
  'sha384': 'sha384', 'sha-384': 'sha384',
  'sha512': 'sha512', 'sha-512': 'sha512',
  'sha512-224': 'sha512', 'sha512-256': 'sha512',
  'sha3-256': 'sha3-256', 'sha3-384': 'sha3-384', 'sha3-512': 'sha3-512',
  'blake2b512': 'blake2b', 'blake2b': 'blake2b',
  'blake2s256': 'blake2s', 'blake2s': 'blake2s',
  'blake3': 'blake3',
  'ripemd160': 'ripemd160', 'ripemd': 'ripemd160', 'rmd160': 'ripemd160',
};

/**
 * Canonicalize a cipher or digest token as written in source code
 * ("des-ede3-cbc", "AES-256-GCM", "SHA-1", "bf-ecb") to a key in ALGORITHM_DB.
 *
 * This is what keeps `createCipheriv('des-ede3-cbc', ...)` from being read as
 * an unknown string, and what stops a family name from collapsing distinct
 * algorithms onto one label.
 *
 * @param {string} token - Algorithm token as it appears in source
 * @returns {string|null} Canonical ALGORITHM_DB key, or null if unrecognized
 */
export function canonicalizeAlgorithmToken(token) {
  if (!token || typeof token !== 'string') return null;
  const t = token.trim().toLowerCase().replace(/[_\s]+/g, '-');
  if (!t) return null;

  if (t in DIGEST_TOKENS) return DIGEST_TOKENS[t];

  // AES: preserve the mode, drop the key length (ECB weakness is mode-borne).
  const aes = t.match(/^aes-?(?:128|192|256)?-?([a-z]+)?(?:-\d+)?$/);
  if (aes && t.startsWith('aes')) {
    const mode = aes[1];
    if (mode && AES_MODES.has(mode)) {
      return mode === 'ecb' ? 'aes-ecb'
        : mode === 'gcm' ? 'aes-gcm'
        : mode === 'cbc' ? 'aes-cbc'
        : mode === 'ctr' ? 'aes-ctr'
        : 'aes';
    }
    return 'aes';
  }

  for (const [prefix, canonical] of CIPHER_FAMILY_PREFIXES) {
    if (t === prefix || t.startsWith(prefix + '-')) {
      return canonical in ALGORITHM_DB ? canonical : null;
    }
  }

  // Fall back to the alias table for everything else (rsa-2048, ml-kem-768, ...).
  return normalize(t);
}

/**
 * Classify an algorithm name using the database.
 * Returns { category, quantumRisk, isWeak, weaknessReason?, cwe? } or null.
 */
export function classifyFromDb(algorithmName) {
  const entry = lookupAlgorithm(algorithmName);
  if (!entry) return null;
  const result = {
    category: entry.category,
    quantumRisk: entry.quantumRisk,
    isWeak: entry.isWeak,
  };
  if (entry.weaknessReason) result.weaknessReason = entry.weaknessReason;
  if (entry.cwe) result.cwe = entry.cwe;
  return result;
}
