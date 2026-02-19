/**
 * Static classification of cryptographic packages across npm and PyPI ecosystems.
 *
 * Tiers:
 *   weak    - Broken, deprecated, or quantum-vulnerable primitives
 *   modern  - Current-generation crypto (not PQC)
 *   pqc     - Post-quantum cryptography
 */

export const TIERS = { WEAK: 'weak', MODERN: 'modern', PQC: 'pqc' };

/**
 * @typedef {Object} CatalogEntry
 * @property {string} name        - Package name
 * @property {string} tier        - One of TIERS values
 * @property {string[]} algorithms - Primary algorithms used/provided
 * @property {string} note        - Brief rationale for classification
 */

/** @type {CatalogEntry[]} */
export const NPM_PACKAGES = [
  // --- weak ---
  { name: 'md5',              tier: TIERS.WEAK,   algorithms: ['MD5'],                   note: 'Collision-broken hash' },
  { name: 'sha1',             tier: TIERS.WEAK,   algorithms: ['SHA-1'],                 note: 'Collision-broken hash (SHAttered)' },
  { name: 'crypto-js',        tier: TIERS.WEAK,   algorithms: ['DES', 'RC4', 'MD5'],     note: 'Bundles weak ciphers, no constant-time ops' },
  { name: 'des.js',           tier: TIERS.WEAK,   algorithms: ['DES', '3DES'],           note: 'Deprecated block cipher' },
  { name: 'js-md5',           tier: TIERS.WEAK,   algorithms: ['MD5'],                   note: 'Collision-broken hash' },
  { name: 'js-sha1',          tier: TIERS.WEAK,   algorithms: ['SHA-1'],                 note: 'Collision-broken hash' },
  { name: 'object-hash',      tier: TIERS.WEAK,   algorithms: ['SHA-1', 'MD5'],          note: 'Defaults to SHA-1' },
  { name: 'hash.js',          tier: TIERS.WEAK,   algorithms: ['SHA-1', 'SHA-256'],      note: 'No PQC, legacy API surface' },
  { name: 'node-forge',       tier: TIERS.WEAK,   algorithms: ['RSA', 'DES', 'RC2'],     note: 'Pure JS RSA, bundles weak ciphers' },
  { name: 'jssha',            tier: TIERS.WEAK,   algorithms: ['SHA-1', 'SHA-256'],      note: 'SHA-1 primary, no PQC' },
  { name: 'rc4',              tier: TIERS.WEAK,   algorithms: ['RC4'],                   note: 'Stream cipher broken since 2013' },
  { name: 'base64-js',        tier: TIERS.WEAK,   algorithms: ['Base64'],                note: 'Encoding, not encryption (commonly misused as crypto)' },

  // --- modern ---
  { name: '@noble/curves',          tier: TIERS.MODERN, algorithms: ['ECDSA', 'EdDSA', 'secp256k1'], note: 'Audited, constant-time elliptic curves' },
  { name: '@noble/hashes',          tier: TIERS.MODERN, algorithms: ['SHA-256', 'SHA-3', 'BLAKE2'], note: 'Audited hash functions' },
  { name: 'tweetnacl',              tier: TIERS.MODERN, algorithms: ['Curve25519', 'XSalsa20'],      note: 'NaCl port, audited' },
  { name: 'sodium-native',          tier: TIERS.MODERN, algorithms: ['Curve25519', 'ChaCha20'],      note: 'libsodium native bindings' },
  { name: 'jose',                   tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'EdDSA'],       note: 'JOSE/JWT/JWE standard library' },
  { name: 'libsodium-wrappers',     tier: TIERS.MODERN, algorithms: ['Curve25519', 'ChaCha20'],      note: 'libsodium WASM build' },
  { name: 'elliptic',               tier: TIERS.MODERN, algorithms: ['ECDSA', 'ECDH'],               note: 'Elliptic curve math' },
  { name: 'bcryptjs',               tier: TIERS.MODERN, algorithms: ['bcrypt'],                      note: 'Password hashing' },
  { name: 'scrypt-js',              tier: TIERS.MODERN, algorithms: ['scrypt'],                      note: 'Memory-hard KDF' },

  // --- pqc ---
  { name: '@noble/post-quantum',    tier: TIERS.PQC,    algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA'], note: 'FIPS 203/204/205 implementations' },
  { name: 'crystals-kyber',         tier: TIERS.PQC,    algorithms: ['Kyber/ML-KEM'],                 note: 'Lattice-based KEM' },
  { name: 'liboqs-node',            tier: TIERS.PQC,    algorithms: ['Kyber', 'Dilithium', 'SPHINCS+'], note: 'Open Quantum Safe bindings' },
  { name: 'kyber-crystals',         tier: TIERS.PQC,    algorithms: ['Kyber/ML-KEM'],                 note: 'Kyber implementation' },
];

/** @type {CatalogEntry[]} */
export const PYPI_PACKAGES = [
  // --- weak ---
  { name: 'pycrypto',       tier: TIERS.WEAK,   algorithms: ['DES', 'Blowfish', 'ARC4'], note: 'Unmaintained since 2013, CVEs unfixed' },
  { name: 'simple-crypt',   tier: TIERS.WEAK,   algorithms: ['AES-CTR'],                  note: 'Wraps pycrypto, inherits vulnerabilities' },

  // --- modern ---
  { name: 'cryptography',   tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA', 'X25519'],  note: 'PyCA reference library' },
  { name: 'pycryptodome',   tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA', 'ChaCha20'], note: 'PyCrypto fork, maintained' },
  { name: 'pynacl',         tier: TIERS.MODERN, algorithms: ['Curve25519', 'XSalsa20'],     note: 'libsodium Python bindings' },
  { name: 'bcrypt',         tier: TIERS.MODERN, algorithms: ['bcrypt'],                     note: 'Password hashing' },
  { name: 'argon2-cffi',    tier: TIERS.MODERN, algorithms: ['Argon2'],                     note: 'Winner of Password Hashing Competition' },
  { name: 'nacl',           tier: TIERS.MODERN, algorithms: ['Curve25519'],                 note: 'NaCl bindings (alias)' },
  { name: 'ecdsa',          tier: TIERS.MODERN, algorithms: ['ECDSA'],                      note: 'Pure Python ECDSA' },
  { name: 'ed25519',        tier: TIERS.MODERN, algorithms: ['Ed25519'],                    note: 'EdDSA signing' },

  // --- pqc ---
  { name: 'liboqs-python',  tier: TIERS.PQC,    algorithms: ['Kyber', 'Dilithium', 'SPHINCS+'], note: 'Open Quantum Safe bindings' },
  { name: 'pqcrypto',       tier: TIERS.PQC,    algorithms: ['Kyber', 'Dilithium'],              note: 'PQC algorithm wrappers' },
  { name: 'oqs',            tier: TIERS.PQC,    algorithms: ['Kyber', 'Dilithium'],              note: 'OQS convenience package' },
];

/**
 * Get all packages for an ecosystem.
 * @param {'npm'|'pypi'} ecosystem
 * @returns {CatalogEntry[]}
 */
export function getPackages(ecosystem) {
  return ecosystem === 'npm' ? NPM_PACKAGES : PYPI_PACKAGES;
}

/**
 * Get package names filtered by tier.
 * @param {'npm'|'pypi'} ecosystem
 * @param {string} tier
 * @returns {string[]}
 */
export function getNamesByTier(ecosystem, tier) {
  return getPackages(ecosystem)
    .filter(p => p.tier === tier)
    .map(p => p.name);
}
