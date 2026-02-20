/**
 * Static classification of cryptographic packages across 11 ecosystems:
 * npm, PyPI, Go, Maven, crates.io, Packagist (PHP), NuGet (.NET),
 * RubyGems, Hex (Elixir), pub.dev (Dart), and CocoaPods (Swift/ObjC).
 *
 * Tiers:
 *   weak    - Broken or deprecated algorithms (MD5, SHA-1, DES, RC4, Blowfish),
 *             unmaintained implementations with known CVEs, or libraries
 *             that default to insecure configurations
 *   modern  - Current-generation cryptography with maintained implementations
 *             (includes both quantum-vulnerable asymmetric crypto like RSA/ECDSA
 *             and quantum-resistant symmetric crypto like AES-256/SHA-256)
 *   pqc     - Post-quantum cryptography (NIST FIPS 203/204/205)
 *
 * Categories:
 *   hashing    - Hash functions (MD5, SHA-*, BLAKE, CRC)
 *   encryption - Symmetric ciphers and AEAD (AES, ChaCha20, DES, RC4)
 *   kdf        - Key derivation and password hashing (PBKDF2, scrypt, Argon2, bcrypt)
 *   signing    - Digital signatures and key exchange (ECDSA, EdDSA, RSA, ML-DSA)
 *   jwt        - JWT/JWS/JWE token libraries
 *   tls        - TLS stacks, SSH, and protocol implementations
 *   general    - Multi-purpose cryptographic libraries
 */

export const TIERS = { WEAK: 'weak', MODERN: 'modern', PQC: 'pqc' };

/** @type {readonly ["hashing","encryption","kdf","signing","jwt","tls","general"]} */
export const CATEGORIES = ['hashing', 'encryption', 'kdf', 'signing', 'jwt', 'tls', 'general'];

// =========================================================================
// npm
// =========================================================================

/** @type {import('./types').CatalogEntry[]} */
export const NPM_PACKAGES = [
  // --- weak ---
  { name: 'md5',              tier: TIERS.WEAK,   algorithms: ['MD5'],                   note: 'Collision-broken hash', category: 'hashing', replacedBy: '@noble/hashes' },
  { name: 'sha1',             tier: TIERS.WEAK,   algorithms: ['SHA-1'],                 note: 'Collision-broken hash (SHAttered)', category: 'hashing', replacedBy: '@noble/hashes' },
  { name: 'crypto-js',        tier: TIERS.WEAK,   algorithms: ['DES', 'RC4', 'MD5'],     note: 'Bundles weak ciphers, no constant-time ops', category: 'encryption', replacedBy: '@noble/ciphers' },
  { name: 'des.js',           tier: TIERS.WEAK,   algorithms: ['DES', '3DES'],           note: 'Deprecated block cipher', category: 'encryption', replacedBy: '@noble/ciphers' },
  { name: 'js-md5',           tier: TIERS.WEAK,   algorithms: ['MD5'],                   note: 'Collision-broken hash', category: 'hashing', replacedBy: '@noble/hashes' },
  { name: 'js-sha1',          tier: TIERS.WEAK,   algorithms: ['SHA-1'],                 note: 'Collision-broken hash', category: 'hashing', replacedBy: '@noble/hashes' },
  { name: 'hash.js',          tier: TIERS.MODERN, algorithms: ['SHA-1', 'SHA-256', 'SHA-512'], note: 'SHA-2 family hashes, dependency of elliptic curve libraries', category: 'hashing' },
  { name: 'node-forge',       tier: TIERS.WEAK,   algorithms: ['RSA', 'DES', 'RC2'],     note: 'Pure JS RSA, bundles weak ciphers', category: 'general', replacedBy: '@noble/curves' },
  { name: 'jssha',            tier: TIERS.MODERN, algorithms: ['SHA-1', 'SHA-256', 'SHA-512', 'SHA-3'], note: 'Multi-algorithm hash library', category: 'hashing' },
  { name: 'rc4',              tier: TIERS.WEAK,   algorithms: ['RC4'],                   note: 'Stream cipher broken since 2013', category: 'encryption', replacedBy: '@noble/ciphers' },
  { name: 'js-sha256',        tier: TIERS.MODERN, algorithms: ['SHA-256'],               note: 'Pure JS SHA-256 implementation', category: 'hashing' },
  { name: 'js-sha512',        tier: TIERS.MODERN, algorithms: ['SHA-512'],               note: 'Pure JS SHA-512 implementation', category: 'hashing' },
  { name: 'js-sha3',          tier: TIERS.MODERN, algorithms: ['SHA-3'],                 note: 'SHA-3 hash functions (unmaintained, prefer @noble/hashes)', category: 'hashing' },
  { name: 'sha.js',           tier: TIERS.MODERN, algorithms: ['SHA-256', 'SHA-512'],    note: 'Streaming SHA-2 hashes (browserify legacy)', category: 'hashing' },
  { name: 'create-hash',      tier: TIERS.MODERN, algorithms: ['SHA-256', 'SHA-512'],    note: 'Node crypto.createHash polyfill for browsers', category: 'hashing' },
  { name: 'create-hmac',      tier: TIERS.MODERN, algorithms: ['HMAC-SHA-256'],          note: 'Node crypto.createHmac polyfill for browsers', category: 'hashing' },
  { name: 'md5.js',           tier: TIERS.WEAK,   algorithms: ['MD5'],                   note: 'Collision-broken hash', category: 'hashing', replacedBy: '@noble/hashes' },
  { name: 'sha1-uint8array',  tier: TIERS.WEAK,   algorithms: ['SHA-1'],                 note: 'SHA-1 variant for typed arrays', category: 'hashing', replacedBy: '@noble/hashes' },
  { name: 'ripemd160',        tier: TIERS.WEAK,   algorithms: ['RIPEMD-160'],            note: 'Legacy 160-bit hash, insufficient margin', category: 'hashing', replacedBy: '@noble/hashes' },
  { name: 'browserify-des',   tier: TIERS.WEAK,   algorithms: ['DES', '3DES'],           note: 'Browserify DES polyfill', category: 'encryption', replacedBy: '@noble/ciphers' },
  { name: 'browserify-cipher', tier: TIERS.WEAK,  algorithms: ['DES', 'Blowfish'],       note: 'Browserify legacy cipher polyfill', category: 'encryption', replacedBy: '@noble/ciphers' },
  { name: 'blowfish-js',      tier: TIERS.WEAK,   algorithms: ['Blowfish'],              note: '64-bit block cipher, Sweet32 vulnerable', category: 'encryption', replacedBy: '@noble/ciphers' },
  { name: 'tripledes',        tier: TIERS.WEAK,   algorithms: ['3DES'],                  note: 'Deprecated by NIST 2023', category: 'encryption', replacedBy: '@noble/ciphers' },

  // --- modern ---
  { name: '@noble/curves',          tier: TIERS.MODERN, algorithms: ['ECDSA', 'EdDSA', 'secp256k1'], note: 'Audited, constant-time elliptic curves', category: 'signing' },
  { name: '@noble/hashes',          tier: TIERS.MODERN, algorithms: ['SHA-256', 'SHA-3', 'BLAKE2'], note: 'Audited hash functions', category: 'hashing' },
  { name: '@noble/ciphers',         tier: TIERS.MODERN, algorithms: ['AES-GCM', 'ChaCha20-Poly1305', 'XSalsa20'], note: 'Audited symmetric ciphers', category: 'encryption' },
  { name: 'tweetnacl',              tier: TIERS.MODERN, algorithms: ['Curve25519', 'XSalsa20'],      note: 'NaCl port, audited', category: 'general' },
  { name: 'sodium-native',          tier: TIERS.MODERN, algorithms: ['Curve25519', 'ChaCha20'],      note: 'libsodium native bindings', category: 'general' },
  { name: 'jose',                   tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'EdDSA'],       note: 'JOSE/JWT/JWE standard library', category: 'jwt' },
  { name: 'libsodium-wrappers',     tier: TIERS.MODERN, algorithms: ['Curve25519', 'ChaCha20'],      note: 'libsodium WASM build', category: 'general' },
  { name: 'elliptic',               tier: TIERS.MODERN, algorithms: ['ECDSA', 'ECDH'],               note: 'Elliptic curve math', category: 'signing' },
  { name: 'bcryptjs',               tier: TIERS.MODERN, algorithms: ['bcrypt'],                      note: 'Password hashing', category: 'kdf' },
  { name: 'scrypt-js',              tier: TIERS.MODERN, algorithms: ['scrypt'],                      note: 'Memory-hard KDF', category: 'kdf' },
  { name: 'argon2',                 tier: TIERS.MODERN, algorithms: ['Argon2id', 'Argon2i'],         note: 'PHC winner password hashing (native)', category: 'kdf' },
  { name: '@types/bcryptjs',        tier: TIERS.MODERN, algorithms: ['bcrypt'],                      note: 'TypeScript types for bcryptjs', category: 'kdf' },
  { name: 'jsonwebtoken',           tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'HS256'],     note: 'JWT implementation', category: 'jwt' },
  { name: 'passport-jwt',           tier: TIERS.MODERN, algorithms: ['JWT'],                         note: 'Passport JWT strategy', category: 'jwt' },
  { name: '@panva/hkdf',            tier: TIERS.MODERN, algorithms: ['HKDF'],                        note: 'HKDF for Web Crypto and Node', category: 'kdf' },
  { name: 'openpgp',                tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'EdDSA', 'AES'], note: 'OpenPGP.js v5+ with modern algorithms', category: 'general' },
  { name: 'secp256k1',              tier: TIERS.MODERN, algorithms: ['secp256k1', 'ECDSA'],          note: 'Bitcoin/Ethereum curve', category: 'signing' },
  { name: '@stablelib/x25519',      tier: TIERS.MODERN, algorithms: ['X25519'],                      note: 'X25519 ECDH', category: 'signing' },
  { name: '@stablelib/chacha20poly1305', tier: TIERS.MODERN, algorithms: ['ChaCha20-Poly1305'],      note: 'AEAD cipher', category: 'encryption' },
  { name: 'noise-protocol',         tier: TIERS.MODERN, algorithms: ['Noise', 'X25519'],             note: 'Noise protocol framework', category: 'tls' },

  // --- pqc ---
  { name: '@noble/post-quantum',    tier: TIERS.PQC,    algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA'], note: 'FIPS 203/204/205 implementations', category: 'general' },
  { name: 'crystals-kyber',         tier: TIERS.PQC,    algorithms: ['Kyber/ML-KEM'],                 note: 'Lattice-based KEM', category: 'encryption' },
  { name: 'liboqs-node',            tier: TIERS.PQC,    algorithms: ['Kyber', 'Dilithium', 'SPHINCS+'], note: 'Open Quantum Safe bindings', category: 'general' },
  { name: 'kyber-crystals',         tier: TIERS.PQC,    algorithms: ['Kyber/ML-KEM'],                 note: 'Kyber implementation', category: 'encryption' },
];

// =========================================================================
// PyPI
// =========================================================================

/** @type {import('./types').CatalogEntry[]} */
export const PYPI_PACKAGES = [
  // --- weak ---
  { name: 'pycrypto',       tier: TIERS.WEAK,   algorithms: ['DES', 'Blowfish', 'ARC4'], note: 'Unmaintained since 2013, CVEs unfixed', category: 'general', replacedBy: 'pycryptodome' },
  { name: 'simple-crypt',   tier: TIERS.WEAK,   algorithms: ['AES-CTR'],                  note: 'Wraps pycrypto, inherits vulnerabilities', category: 'encryption', replacedBy: 'cryptography' },
  { name: 'tlslite',        tier: TIERS.WEAK,   algorithms: ['TLS 1.0', 'RC4', 'DES'],   note: 'Unmaintained, supports deprecated protocols', category: 'tls', replacedBy: 'cryptography' },
  { name: 'pyDes',          tier: TIERS.WEAK,   algorithms: ['DES', '3DES'],              note: 'Pure Python DES, deprecated cipher', category: 'encryption', replacedBy: 'pycryptodome' },
  { name: 'rsa',            tier: TIERS.WEAK,   algorithms: ['RSA-PKCS1v15'],             note: 'Pure Python RSA, no constant-time operations', category: 'signing', replacedBy: 'cryptography' },
  { name: 'Crypto',         tier: TIERS.WEAK,   algorithms: ['DES', 'ARC4', 'MD5'],       note: 'Alias for pycrypto, unmaintained', category: 'general', replacedBy: 'pycryptodome' },
  { name: 'python-gnupg',   tier: TIERS.WEAK,   algorithms: ['RSA', 'DSA', 'CAST5'],     note: 'GnuPG wrapper, often uses legacy defaults', category: 'general', replacedBy: 'cryptography' },

  // --- modern ---
  { name: 'cryptography',   tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA', 'X25519'],  note: 'PyCA reference library', category: 'general' },
  { name: 'pycryptodome',   tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA', 'ChaCha20'], note: 'PyCrypto fork, maintained', category: 'general' },
  { name: 'pynacl',         tier: TIERS.MODERN, algorithms: ['Curve25519', 'XSalsa20'],     note: 'libsodium Python bindings', category: 'general' },
  { name: 'bcrypt',         tier: TIERS.MODERN, algorithms: ['bcrypt'],                     note: 'Password hashing', category: 'kdf' },
  { name: 'argon2-cffi',    tier: TIERS.MODERN, algorithms: ['Argon2'],                     note: 'Winner of Password Hashing Competition', category: 'kdf' },
  { name: 'nacl',           tier: TIERS.MODERN, algorithms: ['Curve25519'],                 note: 'NaCl bindings (alias)', category: 'general' },
  { name: 'ecdsa',          tier: TIERS.MODERN, algorithms: ['ECDSA'],                      note: 'Pure Python ECDSA', category: 'signing' },
  { name: 'ed25519',        tier: TIERS.MODERN, algorithms: ['Ed25519'],                    note: 'EdDSA signing', category: 'signing' },
  { name: 'PyJWT',          tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'HS256'],    note: 'JWT implementation', category: 'jwt' },
  { name: 'python-jose',    tier: TIERS.MODERN, algorithms: ['RS256', 'ES256'],             note: 'JOSE standard library', category: 'jwt' },
  { name: 'paramiko',       tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'Ed25519'],   note: 'SSH protocol implementation', category: 'tls' },
  { name: 'Fernet',         tier: TIERS.MODERN, algorithms: ['AES-CBC', 'HMAC-SHA256'],     note: 'High-level symmetric encryption', category: 'encryption' },
  { name: 'tink',           tier: TIERS.MODERN, algorithms: ['AES-GCM', 'ECDSA', 'Ed25519'], note: 'Google Tink Python', category: 'general' },
  { name: 'passlib',        tier: TIERS.MODERN, algorithms: ['bcrypt', 'Argon2', 'scrypt'], note: 'Multi-algorithm password hashing', category: 'kdf' },
  { name: 'pyotp',          tier: TIERS.MODERN, algorithms: ['HMAC-SHA1', 'TOTP', 'HOTP'],  note: 'One-time password library', category: 'hashing' },

  // --- pqc ---
  { name: 'liboqs-python',  tier: TIERS.PQC,    algorithms: ['Kyber', 'Dilithium', 'SPHINCS+'], note: 'Open Quantum Safe bindings', category: 'general' },
  { name: 'pqcrypto',       tier: TIERS.PQC,    algorithms: ['Kyber', 'Dilithium'],              note: 'PQC algorithm wrappers', category: 'general' },
  { name: 'oqs',            tier: TIERS.PQC,    algorithms: ['Kyber', 'Dilithium'],              note: 'OQS convenience package', category: 'general' },
];

// =========================================================================
// Go Modules
// =========================================================================

/** @type {import('./types').CatalogEntry[]} */
export const GO_PACKAGES = [
  // --- weak (stdlib) ---
  { name: 'crypto/md5',       tier: TIERS.WEAK,   algorithms: ['MD5'],           note: 'Collision-broken hash', category: 'hashing', replacedBy: 'crypto/sha256' },
  { name: 'crypto/sha1',      tier: TIERS.WEAK,   algorithms: ['SHA-1'],         note: 'Collision-broken hash (SHAttered)', category: 'hashing', replacedBy: 'crypto/sha256' },
  { name: 'crypto/des',       tier: TIERS.WEAK,   algorithms: ['DES', '3DES'],   note: 'DES 56-bit brute-forceable, 3DES deprecated by NIST', category: 'encryption', replacedBy: 'crypto/aes' },
  { name: 'crypto/rc4',       tier: TIERS.WEAK,   algorithms: ['RC4'],           note: 'Broken stream cipher, prohibited by RFC 7465', category: 'encryption', replacedBy: 'crypto/aes' },
  { name: 'crypto/dsa',       tier: TIERS.WEAK,   algorithms: ['DSA'],           note: 'Deprecated in Go 1.16+, dropped by NIST FIPS 186-5', category: 'signing', replacedBy: 'crypto/ecdsa' },
  { name: 'crypto/elliptic',  tier: TIERS.MODERN, algorithms: ['ECDH'],          note: 'Low-level API deprecated in Go 1.21, use crypto/ecdh', category: 'signing' },

  // --- weak (x/crypto) ---
  { name: 'golang.org/x/crypto/md4',          tier: TIERS.WEAK,   algorithms: ['MD4'],        note: 'Collision-broken, weaker than MD5', category: 'hashing', replacedBy: 'golang.org/x/crypto/blake2b' },
  { name: 'golang.org/x/crypto/ripemd160',    tier: TIERS.WEAK,   algorithms: ['RIPEMD-160'], note: '160-bit hash with known weaknesses', category: 'hashing', replacedBy: 'golang.org/x/crypto/blake2b' },
  { name: 'golang.org/x/crypto/openpgp',      tier: TIERS.WEAK,   algorithms: ['RSA', 'DSA', 'CAST5'], note: 'Deprecated and frozen', category: 'general', replacedBy: 'github.com/ProtonMail/go-crypto' },
  { name: 'golang.org/x/crypto/bn256',        tier: TIERS.WEAK,   algorithms: ['BN256'],      note: 'Deprecated pairing curve, below 128-bit', category: 'signing', replacedBy: 'github.com/cloudflare/circl' },
  { name: 'golang.org/x/crypto/cast5',        tier: TIERS.WEAK,   algorithms: ['CAST5'],      note: '64-bit block cipher', category: 'encryption', replacedBy: 'crypto/aes' },
  { name: 'golang.org/x/crypto/blowfish',     tier: TIERS.WEAK,   algorithms: ['Blowfish'],   note: '64-bit block, Sweet32 vulnerable', category: 'encryption', replacedBy: 'crypto/aes' },
  { name: 'golang.org/x/crypto/tea',          tier: TIERS.WEAK,   algorithms: ['TEA'],        note: 'Known weaknesses, not for security', category: 'encryption', replacedBy: 'crypto/aes' },
  { name: 'golang.org/x/crypto/salsa20',      tier: TIERS.MODERN, algorithms: ['Salsa20'],    note: 'Stream cipher, predecessor to ChaCha20', category: 'encryption' },

  // --- weak (third-party) ---
  { name: 'github.com/dgrijalva/jwt-go',       tier: TIERS.WEAK,   algorithms: ['HMAC', 'RSA'], note: 'Unmaintained, CVE-2020-26160 none alg bypass', category: 'jwt', replacedBy: 'github.com/golang-jwt/jwt/v5' },
  { name: 'github.com/square/go-jose',         tier: TIERS.WEAK,   algorithms: ['JWE', 'JWS'],  note: 'Deprecated, migrated to go-jose/go-jose', category: 'jwt', replacedBy: 'github.com/go-jose/go-jose/v4' },
  { name: 'github.com/zmap/zcrypto',           tier: TIERS.WEAK,   algorithms: ['TLS 1.0', 'export ciphers'], note: 'Research TLS, speaks deprecated protocols', category: 'tls', replacedBy: 'crypto/tls' },

  // --- modern (stdlib) ---
  { name: 'crypto/aes',       tier: TIERS.MODERN, algorithms: ['AES'],                    note: 'AES block cipher', category: 'encryption' },
  { name: 'crypto/cipher',    tier: TIERS.MODERN, algorithms: ['AES-GCM', 'AES-CTR'],     note: 'Block cipher modes including AEAD', category: 'encryption' },
  { name: 'crypto/sha256',    tier: TIERS.MODERN, algorithms: ['SHA-256'],                 note: 'NIST-approved hash', category: 'hashing' },
  { name: 'crypto/sha512',    tier: TIERS.MODERN, algorithms: ['SHA-384', 'SHA-512'],      note: 'NIST-approved hash', category: 'hashing' },
  { name: 'crypto/sha3',      tier: TIERS.MODERN, algorithms: ['SHA3-256', 'SHAKE'],       note: 'Keccak-based, added Go 1.24', category: 'hashing' },
  { name: 'crypto/rsa',       tier: TIERS.MODERN, algorithms: ['RSA-OAEP', 'RSA-PSS'],    note: 'RSA encryption and signing', category: 'signing' },
  { name: 'crypto/ecdsa',     tier: TIERS.MODERN, algorithms: ['ECDSA'],                   note: 'Elliptic curve digital signatures', category: 'signing' },
  { name: 'crypto/ecdh',      tier: TIERS.MODERN, algorithms: ['ECDH', 'X25519'],          note: 'ECDH key exchange, added Go 1.20', category: 'signing' },
  { name: 'crypto/ed25519',   tier: TIERS.MODERN, algorithms: ['Ed25519'],                 note: 'Edwards-curve signatures', category: 'signing' },
  { name: 'crypto/tls',       tier: TIERS.MODERN, algorithms: ['TLS 1.3', 'X25519MLKEM768'], note: 'TLS with hybrid PQC since Go 1.24', category: 'tls' },
  { name: 'crypto/rand',      tier: TIERS.MODERN, algorithms: ['CSPRNG'],                  note: 'Cryptographic random', category: 'general' },
  { name: 'crypto/hmac',      tier: TIERS.MODERN, algorithms: ['HMAC'],                    note: 'HMAC authentication', category: 'hashing' },
  { name: 'crypto/hkdf',      tier: TIERS.MODERN, algorithms: ['HKDF'],                    note: 'RFC 5869 KDF, added Go 1.24', category: 'kdf' },
  { name: 'crypto/x509',      tier: TIERS.MODERN, algorithms: ['X.509'],                   note: 'Certificate handling', category: 'tls' },

  // --- modern (x/crypto) ---
  { name: 'golang.org/x/crypto/chacha20poly1305', tier: TIERS.MODERN, algorithms: ['ChaCha20-Poly1305'], note: 'AEAD, RFC 8439', category: 'encryption' },
  { name: 'golang.org/x/crypto/curve25519',       tier: TIERS.MODERN, algorithms: ['X25519'],            note: 'ECDH on Curve25519', category: 'signing' },
  { name: 'golang.org/x/crypto/nacl/box',         tier: TIERS.MODERN, algorithms: ['X25519', 'XSalsa20-Poly1305'], note: 'NaCl public-key encryption', category: 'encryption' },
  { name: 'golang.org/x/crypto/nacl/secretbox',   tier: TIERS.MODERN, algorithms: ['XSalsa20-Poly1305'], note: 'NaCl symmetric encryption', category: 'encryption' },
  { name: 'golang.org/x/crypto/argon2',           tier: TIERS.MODERN, algorithms: ['Argon2id'],          note: 'PHC winner password hashing', category: 'kdf' },
  { name: 'golang.org/x/crypto/bcrypt',           tier: TIERS.MODERN, algorithms: ['bcrypt'],            note: 'Adaptive password hashing', category: 'kdf' },
  { name: 'golang.org/x/crypto/scrypt',           tier: TIERS.MODERN, algorithms: ['scrypt'],            note: 'Memory-hard KDF', category: 'kdf' },
  { name: 'golang.org/x/crypto/blake2b',          tier: TIERS.MODERN, algorithms: ['BLAKE2b'],           note: 'Fast cryptographic hash', category: 'hashing' },
  { name: 'golang.org/x/crypto/ssh',              tier: TIERS.MODERN, algorithms: ['SSH'],               note: 'SSH protocol implementation', category: 'tls' },
  { name: 'golang.org/x/crypto/acme/autocert',    tier: TIERS.MODERN, algorithms: ['ACME', 'TLS'],       note: 'Auto TLS certificate provisioning', category: 'tls' },

  // --- modern (third-party) ---
  { name: 'github.com/golang-jwt/jwt/v5',       tier: TIERS.MODERN, algorithms: ['HMAC', 'RSA', 'ECDSA', 'EdDSA'], note: 'Most popular Go JWT library', category: 'jwt' },
  { name: 'github.com/go-jose/go-jose/v4',      tier: TIERS.MODERN, algorithms: ['JWE', 'JWS', 'JWT'],  note: 'JOSE standards', category: 'jwt' },
  { name: 'github.com/tink-crypto/tink-go/v2',  tier: TIERS.MODERN, algorithms: ['AES-GCM', 'ECDSA', 'Ed25519'], note: 'Google Tink misuse-resistant crypto', category: 'general' },
  { name: 'filippo.io/age',                      tier: TIERS.MODERN, algorithms: ['X25519', 'scrypt', 'ChaCha20-Poly1305'], note: 'Modern file encryption', category: 'encryption' },
  { name: 'github.com/ProtonMail/go-crypto',     tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'EdDSA'], note: 'Maintained OpenPGP fork', category: 'general' },
  { name: 'github.com/flynn/noise',              tier: TIERS.MODERN, algorithms: ['Noise', 'X25519', 'ChaCha20-Poly1305'], note: 'Noise protocol framework', category: 'tls' },
  { name: 'golang.zx2c4.com/wireguard',          tier: TIERS.MODERN, algorithms: ['Noise IK', 'X25519', 'ChaCha20-Poly1305'], note: 'WireGuard VPN', category: 'tls' },
  { name: 'github.com/aws/aws-sdk-go-v2/service/kms', tier: TIERS.MODERN, algorithms: ['AES-256', 'RSA', 'ECDSA'], note: 'AWS KMS client', category: 'general' },
  { name: 'cloud.google.com/go/kms/apiv1',       tier: TIERS.MODERN, algorithms: ['AES-256', 'RSA', 'ECDSA'], note: 'GCP Cloud KMS client', category: 'general' },

  // --- pqc ---
  { name: 'crypto/mlkem',                                tier: TIERS.PQC, algorithms: ['ML-KEM-768', 'ML-KEM-1024'], note: 'FIPS 203 in Go stdlib since 1.24', category: 'encryption' },
  { name: 'github.com/cloudflare/circl',                  tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'HPKE'], note: 'Comprehensive PQC + ECC library', category: 'general' },
  { name: 'github.com/cloudflare/circl/kem/mlkem',        tier: TIERS.PQC, algorithms: ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'], note: 'FIPS 203 ML-KEM', category: 'encryption' },
  { name: 'github.com/cloudflare/circl/sign/mldsa',       tier: TIERS.PQC, algorithms: ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'], note: 'FIPS 204 ML-DSA', category: 'signing' },
  { name: 'github.com/cloudflare/circl/sign/slhdsa',      tier: TIERS.PQC, algorithms: ['SLH-DSA'],           note: 'FIPS 205 hash-based signatures', category: 'signing' },
  { name: 'github.com/open-quantum-safe/liboqs-go',       tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA', 'Falcon'], note: 'OQS Go bindings', category: 'general' },
];

// =========================================================================
// Maven Central (Java/Kotlin)
// =========================================================================

/** @type {import('./types').CatalogEntry[]} */
export const MAVEN_PACKAGES = [
  // --- weak ---
  { name: 'org.bouncycastle:bcprov-jdk15on',    tier: TIERS.WEAK, algorithms: ['AES', 'RSA', 'DES'],     note: 'Superseded by jdk18on, no longer maintained', category: 'general', replacedBy: 'org.bouncycastle:bcprov-jdk18on' },
  { name: 'org.bouncycastle:bcprov-jdk16',       tier: TIERS.WEAK, algorithms: ['AES', 'RSA', 'DES'],     note: 'Legacy JDK 1.6 build, unmaintained', category: 'general', replacedBy: 'org.bouncycastle:bcprov-jdk18on' },
  { name: 'org.bouncycastle:bcpkix-jdk15on',     tier: TIERS.WEAK, algorithms: ['RSA', 'ECDSA', 'X.509'], note: 'Superseded by jdk18on', category: 'signing', replacedBy: 'org.bouncycastle:bcpkix-jdk18on' },
  { name: 'org.bouncycastle:bcpg-jdk15on',       tier: TIERS.WEAK, algorithms: ['RSA', 'DSA', 'ElGamal'], note: 'Legacy OpenPGP build', category: 'general', replacedBy: 'org.bouncycastle:bcpg-jdk18on' },
  { name: 'com.madgag.spongycastle:core',        tier: TIERS.WEAK, algorithms: ['AES', 'RSA', 'DES'],     note: 'BC Android fork, deprecated', category: 'general', replacedBy: 'org.bouncycastle:bcprov-jdk18on' },
  { name: 'org.jasypt:jasypt',                    tier: TIERS.WEAK, algorithms: ['PBE', 'DES', 'MD5'],     note: 'Defaults to PBEWithMD5AndDES, unmaintained since 2014', category: 'encryption', replacedBy: 'com.google.crypto.tink:tink' },
  { name: 'org.keyczar:keyczar',                  tier: TIERS.WEAK, algorithms: ['AES', 'RSA', 'DSA'],     note: 'Google Keyczar, archived project', category: 'general', replacedBy: 'com.google.crypto.tink:tink' },
  { name: 'org.apache.commons:commons-crypto',    tier: TIERS.MODERN, algorithms: ['AES-CTR', 'AES-CBC'],   note: 'OpenSSL-backed AES; CTR and CBC modes', category: 'encryption' },
  { name: 'io.jsonwebtoken:jjwt',                 tier: TIERS.MODERN, algorithms: ['HS256', 'RS256', 'ES256'], note: 'JWT library; legacy monolithic artifact, use jjwt-api for modular builds', category: 'jwt' },
  { name: 'org.apache.santuario:xmlsec',          tier: TIERS.WEAK, algorithms: ['RSA', 'SHA-1', 'DSA'],   note: 'XML-DSIG defaults to SHA-1', category: 'signing', replacedBy: 'org.bouncycastle:bcprov-jdk18on' },
  { name: 'org.apache.wss4j:wss4j-ws-security-common', tier: TIERS.WEAK, algorithms: ['SHA-1', 'AES-CBC'], note: 'WS-Security with legacy defaults', category: 'general', replacedBy: 'org.bouncycastle:bcprov-jdk18on' },
  { name: 'org.owasp.esapi:esapi',                tier: TIERS.WEAK, algorithms: ['AES-CBC', 'SHA-1'],      note: 'Legacy OWASP ESAPI, known CVEs', category: 'general', replacedBy: 'com.google.crypto.tink:tink' },

  // --- modern ---
  { name: 'org.bouncycastle:bcprov-jdk18on',      tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA', 'ECDSA', 'Ed25519', 'ChaCha20-Poly1305'], note: 'Comprehensive JCA provider', category: 'general' },
  { name: 'org.bouncycastle:bcpkix-jdk18on',      tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'Ed25519', 'X.509', 'CMS'], note: 'PKI operations', category: 'signing' },
  { name: 'org.bouncycastle:bctls-jdk18on',       tier: TIERS.MODERN, algorithms: ['TLS 1.3', 'AES-GCM'], note: 'BC JSSE TLS provider', category: 'tls' },
  { name: 'org.bouncycastle:bcpg-jdk18on',        tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'Ed25519', 'OpenPGP'], note: 'Modern OpenPGP', category: 'general' },
  { name: 'org.conscrypt:conscrypt-openjdk',       tier: TIERS.MODERN, algorithms: ['TLS 1.3', 'AES-GCM', 'ChaCha20-Poly1305'], note: 'Google BoringSSL-backed provider', category: 'tls' },
  { name: 'software.amazon.cryptools:AmazonCorrettoCryptoProvider', tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA', 'ECDSA', 'HKDF'], note: 'AWS high-perf JCA provider', category: 'general' },
  { name: 'com.google.crypto.tink:tink',           tier: TIERS.MODERN, algorithms: ['AES-GCM', 'AES-SIV', 'ECDSA', 'Ed25519'], note: 'Google Tink misuse-resistant crypto', category: 'general' },
  { name: 'com.nimbusds:nimbus-jose-jwt',          tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'EdDSA', 'AES-GCM'], note: 'Comprehensive JOSE/JWT/JWE', category: 'jwt' },
  { name: 'org.bitbucket.b_c:jose4j',              tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'AES-GCM'], note: 'JCA-only JOSE/JWT', category: 'jwt' },
  { name: 'io.jsonwebtoken:jjwt-api',              tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'EdDSA'], note: 'JJWT modular API', category: 'jwt' },
  { name: 'com.auth0:java-jwt',                    tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'PS256'], note: 'Auth0 JWT library', category: 'jwt' },
  { name: 'org.springframework.security:spring-security-crypto', tier: TIERS.MODERN, algorithms: ['bcrypt', 'scrypt', 'Argon2'], note: 'Spring Security password encoders', category: 'kdf' },
  { name: 'org.mindrot:jbcrypt',                   tier: TIERS.MODERN, algorithms: ['bcrypt'],              note: 'Original Java bcrypt', category: 'kdf' },
  { name: 'com.password4j:password4j',             tier: TIERS.MODERN, algorithms: ['Argon2', 'bcrypt', 'scrypt', 'PBKDF2'], note: 'Multi-algorithm password hashing', category: 'kdf' },
  { name: 'de.mkammerer:argon2-jvm',               tier: TIERS.MODERN, algorithms: ['Argon2'],              note: 'Argon2 JVM native bindings', category: 'kdf' },
  { name: 'software.amazon.awssdk:kms',             tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA', 'ECDSA'], note: 'AWS KMS SDK v2', category: 'general' },
  { name: 'com.amazonaws:aws-encryption-sdk-java',  tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA-OAEP', 'HKDF'], note: 'AWS envelope encryption', category: 'encryption' },
  { name: 'com.google.cloud:google-cloud-kms',      tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA', 'ECDSA'], note: 'GCP KMS client', category: 'general' },
  { name: 'com.azure:azure-security-keyvault-keys', tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'AES-GCM'], note: 'Azure Key Vault keys', category: 'general' },
  { name: 'io.netty:netty-handler',                 tier: TIERS.MODERN, algorithms: ['TLS 1.3', 'AES-GCM'], note: 'Netty SSL/TLS handler', category: 'tls' },
  { name: 'com.squareup.okhttp3:okhttp',            tier: TIERS.MODERN, algorithms: ['TLS 1.3', 'AES-GCM'], note: 'HTTP client with modern TLS', category: 'tls' },
  { name: 'org.signal:libsignal-client',             tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519', 'AES-GCM'], note: 'Signal Protocol primitives', category: 'general' },

  // --- pqc ---
  { name: 'org.bouncycastle:bcpqc-jdk18on',       tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'NTRU', 'FrodoKEM'], note: 'BC PQC suite since v1.79', category: 'general' },
  { name: 'org.openquantumsafe:liboqs-java',       tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'Falcon'], note: 'OQS JNI wrapper', category: 'general' },
];

// =========================================================================
// crates.io (Rust)
// =========================================================================

/** @type {import('./types').CatalogEntry[]} */
export const CRATES_PACKAGES = [
  // --- weak ---
  { name: 'md-5',           tier: TIERS.WEAK, algorithms: ['MD5'],              note: 'Collision-broken hash (RustCrypto)', category: 'hashing', replacedBy: 'sha2' },
  { name: 'md5',            tier: TIERS.WEAK, algorithms: ['MD5'],              note: 'Collision-broken hash (third-party)', category: 'hashing', replacedBy: 'sha2' },
  { name: 'sha1',           tier: TIERS.WEAK, algorithms: ['SHA-1'],            note: 'Collision-broken hash (RustCrypto)', category: 'hashing', replacedBy: 'sha2' },
  { name: 'sha-1',          tier: TIERS.WEAK, algorithms: ['SHA-1'],            note: 'Collision-broken hash alias (RustCrypto)', category: 'hashing', replacedBy: 'sha2' },
  { name: 'des',            tier: TIERS.WEAK, algorithms: ['DES', '3DES'],      note: 'Deprecated block cipher (RustCrypto)', category: 'encryption', replacedBy: 'aes-gcm' },
  { name: 'rc4',            tier: TIERS.WEAK, algorithms: ['RC4'],              note: 'Broken stream cipher', category: 'encryption', replacedBy: 'chacha20poly1305' },
  { name: 'blowfish',       tier: TIERS.WEAK, algorithms: ['Blowfish'],         note: '64-bit block, Sweet32 vulnerable', category: 'encryption', replacedBy: 'aes-gcm' },
  { name: 'cast5',          tier: TIERS.WEAK, algorithms: ['CAST5'],            note: 'Legacy 64-bit block cipher', category: 'encryption', replacedBy: 'aes-gcm' },
  { name: 'idea',           tier: TIERS.WEAK, algorithms: ['IDEA'],             note: 'Legacy 64-bit block cipher', category: 'encryption', replacedBy: 'aes-gcm' },
  { name: 'rust-crypto',    tier: TIERS.WEAK, algorithms: ['AES', 'DES', 'MD5'], note: 'Unmaintained since 2016, RUSTSEC-2016-0005', category: 'general', replacedBy: 'ring' },
  { name: 'ripemd',         tier: TIERS.WEAK, algorithms: ['RIPEMD-160'],       note: 'Legacy 160-bit hash', category: 'hashing', replacedBy: 'sha2' },
  { name: 'sodiumoxide',    tier: TIERS.WEAK, algorithms: ['X25519', 'Ed25519'], note: 'Deprecated on GitHub, use dryoc or libsodium-sys', category: 'general', replacedBy: 'dryoc' },

  // --- modern ---
  { name: 'ring',                tier: TIERS.MODERN, algorithms: ['AES-GCM', 'ChaCha20-Poly1305', 'Ed25519', 'X25519', 'RSA', 'ECDSA'], note: 'BoringSSL-backed, audited', category: 'general' },
  { name: 'aws-lc-rs',          tier: TIERS.MODERN, algorithms: ['AES-GCM', 'ChaCha20-Poly1305', 'Ed25519', 'X25519', 'RSA'], note: 'AWS-LC backed, FIPS 140-3, ring-compatible', category: 'general' },
  { name: 'rustls',             tier: TIERS.MODERN, algorithms: ['TLS 1.2', 'TLS 1.3'],                    note: 'Pure Rust TLS, audited', category: 'tls' },
  { name: 'aes-gcm',            tier: TIERS.MODERN, algorithms: ['AES-128-GCM', 'AES-256-GCM'],            note: 'Audited AEAD (RustCrypto, Cure53)', category: 'encryption' },
  { name: 'chacha20poly1305',   tier: TIERS.MODERN, algorithms: ['ChaCha20-Poly1305', 'XChaCha20-Poly1305'], note: 'Audited AEAD, RFC 8439 (RustCrypto)', category: 'encryption' },
  { name: 'aes',                tier: TIERS.MODERN, algorithms: ['AES-128', 'AES-256'],                    note: 'AES block cipher with HW accel (RustCrypto)', category: 'encryption' },
  { name: 'chacha20',           tier: TIERS.MODERN, algorithms: ['ChaCha20', 'XChaCha20'],                 note: 'Stream cipher (RustCrypto)', category: 'encryption' },
  { name: 'sha2',               tier: TIERS.MODERN, algorithms: ['SHA-256', 'SHA-384', 'SHA-512'],          note: 'NIST hash family (RustCrypto)', category: 'hashing' },
  { name: 'sha3',               tier: TIERS.MODERN, algorithms: ['SHA3-256', 'SHA3-512', 'SHAKE'],          note: 'Keccak-based hash (RustCrypto)', category: 'hashing' },
  { name: 'blake2',             tier: TIERS.MODERN, algorithms: ['BLAKE2b', 'BLAKE2s'],                    note: 'Fast secure hash, RFC 7693 (RustCrypto)', category: 'hashing' },
  { name: 'blake3',             tier: TIERS.MODERN, algorithms: ['BLAKE3'],                                note: 'Fastest secure hash (official crate)', category: 'hashing' },
  { name: 'hmac',               tier: TIERS.MODERN, algorithms: ['HMAC'],                                  note: 'HMAC authentication (RustCrypto)', category: 'hashing' },
  { name: 'hkdf',               tier: TIERS.MODERN, algorithms: ['HKDF'],                                  note: 'RFC 5869 KDF (RustCrypto)', category: 'kdf' },
  { name: 'argon2',             tier: TIERS.MODERN, algorithms: ['Argon2id', 'Argon2i'],                   note: 'PHC winner password hash (RustCrypto)', category: 'kdf' },
  { name: 'bcrypt',             tier: TIERS.MODERN, algorithms: ['bcrypt'],                                note: 'Password hashing (RustCrypto)', category: 'kdf' },
  { name: 'scrypt',             tier: TIERS.MODERN, algorithms: ['scrypt'],                                note: 'Memory-hard KDF (RustCrypto)', category: 'kdf' },
  { name: 'pbkdf2',             tier: TIERS.MODERN, algorithms: ['PBKDF2'],                                note: 'Password KDF, RFC 2898 (RustCrypto)', category: 'kdf' },
  { name: 'ed25519-dalek',      tier: TIERS.MODERN, algorithms: ['Ed25519'],                               note: 'Fast Ed25519, audited (dalek-cryptography)', category: 'signing' },
  { name: 'x25519-dalek',       tier: TIERS.MODERN, algorithms: ['X25519'],                                note: 'X25519 ECDH, audited (dalek-cryptography)', category: 'signing' },
  { name: 'curve25519-dalek',   tier: TIERS.MODERN, algorithms: ['Curve25519', 'Ristretto255'],            note: 'Group operations, audited (dalek-cryptography)', category: 'signing' },
  { name: 'rsa',                tier: TIERS.MODERN, algorithms: ['RSA-OAEP', 'RSA-PSS'],                  note: 'Pure Rust RSA, audited (RustCrypto)', category: 'signing' },
  { name: 'p256',               tier: TIERS.MODERN, algorithms: ['NIST P-256', 'ECDSA', 'ECDH'],          note: 'secp256r1 (RustCrypto)', category: 'signing' },
  { name: 'p384',               tier: TIERS.MODERN, algorithms: ['NIST P-384', 'ECDSA', 'ECDH'],          note: 'secp384r1 (RustCrypto)', category: 'signing' },
  { name: 'k256',               tier: TIERS.MODERN, algorithms: ['secp256k1', 'ECDSA'],                   note: 'Bitcoin/Ethereum curve, audited (RustCrypto)', category: 'signing' },
  { name: 'ecdsa',              tier: TIERS.MODERN, algorithms: ['ECDSA'],                                 note: 'ECDSA signing/verification (RustCrypto)', category: 'signing' },
  { name: 'orion',              tier: TIERS.MODERN, algorithms: ['ChaCha20-Poly1305', 'BLAKE2b', 'Argon2i', 'X25519'], note: 'Pure Rust easy-to-use crypto', category: 'general' },
  { name: 'dryoc',              tier: TIERS.MODERN, algorithms: ['X25519', 'XSalsa20-Poly1305', 'Ed25519'], note: 'Pure Rust libsodium-compatible', category: 'general' },
  { name: 'snow',               tier: TIERS.MODERN, algorithms: ['Noise', 'X25519', 'ChaCha20-Poly1305'], note: 'Noise Protocol Framework', category: 'tls' },
  { name: 'jsonwebtoken',       tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'EdDSA', 'HS256'],     note: 'JWT for Rust', category: 'jwt' },
  { name: 'sequoia-openpgp',    tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'Ed25519', 'AES'],       note: 'Full OpenPGP (RFC 9580)', category: 'general' },
  { name: 'rcgen',              tier: TIERS.MODERN, algorithms: ['X.509', 'ECDSA', 'Ed25519', 'RSA'],     note: 'X.509 certificate generation', category: 'tls' },
  { name: 'subtle',             tier: TIERS.MODERN, algorithms: ['constant-time'],                         note: 'Constant-time ops (dalek-cryptography)', category: 'general' },
  { name: 'zeroize',            tier: TIERS.MODERN, algorithms: ['memory zeroing'],                        note: 'Secure memory zeroing (RustCrypto)', category: 'general' },
  { name: 'crypto-bigint',      tier: TIERS.MODERN, algorithms: ['big integer'],                           note: 'Constant-time bignum (RustCrypto, audited)', category: 'general' },
  { name: 'cryptoki',           tier: TIERS.MODERN, algorithms: ['PKCS#11'],                               note: 'HSM interface', category: 'general' },

  // --- pqc ---
  { name: 'ml-kem',                    tier: TIERS.PQC, algorithms: ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'], note: 'FIPS 203 pure Rust (RustCrypto)', category: 'encryption' },
  { name: 'ml-dsa',                    tier: TIERS.PQC, algorithms: ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'], note: 'FIPS 204 pure Rust (RustCrypto)', category: 'signing' },
  { name: 'slh-dsa',                   tier: TIERS.PQC, algorithms: ['SLH-DSA'],                            note: 'FIPS 205 pure Rust (RustCrypto)', category: 'signing' },
  { name: 'pqcrypto',                  tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA', 'SPHINCS+'],      note: 'Meta-crate, wraps PQClean C', category: 'general' },
  { name: 'pqcrypto-kyber',            tier: TIERS.PQC, algorithms: ['Kyber/ML-KEM'],                      note: 'Kyber KEM (PQClean wrapper)', category: 'encryption' },
  { name: 'pqcrypto-dilithium',        tier: TIERS.PQC, algorithms: ['Dilithium/ML-DSA'],                  note: 'Dilithium signatures (PQClean wrapper)', category: 'signing' },
  { name: 'pqcrypto-sphincsplus',      tier: TIERS.PQC, algorithms: ['SPHINCS+/SLH-DSA'],                  note: 'Hash-based signatures (PQClean wrapper)', category: 'signing' },
  { name: 'pqcrypto-classicmceliece',  tier: TIERS.PQC, algorithms: ['Classic McEliece'],                  note: 'Code-based KEM', category: 'encryption' },
  { name: 'oqs',                       tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA', 'Falcon'],        note: 'OQS Rust wrapper', category: 'general' },
  { name: 'quantcrypt',               tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA'],       note: 'High-level PQC with X.509 integration', category: 'general' },
];

// =========================================================================
// Packagist (PHP)
// =========================================================================

/** @type {import('./types').CatalogEntry[]} */
export const PACKAGIST_PACKAGES = [
  // --- weak ---
  { name: 'paragonie/random_compat',     tier: TIERS.WEAK, algorithms: ['CSPRNG'],                     note: 'PHP 5.x polyfill; obsolete on PHP 7+', category: 'general', replacedBy: 'random_bytes()' },
  { name: 'ircmaxell/password-compat',   tier: TIERS.WEAK, algorithms: ['bcrypt'],                     note: 'PHP 5.3/5.4 polyfill; obsolete on PHP 7+', category: 'kdf', replacedBy: 'password_hash()' },
  { name: 'phpseclib/mcrypt_compat',     tier: TIERS.WEAK, algorithms: ['DES', 'Blowfish', '3DES', 'RC4'], note: 'Polyfill for removed ext-mcrypt', category: 'encryption', replacedBy: 'defuse/php-encryption' },
  { name: 'namshi/jose',                 tier: TIERS.WEAK, algorithms: ['JWT', 'HS256', 'RS256'],      note: 'Last release 2018; CVEs for alg confusion', category: 'jwt', replacedBy: 'firebase/php-jwt' },
  { name: 'gree/jose',                   tier: TIERS.WEAK, algorithms: ['JWT'],                        note: 'Abandoned by maintainer', category: 'jwt', replacedBy: 'web-token/jwt-framework' },
  { name: 'mdanter/ecc',                 tier: TIERS.WEAK, algorithms: ['ECDSA', 'ECDH'],              note: 'Abandoned; superseded by paragonie/ecc', category: 'signing', replacedBy: 'phpseclib/phpseclib' },
  { name: 'laminas/laminas-crypt',       tier: TIERS.WEAK, algorithms: ['AES-CBC', 'RSA', 'bcrypt'],   note: 'Marked abandoned by Laminas', category: 'general', replacedBy: 'defuse/php-encryption' },
  { name: 'bordoni/phpass',              tier: TIERS.WEAK, algorithms: ['bcrypt'],                     note: 'Portable phpass; deprecated API', category: 'kdf', replacedBy: 'password_hash()' },
  { name: 'ircmaxell/random-lib',        tier: TIERS.WEAK, algorithms: ['CSPRNG'],                     note: 'Pre-PHP-7 random library', category: 'general', replacedBy: 'random_bytes()' },

  // --- modern ---
  { name: 'phpseclib/phpseclib',         tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'Ed25519', 'AES-GCM', 'ChaCha20'], note: 'Pure-PHP crypto; use v3.0.36+', category: 'general' },
  { name: 'defuse/php-encryption',       tier: TIERS.MODERN, algorithms: ['AES-256-CTR', 'HMAC-SHA256'],  note: 'Audited symmetric encryption; zero CVEs', category: 'encryption' },
  { name: 'paragonie/sodium_compat',     tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519', 'ChaCha20-Poly1305'], note: 'libsodium polyfill', category: 'general' },
  { name: 'paragonie/halite',            tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519', 'ChaCha20-Poly1305', 'Argon2id'], note: 'Misuse-resistant API over libsodium', category: 'general' },
  { name: 'firebase/php-jwt',            tier: TIERS.MODERN, algorithms: ['HS256', 'RS256', 'ES256', 'EdDSA'], note: 'Most-downloaded PHP JWT; use v7.0+', category: 'jwt' },
  { name: 'lcobucci/jwt',                tier: TIERS.MODERN, algorithms: ['HS256', 'RS256', 'ES256', 'EdDSA'], note: 'Strict JWT; use v5.x', category: 'jwt' },
  { name: 'web-token/jwt-framework',     tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'EdDSA', 'AES-GCM', 'ECDH-ES'], note: 'Full JOSE/JWE/JWS', category: 'jwt' },
  { name: 'symfony/password-hasher',     tier: TIERS.MODERN, algorithms: ['bcrypt', 'Argon2id'],       note: 'Symfony password hasher', category: 'kdf' },
  { name: 'illuminate/hashing',          tier: TIERS.MODERN, algorithms: ['bcrypt', 'Argon2id'],       note: 'Laravel hashing', category: 'kdf' },
  { name: 'paragonie/paseto',            tier: TIERS.MODERN, algorithms: ['Ed25519', 'XChaCha20-Poly1305'], note: 'PASETO v4; preferred over JWT', category: 'jwt' },
  { name: 'spomky-labs/pki-framework',   tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'Ed25519', 'X.509'], note: 'Comprehensive PHP PKI', category: 'signing' },
  { name: 'paragonie/ciphersweet',       tier: TIERS.MODERN, algorithms: ['AES-256-CTR', 'XChaCha20-Poly1305'], note: 'Searchable field-level encryption', category: 'encryption' },

  // --- pqc ---
  { name: 'secudoc/php-liboqs',          tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA'], note: 'PHP C extension wrapping liboqs; experimental', category: 'general' },
];

// =========================================================================
// NuGet (.NET / C#)
// =========================================================================

/** @type {import('./types').CatalogEntry[]} */
export const NUGET_PACKAGES = [
  // --- weak ---
  { name: 'Portable.BouncyCastle',         tier: TIERS.WEAK, algorithms: ['AES', 'RSA', 'DES'],       note: 'EOL since 2021; superseded by BouncyCastle.Cryptography', category: 'general', replacedBy: 'BouncyCastle.Cryptography' },
  { name: 'BouncyCastle.NetCore',           tier: TIERS.WEAK, algorithms: ['AES', 'RSA'],              note: 'Unofficial, unmaintained since 2022', category: 'general', replacedBy: 'BouncyCastle.Cryptography' },
  { name: 'BouncyCastle',                   tier: TIERS.WEAK, algorithms: ['AES', 'RSA'],              note: 'Original namespaced package, EOL', category: 'general', replacedBy: 'BouncyCastle.Cryptography' },
  { name: 'Microsoft.Owin.Security.Jwt',    tier: TIERS.WEAK, algorithms: ['JWT', 'RS256'],            note: 'OWIN-era; no ECDSA/EdDSA', category: 'jwt', replacedBy: 'System.IdentityModel.Tokens.Jwt' },
  { name: 'Microsoft.Azure.KeyVault',       tier: TIERS.WEAK, algorithms: ['RSA', 'AES'],              note: 'Deprecated v1 SDK; use Azure.Security.KeyVault.*', category: 'general', replacedBy: 'Azure.Security.KeyVault.Keys' },
  { name: 'DotNetOpenAuth.Core',            tier: TIERS.WEAK, algorithms: ['RSA', 'HMAC'],             note: 'Archived, unmaintained since 2015', category: 'general', replacedBy: 'Microsoft.IdentityModel.Tokens' },
  { name: 'CryptSharpOfficial',             tier: TIERS.WEAK, algorithms: ['SCrypt', 'MD5-crypt'],     note: 'Legacy crypt implementations', category: 'kdf', replacedBy: 'BCrypt.Net-Next' },
  { name: 'CryptoHelper',                   tier: TIERS.WEAK, algorithms: ['bcrypt'],                  note: 'Unmaintained since 2020', category: 'kdf', replacedBy: 'BCrypt.Net-Next' },

  // --- modern ---
  { name: 'BouncyCastle.Cryptography',      tier: TIERS.MODERN, algorithms: ['AES-GCM', 'ChaCha20-Poly1305', 'Ed25519', 'X25519', 'TLS 1.3', 'ML-KEM', 'ML-DSA'], note: 'Official BC .NET; includes PQC suite since v2.0', category: 'general' },
  { name: 'System.IdentityModel.Tokens.Jwt', tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'HS256'], note: 'Microsoft JWT library', category: 'jwt' },
  { name: 'Microsoft.IdentityModel.Tokens', tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'EdDSA'], note: 'Token validation infrastructure', category: 'jwt' },
  { name: 'Microsoft.AspNetCore.DataProtection', tier: TIERS.MODERN, algorithms: ['AES-256-CBC', 'HMAC-SHA256'], note: 'ASP.NET Core data protection', category: 'encryption' },
  { name: 'BCrypt.Net-Next',                tier: TIERS.MODERN, algorithms: ['bcrypt'],                note: 'Well-maintained bcrypt', category: 'kdf' },
  { name: 'Konscious.Security.Cryptography.Argon2', tier: TIERS.MODERN, algorithms: ['Argon2id', 'Argon2i'], note: 'Pure C# Argon2', category: 'kdf' },
  { name: 'Isopoh.Cryptography.Argon2',     tier: TIERS.MODERN, algorithms: ['Argon2'],               note: 'Argon2 with memory security', category: 'kdf' },
  { name: 'NSec.Cryptography',              tier: TIERS.MODERN, algorithms: ['Ed25519', 'X25519', 'AES-256-GCM', 'ChaCha20-Poly1305'], note: 'Modern .NET 8+ libsodium API', category: 'general' },
  { name: 'libsodium',                      tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519', 'ChaCha20-Poly1305'], note: 'Native libsodium binaries', category: 'general' },
  { name: 'NaCl.Net',                       tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519', 'XSalsa20-Poly1305'], note: 'libsodium .NET bindings', category: 'general' },
  { name: 'Sodium.Core',                    tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519'],     note: 'libsodium managed wrapper', category: 'general' },
  { name: 'JWT',                             tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'HS256', 'PS256'], note: 'Lightweight JWT', category: 'jwt' },
  { name: 'jose-jwt',                       tier: TIERS.MODERN, algorithms: ['JWS', 'JWE', 'AES-GCM', 'ECDH-ES', 'EdDSA'], note: 'Full JOSE', category: 'jwt' },
  { name: 'Azure.Security.KeyVault.Keys',   tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'AES-GCM'], note: 'Azure KV keys', category: 'general' },
  { name: 'AWSSDK.KeyManagementService',    tier: TIERS.MODERN, algorithms: ['AES-256', 'RSA', 'ECDSA'], note: 'AWS KMS .NET SDK', category: 'general' },
  { name: 'MimeKit',                        tier: TIERS.MODERN, algorithms: ['S/MIME', 'RSA-OAEP', 'AES-GCM', 'EdDSA'], note: 'S/MIME and OpenPGP', category: 'general' },
  { name: 'Pkcs11Interop',                  tier: TIERS.MODERN, algorithms: ['PKCS#11'],               note: 'HSM interface', category: 'general' },
  { name: 'Inferno',                        tier: TIERS.MODERN, algorithms: ['AES-CBC', 'HMAC-SHA2'],  note: 'SuiteB authenticated encryption', category: 'encryption' },

  // --- pqc ---
  { name: 'LibOQS.NET',                     tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA', 'Falcon', 'SPHINCS+'], note: 'OQS .NET wrapper', category: 'general' },
];

// =========================================================================
// RubyGems (Ruby)
// =========================================================================

/** @type {import('./types').CatalogEntry[]} */
export const RUBYGEMS_PACKAGES = [
  // --- weak ---
  { name: 'crypt',               tier: TIERS.WEAK, algorithms: ['DES-crypt', 'MD5-crypt'],     note: 'Unix crypt() wrapper, legacy password hashing', category: 'kdf', replacedBy: 'bcrypt' },
  { name: 'fast-aes',            tier: TIERS.WEAK, algorithms: ['AES-ECB'],                    note: 'AES in ECB mode only, no IV, no authentication', category: 'encryption', replacedBy: 'openssl' },
  { name: 'gibberish',           tier: TIERS.WEAK, algorithms: ['AES-256-CBC', 'SHA-1'],       note: 'Uses SHA-1 for key derivation', category: 'encryption', replacedBy: 'openssl' },
  { name: 'ezcrypto',            tier: TIERS.WEAK, algorithms: ['Blowfish', 'DES'],            note: 'Unmaintained since 2009', category: 'encryption', replacedBy: 'openssl' },
  { name: 'crypt19',             tier: TIERS.WEAK, algorithms: ['Blowfish', 'GOST'],           note: 'Legacy ciphers, unmaintained', category: 'encryption', replacedBy: 'openssl' },
  { name: 'gpgme',               tier: TIERS.WEAK, algorithms: ['RSA', 'DSA', 'CAST5'],        note: 'GnuPG bindings, often uses legacy defaults', category: 'general', replacedBy: 'rbnacl' },

  // --- modern ---
  { name: 'openssl',             tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA', 'ECDSA', 'Ed25519', 'ChaCha20-Poly1305'], note: 'Ruby stdlib OpenSSL bindings', category: 'general' },
  { name: 'bcrypt',              tier: TIERS.MODERN, algorithms: ['bcrypt'],                    note: 'OpenBSD bcrypt password hashing', category: 'kdf' },
  { name: 'argon2',              tier: TIERS.MODERN, algorithms: ['Argon2id', 'Argon2i'],       note: 'PHC winner password hashing', category: 'kdf' },
  { name: 'scrypt',              tier: TIERS.MODERN, algorithms: ['scrypt'],                    note: 'Memory-hard KDF', category: 'kdf' },
  { name: 'rbnacl',              tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519', 'XSalsa20-Poly1305', 'ChaCha20-Poly1305', 'BLAKE2b'], note: 'libsodium FFI bindings', category: 'general' },
  { name: 'ed25519',             tier: TIERS.MODERN, algorithms: ['Ed25519'],                   note: 'Ed25519 digital signatures', category: 'signing' },
  { name: 'x25519',              tier: TIERS.MODERN, algorithms: ['X25519'],                    note: 'X25519 Diffie-Hellman key exchange', category: 'signing' },
  { name: 'lockbox',             tier: TIERS.MODERN, algorithms: ['AES-256-GCM'],               note: 'Modern encryption for Ruby/Rails', category: 'encryption' },
  { name: 'attr_encrypted',      tier: TIERS.MODERN, algorithms: ['AES-256-GCM'],               note: 'ActiveRecord attribute encryption', category: 'encryption' },
  { name: 'symmetric-encryption', tier: TIERS.MODERN, algorithms: ['AES-256-CBC', 'AES-256-GCM'], note: 'Enterprise symmetric encryption for Rails', category: 'encryption' },
  { name: 'encryptor',           tier: TIERS.MODERN, algorithms: ['AES-256-GCM'],               note: 'Simple OpenSSL cipher wrapper', category: 'encryption' },
  { name: 'jwt',                 tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'HS256'],   note: 'Ruby JWT implementation', category: 'jwt' },
  { name: 'json-jwt',            tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'EdDSA'],   note: 'JSON JWT/JWS/JWE for Ruby', category: 'jwt' },
  { name: 'jose',                tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'EdDSA', 'AES-GCM'], note: 'JOSE/JWT standards library', category: 'jwt' },
  { name: 'rotp',                tier: TIERS.MODERN, algorithms: ['HMAC-SHA1', 'TOTP', 'HOTP'], note: 'RFC 6238/4226 one-time passwords', category: 'hashing' },
  { name: 'net-ssh',             tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'Ed25519', 'ChaCha20-Poly1305'], note: 'SSH protocol implementation', category: 'tls' },
  { name: 'digest-sha3',         tier: TIERS.MODERN, algorithms: ['SHA-3', 'Keccak'],           note: 'SHA-3 hash function', category: 'hashing' },
  { name: 'fernet',              tier: TIERS.MODERN, algorithms: ['AES-128-CBC', 'HMAC-SHA256'], note: 'Fernet symmetric encryption', category: 'encryption' },

  // --- pqc ---
  { name: 'liboqs',              tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'Falcon'], note: 'Open Quantum Safe Ruby bindings', category: 'general' },
];

// =========================================================================
// Hex (Elixir/Erlang)
// =========================================================================

/** @type {import('./types').CatalogEntry[]} */
export const HEX_PACKAGES = [
  // --- weak ---
  { name: 'cipher',             tier: TIERS.WEAK, algorithms: ['AES-256-CBC', 'MD5'],         note: 'Uses MD5 for key derivation', category: 'encryption', replacedBy: 'cloak' },

  // --- modern ---
  { name: 'keccakf1600',        tier: TIERS.MODERN, algorithms: ['Keccak-f1600'],             note: 'Keccak permutation NIF (core of SHA-3)', category: 'hashing' },
  { name: 'comeonin',           tier: TIERS.MODERN, algorithms: ['bcrypt', 'Argon2', 'Pbkdf2'], note: 'Password hashing behaviour', category: 'kdf' },
  { name: 'bcrypt_elixir',      tier: TIERS.MODERN, algorithms: ['bcrypt'],                    note: 'Bcrypt password hashing', category: 'kdf' },
  { name: 'argon2_elixir',      tier: TIERS.MODERN, algorithms: ['Argon2id', 'Argon2i'],       note: 'PHC winner password hashing', category: 'kdf' },
  { name: 'pbkdf2_elixir',      tier: TIERS.MODERN, algorithms: ['PBKDF2-SHA512'],             note: 'PBKDF2 password hashing', category: 'kdf' },
  { name: 'plug_crypto',        tier: TIERS.MODERN, algorithms: ['AES-GCM', 'HMAC', 'SHA-256'], note: 'Crypto utilities for Plug/Phoenix', category: 'general' },
  { name: 'ex_crypto',          tier: TIERS.MODERN, algorithms: ['AES-GCM', 'AES-CBC', 'RSA'], note: 'Wrapper around Erlang :crypto', category: 'general' },
  { name: 'cloak',              tier: TIERS.MODERN, algorithms: ['AES-GCM', 'AES-CTR'],        note: 'Encryption library, pluggable ciphers', category: 'encryption' },
  { name: 'cloak_ecto',         tier: TIERS.MODERN, algorithms: ['AES-GCM', 'AES-CTR'],        note: 'Ecto types for field encryption via Cloak', category: 'encryption' },
  { name: 'enacl',              tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519', 'XSalsa20-Poly1305', 'ChaCha20-Poly1305'], note: 'NIF bindings to libsodium', category: 'general' },
  { name: 'salty',              tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519', 'XSalsa20-Poly1305'], note: 'NIF bindings to libsodium', category: 'general' },
  { name: 'jose',               tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'EdDSA', 'AES-GCM'], note: 'JOSE/JWT/JWS/JWE for Erlang and Elixir', category: 'jwt' },
  { name: 'joken',              tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'HS256'],   note: 'JWT token utility', category: 'jwt' },
  { name: 'guardian',           tier: TIERS.MODERN, algorithms: ['HS256', 'RS256', 'ES256'],   note: 'Token-based auth for Phoenix', category: 'jwt' },
  { name: 'x509',               tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'X.509'],     note: 'X.509 certificate handling', category: 'tls' },
  { name: 'ex_sha3',            tier: TIERS.MODERN, algorithms: ['SHA-3', 'Keccak'],           note: 'Pure Elixir SHA-3', category: 'hashing' },
  { name: 'nimble_totp',        tier: TIERS.MODERN, algorithms: ['HMAC-SHA1', 'TOTP'],         note: 'TOTP for 2FA', category: 'hashing' },
  { name: 'curve25519',         tier: TIERS.MODERN, algorithms: ['Curve25519'],                note: 'Curve25519 Diffie-Hellman', category: 'signing' },

  // --- pqc ---
  { name: 'pqclean',            tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'Classic McEliece'], note: 'PQClean NIF bindings', category: 'general' },
  { name: 'ex_tholos_pq',       tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA'],            note: 'Elixir NIF bindings for PQC', category: 'general' },
];

// =========================================================================
// pub.dev (Dart/Flutter)
// =========================================================================

/** @type {import('./types').CatalogEntry[]} */
export const PUB_PACKAGES = [
  // --- weak ---
  { name: 'crypto_dart',        tier: TIERS.WEAK, algorithms: ['MD5', 'SHA-1', 'AES-CBC'],    note: 'CryptoJS-like API, includes weak algorithms', category: 'general', replacedBy: 'cryptography' },
  { name: 'md5_plugin',         tier: TIERS.WEAK, algorithms: ['MD5'],                        note: 'MD5 hash only, collision-broken', category: 'hashing', replacedBy: 'hashlib' },
  { name: 'sha1',               tier: TIERS.WEAK, algorithms: ['SHA-1'],                      note: 'SHA-1 only, collision-broken', category: 'hashing', replacedBy: 'hashlib' },

  // --- modern ---
  { name: 'cryptography',       tier: TIERS.MODERN, algorithms: ['AES-GCM', 'ChaCha20', 'Ed25519', 'X25519', 'Argon2id', 'BLAKE2'], note: 'Comprehensive cross-platform crypto', category: 'general' },
  { name: 'cryptography_flutter', tier: TIERS.MODERN, algorithms: ['AES-GCM', 'ChaCha20', 'Ed25519', 'X25519'], note: 'Flutter plugin for OS crypto APIs', category: 'general' },
  { name: 'pointycastle',       tier: TIERS.MODERN, algorithms: ['AES', 'RSA', 'ECDSA', 'SHA-256', 'SHA-3', 'ChaCha20'], note: 'BouncyCastle port for Dart', category: 'general' },
  { name: 'encrypt',            tier: TIERS.MODERN, algorithms: ['AES-CBC', 'AES-GCM', 'RSA', 'Salsa20'], note: 'High-level API over PointyCastle', category: 'encryption' },
  { name: 'webcrypto',          tier: TIERS.MODERN, algorithms: ['AES-GCM', 'AES-CTR', 'RSA-OAEP', 'ECDSA', 'ECDH', 'HMAC'], note: 'Web Crypto API on all platforms', category: 'general' },
  { name: 'fast_rsa',           tier: TIERS.MODERN, algorithms: ['RSA-OAEP', 'RSA-PKCS1v15', 'RSA-PSS'], note: 'Native RSA operations', category: 'signing' },
  { name: 'steel_crypt',        tier: TIERS.MODERN, algorithms: ['AES', 'ChaCha20', 'SHA-256', 'HMAC'], note: 'High-level crypto APIs', category: 'encryption' },
  { name: 'pinenacl',           tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519', 'XSalsa20-Poly1305', 'BLAKE2b'], note: 'TweetNaCl Dart port', category: 'general' },
  { name: 'hashlib',            tier: TIERS.MODERN, algorithms: ['SHA-256', 'SHA-3', 'BLAKE2', 'Argon2', 'bcrypt', 'scrypt'], note: 'Optimized hash and KDF library', category: 'hashing' },
  { name: 'basic_utils',        tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'X.509'],     note: 'Key parsing, CSR generation, X.509', category: 'signing' },
  { name: 'dart_jsonwebtoken',  tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'HS256', 'EdDSA'], note: 'JWT for Dart', category: 'jwt' },
  { name: 'jose',               tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'EdDSA', 'AES-GCM'], note: 'JOSE/JWS/JWE/JWK for Dart', category: 'jwt' },
  { name: 'sodium_libs',        tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519', 'ChaCha20-Poly1305', 'Argon2id'], note: 'FFI bindings to native libsodium', category: 'general' },

  // --- pqc ---
  { name: 'pqcrypto',           tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA'],            note: 'Pure Dart NIST PQC', category: 'general' },
  { name: 'xkyber_crypto',      tier: TIERS.PQC, algorithms: ['Kyber/ML-KEM'],                note: 'Kyber KEM for Dart', category: 'encryption' },
  { name: 'custom_post_quantum', tier: TIERS.PQC, algorithms: ['Kyber/ML-KEM', 'Dilithium/ML-DSA'], note: 'Dart NIST PQC candidates', category: 'general' },
];

// =========================================================================
// CocoaPods (Swift/Objective-C)
// =========================================================================

/** @type {import('./types').CatalogEntry[]} */
export const COCOAPODS_PACKAGES = [
  // --- weak ---
  { name: 'OpenSSL',              tier: TIERS.WEAK, algorithms: ['RSA', 'DES', 'RC4', 'MD5'],     note: 'Deprecated by Apple, bundles weak ciphers', category: 'general', replacedBy: 'CryptoSwift' },
  { name: 'OpenSSL-Universal',    tier: TIERS.WEAK, algorithms: ['RSA', 'DES', 'RC4', 'MD5'],     note: 'Universal OpenSSL build, legacy algorithms', category: 'general', replacedBy: 'CryptoSwift' },
  { name: 'AESCrypt-ObjC',       tier: TIERS.WEAK, algorithms: ['AES-256-CBC'],                   note: 'AES-CBC without authentication', category: 'encryption', replacedBy: 'CryptoSwift' },
  { name: 'Arcane',              tier: TIERS.WEAK, algorithms: ['MD5', 'SHA-1', 'AES-CBC', 'HMAC'], note: 'CommonCrypto wrapper; exposes MD5, SHA-1', category: 'general', replacedBy: 'CryptoSwift' },
  { name: 'CommonCryptoSwift',   tier: TIERS.WEAK, algorithms: ['DES', '3DES', 'MD5', 'SHA-1', 'AES-CBC'], note: 'CommonCrypto Swift wrapper', category: 'general', replacedBy: 'CryptoSwift' },

  // --- modern ---
  { name: 'CryptoSwift',         tier: TIERS.MODERN, algorithms: ['AES', 'ChaCha20', 'Poly1305', 'RSA', 'PBKDF2', 'scrypt', 'HMAC', 'BLAKE2'], note: 'Pure Swift comprehensive crypto', category: 'general' },
  { name: 'IDZSwiftCommonCrypto', tier: TIERS.MODERN, algorithms: ['AES', 'SHA-256', 'SHA-512', 'HMAC'], note: 'Swift wrapper for CommonCrypto', category: 'general' },
  { name: 'SCrypto',             tier: TIERS.MODERN, algorithms: ['SHA-256', 'HMAC', 'PBKDF2', 'AES'], note: 'CommonCrypto digest/HMAC/AES extensions', category: 'general' },
  { name: 'SwCrypt',             tier: TIERS.MODERN, algorithms: ['RSA', 'AES', 'ECDSA'],         note: 'RSA key gen, AES via CommonCrypto', category: 'general' },
  { name: 'SwiftyRSA',           tier: TIERS.MODERN, algorithms: ['RSA-OAEP', 'RSA-PKCS1v15'],    note: 'RSA encryption and signing', category: 'signing' },
  { name: 'Sodium',              tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519', 'ChaCha20-Poly1305', 'Argon2id', 'BLAKE2b'], note: 'Swift libsodium bindings', category: 'general' },
  { name: 'TweetNacl',           tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519', 'XSalsa20-Poly1305'], note: 'TweetNaCl Swift port', category: 'general' },
  { name: 'RNCryptor',           tier: TIERS.MODERN, algorithms: ['AES-256-CBC', 'HMAC-SHA256', 'PBKDF2'], note: 'Cross-platform AES encryption', category: 'encryption' },
  { name: 'themis',              tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA', 'ECDSA', 'Ed25519'], note: 'Cossack Labs data security', category: 'general' },
  { name: 'ObjectivePGP',        tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'Ed25519', 'AES'], note: 'OpenPGP for iOS/macOS', category: 'general' },
  { name: 'JOSESwift',           tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'AES-GCM', 'ECDH-ES'], note: 'JOSE/JWS/JWE/JWK framework', category: 'jwt' },
  { name: 'BlueRSA',             tier: TIERS.MODERN, algorithms: ['RSA-OAEP', 'RSA-PSS'],         note: 'IBM Kitura RSA', category: 'signing' },
  { name: 'BlueCryptor',         tier: TIERS.MODERN, algorithms: ['AES', 'SHA-256', 'SHA-512', 'HMAC'], note: 'IBM Kitura CommonCrypto wrapper', category: 'general' },
  { name: 'Tink',                tier: TIERS.MODERN, algorithms: ['AES-GCM', 'ECDSA', 'Ed25519'], note: 'Google Tink for iOS', category: 'general' },

  // --- pqc ---
  { name: 'liboqs',              tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'Falcon'], note: 'Open Quantum Safe via bridging header', category: 'general' },
];

// =========================================================================
// API
// =========================================================================

/**
 * Get all packages for an ecosystem.
 * @param {'npm'|'pypi'|'go'|'maven'|'crates'|'packagist'|'nuget'|'rubygems'|'hex'|'pub'|'cocoapods'} ecosystem
 * @returns {import('./types').CatalogEntry[]}
 */
export function getPackages(ecosystem) {
  switch (ecosystem) {
    case 'npm':       return NPM_PACKAGES;
    case 'pypi':      return PYPI_PACKAGES;
    case 'go':        return GO_PACKAGES;
    case 'maven':     return MAVEN_PACKAGES;
    case 'crates':    return CRATES_PACKAGES;
    case 'packagist': return PACKAGIST_PACKAGES;
    case 'nuget':     return NUGET_PACKAGES;
    case 'rubygems':  return RUBYGEMS_PACKAGES;
    case 'hex':       return HEX_PACKAGES;
    case 'pub':       return PUB_PACKAGES;
    case 'cocoapods': return COCOAPODS_PACKAGES;
    default:          return [];
  }
}

/**
 * Get package names filtered by tier.
 * @param {'npm'|'pypi'|'go'|'maven'|'crates'|'packagist'|'nuget'|'rubygems'|'hex'|'pub'|'cocoapods'} ecosystem
 * @param {string} tier
 * @returns {string[]}
 */
export function getNamesByTier(ecosystem, tier) {
  return getPackages(ecosystem)
    .filter(p => p.tier === tier)
    .map(p => p.name);
}

/**
 * Total number of packages in the catalog across all ecosystems.
 * @returns {number}
 */
export function getCatalogSize() {
  return NPM_PACKAGES.length + PYPI_PACKAGES.length + GO_PACKAGES.length +
    MAVEN_PACKAGES.length + CRATES_PACKAGES.length +
    PACKAGIST_PACKAGES.length + NUGET_PACKAGES.length +
    RUBYGEMS_PACKAGES.length + HEX_PACKAGES.length +
    PUB_PACKAGES.length + COCOAPODS_PACKAGES.length;
}
