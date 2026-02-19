/**
 * Static classification of cryptographic packages across 11 ecosystems:
 * npm, PyPI, Go, Maven, crates.io, Packagist (PHP), NuGet (.NET),
 * RubyGems, Hex (Elixir), pub.dev (Dart), and CocoaPods (Swift/ObjC).
 *
 * Tiers:
 *   weak    - Broken, deprecated, or quantum-vulnerable primitives
 *   modern  - Current-generation crypto (not PQC)
 *   pqc     - Post-quantum cryptography
 */

export const TIERS = { WEAK: 'weak', MODERN: 'modern', PQC: 'pqc' };

// =========================================================================
// npm
// =========================================================================

/** @type {import('./types').CatalogEntry[]} */
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
  { name: 'js-sha256',        tier: TIERS.WEAK,   algorithms: ['SHA-256'],               note: 'Redundant pure JS hash, no audit' },
  { name: 'js-sha512',        tier: TIERS.WEAK,   algorithms: ['SHA-512'],               note: 'Redundant pure JS hash, no audit' },
  { name: 'js-sha3',          tier: TIERS.WEAK,   algorithms: ['SHA-3'],                 note: 'Unmaintained, use @noble/hashes' },
  { name: 'sha.js',           tier: TIERS.WEAK,   algorithms: ['SHA-1', 'SHA-256'],      note: 'Legacy streaming hash, unmaintained' },
  { name: 'create-hash',      tier: TIERS.WEAK,   algorithms: ['MD5', 'SHA-1', 'SHA-256'], note: 'Legacy polyfill, defaults to SHA-1' },
  { name: 'create-hmac',      tier: TIERS.WEAK,   algorithms: ['HMAC-SHA-1'],            note: 'Legacy polyfill, pairs with create-hash' },
  { name: 'md5.js',           tier: TIERS.WEAK,   algorithms: ['MD5'],                   note: 'Collision-broken hash' },
  { name: 'sha1-uint8array',  tier: TIERS.WEAK,   algorithms: ['SHA-1'],                 note: 'SHA-1 variant for typed arrays' },
  { name: 'ripemd160',        tier: TIERS.WEAK,   algorithms: ['RIPEMD-160'],            note: 'Legacy 160-bit hash, insufficient margin' },
  { name: 'browserify-des',   tier: TIERS.WEAK,   algorithms: ['DES', '3DES'],           note: 'Browserify DES polyfill' },
  { name: 'browserify-cipher', tier: TIERS.WEAK,  algorithms: ['DES', 'Blowfish'],       note: 'Browserify legacy cipher polyfill' },
  { name: 'blowfish-js',      tier: TIERS.WEAK,   algorithms: ['Blowfish'],              note: '64-bit block cipher, Sweet32 vulnerable' },
  { name: 'tripledes',        tier: TIERS.WEAK,   algorithms: ['3DES'],                  note: 'Deprecated by NIST 2023' },

  // --- modern ---
  { name: '@noble/curves',          tier: TIERS.MODERN, algorithms: ['ECDSA', 'EdDSA', 'secp256k1'], note: 'Audited, constant-time elliptic curves' },
  { name: '@noble/hashes',          tier: TIERS.MODERN, algorithms: ['SHA-256', 'SHA-3', 'BLAKE2'], note: 'Audited hash functions' },
  { name: '@noble/ciphers',         tier: TIERS.MODERN, algorithms: ['AES-GCM', 'ChaCha20-Poly1305', 'XSalsa20'], note: 'Audited symmetric ciphers' },
  { name: 'tweetnacl',              tier: TIERS.MODERN, algorithms: ['Curve25519', 'XSalsa20'],      note: 'NaCl port, audited' },
  { name: 'sodium-native',          tier: TIERS.MODERN, algorithms: ['Curve25519', 'ChaCha20'],      note: 'libsodium native bindings' },
  { name: 'jose',                   tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'EdDSA'],       note: 'JOSE/JWT/JWE standard library' },
  { name: 'libsodium-wrappers',     tier: TIERS.MODERN, algorithms: ['Curve25519', 'ChaCha20'],      note: 'libsodium WASM build' },
  { name: 'elliptic',               tier: TIERS.MODERN, algorithms: ['ECDSA', 'ECDH'],               note: 'Elliptic curve math' },
  { name: 'bcryptjs',               tier: TIERS.MODERN, algorithms: ['bcrypt'],                      note: 'Password hashing' },
  { name: 'scrypt-js',              tier: TIERS.MODERN, algorithms: ['scrypt'],                      note: 'Memory-hard KDF' },
  { name: 'argon2',                 tier: TIERS.MODERN, algorithms: ['Argon2id', 'Argon2i'],         note: 'PHC winner password hashing (native)' },
  { name: '@types/bcryptjs',        tier: TIERS.MODERN, algorithms: ['bcrypt'],                      note: 'TypeScript types for bcryptjs' },
  { name: 'jsonwebtoken',           tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'HS256'],     note: 'JWT implementation' },
  { name: 'passport-jwt',           tier: TIERS.MODERN, algorithms: ['JWT'],                         note: 'Passport JWT strategy' },
  { name: '@panva/hkdf',            tier: TIERS.MODERN, algorithms: ['HKDF'],                        note: 'HKDF for Web Crypto and Node' },
  { name: 'openpgp',                tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'EdDSA', 'AES'], note: 'OpenPGP.js v5+ with modern algorithms' },
  { name: 'secp256k1',              tier: TIERS.MODERN, algorithms: ['secp256k1', 'ECDSA'],          note: 'Bitcoin/Ethereum curve' },
  { name: '@stablelib/x25519',      tier: TIERS.MODERN, algorithms: ['X25519'],                      note: 'X25519 ECDH' },
  { name: '@stablelib/chacha20poly1305', tier: TIERS.MODERN, algorithms: ['ChaCha20-Poly1305'],      note: 'AEAD cipher' },
  { name: 'noise-protocol',         tier: TIERS.MODERN, algorithms: ['Noise', 'X25519'],             note: 'Noise protocol framework' },

  // --- pqc ---
  { name: '@noble/post-quantum',    tier: TIERS.PQC,    algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA'], note: 'FIPS 203/204/205 implementations' },
  { name: 'crystals-kyber',         tier: TIERS.PQC,    algorithms: ['Kyber/ML-KEM'],                 note: 'Lattice-based KEM' },
  { name: 'liboqs-node',            tier: TIERS.PQC,    algorithms: ['Kyber', 'Dilithium', 'SPHINCS+'], note: 'Open Quantum Safe bindings' },
  { name: 'kyber-crystals',         tier: TIERS.PQC,    algorithms: ['Kyber/ML-KEM'],                 note: 'Kyber implementation' },
];

// =========================================================================
// PyPI
// =========================================================================

/** @type {import('./types').CatalogEntry[]} */
export const PYPI_PACKAGES = [
  // --- weak ---
  { name: 'pycrypto',       tier: TIERS.WEAK,   algorithms: ['DES', 'Blowfish', 'ARC4'], note: 'Unmaintained since 2013, CVEs unfixed' },
  { name: 'simple-crypt',   tier: TIERS.WEAK,   algorithms: ['AES-CTR'],                  note: 'Wraps pycrypto, inherits vulnerabilities' },
  { name: 'hashlib',        tier: TIERS.WEAK,   algorithms: ['MD5', 'SHA-1'],             note: 'Stdlib wrapper often used for MD5/SHA-1' },
  { name: 'tlslite',        tier: TIERS.WEAK,   algorithms: ['TLS 1.0', 'RC4', 'DES'],   note: 'Unmaintained, supports deprecated protocols' },
  { name: 'pyDes',          tier: TIERS.WEAK,   algorithms: ['DES', '3DES'],              note: 'Pure Python DES, deprecated cipher' },
  { name: 'rsa',            tier: TIERS.WEAK,   algorithms: ['RSA-PKCS1v15'],             note: 'Pure Python RSA, no constant-time operations' },
  { name: 'Crypto',         tier: TIERS.WEAK,   algorithms: ['DES', 'ARC4', 'MD5'],       note: 'Alias for pycrypto, unmaintained' },
  { name: 'python-gnupg',   tier: TIERS.WEAK,   algorithms: ['RSA', 'DSA', 'CAST5'],     note: 'GnuPG wrapper, often uses legacy defaults' },

  // --- modern ---
  { name: 'cryptography',   tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA', 'X25519'],  note: 'PyCA reference library' },
  { name: 'pycryptodome',   tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA', 'ChaCha20'], note: 'PyCrypto fork, maintained' },
  { name: 'pynacl',         tier: TIERS.MODERN, algorithms: ['Curve25519', 'XSalsa20'],     note: 'libsodium Python bindings' },
  { name: 'bcrypt',         tier: TIERS.MODERN, algorithms: ['bcrypt'],                     note: 'Password hashing' },
  { name: 'argon2-cffi',    tier: TIERS.MODERN, algorithms: ['Argon2'],                     note: 'Winner of Password Hashing Competition' },
  { name: 'nacl',           tier: TIERS.MODERN, algorithms: ['Curve25519'],                 note: 'NaCl bindings (alias)' },
  { name: 'ecdsa',          tier: TIERS.MODERN, algorithms: ['ECDSA'],                      note: 'Pure Python ECDSA' },
  { name: 'ed25519',        tier: TIERS.MODERN, algorithms: ['Ed25519'],                    note: 'EdDSA signing' },
  { name: 'PyJWT',          tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'HS256'],    note: 'JWT implementation' },
  { name: 'python-jose',    tier: TIERS.MODERN, algorithms: ['RS256', 'ES256'],             note: 'JOSE standard library' },
  { name: 'paramiko',       tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'Ed25519'],   note: 'SSH protocol implementation' },
  { name: 'Fernet',         tier: TIERS.MODERN, algorithms: ['AES-CBC', 'HMAC-SHA256'],     note: 'High-level symmetric encryption' },
  { name: 'tink',           tier: TIERS.MODERN, algorithms: ['AES-GCM', 'ECDSA', 'Ed25519'], note: 'Google Tink Python' },
  { name: 'passlib',        tier: TIERS.MODERN, algorithms: ['bcrypt', 'Argon2', 'scrypt'], note: 'Multi-algorithm password hashing' },
  { name: 'pyotp',          tier: TIERS.MODERN, algorithms: ['HMAC-SHA1', 'TOTP', 'HOTP'],  note: 'One-time password library' },

  // --- pqc ---
  { name: 'liboqs-python',  tier: TIERS.PQC,    algorithms: ['Kyber', 'Dilithium', 'SPHINCS+'], note: 'Open Quantum Safe bindings' },
  { name: 'pqcrypto',       tier: TIERS.PQC,    algorithms: ['Kyber', 'Dilithium'],              note: 'PQC algorithm wrappers' },
  { name: 'oqs',            tier: TIERS.PQC,    algorithms: ['Kyber', 'Dilithium'],              note: 'OQS convenience package' },
];

// =========================================================================
// Go Modules
// =========================================================================

/** @type {import('./types').CatalogEntry[]} */
export const GO_PACKAGES = [
  // --- weak (stdlib) ---
  { name: 'crypto/md5',       tier: TIERS.WEAK,   algorithms: ['MD5'],           note: 'Collision-broken hash' },
  { name: 'crypto/sha1',      tier: TIERS.WEAK,   algorithms: ['SHA-1'],         note: 'Collision-broken hash (SHAttered)' },
  { name: 'crypto/des',       tier: TIERS.WEAK,   algorithms: ['DES', '3DES'],   note: 'DES 56-bit brute-forceable, 3DES deprecated by NIST' },
  { name: 'crypto/rc4',       tier: TIERS.WEAK,   algorithms: ['RC4'],           note: 'Broken stream cipher, prohibited by RFC 7465' },
  { name: 'crypto/dsa',       tier: TIERS.WEAK,   algorithms: ['DSA'],           note: 'Deprecated in Go 1.16+, dropped by NIST FIPS 186-5' },
  { name: 'crypto/elliptic',  tier: TIERS.WEAK,   algorithms: ['ECDH'],          note: 'Low-level API deprecated in Go 1.21' },

  // --- weak (x/crypto) ---
  { name: 'golang.org/x/crypto/md4',          tier: TIERS.WEAK,   algorithms: ['MD4'],        note: 'Collision-broken, weaker than MD5' },
  { name: 'golang.org/x/crypto/ripemd160',    tier: TIERS.WEAK,   algorithms: ['RIPEMD-160'], note: '160-bit hash with known weaknesses' },
  { name: 'golang.org/x/crypto/openpgp',      tier: TIERS.WEAK,   algorithms: ['RSA', 'DSA', 'CAST5'], note: 'Deprecated and frozen' },
  { name: 'golang.org/x/crypto/bn256',        tier: TIERS.WEAK,   algorithms: ['BN256'],      note: 'Deprecated pairing curve, below 128-bit' },
  { name: 'golang.org/x/crypto/cast5',        tier: TIERS.WEAK,   algorithms: ['CAST5'],      note: '64-bit block cipher' },
  { name: 'golang.org/x/crypto/blowfish',     tier: TIERS.WEAK,   algorithms: ['Blowfish'],   note: '64-bit block, Sweet32 vulnerable' },
  { name: 'golang.org/x/crypto/tea',          tier: TIERS.WEAK,   algorithms: ['TEA'],        note: 'Known weaknesses, not for security' },
  { name: 'golang.org/x/crypto/salsa20',      tier: TIERS.WEAK,   algorithms: ['Salsa20'],    note: 'Superseded by ChaCha20, no AEAD' },

  // --- weak (third-party) ---
  { name: 'github.com/dgrijalva/jwt-go',       tier: TIERS.WEAK,   algorithms: ['HMAC', 'RSA'], note: 'Unmaintained, CVE-2020-26160 none alg bypass' },
  { name: 'github.com/square/go-jose',         tier: TIERS.WEAK,   algorithms: ['JWE', 'JWS'],  note: 'Deprecated, migrated to go-jose/go-jose' },
  { name: 'github.com/zmap/zcrypto',           tier: TIERS.WEAK,   algorithms: ['TLS 1.0', 'export ciphers'], note: 'Research TLS, speaks deprecated protocols' },

  // --- modern (stdlib) ---
  { name: 'crypto/aes',       tier: TIERS.MODERN, algorithms: ['AES'],                    note: 'AES block cipher' },
  { name: 'crypto/cipher',    tier: TIERS.MODERN, algorithms: ['AES-GCM', 'AES-CTR'],     note: 'Block cipher modes including AEAD' },
  { name: 'crypto/sha256',    tier: TIERS.MODERN, algorithms: ['SHA-256'],                 note: 'NIST-approved hash' },
  { name: 'crypto/sha512',    tier: TIERS.MODERN, algorithms: ['SHA-384', 'SHA-512'],      note: 'NIST-approved hash' },
  { name: 'crypto/sha3',      tier: TIERS.MODERN, algorithms: ['SHA3-256', 'SHAKE'],       note: 'Keccak-based, added Go 1.24' },
  { name: 'crypto/rsa',       tier: TIERS.MODERN, algorithms: ['RSA-OAEP', 'RSA-PSS'],    note: 'RSA encryption and signing' },
  { name: 'crypto/ecdsa',     tier: TIERS.MODERN, algorithms: ['ECDSA'],                   note: 'Elliptic curve digital signatures' },
  { name: 'crypto/ecdh',      tier: TIERS.MODERN, algorithms: ['ECDH', 'X25519'],          note: 'ECDH key exchange, added Go 1.20' },
  { name: 'crypto/ed25519',   tier: TIERS.MODERN, algorithms: ['Ed25519'],                 note: 'Edwards-curve signatures' },
  { name: 'crypto/tls',       tier: TIERS.MODERN, algorithms: ['TLS 1.3', 'X25519MLKEM768'], note: 'TLS with hybrid PQC since Go 1.24' },
  { name: 'crypto/rand',      tier: TIERS.MODERN, algorithms: ['CSPRNG'],                  note: 'Cryptographic random' },
  { name: 'crypto/hmac',      tier: TIERS.MODERN, algorithms: ['HMAC'],                    note: 'HMAC authentication' },
  { name: 'crypto/hkdf',      tier: TIERS.MODERN, algorithms: ['HKDF'],                    note: 'RFC 5869 KDF, added Go 1.24' },
  { name: 'crypto/x509',      tier: TIERS.MODERN, algorithms: ['X.509'],                   note: 'Certificate handling' },

  // --- modern (x/crypto) ---
  { name: 'golang.org/x/crypto/chacha20poly1305', tier: TIERS.MODERN, algorithms: ['ChaCha20-Poly1305'], note: 'AEAD, RFC 8439' },
  { name: 'golang.org/x/crypto/curve25519',       tier: TIERS.MODERN, algorithms: ['X25519'],            note: 'ECDH on Curve25519' },
  { name: 'golang.org/x/crypto/nacl/box',         tier: TIERS.MODERN, algorithms: ['X25519', 'XSalsa20-Poly1305'], note: 'NaCl public-key encryption' },
  { name: 'golang.org/x/crypto/nacl/secretbox',   tier: TIERS.MODERN, algorithms: ['XSalsa20-Poly1305'], note: 'NaCl symmetric encryption' },
  { name: 'golang.org/x/crypto/argon2',           tier: TIERS.MODERN, algorithms: ['Argon2id'],          note: 'PHC winner password hashing' },
  { name: 'golang.org/x/crypto/bcrypt',           tier: TIERS.MODERN, algorithms: ['bcrypt'],            note: 'Adaptive password hashing' },
  { name: 'golang.org/x/crypto/scrypt',           tier: TIERS.MODERN, algorithms: ['scrypt'],            note: 'Memory-hard KDF' },
  { name: 'golang.org/x/crypto/blake2b',          tier: TIERS.MODERN, algorithms: ['BLAKE2b'],           note: 'Fast cryptographic hash' },
  { name: 'golang.org/x/crypto/ssh',              tier: TIERS.MODERN, algorithms: ['SSH'],               note: 'SSH protocol implementation' },
  { name: 'golang.org/x/crypto/acme/autocert',    tier: TIERS.MODERN, algorithms: ['ACME', 'TLS'],       note: 'Auto TLS certificate provisioning' },

  // --- modern (third-party) ---
  { name: 'github.com/golang-jwt/jwt/v5',       tier: TIERS.MODERN, algorithms: ['HMAC', 'RSA', 'ECDSA', 'EdDSA'], note: 'Most popular Go JWT library' },
  { name: 'github.com/go-jose/go-jose/v4',      tier: TIERS.MODERN, algorithms: ['JWE', 'JWS', 'JWT'],  note: 'JOSE standards' },
  { name: 'github.com/tink-crypto/tink-go/v2',  tier: TIERS.MODERN, algorithms: ['AES-GCM', 'ECDSA', 'Ed25519'], note: 'Google Tink misuse-resistant crypto' },
  { name: 'filippo.io/age',                      tier: TIERS.MODERN, algorithms: ['X25519', 'scrypt', 'ChaCha20-Poly1305'], note: 'Modern file encryption' },
  { name: 'github.com/ProtonMail/go-crypto',     tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'EdDSA'], note: 'Maintained OpenPGP fork' },
  { name: 'github.com/flynn/noise',              tier: TIERS.MODERN, algorithms: ['Noise', 'X25519', 'ChaCha20-Poly1305'], note: 'Noise protocol framework' },
  { name: 'golang.zx2c4.com/wireguard',          tier: TIERS.MODERN, algorithms: ['Noise IK', 'X25519', 'ChaCha20-Poly1305'], note: 'WireGuard VPN' },
  { name: 'github.com/aws/aws-sdk-go-v2/service/kms', tier: TIERS.MODERN, algorithms: ['AES-256', 'RSA', 'ECDSA'], note: 'AWS KMS client' },
  { name: 'cloud.google.com/go/kms/apiv1',       tier: TIERS.MODERN, algorithms: ['AES-256', 'RSA', 'ECDSA'], note: 'GCP Cloud KMS client' },

  // --- pqc ---
  { name: 'crypto/mlkem',                                tier: TIERS.PQC, algorithms: ['ML-KEM-768', 'ML-KEM-1024'], note: 'FIPS 203 in Go stdlib since 1.24' },
  { name: 'github.com/cloudflare/circl',                  tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'HPKE'], note: 'Comprehensive PQC + ECC library' },
  { name: 'github.com/cloudflare/circl/kem/mlkem',        tier: TIERS.PQC, algorithms: ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'], note: 'FIPS 203 ML-KEM' },
  { name: 'github.com/cloudflare/circl/sign/mldsa',       tier: TIERS.PQC, algorithms: ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'], note: 'FIPS 204 ML-DSA' },
  { name: 'github.com/cloudflare/circl/sign/slhdsa',      tier: TIERS.PQC, algorithms: ['SLH-DSA'],           note: 'FIPS 205 hash-based signatures' },
  { name: 'github.com/open-quantum-safe/liboqs-go',       tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA', 'Falcon'], note: 'OQS Go bindings' },
];

// =========================================================================
// Maven Central (Java/Kotlin)
// =========================================================================

/** @type {import('./types').CatalogEntry[]} */
export const MAVEN_PACKAGES = [
  // --- weak ---
  { name: 'org.bouncycastle:bcprov-jdk15on',    tier: TIERS.WEAK, algorithms: ['AES', 'RSA', 'DES'],     note: 'Superseded by jdk18on, no longer maintained' },
  { name: 'org.bouncycastle:bcprov-jdk16',       tier: TIERS.WEAK, algorithms: ['AES', 'RSA', 'DES'],     note: 'Legacy JDK 1.6 build, unmaintained' },
  { name: 'org.bouncycastle:bcpkix-jdk15on',     tier: TIERS.WEAK, algorithms: ['RSA', 'ECDSA', 'X.509'], note: 'Superseded by jdk18on' },
  { name: 'org.bouncycastle:bcpg-jdk15on',       tier: TIERS.WEAK, algorithms: ['RSA', 'DSA', 'ElGamal'], note: 'Legacy OpenPGP build' },
  { name: 'com.madgag.spongycastle:core',        tier: TIERS.WEAK, algorithms: ['AES', 'RSA', 'DES'],     note: 'BC Android fork, deprecated' },
  { name: 'org.jasypt:jasypt',                    tier: TIERS.WEAK, algorithms: ['PBE', 'DES', 'MD5'],     note: 'Defaults to PBEWithMD5AndDES, unmaintained since 2014' },
  { name: 'org.keyczar:keyczar',                  tier: TIERS.WEAK, algorithms: ['AES', 'RSA', 'DSA'],     note: 'Google Keyczar, archived project' },
  { name: 'commons-codec:commons-codec',          tier: TIERS.WEAK, algorithms: ['MD5', 'SHA-1', 'SHA-256'], note: 'DigestUtils md5Hex/sha1Hex widely used' },
  { name: 'com.google.guava:guava',               tier: TIERS.WEAK, algorithms: ['MD5', 'SHA-1'],          note: 'Hashing.md5()/sha1() convenience methods' },
  { name: 'org.apache.commons:commons-crypto',    tier: TIERS.WEAK, algorithms: ['AES-CTR', 'AES-CBC'],    note: 'No AEAD modes, no GCM support' },
  { name: 'io.jsonwebtoken:jjwt',                 tier: TIERS.WEAK, algorithms: ['HS256', 'RS256'],        note: 'Legacy monolithic artifact, replaced by jjwt-api' },
  { name: 'org.apache.santuario:xmlsec',          tier: TIERS.WEAK, algorithms: ['RSA', 'SHA-1', 'DSA'],   note: 'XML-DSIG defaults to SHA-1' },
  { name: 'org.apache.wss4j:wss4j-ws-security-common', tier: TIERS.WEAK, algorithms: ['SHA-1', 'AES-CBC'], note: 'WS-Security with legacy defaults' },
  { name: 'org.owasp.esapi:esapi',                tier: TIERS.WEAK, algorithms: ['AES-CBC', 'SHA-1'],      note: 'Legacy OWASP ESAPI, known CVEs' },

  // --- modern ---
  { name: 'org.bouncycastle:bcprov-jdk18on',      tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA', 'ECDSA', 'Ed25519', 'ChaCha20-Poly1305'], note: 'Comprehensive JCA provider' },
  { name: 'org.bouncycastle:bcpkix-jdk18on',      tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'Ed25519', 'X.509', 'CMS'], note: 'PKI operations' },
  { name: 'org.bouncycastle:bctls-jdk18on',       tier: TIERS.MODERN, algorithms: ['TLS 1.3', 'AES-GCM'], note: 'BC JSSE TLS provider' },
  { name: 'org.bouncycastle:bcpg-jdk18on',        tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'Ed25519', 'OpenPGP'], note: 'Modern OpenPGP' },
  { name: 'org.conscrypt:conscrypt-openjdk',       tier: TIERS.MODERN, algorithms: ['TLS 1.3', 'AES-GCM', 'ChaCha20-Poly1305'], note: 'Google BoringSSL-backed provider' },
  { name: 'software.amazon.cryptools:AmazonCorrettoCryptoProvider', tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA', 'ECDSA', 'HKDF'], note: 'AWS high-perf JCA provider' },
  { name: 'com.google.crypto.tink:tink',           tier: TIERS.MODERN, algorithms: ['AES-GCM', 'AES-SIV', 'ECDSA', 'Ed25519'], note: 'Google Tink misuse-resistant crypto' },
  { name: 'com.nimbusds:nimbus-jose-jwt',          tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'EdDSA', 'AES-GCM'], note: 'Comprehensive JOSE/JWT/JWE' },
  { name: 'org.bitbucket.b_c:jose4j',              tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'AES-GCM'], note: 'JCA-only JOSE/JWT' },
  { name: 'io.jsonwebtoken:jjwt-api',              tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'EdDSA'], note: 'JJWT modular API' },
  { name: 'com.auth0:java-jwt',                    tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'PS256'], note: 'Auth0 JWT library' },
  { name: 'org.springframework.security:spring-security-crypto', tier: TIERS.MODERN, algorithms: ['bcrypt', 'scrypt', 'Argon2'], note: 'Spring Security password encoders' },
  { name: 'org.mindrot:jbcrypt',                   tier: TIERS.MODERN, algorithms: ['bcrypt'],              note: 'Original Java bcrypt' },
  { name: 'com.password4j:password4j',             tier: TIERS.MODERN, algorithms: ['Argon2', 'bcrypt', 'scrypt', 'PBKDF2'], note: 'Multi-algorithm password hashing' },
  { name: 'de.mkammerer:argon2-jvm',               tier: TIERS.MODERN, algorithms: ['Argon2'],              note: 'Argon2 JVM native bindings' },
  { name: 'software.amazon.awssdk:kms',             tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA', 'ECDSA'], note: 'AWS KMS SDK v2' },
  { name: 'com.amazonaws:aws-encryption-sdk-java',  tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA-OAEP', 'HKDF'], note: 'AWS envelope encryption' },
  { name: 'com.google.cloud:google-cloud-kms',      tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA', 'ECDSA'], note: 'GCP KMS client' },
  { name: 'com.azure:azure-security-keyvault-keys', tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'AES-GCM'], note: 'Azure Key Vault keys' },
  { name: 'io.netty:netty-handler',                 tier: TIERS.MODERN, algorithms: ['TLS 1.3', 'AES-GCM'], note: 'Netty SSL/TLS handler' },
  { name: 'com.squareup.okhttp3:okhttp',            tier: TIERS.MODERN, algorithms: ['TLS 1.3', 'AES-GCM'], note: 'HTTP client with modern TLS' },
  { name: 'org.signal:libsignal-client',             tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519', 'AES-GCM'], note: 'Signal Protocol primitives' },

  // --- pqc ---
  { name: 'org.bouncycastle:bcpqc-jdk18on',       tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'NTRU', 'FrodoKEM'], note: 'BC PQC suite since v1.79' },
  { name: 'org.openquantumsafe:liboqs-java',       tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'Falcon'], note: 'OQS JNI wrapper' },
];

// =========================================================================
// crates.io (Rust)
// =========================================================================

/** @type {import('./types').CatalogEntry[]} */
export const CRATES_PACKAGES = [
  // --- weak ---
  { name: 'md-5',           tier: TIERS.WEAK, algorithms: ['MD5'],              note: 'Collision-broken hash (RustCrypto)' },
  { name: 'md5',            tier: TIERS.WEAK, algorithms: ['MD5'],              note: 'Collision-broken hash (third-party)' },
  { name: 'sha1',           tier: TIERS.WEAK, algorithms: ['SHA-1'],            note: 'Collision-broken hash (RustCrypto)' },
  { name: 'sha-1',          tier: TIERS.WEAK, algorithms: ['SHA-1'],            note: 'Collision-broken hash alias (RustCrypto)' },
  { name: 'des',            tier: TIERS.WEAK, algorithms: ['DES', '3DES'],      note: 'Deprecated block cipher (RustCrypto)' },
  { name: 'rc4',            tier: TIERS.WEAK, algorithms: ['RC4'],              note: 'Broken stream cipher' },
  { name: 'blowfish',       tier: TIERS.WEAK, algorithms: ['Blowfish'],         note: '64-bit block, Sweet32 vulnerable' },
  { name: 'cast5',          tier: TIERS.WEAK, algorithms: ['CAST5'],            note: 'Legacy 64-bit block cipher' },
  { name: 'idea',           tier: TIERS.WEAK, algorithms: ['IDEA'],             note: 'Legacy 64-bit block cipher' },
  { name: 'rust-crypto',    tier: TIERS.WEAK, algorithms: ['AES', 'DES', 'MD5'], note: 'Unmaintained since 2016, RUSTSEC-2016-0005' },
  { name: 'ripemd',         tier: TIERS.WEAK, algorithms: ['RIPEMD-160'],       note: 'Legacy 160-bit hash' },
  { name: 'sodiumoxide',    tier: TIERS.WEAK, algorithms: ['X25519', 'Ed25519'], note: 'Deprecated on GitHub, use dryoc or libsodium-sys' },

  // --- modern ---
  { name: 'ring',                tier: TIERS.MODERN, algorithms: ['AES-GCM', 'ChaCha20-Poly1305', 'Ed25519', 'X25519', 'RSA', 'ECDSA'], note: 'BoringSSL-backed, audited' },
  { name: 'aws-lc-rs',          tier: TIERS.MODERN, algorithms: ['AES-GCM', 'ChaCha20-Poly1305', 'Ed25519', 'X25519', 'RSA'], note: 'AWS-LC backed, FIPS 140-3, ring-compatible' },
  { name: 'rustls',             tier: TIERS.MODERN, algorithms: ['TLS 1.2', 'TLS 1.3'],                    note: 'Pure Rust TLS, audited' },
  { name: 'aes-gcm',            tier: TIERS.MODERN, algorithms: ['AES-128-GCM', 'AES-256-GCM'],            note: 'Audited AEAD (RustCrypto, Cure53)' },
  { name: 'chacha20poly1305',   tier: TIERS.MODERN, algorithms: ['ChaCha20-Poly1305', 'XChaCha20-Poly1305'], note: 'Audited AEAD, RFC 8439 (RustCrypto)' },
  { name: 'aes',                tier: TIERS.MODERN, algorithms: ['AES-128', 'AES-256'],                    note: 'AES block cipher with HW accel (RustCrypto)' },
  { name: 'chacha20',           tier: TIERS.MODERN, algorithms: ['ChaCha20', 'XChaCha20'],                 note: 'Stream cipher (RustCrypto)' },
  { name: 'sha2',               tier: TIERS.MODERN, algorithms: ['SHA-256', 'SHA-384', 'SHA-512'],          note: 'NIST hash family (RustCrypto)' },
  { name: 'sha3',               tier: TIERS.MODERN, algorithms: ['SHA3-256', 'SHA3-512', 'SHAKE'],          note: 'Keccak-based hash (RustCrypto)' },
  { name: 'blake2',             tier: TIERS.MODERN, algorithms: ['BLAKE2b', 'BLAKE2s'],                    note: 'Fast secure hash, RFC 7693 (RustCrypto)' },
  { name: 'blake3',             tier: TIERS.MODERN, algorithms: ['BLAKE3'],                                note: 'Fastest secure hash (official crate)' },
  { name: 'hmac',               tier: TIERS.MODERN, algorithms: ['HMAC'],                                  note: 'HMAC authentication (RustCrypto)' },
  { name: 'hkdf',               tier: TIERS.MODERN, algorithms: ['HKDF'],                                  note: 'RFC 5869 KDF (RustCrypto)' },
  { name: 'argon2',             tier: TIERS.MODERN, algorithms: ['Argon2id', 'Argon2i'],                   note: 'PHC winner password hash (RustCrypto)' },
  { name: 'bcrypt',             tier: TIERS.MODERN, algorithms: ['bcrypt'],                                note: 'Password hashing (RustCrypto)' },
  { name: 'scrypt',             tier: TIERS.MODERN, algorithms: ['scrypt'],                                note: 'Memory-hard KDF (RustCrypto)' },
  { name: 'pbkdf2',             tier: TIERS.MODERN, algorithms: ['PBKDF2'],                                note: 'Password KDF, RFC 2898 (RustCrypto)' },
  { name: 'ed25519-dalek',      tier: TIERS.MODERN, algorithms: ['Ed25519'],                               note: 'Fast Ed25519, audited (dalek-cryptography)' },
  { name: 'x25519-dalek',       tier: TIERS.MODERN, algorithms: ['X25519'],                                note: 'X25519 ECDH, audited (dalek-cryptography)' },
  { name: 'curve25519-dalek',   tier: TIERS.MODERN, algorithms: ['Curve25519', 'Ristretto255'],            note: 'Group operations, audited (dalek-cryptography)' },
  { name: 'rsa',                tier: TIERS.MODERN, algorithms: ['RSA-OAEP', 'RSA-PSS'],                  note: 'Pure Rust RSA, audited (RustCrypto)' },
  { name: 'p256',               tier: TIERS.MODERN, algorithms: ['NIST P-256', 'ECDSA', 'ECDH'],          note: 'secp256r1 (RustCrypto)' },
  { name: 'p384',               tier: TIERS.MODERN, algorithms: ['NIST P-384', 'ECDSA', 'ECDH'],          note: 'secp384r1 (RustCrypto)' },
  { name: 'k256',               tier: TIERS.MODERN, algorithms: ['secp256k1', 'ECDSA'],                   note: 'Bitcoin/Ethereum curve, audited (RustCrypto)' },
  { name: 'ecdsa',              tier: TIERS.MODERN, algorithms: ['ECDSA'],                                 note: 'ECDSA signing/verification (RustCrypto)' },
  { name: 'orion',              tier: TIERS.MODERN, algorithms: ['ChaCha20-Poly1305', 'BLAKE2b', 'Argon2i', 'X25519'], note: 'Pure Rust easy-to-use crypto' },
  { name: 'dryoc',              tier: TIERS.MODERN, algorithms: ['X25519', 'XSalsa20-Poly1305', 'Ed25519'], note: 'Pure Rust libsodium-compatible' },
  { name: 'snow',               tier: TIERS.MODERN, algorithms: ['Noise', 'X25519', 'ChaCha20-Poly1305'], note: 'Noise Protocol Framework' },
  { name: 'jsonwebtoken',       tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'EdDSA', 'HS256'],     note: 'JWT for Rust' },
  { name: 'sequoia-openpgp',    tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'Ed25519', 'AES'],       note: 'Full OpenPGP (RFC 9580)' },
  { name: 'rcgen',              tier: TIERS.MODERN, algorithms: ['X.509', 'ECDSA', 'Ed25519', 'RSA'],     note: 'X.509 certificate generation' },
  { name: 'subtle',             tier: TIERS.MODERN, algorithms: ['constant-time'],                         note: 'Constant-time ops (dalek-cryptography)' },
  { name: 'zeroize',            tier: TIERS.MODERN, algorithms: ['memory zeroing'],                        note: 'Secure memory zeroing (RustCrypto)' },
  { name: 'crypto-bigint',      tier: TIERS.MODERN, algorithms: ['big integer'],                           note: 'Constant-time bignum (RustCrypto, audited)' },
  { name: 'cryptoki',           tier: TIERS.MODERN, algorithms: ['PKCS#11'],                               note: 'HSM interface' },

  // --- pqc ---
  { name: 'ml-kem',                    tier: TIERS.PQC, algorithms: ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'], note: 'FIPS 203 pure Rust (RustCrypto)' },
  { name: 'ml-dsa',                    tier: TIERS.PQC, algorithms: ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'], note: 'FIPS 204 pure Rust (RustCrypto)' },
  { name: 'slh-dsa',                   tier: TIERS.PQC, algorithms: ['SLH-DSA'],                            note: 'FIPS 205 pure Rust (RustCrypto)' },
  { name: 'pqcrypto',                  tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA', 'SPHINCS+'],      note: 'Meta-crate, wraps PQClean C' },
  { name: 'pqcrypto-kyber',            tier: TIERS.PQC, algorithms: ['Kyber/ML-KEM'],                      note: 'Kyber KEM (PQClean wrapper)' },
  { name: 'pqcrypto-dilithium',        tier: TIERS.PQC, algorithms: ['Dilithium/ML-DSA'],                  note: 'Dilithium signatures (PQClean wrapper)' },
  { name: 'pqcrypto-sphincsplus',      tier: TIERS.PQC, algorithms: ['SPHINCS+/SLH-DSA'],                  note: 'Hash-based signatures (PQClean wrapper)' },
  { name: 'pqcrypto-classicmceliece',  tier: TIERS.PQC, algorithms: ['Classic McEliece'],                  note: 'Code-based KEM' },
  { name: 'oqs',                       tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA', 'Falcon'],        note: 'OQS Rust wrapper' },
  { name: 'quantcrypt',               tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA'],       note: 'High-level PQC with X.509 integration' },
];

// =========================================================================
// Packagist (PHP)
// =========================================================================

/** @type {import('./types').CatalogEntry[]} */
export const PACKAGIST_PACKAGES = [
  // --- weak ---
  { name: 'paragonie/random_compat',     tier: TIERS.WEAK, algorithms: ['CSPRNG'],                     note: 'PHP 5.x polyfill; obsolete on PHP 7+' },
  { name: 'ircmaxell/password-compat',   tier: TIERS.WEAK, algorithms: ['bcrypt'],                     note: 'PHP 5.3/5.4 polyfill; obsolete on PHP 7+' },
  { name: 'phpseclib/mcrypt_compat',     tier: TIERS.WEAK, algorithms: ['DES', 'Blowfish', '3DES', 'RC4'], note: 'Polyfill for removed ext-mcrypt' },
  { name: 'namshi/jose',                 tier: TIERS.WEAK, algorithms: ['JWT', 'HS256', 'RS256'],      note: 'Last release 2018; CVEs for alg confusion' },
  { name: 'gree/jose',                   tier: TIERS.WEAK, algorithms: ['JWT'],                        note: 'Abandoned by maintainer' },
  { name: 'mdanter/ecc',                 tier: TIERS.WEAK, algorithms: ['ECDSA', 'ECDH'],              note: 'Abandoned; superseded by paragonie/ecc' },
  { name: 'laminas/laminas-crypt',       tier: TIERS.WEAK, algorithms: ['AES-CBC', 'RSA', 'bcrypt'],   note: 'Marked abandoned by Laminas' },
  { name: 'bordoni/phpass',              tier: TIERS.WEAK, algorithms: ['bcrypt'],                     note: 'Portable phpass; deprecated API' },
  { name: 'ircmaxell/random-lib',        tier: TIERS.WEAK, algorithms: ['CSPRNG'],                     note: 'Pre-PHP-7 random library' },

  // --- modern ---
  { name: 'phpseclib/phpseclib',         tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'Ed25519', 'AES-GCM', 'ChaCha20'], note: 'Pure-PHP crypto; use v3.0.36+' },
  { name: 'defuse/php-encryption',       tier: TIERS.MODERN, algorithms: ['AES-256-CTR', 'HMAC-SHA256'],  note: 'Audited symmetric encryption; zero CVEs' },
  { name: 'paragonie/sodium_compat',     tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519', 'ChaCha20-Poly1305'], note: 'libsodium polyfill' },
  { name: 'paragonie/halite',            tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519', 'ChaCha20-Poly1305', 'Argon2id'], note: 'Misuse-resistant API over libsodium' },
  { name: 'firebase/php-jwt',            tier: TIERS.MODERN, algorithms: ['HS256', 'RS256', 'ES256', 'EdDSA'], note: 'Most-downloaded PHP JWT; use v7.0+' },
  { name: 'lcobucci/jwt',                tier: TIERS.MODERN, algorithms: ['HS256', 'RS256', 'ES256', 'EdDSA'], note: 'Strict JWT; use v5.x' },
  { name: 'web-token/jwt-framework',     tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'EdDSA', 'AES-GCM', 'ECDH-ES'], note: 'Full JOSE/JWE/JWS' },
  { name: 'symfony/password-hasher',     tier: TIERS.MODERN, algorithms: ['bcrypt', 'Argon2id'],       note: 'Symfony password hasher' },
  { name: 'illuminate/hashing',          tier: TIERS.MODERN, algorithms: ['bcrypt', 'Argon2id'],       note: 'Laravel hashing' },
  { name: 'paragonie/paseto',            tier: TIERS.MODERN, algorithms: ['Ed25519', 'XChaCha20-Poly1305'], note: 'PASETO v4; preferred over JWT' },
  { name: 'spomky-labs/pki-framework',   tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'Ed25519', 'X.509'], note: 'Comprehensive PHP PKI' },
  { name: 'paragonie/ciphersweet',       tier: TIERS.MODERN, algorithms: ['AES-256-CTR', 'XChaCha20-Poly1305'], note: 'Searchable field-level encryption' },

  // --- pqc ---
  { name: 'secudoc/php-liboqs',          tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA'], note: 'PHP C extension wrapping liboqs; experimental' },
];

// =========================================================================
// NuGet (.NET / C#)
// =========================================================================

/** @type {import('./types').CatalogEntry[]} */
export const NUGET_PACKAGES = [
  // --- weak ---
  { name: 'Portable.BouncyCastle',         tier: TIERS.WEAK, algorithms: ['AES', 'RSA', 'DES'],       note: 'EOL since 2021; superseded by BouncyCastle.Cryptography' },
  { name: 'BouncyCastle.NetCore',           tier: TIERS.WEAK, algorithms: ['AES', 'RSA'],              note: 'Unofficial, unmaintained since 2022' },
  { name: 'BouncyCastle',                   tier: TIERS.WEAK, algorithms: ['AES', 'RSA'],              note: 'Original namespaced package, EOL' },
  { name: 'Microsoft.Owin.Security.Jwt',    tier: TIERS.WEAK, algorithms: ['JWT', 'RS256'],            note: 'OWIN-era; no ECDSA/EdDSA' },
  { name: 'Microsoft.Azure.KeyVault',       tier: TIERS.WEAK, algorithms: ['RSA', 'AES'],              note: 'Deprecated v1 SDK; use Azure.Security.KeyVault.*' },
  { name: 'DotNetOpenAuth.Core',            tier: TIERS.WEAK, algorithms: ['RSA', 'HMAC'],             note: 'Archived, unmaintained since 2015' },
  { name: 'CryptSharpOfficial',             tier: TIERS.WEAK, algorithms: ['SCrypt', 'MD5-crypt'],     note: 'Legacy crypt implementations' },
  { name: 'CryptoHelper',                   tier: TIERS.WEAK, algorithms: ['bcrypt'],                  note: 'Unmaintained since 2020' },

  // --- modern ---
  { name: 'BouncyCastle.Cryptography',      tier: TIERS.MODERN, algorithms: ['AES-GCM', 'ChaCha20-Poly1305', 'Ed25519', 'X25519', 'TLS 1.3'], note: 'Official BC .NET; actively maintained' },
  { name: 'System.IdentityModel.Tokens.Jwt', tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'HS256'], note: 'Microsoft JWT library' },
  { name: 'Microsoft.IdentityModel.Tokens', tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'EdDSA'], note: 'Token validation infrastructure' },
  { name: 'Microsoft.AspNetCore.DataProtection', tier: TIERS.MODERN, algorithms: ['AES-256-CBC', 'HMAC-SHA256'], note: 'ASP.NET Core data protection' },
  { name: 'BCrypt.Net-Next',                tier: TIERS.MODERN, algorithms: ['bcrypt'],                note: 'Well-maintained bcrypt' },
  { name: 'Konscious.Security.Cryptography.Argon2', tier: TIERS.MODERN, algorithms: ['Argon2id', 'Argon2i'], note: 'Pure C# Argon2' },
  { name: 'Isopoh.Cryptography.Argon2',     tier: TIERS.MODERN, algorithms: ['Argon2'],               note: 'Argon2 with memory security' },
  { name: 'NSec.Cryptography',              tier: TIERS.MODERN, algorithms: ['Ed25519', 'X25519', 'AES-256-GCM', 'ChaCha20-Poly1305'], note: 'Modern .NET 8+ libsodium API' },
  { name: 'libsodium',                      tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519', 'ChaCha20-Poly1305'], note: 'Native libsodium binaries' },
  { name: 'NaCl.Net',                       tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519', 'XSalsa20-Poly1305'], note: 'libsodium .NET bindings' },
  { name: 'Sodium.Core',                    tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519'],     note: 'libsodium managed wrapper' },
  { name: 'JWT',                             tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'HS256', 'PS256'], note: 'Lightweight JWT' },
  { name: 'jose-jwt',                       tier: TIERS.MODERN, algorithms: ['JWS', 'JWE', 'AES-GCM', 'ECDH-ES', 'EdDSA'], note: 'Full JOSE' },
  { name: 'Azure.Security.KeyVault.Keys',   tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'AES-GCM'], note: 'Azure KV keys' },
  { name: 'AWSSDK.KeyManagementService',    tier: TIERS.MODERN, algorithms: ['AES-256', 'RSA', 'ECDSA'], note: 'AWS KMS .NET SDK' },
  { name: 'MimeKit',                        tier: TIERS.MODERN, algorithms: ['S/MIME', 'RSA-OAEP', 'AES-GCM', 'EdDSA'], note: 'S/MIME and OpenPGP' },
  { name: 'Pkcs11Interop',                  tier: TIERS.MODERN, algorithms: ['PKCS#11'],               note: 'HSM interface' },
  { name: 'Inferno',                        tier: TIERS.MODERN, algorithms: ['AES-CBC', 'HMAC-SHA2'],  note: 'SuiteB authenticated encryption' },

  // --- pqc ---
  { name: 'BouncyCastle.Cryptography',      tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'NTRU', 'FrodoKEM'], note: 'BC PQC suite since v2.0' },
  { name: 'LibOQS.NET',                     tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA', 'Falcon', 'SPHINCS+'], note: 'OQS .NET wrapper' },
];

// =========================================================================
// RubyGems (Ruby)
// =========================================================================

/** @type {import('./types').CatalogEntry[]} */
export const RUBYGEMS_PACKAGES = [
  // --- weak ---
  { name: 'digest',              tier: TIERS.WEAK, algorithms: ['MD5', 'SHA-1'],               note: 'Stdlib; Digest::MD5 and Digest::SHA1 widely used' },
  { name: 'digest-crc',          tier: TIERS.WEAK, algorithms: ['CRC32', 'CRC16'],             note: 'CRC checksums, not cryptographic' },
  { name: 'crypt',               tier: TIERS.WEAK, algorithms: ['DES-crypt', 'MD5-crypt'],     note: 'Unix crypt() wrapper, legacy password hashing' },
  { name: 'fast-aes',            tier: TIERS.WEAK, algorithms: ['AES-ECB'],                    note: 'AES in ECB mode only, no IV, no authentication' },
  { name: 'gibberish',           tier: TIERS.WEAK, algorithms: ['AES-256-CBC', 'SHA-1'],       note: 'Uses SHA-1 for key derivation' },
  { name: 'ezcrypto',            tier: TIERS.WEAK, algorithms: ['Blowfish', 'DES'],            note: 'Unmaintained since 2009' },
  { name: 'crypt19',             tier: TIERS.WEAK, algorithms: ['Blowfish', 'GOST'],           note: 'Legacy ciphers, unmaintained' },
  { name: 'gpgme',               tier: TIERS.WEAK, algorithms: ['RSA', 'DSA', 'CAST5'],        note: 'GnuPG bindings, often uses legacy defaults' },

  // --- modern ---
  { name: 'openssl',             tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA', 'ECDSA', 'Ed25519', 'ChaCha20-Poly1305'], note: 'Ruby stdlib OpenSSL bindings' },
  { name: 'bcrypt',              tier: TIERS.MODERN, algorithms: ['bcrypt'],                    note: 'OpenBSD bcrypt password hashing' },
  { name: 'argon2',              tier: TIERS.MODERN, algorithms: ['Argon2id', 'Argon2i'],       note: 'PHC winner password hashing' },
  { name: 'scrypt',              tier: TIERS.MODERN, algorithms: ['scrypt'],                    note: 'Memory-hard KDF' },
  { name: 'rbnacl',              tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519', 'XSalsa20-Poly1305', 'ChaCha20-Poly1305', 'BLAKE2b'], note: 'libsodium FFI bindings' },
  { name: 'ed25519',             tier: TIERS.MODERN, algorithms: ['Ed25519'],                   note: 'Ed25519 digital signatures' },
  { name: 'x25519',              tier: TIERS.MODERN, algorithms: ['X25519'],                    note: 'X25519 Diffie-Hellman key exchange' },
  { name: 'lockbox',             tier: TIERS.MODERN, algorithms: ['AES-256-GCM'],               note: 'Modern encryption for Ruby/Rails' },
  { name: 'attr_encrypted',      tier: TIERS.MODERN, algorithms: ['AES-256-GCM'],               note: 'ActiveRecord attribute encryption' },
  { name: 'symmetric-encryption', tier: TIERS.MODERN, algorithms: ['AES-256-CBC', 'AES-256-GCM'], note: 'Enterprise symmetric encryption for Rails' },
  { name: 'encryptor',           tier: TIERS.MODERN, algorithms: ['AES-256-GCM'],               note: 'Simple OpenSSL cipher wrapper' },
  { name: 'jwt',                 tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'HS256'],   note: 'Ruby JWT implementation' },
  { name: 'json-jwt',            tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'EdDSA'],   note: 'JSON JWT/JWS/JWE for Ruby' },
  { name: 'jose',                tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'EdDSA', 'AES-GCM'], note: 'JOSE/JWT standards library' },
  { name: 'rotp',                tier: TIERS.MODERN, algorithms: ['HMAC-SHA1', 'TOTP', 'HOTP'], note: 'RFC 6238/4226 one-time passwords' },
  { name: 'net-ssh',             tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'Ed25519', 'ChaCha20-Poly1305'], note: 'SSH protocol implementation' },
  { name: 'digest-sha3',         tier: TIERS.MODERN, algorithms: ['SHA-3', 'Keccak'],           note: 'SHA-3 hash function' },
  { name: 'fernet',              tier: TIERS.MODERN, algorithms: ['AES-128-CBC', 'HMAC-SHA256'], note: 'Fernet symmetric encryption' },

  // --- pqc ---
  { name: 'liboqs',              tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'Falcon'], note: 'Open Quantum Safe Ruby bindings' },
];

// =========================================================================
// Hex (Elixir/Erlang)
// =========================================================================

/** @type {import('./types').CatalogEntry[]} */
export const HEX_PACKAGES = [
  // --- weak ---
  { name: 'cipher',             tier: TIERS.WEAK, algorithms: ['AES-256-CBC', 'MD5'],         note: 'Uses MD5 for key derivation' },
  { name: 'crypto',             tier: TIERS.WEAK, algorithms: ['DES', 'RC4', 'MD5'],          note: 'Erlang stdlib with access to weak algorithms' },
  { name: 'keccakf1600',        tier: TIERS.WEAK, algorithms: ['Keccak-f1600'],               note: 'Low-level Keccak permutation NIF' },

  // --- modern ---
  { name: 'comeonin',           tier: TIERS.MODERN, algorithms: ['bcrypt', 'Argon2', 'Pbkdf2'], note: 'Password hashing behaviour' },
  { name: 'bcrypt_elixir',      tier: TIERS.MODERN, algorithms: ['bcrypt'],                    note: 'Bcrypt password hashing' },
  { name: 'argon2_elixir',      tier: TIERS.MODERN, algorithms: ['Argon2id', 'Argon2i'],       note: 'PHC winner password hashing' },
  { name: 'pbkdf2_elixir',      tier: TIERS.MODERN, algorithms: ['PBKDF2-SHA512'],             note: 'PBKDF2 password hashing' },
  { name: 'plug_crypto',        tier: TIERS.MODERN, algorithms: ['AES-GCM', 'HMAC', 'SHA-256'], note: 'Crypto utilities for Plug/Phoenix' },
  { name: 'ex_crypto',          tier: TIERS.MODERN, algorithms: ['AES-GCM', 'AES-CBC', 'RSA'], note: 'Wrapper around Erlang :crypto' },
  { name: 'cloak',              tier: TIERS.MODERN, algorithms: ['AES-GCM', 'AES-CTR'],        note: 'Encryption library, pluggable ciphers' },
  { name: 'cloak_ecto',         tier: TIERS.MODERN, algorithms: ['AES-GCM', 'AES-CTR'],        note: 'Ecto types for field encryption via Cloak' },
  { name: 'enacl',              tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519', 'XSalsa20-Poly1305', 'ChaCha20-Poly1305'], note: 'NIF bindings to libsodium' },
  { name: 'salty',              tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519', 'XSalsa20-Poly1305'], note: 'NIF bindings to libsodium' },
  { name: 'jose',               tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'EdDSA', 'AES-GCM'], note: 'JOSE/JWT/JWS/JWE for Erlang and Elixir' },
  { name: 'joken',              tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'HS256'],   note: 'JWT token utility' },
  { name: 'guardian',           tier: TIERS.MODERN, algorithms: ['HS256', 'RS256', 'ES256'],   note: 'Token-based auth for Phoenix' },
  { name: 'x509',               tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'X.509'],     note: 'X.509 certificate handling' },
  { name: 'ex_sha3',            tier: TIERS.MODERN, algorithms: ['SHA-3', 'Keccak'],           note: 'Pure Elixir SHA-3' },
  { name: 'nimble_totp',        tier: TIERS.MODERN, algorithms: ['HMAC-SHA1', 'TOTP'],         note: 'TOTP for 2FA' },
  { name: 'curve25519',         tier: TIERS.MODERN, algorithms: ['Curve25519'],                note: 'Curve25519 Diffie-Hellman' },

  // --- pqc ---
  { name: 'pqclean',            tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'Classic McEliece'], note: 'PQClean NIF bindings' },
  { name: 'ex_tholos_pq',       tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA'],            note: 'Elixir NIF bindings for PQC' },
];

// =========================================================================
// pub.dev (Dart/Flutter)
// =========================================================================

/** @type {import('./types').CatalogEntry[]} */
export const PUB_PACKAGES = [
  // --- weak ---
  { name: 'crypto',             tier: TIERS.WEAK, algorithms: ['MD5', 'SHA-1', 'SHA-256', 'HMAC'], note: 'Dart team package; includes MD5/SHA-1' },
  { name: 'crypto_dart',        tier: TIERS.WEAK, algorithms: ['MD5', 'SHA-1', 'AES-CBC'],    note: 'CryptoJS-like API, includes weak algorithms' },
  { name: 'md5_plugin',         tier: TIERS.WEAK, algorithms: ['MD5'],                        note: 'MD5 hash only, collision-broken' },
  { name: 'sha1',               tier: TIERS.WEAK, algorithms: ['SHA-1'],                      note: 'SHA-1 only, collision-broken' },

  // --- modern ---
  { name: 'cryptography',       tier: TIERS.MODERN, algorithms: ['AES-GCM', 'ChaCha20', 'Ed25519', 'X25519', 'Argon2id', 'BLAKE2'], note: 'Comprehensive cross-platform crypto' },
  { name: 'cryptography_flutter', tier: TIERS.MODERN, algorithms: ['AES-GCM', 'ChaCha20', 'Ed25519', 'X25519'], note: 'Flutter plugin for OS crypto APIs' },
  { name: 'pointycastle',       tier: TIERS.MODERN, algorithms: ['AES', 'RSA', 'ECDSA', 'SHA-256', 'SHA-3', 'ChaCha20'], note: 'BouncyCastle port for Dart' },
  { name: 'encrypt',            tier: TIERS.MODERN, algorithms: ['AES-CBC', 'AES-GCM', 'RSA', 'Salsa20'], note: 'High-level API over PointyCastle' },
  { name: 'webcrypto',          tier: TIERS.MODERN, algorithms: ['AES-GCM', 'AES-CTR', 'RSA-OAEP', 'ECDSA', 'ECDH', 'HMAC'], note: 'Web Crypto API on all platforms' },
  { name: 'fast_rsa',           tier: TIERS.MODERN, algorithms: ['RSA-OAEP', 'RSA-PKCS1v15', 'RSA-PSS'], note: 'Native RSA operations' },
  { name: 'steel_crypt',        tier: TIERS.MODERN, algorithms: ['AES', 'ChaCha20', 'SHA-256', 'HMAC'], note: 'High-level crypto APIs' },
  { name: 'pinenacl',           tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519', 'XSalsa20-Poly1305', 'BLAKE2b'], note: 'TweetNaCl Dart port' },
  { name: 'hashlib',            tier: TIERS.MODERN, algorithms: ['SHA-256', 'SHA-3', 'BLAKE2', 'Argon2', 'bcrypt', 'scrypt'], note: 'Optimized hash and KDF library' },
  { name: 'basic_utils',        tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'X.509'],     note: 'Key parsing, CSR generation, X.509' },
  { name: 'dart_jsonwebtoken',  tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'HS256', 'EdDSA'], note: 'JWT for Dart' },
  { name: 'jose',               tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'EdDSA', 'AES-GCM'], note: 'JOSE/JWS/JWE/JWK for Dart' },
  { name: 'sodium_libs',        tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519', 'ChaCha20-Poly1305', 'Argon2id'], note: 'FFI bindings to native libsodium' },

  // --- pqc ---
  { name: 'pqcrypto',           tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA'],            note: 'Pure Dart NIST PQC' },
  { name: 'xkyber_crypto',      tier: TIERS.PQC, algorithms: ['Kyber/ML-KEM'],                note: 'Kyber KEM for Dart' },
  { name: 'custom_post_quantum', tier: TIERS.PQC, algorithms: ['Kyber/ML-KEM', 'Dilithium/ML-DSA'], note: 'Dart NIST PQC candidates' },
];

// =========================================================================
// CocoaPods (Swift/Objective-C)
// =========================================================================

/** @type {import('./types').CatalogEntry[]} */
export const COCOAPODS_PACKAGES = [
  // --- weak ---
  { name: 'OpenSSL',              tier: TIERS.WEAK, algorithms: ['RSA', 'DES', 'RC4', 'MD5'],     note: 'Deprecated by Apple, bundles weak ciphers' },
  { name: 'OpenSSL-Universal',    tier: TIERS.WEAK, algorithms: ['RSA', 'DES', 'RC4', 'MD5'],     note: 'Universal OpenSSL build, legacy algorithms' },
  { name: 'AESCrypt-ObjC',       tier: TIERS.WEAK, algorithms: ['AES-256-CBC'],                   note: 'AES-CBC without authentication' },
  { name: 'Arcane',              tier: TIERS.WEAK, algorithms: ['MD5', 'SHA-1', 'AES-CBC', 'HMAC'], note: 'CommonCrypto wrapper; exposes MD5, SHA-1' },
  { name: 'CommonCryptoSwift',   tier: TIERS.WEAK, algorithms: ['DES', '3DES', 'MD5', 'SHA-1', 'AES-CBC'], note: 'CommonCrypto Swift wrapper' },

  // --- modern ---
  { name: 'CryptoSwift',         tier: TIERS.MODERN, algorithms: ['AES', 'ChaCha20', 'Poly1305', 'RSA', 'PBKDF2', 'scrypt', 'HMAC', 'BLAKE2'], note: 'Pure Swift comprehensive crypto' },
  { name: 'IDZSwiftCommonCrypto', tier: TIERS.MODERN, algorithms: ['AES', 'SHA-256', 'SHA-512', 'HMAC'], note: 'Swift wrapper for CommonCrypto' },
  { name: 'SCrypto',             tier: TIERS.MODERN, algorithms: ['SHA-256', 'HMAC', 'PBKDF2', 'AES'], note: 'CommonCrypto digest/HMAC/AES extensions' },
  { name: 'SwCrypt',             tier: TIERS.MODERN, algorithms: ['RSA', 'AES', 'ECDSA'],         note: 'RSA key gen, AES via CommonCrypto' },
  { name: 'SwiftyRSA',           tier: TIERS.MODERN, algorithms: ['RSA-OAEP', 'RSA-PKCS1v15'],    note: 'RSA encryption and signing' },
  { name: 'Sodium',              tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519', 'ChaCha20-Poly1305', 'Argon2id', 'BLAKE2b'], note: 'Swift libsodium bindings' },
  { name: 'TweetNacl',           tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519', 'XSalsa20-Poly1305'], note: 'TweetNaCl Swift port' },
  { name: 'RNCryptor',           tier: TIERS.MODERN, algorithms: ['AES-256-CBC', 'HMAC-SHA256', 'PBKDF2'], note: 'Cross-platform AES encryption' },
  { name: 'themis',              tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA', 'ECDSA', 'Ed25519'], note: 'Cossack Labs data security' },
  { name: 'ObjectivePGP',        tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'Ed25519', 'AES'], note: 'OpenPGP for iOS/macOS' },
  { name: 'JOSESwift',           tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'AES-GCM', 'ECDH-ES'], note: 'JOSE/JWS/JWE/JWK framework' },
  { name: 'BlueRSA',             tier: TIERS.MODERN, algorithms: ['RSA-OAEP', 'RSA-PSS'],         note: 'IBM Kitura RSA' },
  { name: 'BlueCryptor',         tier: TIERS.MODERN, algorithms: ['AES', 'SHA-256', 'SHA-512', 'HMAC'], note: 'IBM Kitura CommonCrypto wrapper' },
  { name: 'Tink',                tier: TIERS.MODERN, algorithms: ['AES-GCM', 'ECDSA', 'Ed25519'], note: 'Google Tink for iOS' },

  // --- pqc ---
  { name: 'liboqs',              tier: TIERS.PQC, algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'Falcon'], note: 'Open Quantum Safe via bridging header' },
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
