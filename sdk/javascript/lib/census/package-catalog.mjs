/**
 * Static classification of cryptographic packages across npm, PyPI, and Maven ecosystems.
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

/** @type {CatalogEntry[]} */
export const MAVEN_PACKAGES = [
  // =========================================================================
  // WEAK - Broken, deprecated, or quantum-vulnerable primitives
  // =========================================================================

  // --- Deprecated/legacy JCA providers ---
  { name: 'org.bouncycastle:bcprov-jdk15on',           tier: TIERS.WEAK, algorithms: ['AES', 'RSA', 'DES', '3DES'],         note: 'Superseded by jdk18on; no longer maintained' },
  { name: 'org.bouncycastle:bcprov-jdk16',              tier: TIERS.WEAK, algorithms: ['AES', 'RSA', 'DES'],                 note: 'Legacy JDK 1.6 build, unmaintained' },
  { name: 'org.bouncycastle:bcprov-jdk14',              tier: TIERS.WEAK, algorithms: ['AES', 'RSA', 'DES'],                 note: 'Legacy JDK 1.4 build, unmaintained' },
  { name: 'org.bouncycastle:bcpkix-jdk15on',            tier: TIERS.WEAK, algorithms: ['RSA', 'ECDSA', 'X.509'],             note: 'Superseded by jdk18on; no longer maintained' },
  { name: 'org.bouncycastle:bcpg-jdk15on',              tier: TIERS.WEAK, algorithms: ['RSA', 'DSA', 'ElGamal'],             note: 'Legacy OpenPGP build, superseded by jdk18on' },
  { name: 'com.madgag.spongycastle:core',               tier: TIERS.WEAK, algorithms: ['AES', 'RSA', 'DES'],                 note: 'BouncyCastle Android fork, deprecated since Android API 28+' },
  { name: 'com.madgag.spongycastle:prov',               tier: TIERS.WEAK, algorithms: ['AES', 'RSA', 'DES'],                 note: 'BouncyCastle Android fork, deprecated' },

  // --- Deprecated standalone crypto libs ---
  { name: 'org.jasypt:jasypt',                          tier: TIERS.WEAK, algorithms: ['PBE', 'DES', 'MD5'],                 note: 'Defaults to PBEWithMD5AndDES, unmaintained since 2014' },
  { name: 'org.jasypt:jasypt-spring31',                 tier: TIERS.WEAK, algorithms: ['PBE', 'DES', 'MD5'],                 note: 'Spring 3.1 integration of jasypt, inherits weak defaults' },
  { name: 'org.keyczar:keyczar',                        tier: TIERS.WEAK, algorithms: ['AES', 'RSA', 'DSA', 'HMAC'],         note: 'Google Keyczar deprecated, archived project' },
  { name: 'com.offbytwo.keyczar:keyczar',               tier: TIERS.WEAK, algorithms: ['AES', 'RSA', 'DSA'],                 note: 'Keyczar community fork, no longer maintained' },

  // --- Libraries exposing MD5/SHA-1/DES as primary purpose ---
  { name: 'commons-codec:commons-codec',                tier: TIERS.WEAK, algorithms: ['MD5', 'SHA-1', 'SHA-256'],           note: 'DigestUtils.md5Hex/sha1Hex widely used for weak hashing' },
  { name: 'com.google.guava:guava',                     tier: TIERS.WEAK, algorithms: ['MD5', 'SHA-1', 'SHA-256'],           note: 'Hashing.md5()/sha1() convenience methods encourage weak use' },
  { name: 'org.apache.commons:commons-crypto',          tier: TIERS.WEAK, algorithms: ['AES-CTR', 'AES-CBC'],                note: 'AES-NI optimized but no AEAD modes, no GCM support' },

  // --- JWT/JOSE with weak algorithm support or unmaintained ---
  { name: 'io.jsonwebtoken:jjwt',                       tier: TIERS.WEAK, algorithms: ['HS256', 'RS256'],                    note: 'Legacy monolithic artifact, replaced by jjwt-api/jjwt-impl' },

  // --- XML crypto with legacy algorithm defaults ---
  { name: 'org.apache.santuario:xmlsec',                tier: TIERS.WEAK, algorithms: ['RSA', 'SHA-1', 'DSA', 'XML-DSIG'],   note: 'XML-DSIG defaults to SHA-1 signatures' },
  { name: 'org.apache.wss4j:wss4j-ws-security-common',  tier: TIERS.WEAK, algorithms: ['RSA', 'SHA-1', 'AES-CBC', 'XML-ENC'], note: 'WS-Security defaults to SHA-1 and AES-CBC' },
  { name: 'org.apache.wss4j:wss4j-ws-security-dom',     tier: TIERS.WEAK, algorithms: ['RSA', 'SHA-1', 'AES-CBC'],           note: 'WS-Security DOM processing with legacy defaults' },

  // --- Deprecated / EOL security libs ---
  { name: 'org.owasp.esapi:esapi',                     tier: TIERS.WEAK, algorithms: ['AES-CBC', 'SHA-1', 'HMAC'],           note: 'Legacy OWASP ESAPI, known CVEs, deprecated crypto module' },

  // =========================================================================
  // MODERN - Current-generation crypto, secure against classical attacks
  // =========================================================================

  // --- JCA/JCE providers ---
  { name: 'org.bouncycastle:bcprov-jdk18on',            tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA', 'ECDSA', 'Ed25519', 'ChaCha20-Poly1305'], note: 'Comprehensive JCA provider, actively maintained' },
  { name: 'org.bouncycastle:bcpkix-jdk18on',            tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'Ed25519', 'X.509', 'CMS'],                  note: 'PKI operations: certs, CMS, OCSP, TSP' },
  { name: 'org.bouncycastle:bcutil-jdk18on',             tier: TIERS.MODERN, algorithms: ['ASN.1', 'PEM'],                                             note: 'ASN.1 and utility APIs for bcpkix/bctls' },
  { name: 'org.bouncycastle:bctls-jdk18on',              tier: TIERS.MODERN, algorithms: ['TLS 1.3', 'TLS 1.2', 'ECDHE', 'AES-GCM'],                  note: 'BC JSSE TLS provider with modern cipher suites' },
  { name: 'org.bouncycastle:bcjmail-jdk18on',            tier: TIERS.MODERN, algorithms: ['S/MIME', 'AES', 'RSA', 'ECDSA'],                            note: 'S/MIME with Jakarta Mail APIs' },
  { name: 'org.bouncycastle:bcpg-jdk18on',              tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'Ed25519', 'AES', 'OpenPGP'],                note: 'OpenPGP implementation with modern algorithms' },
  { name: 'org.conscrypt:conscrypt-openjdk',             tier: TIERS.MODERN, algorithms: ['TLS 1.3', 'AES-GCM', 'ChaCha20-Poly1305', 'ECDHE'],        note: 'Google/Android SSL provider backed by BoringSSL' },
  { name: 'software.amazon.cryptools:AmazonCorrettoCryptoProvider', tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA', 'ECDSA', 'SHA-256', 'HKDF'],   note: 'AWS high-performance JCA provider backed by AWS-LC' },
  { name: 'software.amazon.cryptools:AmazonCorrettoCryptoProvider-FIPS', tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA', 'ECDSA', 'SHA-256'],      note: 'FIPS 140-3 validated variant of ACCP' },
  { name: 'com.wolfssl:wolfcrypt-jni',                   tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA', 'ECC', 'SHA-256', 'ChaCha20'],            note: 'wolfSSL JCE provider, FIPS 140-3 capable' },
  { name: 'com.wolfssl:wolfssl-jsse',                    tier: TIERS.MODERN, algorithms: ['TLS 1.3', 'AES-GCM', 'ECDHE', 'ChaCha20-Poly1305'],       note: 'wolfSSL JSSE provider, TLS 1.3 support' },

  // --- Standalone crypto libraries ---
  { name: 'com.google.crypto.tink:tink',                tier: TIERS.MODERN, algorithms: ['AES-GCM', 'AES-SIV', 'ECDSA', 'Ed25519', 'HKDF'],          note: 'Google Tink: misuse-resistant crypto API' },
  { name: 'com.goterl.lazycode:lazysodium-java',        tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519', 'ChaCha20-Poly1305', 'XSalsa20'],      note: 'libsodium JNA wrapper for Java' },
  { name: 'org.signal:libsignal-client',                 tier: TIERS.MODERN, algorithms: ['X25519', 'Ed25519', 'AES-GCM', 'HMAC-SHA256'],             note: 'Signal Protocol cryptographic primitives' },

  // --- TLS/SSL libraries ---
  { name: 'io.netty:netty-handler',                     tier: TIERS.MODERN, algorithms: ['TLS 1.3', 'TLS 1.2', 'AES-GCM', 'ECDHE'],                  note: 'Netty SSL/TLS handler with OpenSSL/JDK backends' },
  { name: 'io.netty:netty-tcnative-boringssl-static',   tier: TIERS.MODERN, algorithms: ['TLS 1.3', 'AES-GCM', 'ChaCha20-Poly1305'],                 note: 'Netty native TLS via BoringSSL' },
  { name: 'com.squareup.okhttp3:okhttp',                tier: TIERS.MODERN, algorithms: ['TLS 1.3', 'TLS 1.2', 'ECDHE', 'AES-GCM'],                  note: 'HTTP client with modern TLS configuration' },
  { name: 'org.apache.httpcomponents:httpclient',        tier: TIERS.MODERN, algorithms: ['TLS 1.2', 'AES', 'RSA'],                                   note: 'Apache HTTP client with TLS support' },
  { name: 'org.apache.httpcomponents.client5:httpclient5', tier: TIERS.MODERN, algorithms: ['TLS 1.3', 'TLS 1.2', 'AES-GCM'],                        note: 'Apache HTTP Client 5.x with TLS 1.3 support' },

  // --- JWT/JOSE libraries ---
  { name: 'com.nimbusds:nimbus-jose-jwt',               tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'EdDSA', 'AES-GCM', 'ECDH-ES'],           note: 'Comprehensive JOSE/JWT/JWE library' },
  { name: 'org.bitbucket.b_c:jose4j',                   tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'AES-GCM', 'ECDH-ES'],                    note: 'JOSE/JWT library relying solely on JCA' },
  { name: 'io.jsonwebtoken:jjwt-api',                   tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'ES384', 'EdDSA', 'HS256'],                note: 'JJWT modular API artifact' },
  { name: 'io.jsonwebtoken:jjwt-impl',                  tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'EdDSA', 'AES-GCM'],                      note: 'JJWT runtime implementation' },
  { name: 'io.jsonwebtoken:jjwt-jackson',               tier: TIERS.MODERN, algorithms: ['RS256', 'ES256'],                                          note: 'JJWT Jackson JSON serialization' },
  { name: 'com.auth0:java-jwt',                         tier: TIERS.MODERN, algorithms: ['RS256', 'ES256', 'HS256', 'PS256'],                        note: 'Auth0 JWT library for Java' },

  // --- Password hashing ---
  { name: 'org.springframework.security:spring-security-crypto', tier: TIERS.MODERN, algorithms: ['bcrypt', 'scrypt', 'Argon2', 'PBKDF2'],           note: 'Spring Security password encoders' },
  { name: 'org.mindrot:jbcrypt',                        tier: TIERS.MODERN, algorithms: ['bcrypt'],                                                   note: 'Original Java bcrypt implementation' },
  { name: 'at.favre.lib:bcrypt',                        tier: TIERS.MODERN, algorithms: ['bcrypt'],                                                   note: 'Modern bcrypt impl, security-hardened API' },
  { name: 'com.password4j:password4j',                  tier: TIERS.MODERN, algorithms: ['Argon2', 'bcrypt', 'scrypt', 'PBKDF2', 'BalloonHashing'],  note: 'Multi-algorithm password hashing library' },
  { name: 'com.password4j:password4j-jca',              tier: TIERS.MODERN, algorithms: ['Argon2', 'bcrypt', 'scrypt'],                               note: 'Password4j JCA provider extension' },
  { name: 'de.mkammerer:argon2-jvm',                    tier: TIERS.MODERN, algorithms: ['Argon2'],                                                   note: 'Argon2 JVM bindings via native library' },
  { name: 'com.lambdaworks:scrypt',                     tier: TIERS.MODERN, algorithms: ['scrypt'],                                                   note: 'scrypt KDF implementation for Java' },

  // --- Key management / KMS clients ---
  { name: 'software.amazon.awssdk:kms',                 tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA', 'ECDSA', 'HMAC'],                         note: 'AWS KMS SDK v2 client' },
  { name: 'com.amazonaws:aws-java-sdk-kms',             tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA', 'ECDSA'],                                 note: 'AWS KMS SDK v1 client (legacy)' },
  { name: 'com.amazonaws:aws-encryption-sdk-java',       tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA-OAEP', 'ECDH', 'HKDF'],                    note: 'AWS Encryption SDK: envelope encryption' },
  { name: 'com.google.cloud:google-cloud-kms',          tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA', 'ECDSA', 'HMAC'],                         note: 'GCP Cloud KMS client library' },
  { name: 'com.google.crypto.tink:tink-awskms',         tier: TIERS.MODERN, algorithms: ['AES-GCM', 'KMS-envelope'],                                 note: 'Tink AWS KMS integration extension' },
  { name: 'com.google.crypto.tink:tink-gcpkms',         tier: TIERS.MODERN, algorithms: ['AES-GCM', 'KMS-envelope'],                                 note: 'Tink GCP KMS integration extension' },
  { name: 'com.azure:azure-security-keyvault-keys',     tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'AES-GCM'],                                 note: 'Azure Key Vault key operations client' },
  { name: 'com.azure:azure-security-keyvault-secrets',  tier: TIERS.MODERN, algorithms: ['AES', 'RSA'],                                              note: 'Azure Key Vault secrets client' },
  { name: 'com.azure:azure-security-keyvault-jca',      tier: TIERS.MODERN, algorithms: ['TLS', 'RSA', 'ECDSA', 'X.509'],                            note: 'Azure Key Vault JCA provider for TLS certs' },
  { name: 'com.bettercloud:vault-java-driver',          tier: TIERS.MODERN, algorithms: ['AES-GCM', 'RSA', 'Transit'],                               note: 'HashiCorp Vault Java client' },

  // --- XML/SOAP crypto (modern usage) ---
  { name: 'org.opensaml:opensaml-xmlsec-impl',          tier: TIERS.MODERN, algorithms: ['RSA', 'ECDSA', 'SHA-256', 'AES-GCM', 'XML-DSIG'],          note: 'OpenSAML XML security with modern algorithms' },

  // --- Jasypt Spring Boot (modern wrapper) ---
  { name: 'com.github.ulisesbocchio:jasypt-spring-boot-starter', tier: TIERS.MODERN, algorithms: ['AES-GCM', 'PBE'],                                 note: 'Spring Boot jasypt integration, configurable strong algorithms' },

  // --- SSL/TLS configuration utilities ---
  { name: 'io.github.hakky54:sslcontext-kickstart',     tier: TIERS.MODERN, algorithms: ['TLS 1.3', 'TLS 1.2', 'mTLS'],                              note: 'Simplified SSL/TLS context builder' },

  // =========================================================================
  // PQC - Post-quantum cryptography
  // =========================================================================

  { name: 'org.bouncycastle:bcprov-jdk18on',            tier: TIERS.PQC,  algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'NTRU', 'FrodoKEM', 'BIKE', 'HQC'],    note: 'BC provider includes full PQC suite since v1.79' },
  { name: 'org.openquantumsafe:liboqs-java',            tier: TIERS.PQC,  algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'SPHINCS+', 'Falcon'],                  note: 'Open Quantum Safe JNI wrapper for liboqs' },
];

/**
 * Get all packages for an ecosystem.
 * @param {'npm'|'pypi'|'maven'} ecosystem
 * @returns {CatalogEntry[]}
 */
export function getPackages(ecosystem) {
  if (ecosystem === 'npm') return NPM_PACKAGES;
  if (ecosystem === 'pypi') return PYPI_PACKAGES;
  if (ecosystem === 'maven') return MAVEN_PACKAGES;
  return [];
}

/**
 * Get package names filtered by tier.
 * @param {'npm'|'pypi'|'maven'} ecosystem
 * @param {string} tier
 * @returns {string[]}
 */
export function getNamesByTier(ecosystem, tier) {
  return getPackages(ecosystem)
    .filter(p => p.tier === tier)
    .map(p => p.name);
}
