/**
 * Multi-language crypto pattern detection.
 *
 * Detects crypto usage in Go, Python, Java/Kotlin, Rust, and C/C++ source files.
 * Ported from backend/app/core/code_scanner.py LIBRARY_PATTERNS.
 * Zero dependencies.
 */

import { extname } from 'node:path';

// ---------------------------------------------------------------------------
// Per-language regex patterns
// ---------------------------------------------------------------------------

export const LANGUAGE_PATTERNS = {
  go: {
    extensions: ['.go'],
    patterns: [
      { regex: /aes\.NewCipher/g, algorithm: 'aes', category: 'encryption' },
      { regex: /des\.NewCipher/g, algorithm: 'des', category: 'encryption' },
      { regex: /des\.NewTripleDESCipher/g, algorithm: '3des', category: 'encryption' },
      { regex: /sha256\.New\(\)|sha256\.Sum256/g, algorithm: 'sha256', category: 'hashing' },
      { regex: /sha512\.New\(\)|sha512\.Sum512/g, algorithm: 'sha512', category: 'hashing' },
      { regex: /sha1\.New\(\)|sha1\.Sum/g, algorithm: 'sha1', category: 'hashing' },
      { regex: /md5\.New\(\)|md5\.Sum/g, algorithm: 'md5', category: 'hashing' },
      { regex: /rsa\.GenerateKey|rsa\.EncryptOAEP|rsa\.SignPKCS1v15|rsa\.EncryptPKCS1v15/g, algorithm: 'rsa', category: 'encryption' },
      { regex: /ecdsa\.GenerateKey|ecdsa\.Sign|ecdsa\.Verify/g, algorithm: 'ecdsa', category: 'signing' },
      { regex: /ed25519\.GenerateKey|ed25519\.Sign|ed25519\.Verify/g, algorithm: 'ed25519', category: 'signing' },
      { regex: /chacha20poly1305\.New/g, algorithm: 'chacha20-poly1305', category: 'encryption' },
      { regex: /argon2\.IDKey|argon2\.Key/g, algorithm: 'argon2id', category: 'kdf' },
      { regex: /bcrypt\.GenerateFromPassword|bcrypt\.CompareHashAndPassword/g, algorithm: 'bcrypt', category: 'kdf' },
      { regex: /scrypt\.Key/g, algorithm: 'scrypt', category: 'kdf' },
      { regex: /pbkdf2\.Key/g, algorithm: 'pbkdf2', category: 'kdf' },
      { regex: /curve25519\.X25519|ecdh\.P256\(\)|ecdh\.X25519\(\)/g, algorithm: 'x25519', category: 'key_exchange' },
      { regex: /hmac\.New/g, algorithm: 'hmac', category: 'mac' },
      { regex: /hkdf\.New|hkdf\.Expand/g, algorithm: 'hkdf', category: 'kdf' },
      { regex: /tls\.Config\{|tls\.Listen|tls\.Dial/g, algorithm: 'tls', category: 'protocol' },
      { regex: /circl\/.*kyber|circl\/.*dilithium/g, algorithm: 'kyber', category: 'key_exchange' },
    ],
    importPatterns: [
      { regex: /["']crypto\/aes["']/g, library: 'crypto/aes' },
      { regex: /["']crypto\/des["']/g, library: 'crypto/des' },
      { regex: /["']crypto\/rsa["']/g, library: 'crypto/rsa' },
      { regex: /["']crypto\/ecdsa["']/g, library: 'crypto/ecdsa' },
      { regex: /["']crypto\/ed25519["']/g, library: 'crypto/ed25519' },
      { regex: /["']crypto\/sha256["']/g, library: 'crypto/sha256' },
      { regex: /["']crypto\/sha512["']/g, library: 'crypto/sha512' },
      { regex: /["']crypto\/sha1["']/g, library: 'crypto/sha1' },
      { regex: /["']crypto\/md5["']/g, library: 'crypto/md5' },
      { regex: /["']crypto\/hmac["']/g, library: 'crypto/hmac' },
      { regex: /["']crypto\/tls["']/g, library: 'crypto/tls' },
      { regex: /["']crypto\/ecdh["']/g, library: 'crypto/ecdh' },
      { regex: /["']golang\.org\/x\/crypto/g, library: 'golang.org/x/crypto' },
      { regex: /["']github\.com\/cloudflare\/circl/g, library: 'circl' },
    ],
  },
  python: {
    extensions: ['.py'],
    patterns: [
      { regex: /hashlib\.sha256|hashlib\.new\s*\(\s*['"]sha256/g, algorithm: 'sha256', category: 'hashing' },
      { regex: /hashlib\.sha384|hashlib\.new\s*\(\s*['"]sha384/g, algorithm: 'sha384', category: 'hashing' },
      { regex: /hashlib\.sha512|hashlib\.new\s*\(\s*['"]sha512/g, algorithm: 'sha512', category: 'hashing' },
      { regex: /hashlib\.md5|hashlib\.new\s*\(\s*['"]md5/g, algorithm: 'md5', category: 'hashing' },
      { regex: /hashlib\.sha1|hashlib\.new\s*\(\s*['"]sha1/g, algorithm: 'sha1', category: 'hashing' },
      { regex: /hashlib\.sha3_256|hashlib\.new\s*\(\s*['"]sha3_256/g, algorithm: 'sha3-256', category: 'hashing' },
      { regex: /hashlib\.blake2b/g, algorithm: 'blake2b', category: 'hashing' },
      { regex: /from\s+Crypto\.Cipher\s+import\s+AES|AES\.new/g, algorithm: 'aes', category: 'encryption' },
      { regex: /from\s+Crypto\.Cipher\s+import\s+DES\b|DES\.new/g, algorithm: 'des', category: 'encryption' },
      { regex: /from\s+Crypto\.Cipher\s+import\s+DES3|DES3\.new/g, algorithm: '3des', category: 'encryption' },
      { regex: /RSA\.generate|PKCS1_OAEP|RSA\.import_key/g, algorithm: 'rsa', category: 'encryption' },
      { regex: /from\s+cryptography.*import.*Fernet/g, algorithm: 'aes-128-cbc', category: 'encryption' },
      { regex: /AESGCM|algorithms\.AES/g, algorithm: 'aes-gcm', category: 'encryption' },
      { regex: /Ed25519PrivateKey|Ed25519PublicKey/g, algorithm: 'ed25519', category: 'signing' },
      { regex: /X25519PrivateKey|X25519PublicKey/g, algorithm: 'x25519', category: 'key_exchange' },
      { regex: /ECDSA|ec\.SECP256R1|ec\.SECP384R1/g, algorithm: 'ecdsa', category: 'signing' },
      { regex: /bcrypt\.hashpw|bcrypt\.gensalt/g, algorithm: 'bcrypt', category: 'kdf' },
      { regex: /argon2\.PasswordHasher|argon2\.hash_password/g, algorithm: 'argon2', category: 'kdf' },
      { regex: /PBKDF2HMAC/g, algorithm: 'pbkdf2', category: 'kdf' },
      { regex: /Scrypt/g, algorithm: 'scrypt', category: 'kdf' },
      { regex: /ChaCha20Poly1305/g, algorithm: 'chacha20-poly1305', category: 'encryption' },
      { regex: /from\s+hmac\s+import|hmac\.new/g, algorithm: 'hmac', category: 'mac' },
    ],
    importPatterns: [
      { regex: /import\s+hashlib/g, library: 'hashlib' },
      { regex: /from\s+Crypto\b/g, library: 'pycryptodome' },
      { regex: /from\s+cryptography\b/g, library: 'cryptography' },
      { regex: /import\s+bcrypt/g, library: 'bcrypt' },
      { regex: /import\s+argon2/g, library: 'argon2-cffi' },
      { regex: /from\s+nacl\b|import\s+nacl/g, library: 'pynacl' },
      { regex: /import\s+jwt\b|from\s+jwt\b/g, library: 'pyjwt' },
    ],
  },
  java: {
    extensions: ['.java', '.kt', '.scala'],
    patterns: [
      { regex: /Cipher\.getInstance\s*\(\s*["']AES/g, algorithm: 'aes', category: 'encryption' },
      { regex: /Cipher\.getInstance\s*\(\s*["']DES\b/g, algorithm: 'des', category: 'encryption' },
      { regex: /Cipher\.getInstance\s*\(\s*["']DESede/g, algorithm: '3des', category: 'encryption' },
      { regex: /Cipher\.getInstance\s*\(\s*["']RSA/g, algorithm: 'rsa', category: 'encryption' },
      { regex: /Cipher\.getInstance\s*\(\s*["']ChaCha20/g, algorithm: 'chacha20-poly1305', category: 'encryption' },
      { regex: /Cipher\.getInstance\s*\(\s*["']Blowfish/g, algorithm: 'blowfish', category: 'encryption' },
      { regex: /Cipher\.getInstance\s*\(\s*["']RC4/g, algorithm: 'rc4', category: 'encryption' },
      { regex: /MessageDigest\.getInstance\s*\(\s*["']SHA-256/g, algorithm: 'sha256', category: 'hashing' },
      { regex: /MessageDigest\.getInstance\s*\(\s*["']SHA-384/g, algorithm: 'sha384', category: 'hashing' },
      { regex: /MessageDigest\.getInstance\s*\(\s*["']SHA-512/g, algorithm: 'sha512', category: 'hashing' },
      { regex: /MessageDigest\.getInstance\s*\(\s*["']SHA-1/g, algorithm: 'sha1', category: 'hashing' },
      { regex: /MessageDigest\.getInstance\s*\(\s*["']MD5/g, algorithm: 'md5', category: 'hashing' },
      { regex: /KeyPairGenerator\.getInstance\s*\(\s*["']RSA/g, algorithm: 'rsa', category: 'encryption' },
      { regex: /KeyPairGenerator\.getInstance\s*\(\s*["']EC/g, algorithm: 'ecdsa', category: 'signing' },
      { regex: /KeyPairGenerator\.getInstance\s*\(\s*["']DSA/g, algorithm: 'dsa', category: 'signing' },
      { regex: /Signature\.getInstance\s*\(\s*["']SHA256withRSA/g, algorithm: 'rsa', category: 'signing' },
      { regex: /Signature\.getInstance\s*\(\s*["']SHA256withECDSA/g, algorithm: 'ecdsa', category: 'signing' },
      { regex: /SecretKeyFactory\.getInstance\s*\(\s*["']PBKDF2/g, algorithm: 'pbkdf2', category: 'kdf' },
      { regex: /KeyAgreement\.getInstance\s*\(\s*["']ECDH/g, algorithm: 'ecdh', category: 'key_exchange' },
      { regex: /KeyAgreement\.getInstance\s*\(\s*["']DH/g, algorithm: 'dh', category: 'key_exchange' },
      { regex: /SSLContext\.getInstance\s*\(\s*["']TLS/g, algorithm: 'tls', category: 'protocol' },
      { regex: /Mac\.getInstance\s*\(\s*["']HmacSHA/g, algorithm: 'hmac', category: 'mac' },
    ],
    importPatterns: [
      { regex: /import\s+javax\.crypto/g, library: 'javax.crypto' },
      { regex: /import\s+java\.security/g, library: 'java.security' },
      { regex: /import\s+org\.bouncycastle/g, library: 'bouncycastle' },
    ],
  },
  rust: {
    extensions: ['.rs'],
    patterns: [
      { regex: /use\s+aes::|Aes256Gcm|Aes128Gcm|Aes256/g, algorithm: 'aes-gcm', category: 'encryption' },
      { regex: /use\s+chacha20poly1305::|ChaCha20Poly1305/g, algorithm: 'chacha20-poly1305', category: 'encryption' },
      { regex: /use\s+rsa::|RsaPrivateKey|RsaPublicKey/g, algorithm: 'rsa', category: 'encryption' },
      { regex: /use\s+ed25519::|Ed25519/g, algorithm: 'ed25519', category: 'signing' },
      { regex: /use\s+ed25519_dalek::/g, algorithm: 'ed25519', category: 'signing' },
      { regex: /use\s+sha2::|Sha256::new|Sha512::new/g, algorithm: 'sha256', category: 'hashing' },
      { regex: /use\s+sha1::|Sha1::new/g, algorithm: 'sha1', category: 'hashing' },
      { regex: /use\s+md5::|Md5::new/g, algorithm: 'md5', category: 'hashing' },
      { regex: /use\s+blake2::|Blake2b/g, algorithm: 'blake2b', category: 'hashing' },
      { regex: /use\s+argon2::|Argon2/g, algorithm: 'argon2', category: 'kdf' },
      { regex: /use\s+bcrypt::/g, algorithm: 'bcrypt', category: 'kdf' },
      { regex: /use\s+scrypt::/g, algorithm: 'scrypt', category: 'kdf' },
      { regex: /use\s+pbkdf2::/g, algorithm: 'pbkdf2', category: 'kdf' },
      { regex: /use\s+x25519_dalek::|X25519/g, algorithm: 'x25519', category: 'key_exchange' },
      { regex: /use\s+p256::|use\s+p384::/g, algorithm: 'ecdsa', category: 'signing' },
      { regex: /use\s+ring::/g, algorithm: 'aes-gcm', category: 'encryption' },
      { regex: /use\s+pqcrypto::|use\s+oqs::/g, algorithm: 'ml-kem', category: 'key_exchange' },
      { regex: /use\s+hmac::|Hmac::new/g, algorithm: 'hmac', category: 'mac' },
      { regex: /use\s+hkdf::/g, algorithm: 'hkdf', category: 'kdf' },
    ],
    importPatterns: [
      { regex: /\[dependencies\][\s\S]*?(?:aes-gcm|aes)\s*=/g, library: 'aes-gcm' },
      { regex: /\[dependencies\][\s\S]*?ring\s*=/g, library: 'ring' },
      { regex: /\[dependencies\][\s\S]*?pqcrypto\s*=/g, library: 'pqcrypto' },
    ],
  },
  c: {
    extensions: ['.c', '.h', '.cpp', '.hpp', '.cc', '.cxx'],
    patterns: [
      { regex: /EVP_aes_256_gcm|EVP_aes_128_gcm|EVP_aes_256_cbc|AES_encrypt|AES_set_encrypt_key/g, algorithm: 'aes', category: 'encryption' },
      { regex: /EVP_des_|DES_ecb_encrypt|DES_set_key/g, algorithm: 'des', category: 'encryption' },
      { regex: /EVP_des_ede3|DES_ede3_cbc_encrypt/g, algorithm: '3des', category: 'encryption' },
      { regex: /RSA_generate_key|EVP_PKEY_RSA|RSA_public_encrypt/g, algorithm: 'rsa', category: 'encryption' },
      { regex: /EVP_sha256|SHA256_Init|SHA256_Update/g, algorithm: 'sha256', category: 'hashing' },
      { regex: /EVP_sha1|SHA1_Init|SHA1_Update/g, algorithm: 'sha1', category: 'hashing' },
      { regex: /EVP_md5|MD5_Init|MD5_Update/g, algorithm: 'md5', category: 'hashing' },
      { regex: /EVP_sha512|SHA512_Init/g, algorithm: 'sha512', category: 'hashing' },
      { regex: /EVP_sha3_256/g, algorithm: 'sha3-256', category: 'hashing' },
      { regex: /EC_KEY_generate|ECDSA_sign|ECDSA_verify/g, algorithm: 'ecdsa', category: 'signing' },
      { regex: /EVP_chacha20_poly1305/g, algorithm: 'chacha20-poly1305', category: 'encryption' },
      { regex: /PKCS5_PBKDF2_HMAC/g, algorithm: 'pbkdf2', category: 'kdf' },
      { regex: /EVP_PKEY_X25519/g, algorithm: 'x25519', category: 'key_exchange' },
      { regex: /HMAC_Init|HMAC_Update|HMAC_CTX/g, algorithm: 'hmac', category: 'mac' },
      { regex: /EVP_PKEY_EC|EC_GROUP_new/g, algorithm: 'ecdh', category: 'key_exchange' },
      { regex: /EVP_bf_cbc|BF_encrypt/g, algorithm: 'blowfish', category: 'encryption' },
      { regex: /EVP_rc4|RC4_set_key/g, algorithm: 'rc4', category: 'encryption' },
      { regex: /SSL_CTX_new|TLS_method|SSLv23_method/g, algorithm: 'tls', category: 'protocol' },
    ],
    importPatterns: [
      { regex: /#include\s*<openssl\/evp\.h>/g, library: 'openssl' },
      { regex: /#include\s*<openssl\/aes\.h>/g, library: 'openssl' },
      { regex: /#include\s*<openssl\/rsa\.h>/g, library: 'openssl' },
      { regex: /#include\s*<openssl\/ssl\.h>/g, library: 'openssl' },
      { regex: /#include\s*<sodium\.h>/g, library: 'libsodium' },
      { regex: /#include\s*<oqs\/oqs\.h>/g, library: 'liboqs' },
    ],
  },
};

// ---------------------------------------------------------------------------
// Extension → language mapping
// ---------------------------------------------------------------------------

const EXT_MAP = {};
for (const [lang, def] of Object.entries(LANGUAGE_PATTERNS)) {
  for (const ext of def.extensions) {
    EXT_MAP[ext] = lang;
  }
}

/**
 * Detect programming language from file extension.
 * Returns language key (go, python, java, rust, c) or null.
 */
export function detectLanguage(filePath) {
  const ext = extname(filePath).toLowerCase();
  return EXT_MAP[ext] || null;
}

/**
 * Scan a source file for crypto patterns in the specified language.
 * Returns { algorithms: [{ algorithm, category, line? }], imports: [{ library }] }.
 */
export function scanSourceFile(filePath, content, language) {
  const langDef = LANGUAGE_PATTERNS[language];
  if (!langDef) return { algorithms: [], imports: [] };

  const algorithms = [];
  const imports = [];
  const seenAlgos = new Set();
  const seenImports = new Set();

  for (const { regex, algorithm, category } of langDef.patterns) {
    regex.lastIndex = 0;
    if (regex.test(content) && !seenAlgos.has(algorithm)) {
      seenAlgos.add(algorithm);
      algorithms.push({ algorithm, category });
    }
  }

  for (const { regex, library } of langDef.importPatterns) {
    regex.lastIndex = 0;
    if (regex.test(content) && !seenImports.has(library)) {
      seenImports.add(library);
      imports.push({ library });
    }
  }

  return { algorithms, imports };
}

/**
 * All supported non-JS source extensions for the file walker.
 */
export const MULTI_LANG_EXTENSIONS = new Set(Object.values(LANGUAGE_PATTERNS).flatMap(l => l.extensions));
