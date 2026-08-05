/**
 * Multi-language crypto pattern detection.
 *
 * Detects crypto usage in JavaScript/TypeScript, Go, Python, Java/Kotlin, Rust,
 * and C/C++ source files. Ported from backend/app/core/code_scanner.py
 * LIBRARY_PATTERNS. Zero dependencies.
 *
 * A pattern entry is either:
 *   { regex, algorithm, category }   - fixed algorithm label
 *   { regex, capture: n, category }  - algorithm read from capture group n and
 *                                      canonicalized via algorithm-db. Used for
 *                                      APIs that name the algorithm in an
 *                                      argument ("des-ede3-cbc", "SHA-1"), where
 *                                      a fixed label would collapse distinct
 *                                      algorithms onto one name.
 *
 * Every match carries the 1-based source line so findings are addressable.
 */

import { extname } from 'node:path';
import { canonicalizeAlgorithmToken, lookupAlgorithm } from './algorithm-db.mjs';
import { stripTerminalUnsafe } from './waivers.mjs';

// ---------------------------------------------------------------------------
// Per-language regex patterns
// ---------------------------------------------------------------------------

export const LANGUAGE_PATTERNS = {
  javascript: {
    extensions: ['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx'],
    patterns: [
      // node:crypto — the algorithm is an argument, so read it from the source.
      { regex: /create(?:Hash|Hmac)\s*\(\s*['"`]([\w./-]+)['"`]/g, capture: 1, category: 'hashing' },
      { regex: /create(?:Cipher|Decipher)iv\s*\(\s*['"`]([\w./-]+)['"`]/g, capture: 1, category: 'encryption' },
      { regex: /create(?:Cipher|Decipher)\s*\(\s*['"`]([\w./-]+)['"`]/g, capture: 1, category: 'encryption' },
      { regex: /createSign\s*\(\s*['"`]([\w./-]+)['"`]/g, capture: 1, category: 'signing' },
      { regex: /createVerify\s*\(\s*['"`]([\w./-]+)['"`]/g, capture: 1, category: 'signing' },
      { regex: /generateKeyPair(?:Sync)?\s*\(\s*['"`]([\w./-]+)['"`]/g, capture: 1, category: 'signing' },
      { regex: /createECDH\s*\(\s*['"`]([\w./-]+)['"`]/g, capture: 1, category: 'key_exchange' },
      { regex: /createDiffieHellman(?:Group)?\s*\(/g, algorithm: 'dh', category: 'key_exchange' },
      { regex: /\bscrypt(?:Sync)?\s*\(/g, algorithm: 'scrypt', category: 'kdf' },
      { regex: /\bpbkdf2(?:Sync)?\s*\(/g, algorithm: 'pbkdf2', category: 'kdf' },
      { regex: /\bhkdf(?:Sync)?\s*\(/g, algorithm: 'hkdf', category: 'kdf' },
      { regex: /\brandomBytes\s*\(|\brandomUUID\s*\(|\bgetRandomValues\s*\(/g, algorithm: 'csprng', category: 'random' },

      // WebCrypto — algorithm names live in a `name:` property or a digest arg.
      // The capture is restricted to the WebCrypto registry so an unrelated
      // `name: "..."` in a config object cannot be read as an algorithm.
      { regex: /name\s*:\s*['"`](RSASSA-PKCS1-v1_5|RSA-PSS|RSA-OAEP|ECDSA|ECDH|Ed25519|Ed448|X25519|X448|AES-CTR|AES-CBC|AES-GCM|AES-KW|HMAC|PBKDF2|HKDF|SHA-1|SHA-256|SHA-384|SHA-512)['"`]/gi, capture: 1, category: 'encryption' },
      { regex: /subtle\s*\.\s*digest\s*\(\s*(?:\{\s*name\s*:\s*)?['"`]([\w-]+)['"`]/g, capture: 1, category: 'hashing' },

      // JWT / JOSE algorithm identifiers.
      { regex: /algorithms?\s*:\s*\[?\s*['"`]((?:HS|RS|ES|PS)(?:256|384|512)|EdDSA|none)['"`]/g, capture: 1, category: 'signing' },

      // Bare algorithm string literals, e.g. `const alg = 'ed25519'` or an
      // algorithm passed through a variable. Call-site patterns alone miss
      // these, and among them are weak algorithms ('dsa', 'des', 'rc4') whose
      // detection must not depend on the call being inline. The token list is
      // an explicit allowlist rather than "any quoted string", and the
      // category comes from the algorithm database rather than being fixed
      // per pattern, which is what previously collapsed sha1 onto SHA-256.
      { regex: /['"`](ed25519|ed448|x25519|x448|curve25519|secp256k1|secp384r1|secp256r1|prime256v1|chacha20-poly1305|xchacha20-poly1305|chacha20|rsa-pss|rsa-oaep|ecdsa|ecdh|rsa|dsa|md5|md4|sha1|sha224|sha256|sha384|sha512|sha3-256|sha3-512|blake2b|blake2s|3des|des-ede3|des|rc4|rc2|blowfish|idea|cast5|argon2id|argon2|bcrypt|scrypt|pbkdf2|hkdf|ml-kem|ml-dsa|kyber|dilithium)['"`]/gi, capture: 1, category: null },

      // crypto-js
      { regex: /CryptoJS\s*\.\s*(MD5|SHA1|SHA224|SHA256|SHA384|SHA512|SHA3|RIPEMD160|AES|DES|TripleDES|RC4|Rabbit|HmacMD5|HmacSHA1|HmacSHA256)\b/g, capture: 1, category: 'encryption' },

      // node-forge
      { regex: /forge\s*\.\s*md\s*\.\s*(md5|sha1|sha256|sha384|sha512)\b/g, capture: 1, category: 'hashing' },
      { regex: /forge\s*\.\s*cipher\s*\.\s*create(?:Cipher|Decipher)\s*\(\s*['"`]([\w-]+)['"`]/g, capture: 1, category: 'encryption' },
      { regex: /forge\s*\.\s*pki\s*\.\s*rsa\b/g, algorithm: 'rsa', category: 'encryption' },

      // tweetnacl / libsodium bindings
      { regex: /nacl\s*\.\s*(?:secretbox|box)\b/g, algorithm: 'xsalsa20', category: 'encryption' },
      { regex: /nacl\s*\.\s*sign\b/g, algorithm: 'ed25519', category: 'signing' },
      { regex: /crypto_(?:secretbox|aead_xchacha20poly1305)\w*/g, algorithm: 'xchacha20-poly1305', category: 'encryption' },

      // bcrypt / argon2 npm packages used as functions
      { regex: /\bbcrypt\s*\.\s*(?:hash|hashSync|compare|compareSync|genSalt)\s*\(/g, algorithm: 'bcrypt', category: 'kdf' },
      { regex: /\bargon2\s*\.\s*(?:hash|verify)\s*\(/g, algorithm: 'argon2', category: 'kdf' },

      // PQC bindings
      { regex: /\b(?:ml_kem|mlkem|MlKem|ML_KEM)\d*\b/g, algorithm: 'ml-kem', category: 'key_exchange' },
      { regex: /\b(?:ml_dsa|mldsa|MlDsa|ML_DSA)\d*\b/g, algorithm: 'ml-dsa', category: 'signing' },
    ],
    // `require('x')` and `from 'x'` both reduce to an optional paren followed by
    // a quoted specifier. The older form used a single character class, which
    // could match the paren OR the quote but never both, so no require() call
    // was ever recognized.
    importPatterns: [
      { regex: /(?:require|from|import)\s*\(?\s*['"`]node:crypto['"`]/g, library: 'node:crypto' },
      { regex: /(?:require|from|import)\s*\(?\s*['"`]crypto['"`]/g, library: 'node:crypto' },
      { regex: /(?:require|from|import)\s*\(?\s*['"`]crypto-js['"`]|CryptoJS\s*\./g, library: 'crypto-js' },
      { regex: /(?:require|from|import)\s*\(?\s*['"`]node-forge['"`]|\bforge\s*\.\s*\w+/g, library: 'node-forge' },
      { regex: /(?:require|from|import)\s*\(?\s*['"`]tweetnacl['"`]|\bnacl\s*\.\s*\w+/g, library: 'tweetnacl' },
      { regex: /(?:require|from|import)\s*\(?\s*['"`]jsonwebtoken['"`]/g, library: 'jsonwebtoken' },
      { regex: /(?:require|from|import)\s*\(?\s*['"`]jose['"`]/g, library: 'jose' },
      { regex: /(?:require|from|import)\s*\(?\s*['"`]bcryptjs?['"`]/g, library: 'bcrypt' },
      { regex: /(?:require|from|import)\s*\(?\s*['"`]argon2['"`]/g, library: 'argon2' },
      { regex: /(?:require|from|import)\s*\(?\s*['"`]@noble\/[\w-]+['"`]/g, library: '@noble' },
    ],
  },
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

      // pyca/cryptography — the dominant Python crypto library. Its key
      // constructors and legacy ciphers were previously unmatched, so a project
      // built on it scanned as having almost no cryptography at all.
      { regex: /\brsa\s*\.\s*generate_private_key\s*\(|\brsa\s*\.\s*RSAPrivateKey\b|load_pem_private_key\s*\(/g, algorithm: 'rsa', category: 'encryption' },
      { regex: /\bec\s*\.\s*generate_private_key\s*\(|\bec\s*\.\s*ECDSA\s*\(/g, algorithm: 'ecdsa', category: 'signing' },
      { regex: /\bdsa\s*\.\s*generate_private_key\s*\(/g, algorithm: 'dsa', category: 'signing' },
      { regex: /\bdh\s*\.\s*generate_parameters\s*\(/g, algorithm: 'dh', category: 'key_exchange' },
      { regex: /\bpadding\s*\.\s*OAEP\s*\(/g, algorithm: 'rsa-oaep', category: 'encryption' },
      { regex: /\bpadding\s*\.\s*PSS\s*\(/g, algorithm: 'rsa-pss', category: 'signing' },
      { regex: /\bpadding\s*\.\s*PKCS1v15\s*\(/g, algorithm: 'rsa', category: 'signing' },
      { regex: /\bhashes\s*\.\s*(MD5|SHA1|SHA224|SHA256|SHA384|SHA512|SHA3_256|SHA3_512|BLAKE2b|BLAKE2s)\s*\(/g, capture: 1, category: 'hashing' },
      { regex: /\balgorithms\s*\.\s*(TripleDES|Blowfish|ARC4|CAST5|IDEA|SEED|Camellia|ChaCha20)\b/g, capture: 1, category: 'encryption' },
      { regex: /\bmodes\s*\.\s*ECB\s*\(/g, algorithm: 'aes-ecb', category: 'encryption' },
      { regex: /\bChaCha20Poly1305\s*\(|\bAESCCM\s*\(|\bAESOCB3\s*\(|\bAESSIV\s*\(/g, algorithm: 'chacha20-poly1305', category: 'encryption' },
      { regex: /\bEd448PrivateKey\b/g, algorithm: 'ed448', category: 'signing' },
      { regex: /\bX448PrivateKey\b/g, algorithm: 'x448', category: 'key_exchange' },
      { regex: /\bHKDF(?:Expand)?\s*\(/g, algorithm: 'hkdf', category: 'kdf' },
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
 * Returns language key (javascript, go, python, java, rust, c) or null.
 */
export function detectLanguage(filePath) {
  const ext = extname(filePath).toLowerCase();
  return EXT_MAP[ext] || null;
}

// ---------------------------------------------------------------------------
// Line resolution
// ---------------------------------------------------------------------------

/**
 * Build the sorted list of newline offsets so a match index can be resolved to
 * a 1-based line number in O(log n) instead of re-splitting the file per match.
 */
export function newlineOffsets(content) {
  const offsets = [];
  let i = content.indexOf('\n');
  while (i !== -1) {
    offsets.push(i);
    i = content.indexOf('\n', i + 1);
  }
  return offsets;
}

export function lineAt(offsets, index) {
  let lo = 0;
  let hi = offsets.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (offsets[mid] < index) lo = mid + 1;
    else hi = mid;
  }
  return lo + 1;
}

// ---------------------------------------------------------------------------
// Weak key sizes
// ---------------------------------------------------------------------------

// Finite-field and RSA moduli below 2048 bits are below every current floor
// (NIST SP 800-57 Rev.5, BSI TR-02102-1). Only forms where the algorithm and
// the bit length are unambiguous in a single expression are matched, so a bare
// `1024` elsewhere in the file can never be read as a key size.
const WEAK_KEY_SIZE_PATTERNS = [
  { regex: /modulusLength\s*:\s*(\d{3,6})/g, algorithm: 'rsa' },              // node:crypto
  { regex: /key_size\s*=\s*(\d{3,6})/g, algorithm: 'rsa' },                   // pyca/cryptography
  { regex: /RSA\.generate\s*\(\s*(\d{3,6})/g, algorithm: 'rsa' },             // pycryptodome
  { regex: /rsa\.GenerateKey\s*\([^,)]*,\s*(\d{3,6})/g, algorithm: 'rsa' },   // Go
  { regex: /RSA_generate_key(?:_ex)?\s*\(\s*(\d{3,6})/g, algorithm: 'rsa' },  // OpenSSL C
  { regex: /RsaPrivateKey::new\s*\([^,)]*,\s*(\d{3,6})/g, algorithm: 'rsa' }, // Rust rsa crate
  { regex: /\bgenrsa\b[^\n]*?\b(\d{3,6})\b/g, algorithm: 'rsa' },             // openssl CLI in scripts
];

const MIN_SAFE_RSA_BITS = 2048;

/**
 * Find asymmetric keys generated below the current minimum size.
 * Language-independent: the patterns are keyed on the API, not the file type.
 *
 * @returns {Array<{algorithm: string, bits: number, line: number, category: string, isWeak: true, weaknessReason: string, cwe: string}>}
 */
export function scanWeakKeySizes(content) {
  const offsets = newlineOffsets(content);
  const findings = [];
  const seen = new Set();

  for (const { regex, algorithm } of WEAK_KEY_SIZE_PATTERNS) {
    regex.lastIndex = 0;
    let m;
    while ((m = regex.exec(content)) !== null) {
      const bits = Number(m[1]);
      if (!Number.isFinite(bits) || bits >= MIN_SAFE_RSA_BITS) continue;
      // Below 512 the number is far more likely to be a buffer length or a
      // port than a modulus, so stay out of guessing territory.
      if (bits < 512) continue;
      const line = lineAt(offsets, m.index);
      const key = `${algorithm}:${bits}:${line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        algorithm: `${algorithm}-${bits}`,
        bits,
        line,
        category: 'encryption',
        isWeak: true,
        weaknessReason: `${bits}-bit key is below the 2048-bit minimum`,
        cwe: 'CWE-326',
      });
    }
  }

  return findings;
}

/**
 * Scan a source file for crypto patterns in the specified language.
 *
 * @returns {{algorithms: Array<{algorithm: string, category: string, line: number, evidence: string}>,
 *            imports: Array<{library: string, line: number}>}}
 */
export function scanSourceFile(filePath, content, language) {
  const langDef = LANGUAGE_PATTERNS[language];
  if (!langDef) return { algorithms: [], imports: [] };

  const offsets = newlineOffsets(content);
  const algorithms = [];
  const imports = [];
  const seenAlgos = new Set();
  const seenImports = new Set();

  for (const { regex, algorithm, capture, category } of langDef.patterns) {
    regex.lastIndex = 0;
    let m;
    while ((m = regex.exec(content)) !== null) {
      // A capture-based pattern reads the algorithm out of the source token so
      // that "des-ede3-cbc" stays 3DES and "sha1" never lands under SHA-256.
      const name = capture ? canonicalizeAlgorithmToken(m[capture]) : algorithm;
      if (!name) {
        if (m[0].length === 0) regex.lastIndex++; // never spin on a zero-width match
        continue;
      }
      // A null category on a pattern means the algorithm identity alone
      // determines it, so read it from the database instead of hardcoding one
      // label across a set of unrelated algorithms.
      const resolvedCategory = category || lookupAlgorithm(name)?.category || 'general';
      if (!seenAlgos.has(name)) {
        seenAlgos.add(name);
        algorithms.push({
          algorithm: name,
          category: resolvedCategory,
          line: lineAt(offsets, m.index),
          // Stripped for the same reason as the misuse site in `scanner.mjs`,
          // and in the same round: several algorithm patterns span arbitrary
          // characters between their anchors, so matched text reaches
          // `sourceAlgorithms[].evidence` carrying whatever sat there. DEL and
          // the C1 block survive `JSON.stringify` unescaped and U+009B is a
          // one-byte CSI, so a saved `--format json` report can drive the
          // terminal that later reads it. Display only: nothing decides
          // anything on evidence.
          evidence: stripTerminalUnsafe(m[0]).slice(0, 80),
        });
      }
      if (m[0].length === 0) regex.lastIndex++;
    }
  }

  for (const { regex, library } of langDef.importPatterns) {
    regex.lastIndex = 0;
    const m = regex.exec(content);
    if (m && !seenImports.has(library)) {
      seenImports.add(library);
      imports.push({ library, line: lineAt(offsets, m.index) });
    }
  }

  return { algorithms, imports };
}

/**
 * Source extensions handled by the language pattern tables.
 */
export const MULTI_LANG_EXTENSIONS = new Set(Object.values(LANGUAGE_PATTERNS).flatMap(l => l.extensions));
