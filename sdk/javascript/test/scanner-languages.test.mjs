import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { detectLanguage, scanSourceFile, LANGUAGE_PATTERNS, MULTI_LANG_EXTENSIONS } from '../lib/scanner-languages.mjs';

describe('detectLanguage', () => {
  it('detects Go files', () => {
    assert.equal(detectLanguage('/path/to/main.go'), 'go');
  });

  it('detects Python files', () => {
    assert.equal(detectLanguage('/path/to/app.py'), 'python');
  });

  it('detects Java files', () => {
    assert.equal(detectLanguage('/path/to/Main.java'), 'java');
  });

  it('detects Kotlin files', () => {
    assert.equal(detectLanguage('/path/to/Main.kt'), 'java');
  });

  it('detects Rust files', () => {
    assert.equal(detectLanguage('/path/to/main.rs'), 'rust');
  });

  it('detects C files', () => {
    assert.equal(detectLanguage('/path/to/crypto.c'), 'c');
    assert.equal(detectLanguage('/path/to/crypto.h'), 'c');
    assert.equal(detectLanguage('/path/to/crypto.cpp'), 'c');
  });

  it('returns null for JS/TS files', () => {
    assert.equal(detectLanguage('/path/to/app.js'), null);
    assert.equal(detectLanguage('/path/to/app.ts'), null);
  });

  it('returns null for unknown extensions', () => {
    assert.equal(detectLanguage('/path/to/file.txt'), null);
    assert.equal(detectLanguage('/path/to/Makefile'), null);
  });
});

describe('scanSourceFile - Go', () => {
  it('detects SHA-256 usage', () => {
    const content = `
      package main
      import "crypto/sha256"
      func hash() { sha256.Sum256([]byte("test")) }
    `;
    const result = scanSourceFile('main.go', content, 'go');
    assert.ok(result.algorithms.some(a => a.algorithm === 'sha256'));
  });

  it('detects RSA usage', () => {
    const content = `
      package main
      import "crypto/rsa"
      key, _ := rsa.GenerateKey(rand.Reader, 2048)
    `;
    const result = scanSourceFile('main.go', content, 'go');
    assert.ok(result.algorithms.some(a => a.algorithm === 'rsa'));
  });

  it('detects Ed25519 usage', () => {
    const content = `ed25519.GenerateKey(rand.Reader)`;
    const result = scanSourceFile('main.go', content, 'go');
    assert.ok(result.algorithms.some(a => a.algorithm === 'ed25519'));
  });

  it('detects bcrypt usage', () => {
    const content = `bcrypt.GenerateFromPassword([]byte(password), 10)`;
    const result = scanSourceFile('main.go', content, 'go');
    assert.ok(result.algorithms.some(a => a.algorithm === 'bcrypt'));
  });

  it('detects crypto imports', () => {
    const content = `import "crypto/rsa"`;
    const result = scanSourceFile('main.go', content, 'go');
    assert.ok(result.imports.some(i => i.library === 'crypto/rsa'));
  });

  it('detects x/crypto library', () => {
    const content = `import "golang.org/x/crypto/bcrypt"`;
    const result = scanSourceFile('main.go', content, 'go');
    assert.ok(result.imports.some(i => i.library === 'golang.org/x/crypto'));
  });
});

describe('scanSourceFile - Python', () => {
  it('detects hashlib SHA-256', () => {
    const content = `hashlib.sha256(b"test").hexdigest()`;
    const result = scanSourceFile('app.py', content, 'python');
    assert.ok(result.algorithms.some(a => a.algorithm === 'sha256'));
  });

  it('detects PyCryptodome AES', () => {
    const content = `from Crypto.Cipher import AES`;
    const result = scanSourceFile('app.py', content, 'python');
    assert.ok(result.algorithms.some(a => a.algorithm === 'aes'));
  });

  it('detects bcrypt', () => {
    const content = `bcrypt.hashpw(password, bcrypt.gensalt())`;
    const result = scanSourceFile('app.py', content, 'python');
    assert.ok(result.algorithms.some(a => a.algorithm === 'bcrypt'));
  });

  it('detects MD5 (weak)', () => {
    const content = `hashlib.md5(b"test")`;
    const result = scanSourceFile('app.py', content, 'python');
    assert.ok(result.algorithms.some(a => a.algorithm === 'md5'));
  });
});

describe('scanSourceFile - Java', () => {
  it('detects AES cipher', () => {
    const content = `Cipher c = Cipher.getInstance("AES/GCM/NoPadding");`;
    const result = scanSourceFile('Main.java', content, 'java');
    assert.ok(result.algorithms.some(a => a.algorithm === 'aes'));
  });

  it('detects SHA-256 digest', () => {
    const content = `MessageDigest.getInstance("SHA-256");`;
    const result = scanSourceFile('Main.java', content, 'java');
    assert.ok(result.algorithms.some(a => a.algorithm === 'sha256'));
  });

  it('detects RSA key generation', () => {
    const content = `KeyPairGenerator.getInstance("RSA");`;
    const result = scanSourceFile('Main.java', content, 'java');
    assert.ok(result.algorithms.some(a => a.algorithm === 'rsa'));
  });
});

describe('scanSourceFile - Rust', () => {
  it('detects AES-GCM crate', () => {
    const content = `use aes_gcm::{Aes256Gcm, Key, Nonce};`;
    // Note: the regex uses `Aes256Gcm` not `aes_gcm::`
    const result = scanSourceFile('main.rs', content, 'rust');
    assert.ok(result.algorithms.some(a => a.algorithm === 'aes-gcm'));
  });

  it('detects ed25519', () => {
    const content = `use ed25519_dalek::Keypair;`;
    const result = scanSourceFile('main.rs', content, 'rust');
    assert.ok(result.algorithms.some(a => a.algorithm === 'ed25519'));
  });
});

describe('scanSourceFile - C/C++', () => {
  it('detects OpenSSL AES', () => {
    const content = `EVP_aes_256_gcm();`;
    const result = scanSourceFile('crypto.c', content, 'c');
    assert.ok(result.algorithms.some(a => a.algorithm === 'aes'));
  });

  it('detects OpenSSL RSA', () => {
    const content = `RSA_generate_key(2048, RSA_F4, NULL, NULL);`;
    const result = scanSourceFile('crypto.c', content, 'c');
    assert.ok(result.algorithms.some(a => a.algorithm === 'rsa'));
  });

  it('detects OpenSSL includes', () => {
    const content = `#include <openssl/evp.h>`;
    const result = scanSourceFile('crypto.c', content, 'c');
    assert.ok(result.imports.some(i => i.library === 'openssl'));
  });
});

describe('MULTI_LANG_EXTENSIONS', () => {
  it('includes Go, Python, Java, Rust, C extensions', () => {
    assert.ok(MULTI_LANG_EXTENSIONS.has('.go'));
    assert.ok(MULTI_LANG_EXTENSIONS.has('.py'));
    assert.ok(MULTI_LANG_EXTENSIONS.has('.java'));
    assert.ok(MULTI_LANG_EXTENSIONS.has('.rs'));
    assert.ok(MULTI_LANG_EXTENSIONS.has('.c'));
    assert.ok(MULTI_LANG_EXTENSIONS.has('.cpp'));
    assert.ok(MULTI_LANG_EXTENSIONS.has('.h'));
  });

  it('does not include JS/TS extensions', () => {
    assert.ok(!MULTI_LANG_EXTENSIONS.has('.js'));
    assert.ok(!MULTI_LANG_EXTENSIONS.has('.ts'));
  });
});
