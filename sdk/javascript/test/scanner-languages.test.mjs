import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { detectLanguage, scanSourceFile, scanWeakKeySizes, LANGUAGE_PATTERNS, MULTI_LANG_EXTENSIONS } from '../lib/scanner-languages.mjs';

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

  it('detects JavaScript and TypeScript files', () => {
    // JS/TS used to return null and run down a separate code path in
    // scanner.mjs. That path collapsed SHA-1 onto the SHA-256 label and never
    // recognized 3DES or Blowfish. All languages now share one table.
    assert.equal(detectLanguage('/path/to/app.js'), 'javascript');
    assert.equal(detectLanguage('/path/to/app.ts'), 'javascript');
    assert.equal(detectLanguage('/path/to/app.mjs'), 'javascript');
    assert.equal(detectLanguage('/path/to/app.tsx'), 'javascript');
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

  it('includes JS/TS extensions', () => {
    assert.ok(MULTI_LANG_EXTENSIONS.has('.js'));
    assert.ok(MULTI_LANG_EXTENSIONS.has('.ts'));
  });
});

describe('scanSourceFile - JavaScript', () => {
  it('reports SHA-1 as sha1, not sha256', () => {
    // Regression: ALGO_LITERALS matched /sha(?:256|384|512|1)/ and labelled
    // every hit "SHA-256", so a broken hash was inventoried as a strong one.
    const result = scanSourceFile('a.js', `crypto.createHash('sha1')`, 'javascript');
    assert.ok(result.algorithms.some(a => a.algorithm === 'sha1'), 'sha1 must be detected');
    assert.ok(!result.algorithms.some(a => a.algorithm === 'sha256'), 'sha1 must not be reported as sha256');
  });

  it('keeps distinct digests distinct', () => {
    const content = `
      createHash('md5');
      createHash('sha1');
      createHash('sha256');
      createHash('sha512');
    `;
    const found = scanSourceFile('a.js', content, 'javascript').algorithms.map(a => a.algorithm);
    for (const expected of ['md5', 'sha1', 'sha256', 'sha512']) {
      assert.ok(found.includes(expected), `${expected} missing from ${JSON.stringify(found)}`);
    }
  });

  it('detects 3DES written as an OpenSSL cipher name', () => {
    // Regression: /['"](?:des|DES|3des|des-ede3)['"]/ required the closing quote
    // immediately after the family, so "des-ede3-cbc" matched nothing at all.
    const result = scanSourceFile('a.js', `createCipheriv('des-ede3-cbc', k, iv)`, 'javascript');
    assert.ok(result.algorithms.some(a => a.algorithm === '3des'), '3des must be detected');
  });

  it('detects Blowfish, RC2 and RC4 cipher names', () => {
    const content = `
      createCipheriv('bf-cbc', k, iv);
      createCipheriv('rc2-40-cbc', k, iv);
      createCipheriv('rc4', k, iv);
    `;
    const found = scanSourceFile('a.js', content, 'javascript').algorithms.map(a => a.algorithm);
    assert.ok(found.includes('blowfish'), `blowfish missing from ${JSON.stringify(found)}`);
    assert.ok(found.includes('rc2'), `rc2 missing from ${JSON.stringify(found)}`);
    assert.ok(found.includes('rc4'), `rc4 missing from ${JSON.stringify(found)}`);
  });

  it('preserves AES mode so ECB is separable from GCM', () => {
    const content = `
      createCipheriv('aes-256-gcm', k, iv);
      createCipheriv('aes-128-ecb', k, iv);
    `;
    const found = scanSourceFile('a.js', content, 'javascript').algorithms.map(a => a.algorithm);
    assert.ok(found.includes('aes-gcm'));
    assert.ok(found.includes('aes-ecb'));
  });

  it('reports a 1-based line number for every algorithm', () => {
    const content = `line one\nline two\ncrypto.createHash('md5')\n`;
    const result = scanSourceFile('a.js', content, 'javascript');
    const md5 = result.algorithms.find(a => a.algorithm === 'md5');
    assert.ok(md5, 'md5 must be detected');
    assert.equal(md5.line, 3);
  });

  it('detects WebCrypto algorithm names', () => {
    const content = `await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, key, data);`;
    const found = scanSourceFile('a.js', content, 'javascript').algorithms.map(a => a.algorithm);
    assert.ok(found.includes('rsa-pss'), `rsa-pss missing from ${JSON.stringify(found)}`);
  });

  it('does not read a non-crypto name field as an algorithm', () => {
    const content = `const config = { name: 'billing-service', region: 'us-east-1' };`;
    const found = scanSourceFile('a.js', content, 'javascript').algorithms;
    assert.equal(found.length, 0, `expected no findings, got ${JSON.stringify(found)}`);
  });

  it('recognizes require() and import specifiers', () => {
    const cjs = scanSourceFile('a.js', `const c = require('node:crypto');`, 'javascript');
    assert.ok(cjs.imports.some(i => i.library === 'node:crypto'), 'require() form');
    const esm = scanSourceFile('a.mjs', `import c from 'node:crypto';`, 'javascript');
    assert.ok(esm.imports.some(i => i.library === 'node:crypto'), 'import form');
  });
});

describe('scanSourceFile - Python cryptography library', () => {
  it('detects rsa.generate_private_key', () => {
    // Regression: only pycryptodome idioms (RSA.generate) were matched, so a
    // project on pyca/cryptography scanned as having no RSA at all.
    const content = `key = rsa.generate_private_key(public_exponent=65537, key_size=2048)`;
    const found = scanSourceFile('k.py', content, 'python').algorithms.map(a => a.algorithm);
    assert.ok(found.includes('rsa'), `rsa missing from ${JSON.stringify(found)}`);
  });

  it('detects ec.generate_private_key and hashes.SHA1', () => {
    const content = `
      key = ec.generate_private_key(ec.SECP384R1())
      digest = hashes.SHA1()
    `;
    const found = scanSourceFile('k.py', content, 'python').algorithms.map(a => a.algorithm);
    assert.ok(found.includes('ecdsa'), `ecdsa missing from ${JSON.stringify(found)}`);
    assert.ok(found.includes('sha1'), `sha1 missing from ${JSON.stringify(found)}`);
  });

  it('detects legacy ciphers exposed via algorithms.*', () => {
    const content = `
      Cipher(algorithms.TripleDES(key), modes.CBC(iv))
      Cipher(algorithms.Blowfish(key), modes.ECB())
      Cipher(algorithms.ARC4(key), None)
    `;
    const found = scanSourceFile('k.py', content, 'python').algorithms.map(a => a.algorithm);
    assert.ok(found.includes('3des'), `3des missing from ${JSON.stringify(found)}`);
    assert.ok(found.includes('blowfish'), `blowfish missing from ${JSON.stringify(found)}`);
    assert.ok(found.includes('rc4'), `rc4 missing from ${JSON.stringify(found)}`);
  });
});

describe('scanWeakKeySizes', () => {
  it('flags a 1024-bit RSA key in Python', () => {
    const found = scanWeakKeySizes(`rsa.generate_private_key(public_exponent=65537, key_size=1024)`);
    assert.equal(found.length, 1);
    assert.equal(found[0].algorithm, 'rsa-1024');
    assert.equal(found[0].bits, 1024);
    assert.equal(found[0].line, 1);
  });

  it('flags a 1024-bit RSA key in Go and Node', () => {
    const go = scanWeakKeySizes(`key, _ := rsa.GenerateKey(rand.Reader, 1024)`);
    assert.equal(go[0]?.algorithm, 'rsa-1024');
    const node = scanWeakKeySizes(`generateKeyPairSync('rsa', { modulusLength: 1024 })`);
    assert.equal(node[0]?.algorithm, 'rsa-1024');
  });

  it('accepts 2048 and above', () => {
    assert.equal(scanWeakKeySizes(`key_size=2048`).length, 0);
    assert.equal(scanWeakKeySizes(`rsa.GenerateKey(rand.Reader, 4096)`).length, 0);
  });

  it('ignores unrelated small numbers', () => {
    const content = `const port = 1024;\nconst bufferSize = 1024;\nsetTimeout(fn, 1000);`;
    assert.equal(scanWeakKeySizes(content).length, 0);
  });
});

describe('scanSourceFile - bare algorithm literals (narrowing regression)', () => {
  // Moving JS onto the shared engine made every pattern call-site anchored,
  // which silently dropped algorithms named in a variable. An adversarial diff
  // of old-vs-new matcher output caught it: 'dsa' is weak, and losing it loses
  // a weak-crypto finding entirely.
  it('detects a weak algorithm named in a variable', () => {
    const found = scanSourceFile('a.js', `const alg = 'dsa';`, 'javascript').algorithms;
    assert.ok(found.some(a => a.algorithm === 'dsa'), `dsa missing from ${JSON.stringify(found)}`);
  });

  it('detects curve and KEM names assigned to variables', () => {
    const content = `
      const curve = 'ed25519';
      const kx = 'x25519';
      const sig = 'ecdsa';
      const legacy = 'rsa';
      const aead = 'chacha20-poly1305';
      const p = 'prime256v1';
    `;
    const found = scanSourceFile('a.js', content, 'javascript').algorithms.map(a => a.algorithm);
    for (const expected of ['ed25519', 'x25519', 'ecdsa', 'rsa', 'chacha20-poly1305', 'prime256v1']) {
      assert.ok(found.includes(expected), `${expected} missing from ${JSON.stringify(found)}`);
    }
  });

  it('takes the category from the algorithm database, not the pattern', () => {
    // One literal pattern covers unrelated algorithms, so a fixed category on
    // the pattern would mislabel most of them. This is the same class of bug
    // as the old matcher labelling every digest "SHA-256".
    const found = scanSourceFile('a.js', `const a='ed25519'; const b='md5'; const c='pbkdf2';`, 'javascript').algorithms;
    const by = Object.fromEntries(found.map(f => [f.algorithm, f.category]));
    assert.equal(by['ed25519'], 'signing');
    assert.equal(by['md5'], 'hashing');
    assert.equal(by['pbkdf2'], 'kdf');
  });

  it('does not treat arbitrary quoted strings as algorithms', () => {
    const content = `const name = 'billing'; const mode = 'production'; const s = 'description';`;
    assert.equal(scanSourceFile('a.js', content, 'javascript').algorithms.length, 0);
  });
});
