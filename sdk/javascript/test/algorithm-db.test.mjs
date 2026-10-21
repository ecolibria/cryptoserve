import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ALGORITHM_DB, lookupAlgorithm, classifyFromDb, canonicalizeAlgorithmToken } from '../lib/algorithm-db.mjs';

describe('ALGORITHM_DB', () => {
  it('contains at least 80 entries', () => {
    assert.ok(Object.keys(ALGORITHM_DB).length >= 80, `expected >=80 entries, got ${Object.keys(ALGORITHM_DB).length}`);
  });

  it('all entries have required fields', () => {
    for (const [name, entry] of Object.entries(ALGORITHM_DB)) {
      assert.ok(entry.category, `${name} missing category`);
      assert.ok(entry.quantumRisk, `${name} missing quantumRisk`);
      assert.equal(typeof entry.isWeak, 'boolean', `${name} isWeak should be boolean`);
    }
  });

  it('weak entries have weaknessReason and cwe', () => {
    for (const [name, entry] of Object.entries(ALGORITHM_DB)) {
      if (entry.isWeak) {
        assert.ok(entry.weaknessReason, `${name} is weak but missing weaknessReason`);
        assert.ok(entry.cwe, `${name} is weak but missing cwe`);
      }
    }
  });

  it('PQC algorithms have quantumRisk none', () => {
    const pqcNames = ['kyber', 'ml-kem', 'dilithium', 'ml-dsa', 'sphincs', 'slh-dsa', 'falcon'];
    for (const name of pqcNames) {
      assert.equal(ALGORITHM_DB[name].quantumRisk, 'none', `${name} should have quantumRisk none`);
    }
  });

  it('asymmetric algorithms have quantumRisk high', () => {
    const asymNames = ['rsa', 'ecdsa', 'ed25519', 'ecdh', 'x25519', 'dh'];
    for (const name of asymNames) {
      assert.equal(ALGORITHM_DB[name].quantumRisk, 'high', `${name} should have quantumRisk high`);
    }
  });

  it('weak hashes have quantumRisk critical', () => {
    assert.equal(ALGORITHM_DB['md5'].quantumRisk, 'critical');
    assert.equal(ALGORITHM_DB['sha1'].quantumRisk, 'critical');
    assert.equal(ALGORITHM_DB['md5'].isWeak, true);
    assert.equal(ALGORITHM_DB['sha1'].isWeak, true);
  });

  it('AES variants are not weak', () => {
    assert.equal(ALGORITHM_DB['aes'].isWeak, false);
    assert.equal(ALGORITHM_DB['aes-256-gcm'].isWeak, false);
    assert.equal(ALGORITHM_DB['aes-128'].isWeak, false);
  });

  it('ECB mode is weak', () => {
    assert.equal(ALGORITHM_DB['aes-ecb'].isWeak, true);
  });
});

describe('lookupAlgorithm', () => {
  it('finds exact lowercase names', () => {
    const result = lookupAlgorithm('aes');
    assert.ok(result);
    assert.equal(result.category, 'encryption');
  });

  it('is case-insensitive', () => {
    assert.ok(lookupAlgorithm('AES'));
    assert.ok(lookupAlgorithm('SHA256'));
    assert.ok(lookupAlgorithm('RSA'));
  });

  it('resolves aliases', () => {
    const result = lookupAlgorithm('triple-des');
    assert.ok(result);
    assert.equal(result.name, '3des');
  });

  it('resolves SHA-256 alias', () => {
    const result = lookupAlgorithm('SHA-256');
    assert.ok(result);
    assert.equal(result.category, 'hashing');
  });

  it('resolves TLS version aliases', () => {
    assert.ok(lookupAlgorithm('TLSv1.0'));
    assert.ok(lookupAlgorithm('SSLv3'));
  });

  it('returns null for unknown algorithms', () => {
    assert.equal(lookupAlgorithm('unknown-algo'), null);
    assert.equal(lookupAlgorithm(''), null);
    assert.equal(lookupAlgorithm(null), null);
  });

  it('normalizes whitespace', () => {
    const result = lookupAlgorithm('  aes  ');
    assert.ok(result);
    assert.equal(result.category, 'encryption');
  });
});

describe('classifyFromDb', () => {
  it('classifies AES-256-GCM as encryption/none risk', () => {
    const result = classifyFromDb('AES-256-GCM');
    assert.ok(result);
    assert.equal(result.category, 'encryption');
    assert.equal(result.quantumRisk, 'none');
    assert.equal(result.isWeak, false);
  });

  it('classifies RSA as encryption/high risk', () => {
    const result = classifyFromDb('RSA');
    assert.ok(result);
    assert.equal(result.category, 'encryption');
    assert.equal(result.quantumRisk, 'high');
  });

  it('classifies MD5 as weak with CWE', () => {
    const result = classifyFromDb('MD5');
    assert.ok(result);
    assert.equal(result.isWeak, true);
    assert.equal(result.cwe, 'CWE-328');
  });

  it('classifies ML-KEM as key_exchange/none risk', () => {
    const result = classifyFromDb('ML-KEM');
    assert.ok(result);
    assert.equal(result.category, 'key_exchange');
    assert.equal(result.quantumRisk, 'none');
  });

  it('returns null for unknown algorithms', () => {
    assert.equal(classifyFromDb('nonexistent'), null);
  });
});

/**
 * An algorithm name can be the scanned tree's own text, and each table is a
 * plain object. `in` was true for a name inherited from Object.prototype, so
 * the token `constructor` canonicalized to the Object function and
 * `con-structor` to the string "constructor", and `lookupAlgorithm` returned
 * an entry for `constructor` and `__proto__` instead of null.
 */
describe('a name inherited from Object.prototype', () => {
  // Each name Object.prototype holds, and spellings that
  // canonicalizeAlgorithmToken or lookupAlgorithm reduce to one of them.
  const INHERITED = [
    ...Object.getOwnPropertyNames(Object.prototype),
    'CONSTRUCTOR', ' constructor ', 'con-structor', 'con_structor', '__PROTO__',
  ];

  it('is not an algorithm token', () => {
    for (const name of INHERITED) {
      assert.equal(canonicalizeAlgorithmToken(name), null, JSON.stringify(name));
    }
  });

  it('is not an algorithm', () => {
    for (const name of INHERITED) {
      assert.equal(lookupAlgorithm(name), null, JSON.stringify(name));
      assert.equal(classifyFromDb(name), null, JSON.stringify(name));
    }
  });

  it('leaves the names each table owns resolving', () => {
    assert.equal(canonicalizeAlgorithmToken('SHA-1'), 'sha1');                // digest table
    assert.equal(canonicalizeAlgorithmToken('des-ede3-cbc'), '3des');         // cipher family
    assert.equal(canonicalizeAlgorithmToken('rsa-2048'), 'rsa-2048');         // database key
    assert.equal(canonicalizeAlgorithmToken('triple-des'), '3des');           // alias
    assert.equal(canonicalizeAlgorithmToken('chacha-20'), 'chacha20');        // database key, hyphens dropped
    assert.equal(canonicalizeAlgorithmToken('x25519-kyber768'), 'kyber-768'); // alias, hyphens dropped
  });
});
