import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { CRYPTO_PACKAGES, lookupPackage, lookupNpmPackage } from '../lib/crypto-registry.mjs';

describe('CRYPTO_PACKAGES', () => {
  it('has all 5 ecosystems', () => {
    assert.ok(CRYPTO_PACKAGES.npm);
    assert.ok(CRYPTO_PACKAGES.go);
    assert.ok(CRYPTO_PACKAGES.pypi);
    assert.ok(CRYPTO_PACKAGES.cargo);
    assert.ok(CRYPTO_PACKAGES.maven);
  });

  it('npm has common packages', () => {
    assert.ok(CRYPTO_PACKAGES.npm['jsonwebtoken']);
    assert.ok(CRYPTO_PACKAGES.npm['bcrypt']);
    assert.ok(CRYPTO_PACKAGES.npm['@noble/curves']);
    assert.ok(CRYPTO_PACKAGES.npm['@noble/post-quantum']);
  });

  it('go has standard library crypto', () => {
    assert.ok(CRYPTO_PACKAGES.go['crypto/rsa']);
    assert.ok(CRYPTO_PACKAGES.go['crypto/ecdsa']);
    assert.ok(CRYPTO_PACKAGES.go['golang.org/x/crypto']);
  });

  it('pypi has cryptography and bcrypt', () => {
    assert.ok(CRYPTO_PACKAGES.pypi['cryptography']);
    assert.ok(CRYPTO_PACKAGES.pypi['bcrypt']);
  });

  it('cargo has ring and aes-gcm', () => {
    assert.ok(CRYPTO_PACKAGES.cargo['ring']);
    assert.ok(CRYPTO_PACKAGES.cargo['aes-gcm']);
  });

  it('maven has bouncycastle', () => {
    assert.ok(CRYPTO_PACKAGES.maven['org.bouncycastle']);
  });
});

describe('lookupPackage', () => {
  it('finds direct npm match', () => {
    const result = lookupPackage('jsonwebtoken', 'npm');
    assert.ok(result);
    assert.equal(result.quantumRisk, 'high');
  });

  it('finds Go crypto subpackage', () => {
    const result = lookupPackage('golang.org/x/crypto/argon2', 'go');
    assert.ok(result);
    assert.ok(result.algorithms.includes('argon2'));
  });

  it('finds Go standard library', () => {
    const result = lookupPackage('crypto/rsa', 'go');
    assert.ok(result);
    assert.ok(result.algorithms.includes('rsa'));
  });

  it('finds Maven by groupId', () => {
    const result = lookupPackage('org.bouncycastle:bcprov-jdk18on', 'maven');
    assert.ok(result);
    assert.equal(result.name, 'org.bouncycastle');
  });

  it('returns null for unknown package', () => {
    assert.equal(lookupPackage('unknown-pkg', 'npm'), null);
  });

  it('returns null for unknown ecosystem', () => {
    assert.equal(lookupPackage('test', 'swift'), null);
  });
});

describe('lookupNpmPackage', () => {
  it('returns display-name algorithms', () => {
    const result = lookupNpmPackage('jsonwebtoken');
    assert.ok(result);
    assert.ok(result.algorithms.includes('RS256'));
    assert.equal(result.quantumRisk, 'high');
    assert.equal(result.category, 'token');
  });

  it('returns correct category for crypto-js', () => {
    const result = lookupNpmPackage('crypto-js');
    assert.ok(result);
    assert.equal(result.category, 'symmetric');
    assert.ok(result.algorithms.includes('AES'));
  });

  it('returns correct data for @noble/post-quantum', () => {
    const result = lookupNpmPackage('@noble/post-quantum');
    assert.ok(result);
    assert.equal(result.quantumRisk, 'none');
    assert.equal(result.category, 'pqc');
    assert.ok(result.algorithms.includes('ML-KEM'));
  });

  it('returns null for unknown npm package', () => {
    assert.equal(lookupNpmPackage('express'), null);
  });
});
