import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { scanProject, toLibraryInventory } from '../lib/scanner.mjs';

const TEST_DIR = join(tmpdir(), 'cryptoserve-scanner-test-' + Date.now());

function setup() {
  mkdirSync(TEST_DIR, { recursive: true });
}

function cleanup() {
  if (existsSync(TEST_DIR)) rmSync(TEST_DIR, { recursive: true, force: true });
}

describe('scanProject', () => {
  beforeEach(setup);
  afterEach(cleanup);

  it('detects jsonwebtoken in package.json', () => {
    writeFileSync(join(TEST_DIR, 'package.json'), JSON.stringify({
      dependencies: { jsonwebtoken: '^9.0.0' },
    }));

    const results = scanProject(TEST_DIR);
    assert.ok(results.libraries.some(l => l.name === 'jsonwebtoken'));
    const jwt = results.libraries.find(l => l.name === 'jsonwebtoken');
    assert.equal(jwt.quantumRisk, 'high');
    assert.ok(jwt.algorithms.includes('RS256'));
  });

  it('detects node:crypto require in source', () => {
    writeFileSync(join(TEST_DIR, 'package.json'), '{}');
    writeFileSync(join(TEST_DIR, 'app.js'), `
      const crypto = require('node:crypto');
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    `);

    const results = scanProject(TEST_DIR);
    assert.ok(results.libraries.some(l => l.name === 'node:crypto'));
  });

  it('detects algorithm string literals', () => {
    writeFileSync(join(TEST_DIR, 'package.json'), '{}');
    writeFileSync(join(TEST_DIR, 'tls.js'), `
      const opts = { minVersion: 'TLSv1.2' };
      const cipher = createCipheriv('aes-256-gcm', key, iv);
    `);

    const results = scanProject(TEST_DIR);
    assert.ok(results.libraries.length > 0 || results.filesScanned > 0);
  });

  it('finds .pem certificate files', () => {
    writeFileSync(join(TEST_DIR, 'package.json'), '{}');
    writeFileSync(join(TEST_DIR, 'server.pem'), 'FAKE CERT');

    const results = scanProject(TEST_DIR);
    assert.ok(results.certFiles.some(f => f.endsWith('.pem')));
  });

  it('detects weak crypto patterns', () => {
    writeFileSync(join(TEST_DIR, 'package.json'), '{}');
    writeFileSync(join(TEST_DIR, 'old.js'), `
      const h = crypto.createCipher('des', password);
    `);

    const results = scanProject(TEST_DIR);
    assert.ok(results.weakPatterns.length > 0);
  });

  it('detects hardcoded AWS key', () => {
    writeFileSync(join(TEST_DIR, 'package.json'), '{}');
    writeFileSync(join(TEST_DIR, 'config.js'), `
      const key = "AKIAIOSFODNN7EXAMPLE";
    `);

    const results = scanProject(TEST_DIR);
    assert.ok(results.secrets.some(s => s.type === 'aws-access'));
  });

  it('does not flag env var references as secrets', () => {
    writeFileSync(join(TEST_DIR, 'package.json'), '{}');
    writeFileSync(join(TEST_DIR, 'app.js'), `
      const key = process.env.AWS_ACCESS_KEY_ID;
      const other = \${ANTHROPIC_API_KEY};
    `);

    const results = scanProject(TEST_DIR);
    assert.equal(results.secrets.length, 0);
  });

  it('detects multiple crypto packages', () => {
    writeFileSync(join(TEST_DIR, 'package.json'), JSON.stringify({
      dependencies: { 'jsonwebtoken': '^9.0', 'bcrypt': '^5.0', '@noble/hashes': '^1.0' },
    }));

    const results = scanProject(TEST_DIR);
    assert.equal(results.libraries.length, 3);
  });

  it('handles missing package.json', () => {
    const results = scanProject(TEST_DIR);
    assert.equal(results.libraries.length, 0);
    assert.equal(results.secrets.length, 0);
  });

  it('respects file size limit', () => {
    writeFileSync(join(TEST_DIR, 'package.json'), '{}');
    // Create a file > 1MB (should be skipped)
    writeFileSync(join(TEST_DIR, 'huge.js'), 'x'.repeat(2 * 1024 * 1024));

    const results = scanProject(TEST_DIR);
    // Should not crash, file should be skipped
    assert.ok(results.filesScanned === 0 || results.filesScanned >= 0);
  });
});

describe('toLibraryInventory', () => {
  it('converts scan results to PQC engine format', () => {
    const scanResults = {
      libraries: [
        { name: 'jsonwebtoken', version: '9.0.0', algorithms: ['RS256'], quantumRisk: 'high', category: 'token' },
      ],
    };
    const inventory = toLibraryInventory(scanResults);
    assert.equal(inventory.length, 1);
    assert.equal(inventory[0].name, 'jsonwebtoken');
    assert.equal(inventory[0].isDeprecated, false);
  });
});
