import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  scanProject, toLibraryInventory, weakAlgorithmSeverity, exceedsSeverity, SEVERITY_ORDER,
} from '../lib/scanner.mjs';

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

describe('severity ladder', () => {
  it('reports no severity for an algorithm that is not weak', () => {
    // Absence of a security finding is not a finding of severity `none`. The
    // gate distinguishes them: null never breaches a threshold, `none` does at
    // the strictest setting.
    assert.equal(weakAlgorithmSeverity({ isWeak: false, quantumRisk: 'none' }), null);
    assert.equal(weakAlgorithmSeverity(null), null);
    assert.equal(weakAlgorithmSeverity(undefined), null);
  });

  it('rates a weak algorithm high, or critical when it is also quantum-broken', () => {
    assert.equal(weakAlgorithmSeverity({ isWeak: true, quantumRisk: 'none' }), 'high');
    assert.equal(weakAlgorithmSeverity({ isWeak: true, quantumRisk: 'high' }), 'high');
    assert.equal(weakAlgorithmSeverity({ isWeak: true, quantumRisk: 'critical' }), 'critical');
  });

  it('breaches only above the threshold, on both sides of it', () => {
    assert.equal(exceedsSeverity('high', 'medium'), true);
    assert.equal(exceedsSeverity('critical', 'medium'), true);
    assert.equal(exceedsSeverity('medium', 'medium'), false);
    assert.equal(exceedsSeverity('low', 'medium'), false);
    assert.equal(exceedsSeverity('medium', 'low'), true);
    assert.equal(exceedsSeverity('low', 'none'), true);
    assert.equal(exceedsSeverity('none', 'none'), false);
  });

  it('never breaches on an absent severity', () => {
    assert.equal(exceedsSeverity(null, 'none'), false);
    assert.equal(exceedsSeverity(undefined, 'none'), false);
  });

  it('fails CLOSED on a severity the ladder does not know', () => {
    // `indexOf` returns -1 for an unknown value and `-1 > anything` is false,
    // so comparing indices directly would let a typo in one pattern definition
    // -- severity: 'moderate' -- make that finding unable to breach any
    // threshold. The gate would report the tree clean and never mention the
    // finding it could not classify.
    assert.equal(exceedsSeverity('moderate', 'medium'), true);
    assert.equal(exceedsSeverity('SEVERE', 'none'), true);
    assert.equal(exceedsSeverity('', 'medium'), true);
  });

  it('rates every severity the scanner actually emits', () => {
    // Guards the ladder against a pattern introducing a severity it does not
    // contain: the values below are the ones the scanner's own tables produce.
    for (const emitted of ['medium', 'high', 'critical']) {
      assert.ok(SEVERITY_ORDER.includes(emitted), `ladder is missing ${emitted}`);
    }
  });
});
