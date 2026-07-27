import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { collectFindings, toSarif } from '../lib/sarif.mjs';
import { VERSION } from '../lib/version.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

const SCAN = {
  weakPatterns: [
    { file: 'src/auth.js', line: 4, algorithm: 'md5', issue: 'MD5: Collision attacks', severity: 'critical', cwe: 'CWE-328' },
    { file: 'src/auth.js', line: 9, issue: 'createCipher derives an IV from the key', severity: 'critical', fix: 'use createCipheriv' },
  ],
  secrets: [
    { type: 'stripe', name: 'Stripe Secret Key', file: 'src/auth.js', line: 2, envVar: 'STRIPE_SECRET_KEY', severity: 'critical' },
  ],
  tlsFindings: [
    { protocol: 'TLSv1.0', risk: 'critical', file: 'nginx.conf', line: 12, recommendation: 'require TLS 1.2 or newer' },
  ],
};

describe('version', () => {
  it('matches package.json rather than a hardcoded literal', () => {
    const pkg = JSON.parse(readFileSync(join(HERE, '..', 'package.json'), 'utf-8'));
    assert.equal(VERSION, pkg.version);
  });

  it('is never the placeholder', () => {
    assert.notEqual(VERSION, '0.0.0-unknown');
  });
});

describe('collectFindings', () => {
  it('collects weak algorithms, secrets and TLS findings', () => {
    const findings = collectFindings(SCAN);
    assert.equal(findings.length, 4);
    assert.ok(findings.some(f => f.kind === 'weak-algorithm' && f.algorithm === 'md5'));
    assert.ok(findings.some(f => f.kind === 'misuse'));
    assert.ok(findings.some(f => f.kind === 'secret' && f.type === 'stripe'));
    assert.ok(findings.some(f => f.kind === 'tls'));
  });

  it('tolerates a scan result with no findings', () => {
    assert.deepEqual(collectFindings({}), []);
  });
});

describe('toSarif', () => {
  it('emits a well-formed SARIF 2.1.0 log', () => {
    const doc = toSarif(collectFindings(SCAN));
    assert.equal(doc.version, '2.1.0');
    assert.ok(doc.$schema.includes('sarif-2.1.0'));
    assert.equal(doc.runs.length, 1);
    assert.equal(doc.runs[0].tool.driver.name, 'CryptoServe');
    assert.equal(doc.runs[0].tool.driver.version, VERSION);
  });

  it('gives every result a physical location with a line', () => {
    // A SARIF result without a location cannot be rendered by GitHub code
    // scanning. This is the reason findings carry file:line at all.
    const doc = toSarif(collectFindings(SCAN));
    for (const result of doc.runs[0].results) {
      assert.equal(result.locations.length, 1, `no location on ${result.ruleId}`);
      const phys = result.locations[0].physicalLocation;
      assert.ok(phys.artifactLocation.uri, `no uri on ${result.ruleId}`);
      assert.ok(phys.region.startLine > 0, `no startLine on ${result.ruleId}`);
    }
  });

  it('declares a rule for every distinct ruleId used', () => {
    const doc = toSarif(collectFindings(SCAN));
    const declared = new Set(doc.runs[0].tool.driver.rules.map(r => r.id));
    for (const result of doc.runs[0].results) {
      assert.ok(declared.has(result.ruleId), `undeclared rule ${result.ruleId}`);
    }
  });

  it('maps severity onto SARIF levels', () => {
    const doc = toSarif([
      { kind: 'weak-algorithm', algorithm: 'md5', message: 'a', severity: 'critical', file: 'a.js', line: 1 },
      { kind: 'weak-algorithm', algorithm: 'aes-cbc', message: 'b', severity: 'medium', file: 'a.js', line: 2 },
      { kind: 'weak-algorithm', algorithm: 'x', message: 'c', severity: 'low', file: 'a.js', line: 3 },
    ]);
    assert.deepEqual(doc.runs[0].results.map(r => r.level), ['error', 'warning', 'note']);
  });

  it('carries the fix into the result message', () => {
    const doc = toSarif(collectFindings(SCAN));
    const misuse = doc.runs[0].results.find(r => r.ruleId === 'cryptoserve/api-misuse');
    assert.ok(misuse.message.text.includes('Fix:'));
  });

  it('normalizes Windows path separators to forward slashes', () => {
    const doc = toSarif([{ kind: 'secret', type: 'aws', message: 'm', severity: 'critical', file: 'src\\deep\\a.js', line: 1 }]);
    assert.equal(doc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'src/deep/a.js');
  });

  it('produces an empty run rather than throwing on no findings', () => {
    const doc = toSarif([]);
    assert.deepEqual(doc.runs[0].results, []);
    assert.deepEqual(doc.runs[0].tool.driver.rules, []);
  });
});
