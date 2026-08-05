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

  /**
   * SARIF is the one artifact a CI job uploads, so it must not be the only
   * surface that cannot tell a clean tree from a waived one. This repository
   * has been burned by that already: a gate failed a build on three manifest
   * violations and uploaded a document naming none of them.
   */
  describe('waived findings', () => {
    const WAIVED = {
      weakPatterns: [],
      waivedFindings: [{
        rule: 'misuse/node-tls-reject-unauthorized',
        file: 'app.js',
        line: 4,
        issue: 'TLS certificate verification disabled process-wide',
        severity: 'critical',
        reason: 'a severity table, not an assignment',
      }],
    };

    it('reports a waived finding as a suppressed result', () => {
      // Present and dismissed, not absent. An alert that is missing and an
      // alert that was deliberately cleared are different claims, and only one
      // of them is auditable after the fact.
      const [result] = toSarif(collectFindings(WAIVED)).runs[0].results;
      assert.equal(result.ruleId, 'cryptoserve/api-misuse');
      assert.equal(result.suppressions.length, 1);
      assert.equal(result.suppressions[0].kind, 'inSource');
      assert.match(result.suppressions[0].justification, /a severity table, not an assignment/);
    });

    it('names the rule that was waived in the justification', () => {
      const [result] = toSarif(collectFindings(WAIVED)).runs[0].results;
      assert.match(result.suppressions[0].justification, /misuse\/node-tls-reject-unauthorized/);
    });

    it('keeps the location so the dismissed alert points somewhere', () => {
      const [result] = toSarif(collectFindings(WAIVED)).runs[0].results;
      assert.equal(result.locations[0].physicalLocation.region.startLine, 4);
    });

    it('does not put suppressions on findings nobody waived', () => {
      // The other direction. A stray `suppressions` array on a live finding
      // would dismiss a real alert in code scanning.
      for (const result of toSarif(collectFindings(SCAN)).runs[0].results) {
        assert.equal(result.suppressions, undefined, JSON.stringify(result));
      }
    });

    it('collects a waived finding count that no argument limit can reject', () => {
      // `push(...arr)` passes every element as a separate argument, so a large
      // enough array throws RangeError instead of being appended. The misuse
      // loop deliberately keeps reading past a waived match, so this array is
      // unbounded per file where the pre-waiver code reported at most one
      // finding per pattern per file -- which is why the same spread was safe
      // before and is not now.
      //
      // Measured rather than assumed: four ~1MB files, each under the DEFAULT
      // maxFileSize with no config change, took `scan --format sarif` and
      // `gate --format sarif` to "Maximum call stack size exceeded", and with
      // `--output` no file was written at all, so a CI upload step received
      // nothing. The identical hazard was found and fixed at the waiver-warning
      // site in lib/scanner.mjs; these two sites are the rest of that class.
      const waivedFindings = Array.from({ length: 200_000 }, (_, i) => ({
        rule: 'misuse/tls-verify-disabled',
        file: 'src/bulk.js',
        line: i + 1,
        issue: 'TLS certificate verification disabled',
        severity: 'critical',
        reason: 'bulk',
        evidence: 'rejectUnauthorized: false',
      }));

      const findings = collectFindings({ ...SCAN, waivedFindings });
      assert.equal(findings.length, 200_000 + 4);
      // And the document still builds from them.
      assert.equal(toSarif(findings).runs[0].results.length, 200_000 + 4);
    });
  });
});
