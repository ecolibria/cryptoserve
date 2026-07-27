import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { scanProject } from '../lib/scanner.mjs';
import {
  buildFindingRecords,
  pathFlags,
  wideContext,
  extractImportBlock,
  findingId,
  projectIdentity,
  toJsonl,
} from '../lib/finding-records.mjs';

// Kept in lockstep with triage-slm corpusgen/schema.py TOP_LEVEL_KEYS. The
// pipeline validator rejects a record with any key outside its closed set, so
// drift here means every emitted record is silently refused at ingestion.
const REQUIRED_KEYS = [
  'findingId', 'package', 'file', 'line', 'column', 'language', 'detector',
  'algorithm', 'category', 'library', 'functionCall', 'confidencePrior', 'cwe',
  'pathFlags', 'context', 'labels', 'generatorVersion', 'sanitizerVersion',
];
const OPTIONAL_KEYS = ['origin'];
const LABEL_KEYS = ['realVsNoise', 'algorithmClass', 'quantumStatus', 'migrationPriority'];
const PATH_FLAG_KEYS = ['isTestLike', 'isVendoredLike', 'isDocsLike'];

let dir;
function setup() {
  dir = mkdtempSync(join(tmpdir(), 'cs-records-'));
  mkdirSync(join(dir, 'src'), { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'demo-app', version: '2.1.0' }));
  writeFileSync(join(dir, 'src', 'a.js'), [
    "const crypto = require('node:crypto');",
    '',
    'function legacy(v) {',
    "  return crypto.createHash('md5').update(v).digest('hex');",
    '}',
  ].join('\n'));
}
function cleanup() { rmSync(dir, { recursive: true, force: true }); }

describe('pathFlags', () => {
  it('matches whole lowercased segments only', () => {
    assert.deepEqual(pathFlags('src/tests/a.js'), { isTestLike: true, isVendoredLike: false, isDocsLike: false });
    assert.deepEqual(pathFlags('vendor/x/a.js'), { isTestLike: false, isVendoredLike: true, isDocsLike: false });
    assert.deepEqual(pathFlags('docs/a.js'), { isTestLike: false, isVendoredLike: false, isDocsLike: true });
  });

  it('does not match a segment by substring', () => {
    // "contest" contains "test"; the corpus heuristic is exact-segment, and a
    // looser rule here would shift the model's input distribution.
    assert.equal(pathFlags('src/contest/a.js').isTestLike, false);
    assert.equal(pathFlags('src/latest/a.js').isTestLike, false);
  });

  it('is case insensitive', () => {
    assert.equal(pathFlags('src/Tests/a.js').isTestLike, true);
  });
});

describe('wideContext', () => {
  const lines = Array.from({ length: 40 }, (_, i) => `line ${i + 1}`);

  it('takes up to 10 lines either side', () => {
    const ctx = wideContext(lines, 20, 'javascript');
    assert.equal(ctx.before.length, 10);
    assert.equal(ctx.after.length, 10);
    assert.equal(ctx.line, 'line 20');
    assert.equal(ctx.before[0], 'line 10');
    assert.equal(ctx.after[9], 'line 30');
  });

  it('clamps at the start and end of a file', () => {
    assert.equal(wideContext(lines, 1, 'javascript').before.length, 0);
    assert.equal(wideContext(lines, 40, 'javascript').after.length, 0);
  });

  it('returns an empty context for an out-of-range line', () => {
    const ctx = wideContext(lines, 999, 'javascript');
    assert.equal(ctx.line, '');
    assert.deepEqual(ctx.before, []);
  });

  it('truncates a long line with the corpus marker', () => {
    const ctx = wideContext(['x'.repeat(500)], 1, 'javascript');
    assert.ok(ctx.line.endsWith('...[TRUNCATED]'));
    assert.equal(ctx.line.length, 400 + '...[TRUNCATED]'.length);
  });
});

describe('extractImportBlock', () => {
  it('collects require and import forms in file order', () => {
    const imports = extractImportBlock([
      "const a = require('node:crypto');",
      'const x = 1;',
      "import b from 'jose';",
    ], 'javascript');
    assert.equal(imports.length, 2);
    assert.match(imports[0], /require/);
  });

  it('caps the block at 20 lines', () => {
    const many = Array.from({ length: 50 }, (_, i) => `import x${i} from 'm${i}';`);
    assert.equal(extractImportBlock(many, 'javascript').length, 20);
  });

  it('returns empty for a language with no import matcher', () => {
    assert.deepEqual(extractImportBlock(['anything'], 'cobol'), []);
  });
});

describe('findingId', () => {
  it('is 16 lowercase hex characters', () => {
    const id = findingId({ name: 'demo', ecosystem: 'npm', version: '1.0.0' }, 'a.js', 4, 'md5');
    assert.match(id, /^[0-9a-f]{16}$/);
  });

  it('is stable for the same identity, location and algorithm', () => {
    const pkg = { name: 'demo', ecosystem: 'npm', version: '1.0.0' };
    assert.equal(findingId(pkg, 'a.js', 4, 'md5'), findingId(pkg, 'a.js', 4, 'md5'));
  });

  it('differs when any component differs', () => {
    const pkg = { name: 'demo', ecosystem: 'npm', version: '1.0.0' };
    const base = findingId(pkg, 'a.js', 4, 'md5');
    assert.notEqual(base, findingId(pkg, 'a.js', 5, 'md5'));
    assert.notEqual(base, findingId(pkg, 'b.js', 4, 'md5'));
    assert.notEqual(base, findingId(pkg, 'a.js', 4, 'sha1'));
    assert.notEqual(base, findingId({ ...pkg, version: '1.0.1' }, 'a.js', 4, 'md5'));
  });
});

describe('projectIdentity', () => {
  beforeEach(setup);
  afterEach(cleanup);

  it('reads name and version from package.json under the local ecosystem', () => {
    // Never a registry ecosystem: a private fork must not be recorded under the
    // public package's identity.
    assert.deepEqual(projectIdentity(dir), { name: 'demo-app', ecosystem: 'local', version: '2.1.0' });
  });

  it('falls back to the directory name with no manifest', () => {
    const bare = mkdtempSync(join(tmpdir(), 'cs-bare-'));
    try {
      const id = projectIdentity(bare);
      assert.equal(id.ecosystem, 'local');
      assert.ok(id.name.length > 0);
      assert.equal(id.version, '0.0.0');
    } finally {
      rmSync(bare, { recursive: true, force: true });
    }
  });
});

describe('buildFindingRecords', () => {
  beforeEach(setup);
  afterEach(cleanup);

  it('emits one schema-shaped record per source algorithm', () => {
    const records = buildFindingRecords(scanProject(dir), dir);
    assert.ok(records.length > 0, 'expected at least one record');

    for (const r of records) {
      for (const key of REQUIRED_KEYS) {
        assert.ok(key in r, `missing required key ${key}`);
      }
      for (const key of Object.keys(r)) {
        assert.ok(
          REQUIRED_KEYS.includes(key) || OPTIONAL_KEYS.includes(key),
          `key ${key} is outside the corpus schema and will be rejected at ingestion`
        );
      }
      assert.deepEqual(Object.keys(r.labels).sort(), [...LABEL_KEYS].sort());
      assert.deepEqual(Object.keys(r.pathFlags).sort(), [...PATH_FLAG_KEYS].sort());
      assert.deepEqual(Object.keys(r.package).sort(), ['ecosystem', 'name', 'version']);
    }
  });

  it('never fills a label', () => {
    // Labels come from a teacher LLM or a human. A scan has no ground truth,
    // and a triage model must never label its own training data.
    const records = buildFindingRecords(scanProject(dir), dir);
    for (const r of records) {
      for (const axis of LABEL_KEYS) {
        assert.equal(r.labels[axis], null, `${axis} was filled by the emitter`);
      }
    }
  });

  it('marks every record as field origin', () => {
    // The eval path excludes this origin. Without the marker, records from a
    // user's own tree could reach a gold set and every released number would
    // be scored on data the model may have trained on.
    const records = buildFindingRecords(scanProject(dir), dir);
    assert.ok(records.length > 0);
    for (const r of records) assert.equal(r.origin, 'field');
  });

  it('carries the detected line, its context and the import block', () => {
    const records = buildFindingRecords(scanProject(dir), dir);
    const md5 = records.find(r => r.algorithm === 'md5');
    assert.ok(md5, 'md5 record expected');
    assert.equal(md5.file, 'src/a.js');
    assert.equal(md5.line, 4);
    assert.match(md5.context.line, /createHash\('md5'\)/);
    assert.ok(md5.context.imports.some(i => /require\('node:crypto'\)/.test(i)));
    assert.equal(md5.detector, 'regex');
    assert.ok(md5.confidencePrior > 0 && md5.confidencePrior <= 1);
  });

  it('deduplicates identical findings', () => {
    const records = buildFindingRecords(scanProject(dir), dir);
    const ids = records.map(r => r.findingId);
    assert.equal(new Set(ids).size, ids.length);
  });

  it('returns an empty list for a scan with no source algorithms', () => {
    assert.deepEqual(buildFindingRecords({ sourceAlgorithms: [] }, dir), []);
    assert.deepEqual(buildFindingRecords({}, dir), []);
  });
});

describe('toJsonl', () => {
  beforeEach(setup);
  afterEach(cleanup);

  it('emits one parseable JSON object per line', () => {
    const records = buildFindingRecords(scanProject(dir), dir);
    const lines = toJsonl(records).split('\n');
    assert.equal(lines.length, records.length);
    for (const line of lines) {
      assert.equal(typeof JSON.parse(line).findingId, 'string');
    }
  });

  it('emits nothing for no records', () => {
    assert.equal(toJsonl([]), '');
  });
});

describe('credential redaction', () => {
  let secretDir;
  // Assembled at runtime. A literal in this file matches the same detectors the
  // scanner uses, so GitHub push protection rejects the commit and the
  // regression test can never be committed at all. The temp fixture written
  // below still contains the full string, which is what the scanner reads.
  const FAKE_STRIPE = 'sk_' + 'live_' + '0'.repeat(28);
  const FAKE_AWS = 'AKI' + 'A' + '0'.repeat(16);

  beforeEach(() => {
    secretDir = mkdtempSync(join(tmpdir(), 'cs-redact-'));
    mkdirSync(join(secretDir, 'src'), { recursive: true });
    writeFileSync(join(secretDir, 'package.json'), JSON.stringify({ name: 'leaky', version: '1.0.0' }));
    writeFileSync(join(secretDir, 'src', 'a.js'), [
      "const crypto = require('node:crypto');",
      `const KEY = '${FAKE_STRIPE}';`,
      `const AWS = '${FAKE_AWS}';`,
      "const h = crypto.createHash('md5');",
    ].join('\n'));
  });
  afterEach(() => rmSync(secretDir, { recursive: true, force: true }));

  it('never writes a credential into an emitted record', () => {
    // Context is the caller's own source. Emitting it verbatim would copy any
    // credential inside the window into a corpus file.
    const records = buildFindingRecords(scanProject(secretDir), secretDir);
    assert.ok(records.length > 0);
    const serialized = toJsonl(records);
    assert.ok(!serialized.includes(FAKE_STRIPE), 'Stripe key leaked into records');
    assert.ok(!serialized.includes(FAKE_AWS), 'AWS key leaked into records');
    assert.ok(serialized.includes('[REDACTED-CREDENTIAL]'), 'expected a redaction marker');
  });

  it('records the redaction pass it actually ran', () => {
    // Never null and never the corpus sanitizer's version: claiming a
    // sanitizer that did not run is worse than recording a weaker one.
    const records = buildFindingRecords(scanProject(secretDir), secretDir);
    for (const r of records) {
      assert.equal(r.sanitizerVersion, 'cryptoserve-cli-redact/1');
    }
  });

  it('keeps non-credential source intact', () => {
    const records = buildFindingRecords(scanProject(secretDir), secretDir);
    const md5 = records.find(r => r.algorithm === 'md5');
    assert.ok(md5.context.line.includes("createHash('md5')"));
  });
});
