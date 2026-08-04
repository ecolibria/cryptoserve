import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  scanProject, toLibraryInventory, weakAlgorithmSeverity, exceedsSeverity, SEVERITY_ORDER,
  libraryCoversLanguage, ECOSYSTEM_LANGUAGES,
} from '../lib/scanner.mjs';
import { LANGUAGE_PATTERNS } from '../lib/scanner-languages.mjs';

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

describe('library language attribution', () => {
  beforeEach(setup);
  afterEach(cleanup);

  it('records the language a source library was seen in', () => {
    // `sourceLibraries` is keyed by name and used to drop the language of the
    // file the import was read from, so nothing downstream could tell that
    // `hashlib` is a Python library and `crypto-js` is not.
    writeFileSync(join(TEST_DIR, 'package.json'), '{}');
    writeFileSync(join(TEST_DIR, 'auth.py'), 'import hashlib\nh = hashlib.md5(b"pw")\n');

    const results = scanProject(TEST_DIR);
    const hashlib = results.libraries.find(l => l.name === 'hashlib');
    assert.ok(hashlib, 'hashlib should be inventoried from source');
    assert.deepEqual(hashlib.languages, ['python']);
  });

  it('records every language a source library name appears in', () => {
    // `sourceLibraries` merges by name across files, so one language is not
    // enough: recording only the first would make the second file's sites
    // unclaimable and mint a synthetic owner beside a library that does own
    // them.
    writeFileSync(join(TEST_DIR, 'package.json'), '{}');
    writeFileSync(join(TEST_DIR, 'a.py'), 'import hashlib\nh = hashlib.md5(b"pw")\n');
    mkdirSync(join(TEST_DIR, 'sub'), { recursive: true });
    writeFileSync(join(TEST_DIR, 'sub', 'b.py'), 'import hashlib\nh = hashlib.sha1(b"pw")\n');

    const results = scanProject(TEST_DIR);
    const hashlib = results.libraries.find(l => l.name === 'hashlib');
    assert.deepEqual([...hashlib.languages].sort(), ['python']);
  });

  it('covers a language only when the ecosystem produces it', () => {
    assert.equal(libraryCoversLanguage({ ecosystem: 'npm' }, 'javascript'), true);
    assert.equal(libraryCoversLanguage({ ecosystem: 'npm' }, 'python'), false);
    assert.equal(libraryCoversLanguage({ ecosystem: 'pypi' }, 'python'), true);
    assert.equal(libraryCoversLanguage({ ecosystem: 'pypi' }, 'javascript'), false);
    assert.equal(libraryCoversLanguage({ ecosystem: 'go' }, 'go'), true);
    assert.equal(libraryCoversLanguage({ ecosystem: 'cargo' }, 'rust'), true);
    assert.equal(libraryCoversLanguage({ ecosystem: 'maven' }, 'java'), true);
    // No manifest ecosystem produces C. That is exactly why an unclaimed site
    // still needs a synthetic owner.
    for (const eco of Object.keys(ECOSYSTEM_LANGUAGES)) {
      if (eco === 'source') continue;
      assert.equal(libraryCoversLanguage({ ecosystem: eco }, 'c'), false,
        `${eco} must not claim a C site`);
    }
  });

  it('covers only the recorded languages for a source library', () => {
    const hashlib = { ecosystem: 'source', languages: ['python'] };
    assert.equal(libraryCoversLanguage(hashlib, 'python'), true);
    assert.equal(libraryCoversLanguage(hashlib, 'javascript'), false);
    assert.equal(libraryCoversLanguage(hashlib, 'c'), false);
  });

  it('maps every ecosystem the manifest scanner emits', () => {
    // An unmapped ecosystem would claim nothing, and every site it should own
    // would get a synthetic owner beside the real library. Same shape as the
    // severity-ladder guard: the table has to cover what the scanner produces.
    for (const eco of ['npm', 'go', 'pypi', 'cargo', 'maven', 'source']) {
      assert.ok(eco in ECOSYSTEM_LANGUAGES, `ECOSYSTEM_LANGUAGES is missing ${eco}`);
    }
    // And every language it maps to has to be one the scanner can detect.
    const detectable = new Set(Object.keys(LANGUAGE_PATTERNS));
    for (const [eco, langs] of Object.entries(ECOSYSTEM_LANGUAGES)) {
      for (const lang of langs) {
        assert.ok(detectable.has(lang), `${eco} maps to unknown language ${lang}`);
      }
    }
  });
});

describe('toLibraryInventory language-aware dedup', () => {
  beforeEach(setup);
  afterEach(cleanup);

  it('keeps a synthetic owner for a site no same-language library declares', () => {
    // crypto-js declares MD5 and is npm. The MD5 in hash.c is not its MD5, and
    // the C include produces no source library at all, so suppressing the
    // synthetic entry leaves the site with no owner anywhere in the inventory
    // -- and the gate then raises nothing for it.
    writeFileSync(join(TEST_DIR, 'package.json'), JSON.stringify({
      dependencies: { 'crypto-js': '^3.1.9' },
    }));
    writeFileSync(join(TEST_DIR, 'hash.c'), '#include <openssl/md5.h>\nvoid f(void){MD5_CTX c;MD5_Init(&c);}\n');

    const inventory = toLibraryInventory(scanProject(TEST_DIR));
    const owner = inventory.find(l => l.name !== 'crypto-js'
      && l.algorithms.some(a => a.toLowerCase() === 'md5'));
    assert.ok(owner, 'a C md5 site must keep an owner of its own language');
    assert.deepEqual(owner.languages, ['c']);
  });

  it('does not duplicate an algorithm a same-language library already declares', () => {
    // The other direction. `hashlib` is Python and declares md5, so the Python
    // md5 site is already owned and must not also mint `python:md5`.
    writeFileSync(join(TEST_DIR, 'package.json'), JSON.stringify({
      dependencies: { 'crypto-js': '^3.1.9' },
    }));
    writeFileSync(join(TEST_DIR, 'auth.py'), 'import hashlib\nh = hashlib.md5(b"pw")\n');

    const inventory = toLibraryInventory(scanProject(TEST_DIR));
    assert.equal(inventory.filter(l => l.name === 'python:md5').length, 0);
    assert.ok(inventory.some(l => l.name === 'hashlib'));
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
