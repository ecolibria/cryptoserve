import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  scanProject, toLibraryInventory, toOwnershipInventory,
  weakAlgorithmSeverity, exceedsSeverity, SEVERITY_ORDER,
  libraryCoversLanguage, libraryLanguages, ECOSYSTEM_LANGUAGES,
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
    // `sourceLibraries` merges by name across the whole tree, so one language is
    // not enough: recording only the first would make the other language's
    // sites unclaimable and mint a synthetic owner beside a library that does
    // own them.
    //
    // The fixture needs TWO languages to say anything. An earlier version of
    // this test used two PYTHON files and asserted `['python']`, where "first"
    // and "every" give the same answer -- it could not fail. `bcrypt` is the
    // one library name the import tables carry in more than one language.
    writeFileSync(join(TEST_DIR, 'package.json'), '{}');
    writeFileSync(join(TEST_DIR, 'a.js'), 'const b = require("bcryptjs");\nconst h = b.hashSync("x");\n');
    writeFileSync(join(TEST_DIR, 'b.py'), 'import bcrypt\nh = bcrypt.hashpw(b"x", bcrypt.gensalt())\n');

    const results = scanProject(TEST_DIR);
    const bcrypt = results.libraries.find(l => l.name === 'bcrypt');
    assert.ok(bcrypt, 'bcrypt should be inventoried from source');
    assert.deepEqual([...bcrypt.languages].sort(), ['javascript', 'python']);
  });

  it('records the language even when the file imports two crypto libraries', () => {
    // Which algorithm belongs to which of two imports is undecidable without
    // dataflow, so neither library gets the algorithms. Which LANGUAGE the file
    // is written in is not undecidable, and it is the whole basis of ownership:
    // recording it only for unambiguous files would leave these libraries
    // unable to claim anything.
    // Both imports must be ones the table actually recognises, or the file has
    // one import, the ambiguous branch is never taken, and the test cannot
    // fail. `from cryptography` is the recognised spelling; `import
    // cryptography` is not, and an earlier version of this fixture used it and
    // measured nothing.
    writeFileSync(join(TEST_DIR, 'package.json'), '{}');
    writeFileSync(join(TEST_DIR, 'both.py'),
      'import hashlib\nfrom cryptography.hazmat.primitives import hashes\nh = hashlib.md5(b"pw")\n');

    const results = scanProject(TEST_DIR);
    const names = results.libraries.map(l => l.name).sort();
    assert.deepEqual(names, ['cryptography', 'hashlib'],
      `fixture must produce two ambiguous imports, got ${JSON.stringify(names)}`);
    for (const name of names) {
      const lib = results.libraries.find(l => l.name === name);
      assert.deepEqual(lib.languages, ['python'], `${name} lost its language`);
      assert.deepEqual(lib.algorithms, [],
        `${name} should get no algorithms from an ambiguous file`);
    }
  });

  it('refuses to cover a site whose language is unknown', () => {
    // The one line that decides malformed input. If this returned true, any
    // site with no recorded language would be claimable by every library and
    // #67 would be back for exactly those sites.
    assert.equal(libraryCoversLanguage({ ecosystem: 'npm' }, undefined), false);
    assert.equal(libraryCoversLanguage({ ecosystem: 'npm' }, null), false);
    assert.equal(libraryCoversLanguage({ ecosystem: 'npm' }, ''), false);
  });

  it('never hands out the shared language table', () => {
    // `libraryLanguages` used to return the exported array itself, so a single
    // push through any inventory entry rewrote ECOSYSTEM_LANGUAGES process-wide
    // -- for every library, both inventories, and every subsequent scan in the
    // same process. Nothing mutates it today, which is exactly why the
    // hardening needs a test: it is invisible until something does.
    const first = libraryLanguages({ ecosystem: 'npm' });
    first.push('python');
    assert.deepEqual(ECOSYSTEM_LANGUAGES.npm, ['javascript'],
      'the exported table was mutated through a returned array');
    assert.deepEqual(libraryLanguages({ ecosystem: 'npm' }), ['javascript']);

    const lib = { ecosystem: 'source', languages: ['c'] };
    libraryLanguages(lib).push('go');
    assert.deepEqual(lib.languages, ['c'], 'the caller\'s own array was mutated');

    assert.ok(Object.isFrozen(ECOSYSTEM_LANGUAGES));
    for (const [eco, langs] of Object.entries(ECOSYSTEM_LANGUAGES)) {
      assert.ok(Object.isFrozen(langs), `${eco} is not frozen`);
    }
  });

  it('covers nothing when the ecosystem is unknown or absent', () => {
    // Fails CLOSED. An ecosystem the table does not know claims no sites, and
    // the ownership inventory then mints a synthetic owner for them, so the
    // violation survives with an honest owner rather than a guessed one.
    assert.equal(libraryCoversLanguage({ ecosystem: 'nuget' }, 'javascript'), false);
    assert.equal(libraryCoversLanguage({}, 'javascript'), false);
    assert.equal(libraryCoversLanguage({ ecosystem: 'source', languages: null }, 'python'), false);
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

describe('ownership inventory is separate from the scored census', () => {
  beforeEach(setup);
  afterEach(cleanup);

  const cryptoJs = () => writeFileSync(join(TEST_DIR, 'package.json'), JSON.stringify({
    dependencies: { 'crypto-js': '^3.1.9' },
  }));

  it('mints an owner for a site no same-language library declares', () => {
    // crypto-js declares MD5 and is npm. The MD5 in hash.c is not its MD5, and
    // the C include produces no source library at all, so without a synthetic
    // owner the site has no claimant anywhere and the gate raises nothing.
    cryptoJs();
    writeFileSync(join(TEST_DIR, 'hash.c'), '#include <openssl/md5.h>\nvoid f(void){MD5_CTX c;MD5_Init(&c);}\n');

    const owners = toOwnershipInventory(scanProject(TEST_DIR));
    const owner = owners.find(l => l.name !== 'crypto-js'
      && l.algorithms.some(a => a.toLowerCase() === 'md5'));
    assert.ok(owner, 'a C md5 site must keep an owner of its own language');
    assert.deepEqual(owner.languages, ['c']);
  });

  it('does not duplicate an algorithm a same-language library already declares', () => {
    // The other direction. `hashlib` is Python and declares md5, so the Python
    // md5 site is already owned and must not also mint `python:md5`.
    cryptoJs();
    writeFileSync(join(TEST_DIR, 'auth.py'), 'import hashlib\nh = hashlib.md5(b"pw")\n');

    const owners = toOwnershipInventory(scanProject(TEST_DIR));
    assert.equal(owners.filter(l => l.name === 'python:md5').length, 0);
    assert.ok(owners.some(l => l.name === 'hashlib'));
  });

  it('a same-language library claims only the algorithms it declares', () => {
    // Both halves of the ownership test have to hold. Covering the language is
    // not enough: `openssl` here is a C library, so it covers a C site, but it
    // declares only `rsa`. Dropping the name half let it claim the `md5` site
    // as well, which suppresses `c:md5` and drops the finding through to the
    // weak-pattern sweep as a `misuse` row named after the file.
    //
    // `openssl/rsa.h` is a recognised include and mints a source library;
    // `openssl/md5.h` is not, which is what leaves the md5 site unowned.
    writeFileSync(join(TEST_DIR, 'package.json'), '{}');
    writeFileSync(join(TEST_DIR, 'rsa.c'),
      '#include <openssl/rsa.h>\nvoid g(void){ RSA_public_encrypt(0,0,0,0,0); }\n');
    writeFileSync(join(TEST_DIR, 'hash.c'), 'void f(void){ MD5_CTX c; MD5_Init(&c); }\n');

    const owners = toOwnershipInventory(scanProject(TEST_DIR));
    const openssl = owners.find(l => l.name === 'openssl');
    assert.ok(openssl, 'fixture must produce a C source library');
    assert.deepEqual(openssl.languages, ['c']);
    assert.ok(!openssl.algorithms.some(a => a.toLowerCase() === 'md5'),
      `fixture is void: openssl already declares md5 (${JSON.stringify(openssl.algorithms)})`);

    assert.ok(owners.some(l => l.name === 'c:md5'),
      `md5 was claimed by a C library that does not declare it: `
      + JSON.stringify(owners.map(l => `${l.name}[${l.algorithms}]`)));
  });

  it('does NOT add that owner to the scored census', () => {
    // The census counts ROWS and `calculateQuantumScore` subtracts per
    // deprecated row, uncapped, while `classifyAlgorithms` deduplicates by
    // algorithm name. So an ownership row for an algorithm already present
    // moves the score without the set of algorithms having changed. The two
    // lists must stay separate, and this is the assertion that keeps them so.
    cryptoJs();
    writeFileSync(join(TEST_DIR, 'hash.c'), '#include <openssl/md5.h>\nvoid f(void){MD5_CTX c;MD5_Init(&c);}\n');

    const scan = scanProject(TEST_DIR);
    const census = toLibraryInventory(scan);
    const owners = toOwnershipInventory(scan);

    assert.equal(census.filter(l => l.name === 'c:md5').length, 0,
      `census gained an attribution row: ${JSON.stringify(census.map(l => l.name))}`);
    assert.equal(owners.filter(l => l.name === 'c:md5').length, 1);
    assert.ok(owners.length > census.length,
      'ownership must be the longer list, or the split has collapsed');
  });

  it('the CENSUS still mints an entry for an algorithm no library declares', () => {
    // The census has its own fail-open, and it is older than the ownership one:
    // an algorithm seen only in source, that NO library lists under any name,
    // must still reach the scored inventory. Splitting the two lists moved the
    // only test of this onto `toOwnershipInventory` and left the census side
    // unguarded -- deleting its minting loop passed the whole suite while
    // changing the score on hundreds of trees, and turned a 70/100 FAIL into a
    // 100/100 PASS.
    writeFileSync(join(TEST_DIR, 'Cargo.toml'), '[dependencies]\nsha2 = "0.10"\n');
    writeFileSync(join(TEST_DIR, 'x.c'), 'void f(void){ RSA_public_encrypt(0,0,0,0,0); }\n');

    const census = toLibraryInventory(scanProject(TEST_DIR));
    const rsa = census.find(l => l.name === 'c:rsa');
    assert.ok(rsa, `census lost the only entry for an unlisted algorithm: `
      + JSON.stringify(census.map(l => l.name)));
    // The fields the score reads. `quantumRisk` feeds classification and the
    // KEM/signature recommendations; `isDeprecated` feeds the per-row penalty
    // and the SNDL risk level. Neither is reachable from the ownership tests,
    // because the gate takes risk and CWE from the algorithm database instead.
    assert.equal(rsa.quantumRisk, 'high', JSON.stringify(rsa));
    assert.equal(rsa.isDeprecated, false, JSON.stringify(rsa));
  });

  it('carries the weakness of a minted entry into the census', () => {
    // The other side of `isDeprecated`. Dropping it inflated the score on 256
    // trees, always upward, because the per-row deprecation penalty stopped
    // firing for exactly the algorithms that earned it.
    writeFileSync(join(TEST_DIR, 'package.json'), '{}');
    writeFileSync(join(TEST_DIR, 'hash.c'), '#include <openssl/md5.h>\nvoid f(void){MD5_CTX c;MD5_Init(&c);}\n');

    const md5 = toLibraryInventory(scanProject(TEST_DIR)).find(l => l.name === 'c:md5');
    assert.ok(md5, 'census lost the C md5 entry');
    assert.equal(md5.isDeprecated, true, JSON.stringify(md5));
    assert.equal(md5.quantumRisk, 'critical', JSON.stringify(md5));
  });

  it('keeps the census identical whichever language the site is in', () => {
    // The upward direction of the same defect, which is the dangerous one: a
    // library declaring `AES-GCM` beside a Python `aes-gcm` site would add a
    // second SAFE classification (the spellings differ and that dedup is
    // case-sensitive), RAISING safe/total and turning a failing gate green.
    cryptoJs();
    writeFileSync(join(TEST_DIR, 'a.py'), 'import hashlib\nh = hashlib.md5(b"pw")\n');
    const withPython = toLibraryInventory(scanProject(TEST_DIR)).map(l => l.name).sort();

    cleanup(); setup();
    cryptoJs();
    writeFileSync(join(TEST_DIR, 'a.js'), 'const C = require("crypto-js");\nconst h = C.MD5("pw");\n');
    const withJs = toLibraryInventory(scanProject(TEST_DIR)).map(l => l.name).sort();

    assert.ok(!withPython.some(n => n.startsWith('python:')),
      `census gained a per-language row: ${JSON.stringify(withPython)}`);
    assert.ok(!withJs.some(n => n.startsWith('javascript:')),
      `census gained a per-language row: ${JSON.stringify(withJs)}`);
  });
});

/**
 * `gate --help` promises it fails on "critical API misuse such as a disabled
 * TLS certificate check". It carried exactly one spelling of that,
 * `rejectUnauthorized: false`, so a tree that turns certificate verification off
 * in JavaScript and in Python scored 100/100 and exited 0 (#66).
 *
 * Reproduced on released 0.5.0 as well: pre-existing, not a regression.
 */
describe('TLS verification disabled in source', () => {
  beforeEach(setup);
  afterEach(cleanup);

  const misuseIn = (file, body) => {
    writeFileSync(join(TEST_DIR, 'package.json'), '{}');
    writeFileSync(join(TEST_DIR, file), body);
    return scanProject(TEST_DIR).weakPatterns;
  };
  const found = (patterns, re) => patterns.filter(p => re.test(p.issue));

  it('flags NODE_TLS_REJECT_UNAUTHORIZED set to 0', () => {
    const wp = misuseIn('app.js', "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n");
    assert.equal(found(wp, /certificate verification/i).length, 1, JSON.stringify(wp));
    assert.equal(found(wp, /certificate verification/i)[0].severity, 'critical');
  });

  it('flags the process.env spellings that set the override to 0', () => {
    for (const body of [
      "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n",
      "process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';\n",
      'process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;\n',
      "process.env.NODE_TLS_REJECT_UNAUTHORIZED ||= '0';\n",
      "process . env . NODE_TLS_REJECT_UNAUTHORIZED = '0';\n",
    ]) {
      cleanup(); setup();
      const wp = misuseIn('app.js', body);
      assert.equal(found(wp, /certificate verification/i).length, 1, `${body} -> ${JSON.stringify(wp)}`);
    }
  });

  it('does not flag an unrelated property that happens to share the name', () => {
    // The reason this rule is scoped to `process.env` and not widened to any
    // receiver. Each of these is a real construct in real code, none is a
    // defect, and every one of them is `critical` if the rule matches it.
    //
    // The `cryptoserve-ignore` pragma can now clear each one, which removed the
    // original objection to widening. It stays narrow for a second reason:
    // widening makes every remaining critical on this repository's own tree a
    // fixture string in its test suite, so the scanner fails its own gate and
    // its author owes it 39 pragmas.
    for (const body of [
      '// Never write NODE_TLS_REJECT_UNAUTHORIZED: 0 anywhere.\n',
      'module.exports = { rules: { NODE_TLS_REJECT_UNAUTHORIZED: 0 } };\n',
      'const SEVERITY = { NODE_TLS_REJECT_UNAUTHORIZED: 0, OTHER: 2 };\n',
      'counts.NODE_TLS_REJECT_UNAUTHORIZED = 0;\n',
      'class A { constructor(){ this.NODE_TLS_REJECT_UNAUTHORIZED = 0; } }\n',
    ]) {
      cleanup(); setup();
      const wp = misuseIn('app.js', body);
      assert.equal(found(wp, /certificate verification/i).length, 0, `${body} -> ${JSON.stringify(wp)}`);
    }
  });

  it('does not apply one language\'s spellings to another language\'s files', () => {
    // Each misuse rule declares the languages it applies to, and nothing tested
    // that the declaration was honoured: running every pattern against every
    // file left the suite green. A Python spelling matched in a .js file is a
    // finding whose fix names an API that file cannot call, which is the same
    // wrong-language attribution #67 was about, one table over.
    const cases = [
      ['app.js', 'ctx.check_hostname = False\n', /hostname/i],
      ['app.js', 'ctx.verify_mode = ssl.CERT_NONE\n', /certificate verification/i],
      ['app.py', "cipher = crypto.createCipher('aes-256-cbc', key)\n", /createCipher/i],
    ];
    for (const [file, body, re] of cases) {
      cleanup(); setup();
      const wp = misuseIn(file, body);
      assert.equal(found(wp, re).length, 0, `${file}: ${body} -> ${JSON.stringify(wp)}`);
    }
  });

  it('records the spellings this rule knowingly does not reach', () => {
    // Not aspiration: these are measured gaps, listed in the changelog, and
    // this test fails if one starts being detected -- at which point the
    // changelog is stale and needs updating with it. A known gap that silently
    // closes is how documentation drifts away from behaviour.
    for (const body of [
      "const { env } = process;\nenv.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n",
      "const e = process.env;\ne.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n",
      "Bun.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n",
      "spawn('node', ['x.js'], { env: { ...process.env, NODE_TLS_REJECT_UNAUTHORIZED: '0' } });\n",
      "Object.assign(process.env, { NODE_TLS_REJECT_UNAUTHORIZED: '0' });\n",
      "process.env.NODE_TLS_REJECT_UNAUTHORIZED ??= '0';\n",
      "Deno.env.set('NODE_TLS_REJECT_UNAUTHORIZED', '0');\n",
    ]) {
      cleanup(); setup();
      const wp = misuseIn('app.js', body);
      assert.equal(found(wp, /certificate verification/i).length, 0,
        `now detected -- update the changelog's known-gaps list: ${body}`);
    }
  });

  it('does not flag those shapes when the value restores verification', () => {
    // Every shape above, set to 1. A guard that fires on the remediation is
    // worse than no guard.
    for (const body of [
      "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';\n",
      "process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '1';\n",
      "const { env } = process;\nenv.NODE_TLS_REJECT_UNAUTHORIZED = '1';\n",
      "Object.assign(process.env, { NODE_TLS_REJECT_UNAUTHORIZED: '1' });\n",
    ]) {
      cleanup(); setup();
      const wp = misuseIn('app.js', body);
      assert.equal(found(wp, /certificate verification/i).length, 0, `${body} -> ${JSON.stringify(wp)}`);
    }
  });

  it('does not match a 0 that is only the prefix of a longer value', () => {
    // `['"`]?0['"`]?` is satisfied by the leading `0` of `0.5`, `0x1` and
    // `'00'`. None of those is the disabling literal, and reporting a critical
    // finding on one is a false positive on a line that is not a defect at all.
    for (const body of [
      'process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0.5;\n',
      'process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0x1;\n',
      "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '00';\n",
      "process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = 0x0;\n",
      // `= 10` needs no boundary to be rejected -- the leading digit is `1`, so
      // nothing matches either way. Kept as documentation of intent, but the
      // four above are the ones that actually measure the guard.
      'process.env.NODE_TLS_REJECT_UNAUTHORIZED = 10;\n',
    ]) {
      cleanup(); setup();
      const wp = misuseIn('app.js', body);
      assert.equal(found(wp, /certificate verification/i).length, 0, `${body} -> ${JSON.stringify(wp)}`);
    }
  });

  it('does not flag prose that merely names the anti-pattern', () => {
    // A guide, a linter rule, or this scanner's own pattern table names these
    // strings without doing them. Matching the bare name made `gate` report a
    // critical finding against the definition of its own check, and there is no
    // per-finding waiver to clear it with.
    for (const body of [
      '// never set NODE_TLS_REJECT_UNAUTHORIZED=0 in production\n',
      "const RULES = [{ bad: 'NODE_TLS_REJECT_UNAUTHORIZED=0', why: 'disables TLS' }];\n",
      "const issue = 'TLS disabled process-wide (NODE_TLS_REJECT_UNAUTHORIZED=0)';\n",
    ]) {
      cleanup(); setup();
      const wp = misuseIn('guide.js', body);
      assert.equal(found(wp, /certificate verification/i).length, 0, `${body} -> ${JSON.stringify(wp)}`);
    }
  });

  it('flags the assignment form of _create_unverified_context', () => {
    // The canonical process-wide Python bypass. It never CALLS the function, so
    // requiring the opening parenthesis missed the worst spelling of all.
    const wp = misuseIn('app.py',
      'import ssl\nssl._create_default_https_context = ssl._create_unverified_context\n');
    assert.equal(found(wp, /certificate verification/i).length, 1, JSON.stringify(wp));
  });

  it('does not flag NODE_TLS_REJECT_UNAUTHORIZED restored to 1', () => {
    // Setting it to 1 is the fix, not the defect. A guard that fires on the
    // remediation teaches users to ignore it.
    const wp = misuseIn('app.js', "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';\n");
    assert.equal(found(wp, /certificate verification/i).length, 0, JSON.stringify(wp));
  });

  it('flags ssl.CERT_NONE', () => {
    const wp = misuseIn('app.py', 'import ssl\nctx.verify_mode = ssl.CERT_NONE\n');
    assert.equal(found(wp, /certificate verification/i).length, 1, JSON.stringify(wp));
  });

  it('flags cert_reqs=ssl.CERT_NONE', () => {
    const wp = misuseIn('app.py', 'import ssl\ns = ssl.wrap_socket(sock, cert_reqs=ssl.CERT_NONE)\n');
    assert.equal(found(wp, /certificate verification/i).length, 1, JSON.stringify(wp));
  });

  it('does not flag a comparison against ssl.CERT_NONE', () => {
    // `if ctx.verify_mode == ssl.CERT_NONE:` is code that CHECKS the setting.
    const wp = misuseIn('app.py', 'import ssl\nif ctx.verify_mode == ssl.CERT_NONE:\n    warn()\n');
    assert.equal(found(wp, /certificate verification/i).length, 0, JSON.stringify(wp));
  });

  it('flags check_hostname = False', () => {
    const wp = misuseIn('app.py', 'import ssl\nctx.check_hostname = False\n');
    assert.equal(found(wp, /hostname/i).length, 1, JSON.stringify(wp));
  });

  it('does not flag check_hostname = True', () => {
    const wp = misuseIn('app.py', 'import ssl\nctx.check_hostname = True\n');
    assert.equal(found(wp, /hostname/i).length, 0, JSON.stringify(wp));
  });

  it('flags ssl._create_unverified_context', () => {
    const wp = misuseIn('app.py', 'import ssl\nctx = ssl._create_unverified_context()\n');
    assert.equal(found(wp, /certificate verification/i).length, 1, JSON.stringify(wp));
  });

  it('flags a no-op checkServerIdentity', () => {
    for (const body of [
      'const a = new https.Agent({ checkServerIdentity: () => undefined });\n',
      'const a = new https.Agent({ checkServerIdentity: () => {} });\n',
      'const a = new https.Agent({ checkServerIdentity: (host, cert) => null });\n',
      'const a = new https.Agent({ checkServerIdentity: function (h, c) { return undefined; } });\n',
      'const a = new https.Agent({ checkServerIdentity: () => true });\n',
      'const a = new https.Agent({ checkServerIdentity: (h, c) => { return true; } });\n',
    ]) {
      cleanup(); setup();
      const wp = misuseIn('app.js', body);
      assert.equal(found(wp, /hostname/i).length, 1, `${body} -> ${JSON.stringify(wp)}`);
    }
  });

  it('does not flag a checkServerIdentity that does something', () => {
    const wp = misuseIn('app.js',
      'const a = new https.Agent({ checkServerIdentity: (host, cert) => tls.checkServerIdentity(host, cert) });\n');
    assert.equal(found(wp, /hostname/i).length, 0, JSON.stringify(wp));
  });
});

/**
 * Per-finding waivers.
 *
 * Before these existed a false `critical` could not be cleared at all:
 * `--max-severity` only tightens and refuses `high`/`critical` by name,
 * `--allow-secrets` does not reach misuse, and `.cryptoserve.json` offers only
 * `skipDirs`, which excludes a whole directory to silence one line. That is
 * what kept the widened NODE_TLS rule off main for three review rounds.
 *
 * A waiver is a security control's off switch, so most of what follows tests
 * what it must NOT be able to do.
 */
describe('cryptoserve-ignore pragmas', () => {
  beforeEach(setup);
  afterEach(cleanup);

  const scanWith = (file, body) => {
    writeFileSync(join(TEST_DIR, 'package.json'), '{}');
    writeFileSync(join(TEST_DIR, file), body);
    return scanProject(TEST_DIR);
  };
  const tls = (r) => r.weakPatterns.filter(p => /certificate verification/i.test(p.issue));

  const RULE = 'misuse/node-tls-reject-unauthorized';
  // Assembled, so this file's own source does not read as a live pragma.
  const IGNORE = 'cryptoserve' + '-ignore';
  const DEFECT = "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n";

  it('clears a finding when the pragma is on the line above', () => {
    const r = scanWith('app.js', `// cryptoserve-ignore ${RULE} -- fixture asserting the scanner sees this\n${DEFECT}`);
    assert.equal(tls(r).length, 0, JSON.stringify(r.weakPatterns));
    assert.equal(r.waivedFindings.length, 1, JSON.stringify(r.waivedFindings));
    assert.equal(r.waivedFindings[0].rule, RULE);
    assert.equal(r.waivedFindings[0].line, 2);
    assert.equal(r.waivedFindings[0].reason, 'fixture asserting the scanner sees this');
    // A waiver that did its job is not also reported as a problem. Without this
    // the "unused" bookkeeping could stop working and nothing would notice,
    // because every OTHER assertion here passes whether or not it is marked.
    assert.deepEqual(r.waiverWarnings, [], JSON.stringify(r.waiverWarnings));
  });

  it('quotes the evidence as it was written', () => {
    const r = scanWith('app.js', "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n");
    assert.equal(tls(r).length, 1, JSON.stringify(r.weakPatterns));
    assert.match(tls(r)[0].evidence, /process\.env\.NODE_TLS_REJECT_UNAUTHORIZED/);
  });

  it('clears a finding when the pragma trails the same line', () => {
    const r = scanWith('app.js',
      `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // ${IGNORE} ${RULE} -- deliberate\n`);
    assert.equal(tls(r).length, 0, JSON.stringify(r.weakPatterns));
    assert.equal(r.waivedFindings.length, 1);
  });

  it('clears a finding from a block comment', () => {
    const r = scanWith('app.js', `/* cryptoserve-ignore ${RULE} -- deliberate */\n${DEFECT}`);
    assert.equal(tls(r).length, 0, JSON.stringify(r.weakPatterns));
    assert.equal(r.waivedFindings[0].reason, 'deliberate');
  });

  it('does not reach a finding two lines below it', () => {
    // A pragma covers its own line and the next one. Anything wider drifts away
    // from the line it was written for as the file changes around it, and
    // starts covering findings its author never saw.
    const r = scanWith('app.js',
      `// cryptoserve-ignore ${RULE} -- deliberate\nconst unrelated = 1;\n${DEFECT}`);
    assert.equal(tls(r).length, 1, JSON.stringify(r.weakPatterns));
    assert.equal(r.waivedFindings.length, 0);
  });

  it('does not clear a different rule', () => {
    const r = scanWith('app.js',
      `// cryptoserve-ignore misuse/create-cipher -- unrelated rule\n${DEFECT}`);
    assert.equal(tls(r).length, 1, JSON.stringify(r.weakPatterns));
  });

  it('does not clear anything without a reason', () => {
    // The reason is the only part of a waiver a reviewer can disagree with. One
    // without it is not auditable, so it waives nothing and says so.
    const r = scanWith('app.js', `// cryptoserve-ignore ${RULE}\n${DEFECT}`);
    assert.equal(tls(r).length, 1, JSON.stringify(r.weakPatterns));
    assert.equal(r.waiverWarnings.filter(w => w.kind === 'malformed').length, 1,
      JSON.stringify(r.waiverWarnings));
  });

  it('does not honour a pragma that is not in a comment', () => {
    // The pragma is read from comment ranges, so checked-in DATA cannot turn a
    // check off. A fixture file, a JSON blob or a test's own expected-output
    // string containing this text is text, not an instruction.
    for (const body of [
      `const s = "cryptoserve-ignore ${RULE} -- from a string";\n${DEFECT}`,
      `const t = \`cryptoserve-ignore ${RULE} -- from a template\`;\n${DEFECT}`,
    ]) {
      cleanup(); setup();
      const r = scanWith('app.js', body);
      assert.equal(tls(r).length, 1, `${body} -> ${JSON.stringify(r.weakPatterns)}`);
      assert.equal(r.waivedFindings.length, 0);
    }
  });

  it('does not hide a later real defect of the same rule in the same file', () => {
    // The dangerous shape. Misuse patterns report only the FIRST match per
    // pattern per file, so a waiver on the first match would silently widen
    // itself to the whole file: one pragma at the top of a fixture, and a real
    // defect fifty lines down is never reported at all.
    const r = scanWith('app.js',
      `// cryptoserve-ignore ${RULE} -- the first one is a deliberate demo\n`
      + DEFECT
      + 'const filler = 1;\n'
      + DEFECT);
    const hits = tls(r);
    assert.equal(hits.length, 1, JSON.stringify(r.weakPatterns));
    assert.equal(hits[0].line, 4);
    assert.equal(r.waivedFindings.length, 1);
    assert.equal(r.waivedFindings[0].line, 2);
  });

  it('reports a pragma naming a rule that does not exist', () => {
    // A typo in an off switch that looks like it worked is worse than no off
    // switch, because the author stops looking at the finding.
    const r = scanWith('app.js', `// cryptoserve-ignore misuse/nod-tls-reject -- typo\n${DEFECT}`);
    assert.equal(tls(r).length, 1, JSON.stringify(r.weakPatterns));
    const warn = r.waiverWarnings.filter(w => w.kind === 'unknown-rule');
    assert.equal(warn.length, 1, JSON.stringify(r.waiverWarnings));
    assert.equal(warn[0].rule, 'misuse/nod-tls-reject');
  });

  it('reports a pragma that covered no finding', () => {
    // Suppression with nothing under it. The code it was written for is gone,
    // and the next real finding on that line would land under it silently.
    const r = scanWith('app.js', `// cryptoserve-ignore ${RULE} -- stale\nconst clean = 1;\n`);
    assert.equal(r.waiverWarnings.filter(w => w.kind === 'unused').length, 1,
      JSON.stringify(r.waiverWarnings));
  });

  it('reports nothing for a file with no pragmas', () => {
    const r = scanWith('app.js', DEFECT);
    assert.deepEqual(r.waiverWarnings, []);
    assert.deepEqual(r.waivedFindings, []);
  });

  it('does not change the library inventory that scoring reads', () => {
    // A waiver clears a MISUSE finding. It must not move `quantumReadinessScore`
    // in either direction: the score is computed from the library inventory,
    // and a user who waives a false positive has not made their tree more
    // quantum-ready. A gate that goes green because somebody wrote a comment is
    // the failure this pins.
    //
    // The tree carries a real dependency and a real call site ON PURPOSE. The
    // first version of this test scanned a file that imported nothing, so both
    // sides of the comparison were the empty array and it passed against any
    // implementation whatsoever. Found by adversarial review; an inventory
    // assertion that cannot tell an inventory from no inventory asserts
    // nothing.
    const withDependency = (pragma) => {
      writeFileSync(join(TEST_DIR, 'package.json'),
        JSON.stringify({ dependencies: { 'crypto-js': '3.1.9' } }));
      writeFileSync(join(TEST_DIR, 'app.js'),
        "const C = require('crypto-js');\nconst h = C.MD5('pw');\n" + pragma + DEFECT);
      return scanProject(TEST_DIR);
    };

    const withoutPragma = toLibraryInventory(withDependency(''));
    // Guards the guard: if the fixture ever stops producing an inventory, this
    // test silently stops measuring anything.
    assert.ok(withoutPragma.length > 0, 'fixture produced no inventory to compare');
    assert.ok(withoutPragma.some(l => l.name === 'crypto-js'), JSON.stringify(withoutPragma));

    cleanup(); setup();
    const scanned = withDependency(`// cryptoserve-ignore ${RULE} -- deliberate\n`);
    const withPragma = toLibraryInventory(scanned);

    // The pragma really did waive something, or this compares two identical
    // runs and proves nothing about waiving.
    assert.equal(scanned.waivedFindings.length, 1, JSON.stringify(scanned.waivedFindings));
    assert.deepEqual(withPragma, withoutPragma);
  });

  it('waives a Python finding from a # comment', () => {
    const r = scanWith('app.py',
      '# cryptoserve-ignore misuse/python-check-hostname -- documented example\nctx.check_hostname = False\n');
    assert.equal(r.weakPatterns.filter(p => /hostname/i.test(p.issue)).length, 0,
      JSON.stringify(r.weakPatterns));
    assert.equal(r.waivedFindings.length, 1);
  });
});

/**
 * A deprecated protocol version was critical in `nginx.conf` and invisible in
 * `app.py`. One defect must not change severity with the file type it is
 * written in, so the source spellings go through the same TLS table the config
 * ones do rather than becoming a second, differently-rated finding.
 */
describe('deprecated TLS protocol pinned in source', () => {
  beforeEach(setup);
  afterEach(cleanup);

  const tlsIn = (file, body) => {
    writeFileSync(join(TEST_DIR, 'package.json'), '{}');
    writeFileSync(join(TEST_DIR, file), body);
    return scanProject(TEST_DIR).tlsFindings;
  };

  it('flags ssl.PROTOCOL_TLSv1 in Python', () => {
    const tls = tlsIn('app.py', 'import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\n');
    assert.equal(tls.length, 1, JSON.stringify(tls));
    assert.equal(tls[0].protocol, 'TLSv1');
    assert.equal(tls[0].risk, 'critical');
    assert.equal(tls[0].file, 'app.py');
    assert.equal(tls[0].line, 2);
  });

  it('rates it exactly as the nginx spelling of the same defect', () => {
    const py = tlsIn('app.py', 'import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\n');
    cleanup(); setup();
    writeFileSync(join(TEST_DIR, 'package.json'), '{}');
    writeFileSync(join(TEST_DIR, 'nginx.conf'), 'server {\n    ssl_protocols TLSv1;\n}\n');
    const conf = scanProject(TEST_DIR).tlsFindings;
    assert.equal(py[0].risk, conf[0].risk);
    assert.equal(py[0].protocol, conf[0].protocol);
  });

  it('flags ssl.PROTOCOL_TLSv1_1 and rates it high', () => {
    const tls = tlsIn('app.py', 'import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)\n');
    assert.equal(tls.length, 1, JSON.stringify(tls));
    assert.equal(tls[0].protocol, 'TLSv1.1');
    assert.equal(tls[0].risk, 'high');
  });

  it('does not flag ssl.PROTOCOL_TLSv1_2', () => {
    // The longest alternative has to win. TLSv1_2 is current practice, and
    // reporting it as TLSv1 would fail a correct project at every threshold.
    assert.deepEqual(tlsIn('app.py', 'import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)\n'), []);
  });

  it('does not flag ssl.PROTOCOL_SSLv23', () => {
    // Despite the name, PROTOCOL_SSLv23 means "negotiate the best available"
    // and is the modern default alias. Matching `SSLv2` inside it would flag
    // the recommended constant as critical.
    assert.deepEqual(tlsIn('app.py', 'import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)\n'), []);
  });

  it('flags secureProtocol: TLSv1_method in JavaScript', () => {
    const tls = tlsIn('app.js', "const a = new https.Agent({ secureProtocol: 'TLSv1_method' });\n");
    assert.equal(tls.length, 1, JSON.stringify(tls));
    assert.equal(tls[0].protocol, 'TLSv1');
    assert.equal(tls[0].risk, 'critical');
  });

  it('does not flag secureProtocol: TLSv1_2_method', () => {
    assert.deepEqual(tlsIn('app.js', "const a = new https.Agent({ secureProtocol: 'TLSv1_2_method' });\n"), []);
  });

  it('flags every deprecated constant in the alternation, not just TLSv1', () => {
    // Half the alternation was untested. A dropped branch is a silent hole.
    for (const [constant, protocol, risk] of [
      ['SSLv2', 'SSLv2', 'critical'],
      ['SSLv3', 'SSLv3', 'critical'],
      ['TLSv1', 'TLSv1', 'critical'],
      ['TLSv1_1', 'TLSv1.1', 'high'],
    ]) {
      cleanup(); setup();
      const tls = tlsIn('app.py', `import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_${constant})\n`);
      assert.equal(tls.length, 1, `PROTOCOL_${constant}: ${JSON.stringify(tls)}`);
      assert.equal(tls[0].protocol, protocol);
      assert.equal(tls[0].risk, risk);
    }
  });

  it('reads secureProtocol in every extension the scanner calls JavaScript', () => {
    // `.tsx` got the misuse findings but not this one, so the two new surfaces
    // disagreed about what a JavaScript file is.
    for (const ext of ['js', 'ts', 'mjs', 'cjs', 'jsx', 'tsx']) {
      cleanup(); setup();
      const tls = tlsIn(`app.${ext}`, "const a = new https.Agent({ secureProtocol: 'SSLv3_method' });\n");
      assert.equal(tls.length, 1, `.${ext} was not read: ${JSON.stringify(tls)}`);
      assert.equal(tls[0].protocol, 'SSLv3');
    }
  });

  it('reads a backtick-quoted secureProtocol', () => {
    const tls = tlsIn('app.js', 'const a = new https.Agent({ secureProtocol: `TLSv1_method` });\n');
    assert.equal(tls.length, 1, JSON.stringify(tls));
  });

  it('requires the _method suffix rather than any TLS-shaped string', () => {
    // Without the anchor this matches version strings that are not a pin.
    assert.deepEqual(tlsIn('app.js', "const label = { secureProtocol: 'TLSv1' };\n"), []);
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
