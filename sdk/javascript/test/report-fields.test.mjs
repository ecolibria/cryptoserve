/**
 * No report field built from the scanned tree, other than the scanned
 * directory's own path, carries a terminal-steering character, in the JSON,
 * SARIF and CBOM documents of `scan`, `gate`, `cbom` and `pqc` or in the
 * `scan`, `gate` and `pqc` text reports.
 *
 * This class was fixed one field at a time twice, and each time the review
 * that followed found a field the fix had missed. So this test does not list
 * fields. It builds one tree, from file and directory NAMES, manifests in four
 * ecosystems (npm, PyPI, Cargo, Maven), source, config, certificate, binary,
 * waiver pragmas and git metadata, that reaches every finding category the
 * scanner reports, runs those reports over it, and walks every string in each.
 * A finding category added later fails the coverage check below until this
 * tree is taught to reach it.
 *
 * Nothing else is walked: not stderr, not the summary `cbom --output` prints,
 * and not the records `scan --emit-findings` writes, which keep these
 * characters in the source lines they quote and in the project name and
 * version they record.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { scanProject, toLibraryInventory } from '../lib/scanner.mjs';
import { scanBinaries, BINARY_SIGNATURES } from '../lib/scanner-binary.mjs';
import { collectFindings, toSarif } from '../lib/sarif.mjs';
import { generateCbom, toCycloneDx, toSpdx, toNativeJson } from '../lib/cbom.mjs';
import { analyzeOffline } from '../lib/pqc-engine.mjs';
import { printablePath } from '../lib/waivers.mjs';
import { buildFindingRecords } from '../lib/finding-records.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = join(__dirname, '..', 'bin', 'cryptoserve.mjs');

// The class, written out here rather than imported, so narrowing the code's
// own definition cannot narrow what this test demands: every control character
// except tab, DEL, the C1 block (U+009B is a one-byte CSI), and the bidi
// overrides and isolates.
const STEERING = /[\u0000-\u0008\u000a-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/;

// Built from code points, never written as literals: an override is invisible
// in a diff. ESC, DEL, CSI, RLO and RLI, plus a newline for names, where it
// would forge a whole report line.
const IN_TEXT = String.fromCodePoint(0x1b, 0x7f, 0x9b, 0x202e, 0x2067);
const IN_NAME = IN_TEXT + '\n';
// git refuses C0 and DEL in a ref name, and accepts the rest.
const IN_REF = String.fromCodePoint(0x9b, 0x202e);

/** A failure message must not itself steer the terminal that shows it. */
const show = (s) => s.replace(/[^\x20-\x7e]/g, (ch) => `\\u${ch.codePointAt(0).toString(16).padStart(4, '0')}`);

/** Every string, and every key, anywhere in a document, that carries the class. */
function steering(value, path = '$', out = []) {
  if (typeof value === 'string') {
    if (STEERING.test(value)) out.push(`${path} = "${show(value)}"`);
  } else if (Array.isArray(value)) {
    value.forEach((v, i) => steering(v, `${path}[${i}]`, out));
  } else if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      if (STEERING.test(k)) out.push(`${path} has key "${show(k)}"`);
      steering(v, `${path}.${show(k)}`, out);
    }
  }
  return out;
}

function assertClean(label, document) {
  const found = steering(document);
  assert.deepEqual(found, [], `${label} carries a terminal-steering character:\n  ${found.join('\n  ')}`);
}

/** Was this path built from one of the hostile names below? */
const fromHostileName = (p) => typeof p === 'string' && decodeURIComponent(p).includes(IN_NAME);

function run(args) {
  try {
    return execFileSync(process.execPath, [CLI, ...args], {
      encoding: 'utf-8', timeout: 60000, stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (e) {
    // `gate` exits non-zero on this tree by design; its report is still on stdout.
    if (typeof e.stdout === 'string' && e.stdout.length > 0) return e.stdout;
    throw e;
  }
}

function git(cwd, ...args) {
  return execFileSync('git', [
    '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false',
    ...args,
  ], { cwd, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] });
}

describe('report fields built from the scanned tree', () => {
  let root;
  let results;
  let gitReached = false;

  before(() => {
    root = mkdtempSync(join(tmpdir(), 'cryptoserve-report-fields-'));
    const at = (...parts) => join(root, ...parts);

    // Manifests: a hostile VERSION in every ecosystem whose parser keeps one,
    // and a hostile DIRECTORY above a nested workspace manifest.
    writeFileSync(at('package.json'), JSON.stringify({
      name: 'fixture', dependencies: { 'crypto-js': `^3.1.9${IN_TEXT}` },
    }));
    mkdirSync(at('packages', `pkg${IN_NAME}`), { recursive: true });
    writeFileSync(at('packages', `pkg${IN_NAME}`, 'package.json'), JSON.stringify({
      name: 'nested', dependencies: { 'node-forge': `1.3.1${IN_TEXT}` },
    }));
    writeFileSync(at('requirements.txt'), `cryptography==41.0.0${IN_TEXT}\n`);
    writeFileSync(at('Cargo.toml'), `[dependencies]\naes-gcm = "0.10.3${IN_TEXT}"\n`);
    writeFileSync(at('pom.xml'), '<project><dependencies><dependency><groupId>org.bouncycastle</groupId>'
      + `<artifactId>bcprov-jdk18on</artifactId><version>1.78${IN_TEXT}</version></dependency></dependencies></project>\n`);

    // One source file reaching every per-file finding builder: weak algorithm,
    // weak key size, misuse, a waived misuse, a pragma that names no rule, and
    // a hardcoded secret.
    writeFileSync(at(`weak${IN_NAME}.js`), [
      "const crypto = require('crypto');",
      "crypto.createHash('md5');",
      "const token = Math.random() + 'token';",
      '// cryptoserve-ignore misuse/tls-verify-disabled -- fixture for the report-field test',
      'const agent = { rejectUnauthorized: false };',
      '// cryptoserve-ignore misuse/no-such-rule -- fixture for the report-field test',
      "crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });",
      `const id = '${'AKIA' + 'Q'.repeat(16)}';`,
      '',
    ].join('\n'));
    writeFileSync(at(`tls${IN_NAME}.js`), "module.exports = { minVersion: 'TLSv1' };\n");
    writeFileSync(at(`config${IN_NAME}.yaml`), `AWS_SECRET_ACCESS_KEY: ${'Ab1/'.repeat(10)}\n`);
    writeFileSync(at(`server${IN_NAME}.pem`), `-----BEGIN ${'PRIVATE KEY'}-----\nMIIfixture\n`);
    writeFileSync(at(`native${IN_NAME}.so`), Buffer.concat([Buffer.alloc(64), BINARY_SIGNATURES[0].bytes, Buffer.alloc(64)]));

    // git metadata reaches the CBOM. Best effort: without git the CBOM checks
    // still run, they just cannot reach these two fields.
    try {
      git(root, 'init', '-q');
      git(root, 'symbolic-ref', 'HEAD', `refs/heads/main${IN_REF}`);
      git(root, 'commit', '-q', '--allow-empty', '-m', 'fixture');
      git(root, 'remote', 'add', 'origin', `https://example.invalid/fixture${IN_REF}.git`);
      gitReached = true;
    } catch { /* git unavailable */ }

    results = scanProject(root);
    results.binaryFindings = scanBinaries(root); // what `scan --binary` does
  });

  after(() => { if (root) rmSync(root, { recursive: true, force: true }); });

  it('reaches every finding category the scanner reports', () => {
    // Enumerated from the result, not from a list here. A category added later
    // that this tree does not reach fails this until the tree is extended to
    // reach it -- otherwise the checks below would pass over it vacuously.
    for (const [key, list] of Object.entries(results).filter(([, v]) => Array.isArray(v))) {
      assert.ok(list.length > 0, `results.${key} is empty on the hostile tree; extend the fixture to reach it`);
      // Every category whose entries name a file must name a hostile one, so
      // its builder is the one being tested.
      const paths = list.map(e => e?.file).filter(p => p !== undefined);
      if (paths.length > 0) {
        assert.ok(paths.some(fromHostileName), `no entry of results.${key} names a hostile file`);
      }
    }
    // The two categories that are lists of bare paths.
    assert.ok(results.certFiles.some(fromHostileName), 'no certificate file with a hostile name was recorded');
    assert.ok(results.privateKeyFiles.some(fromHostileName), 'no private key file with a hostile name was recorded');
    for (const ecosystem of ['npm', 'pypi', 'cargo', 'maven']) {
      assert.ok(results.libraries.some(l => l.ecosystem === ecosystem && l.version !== 'unknown'),
        `no ${ecosystem} library with a version was read`);
    }
    assert.ok(results.libraries.some(l => fromHostileName(l.source)), 'the nested manifest under a hostile directory was not read');
  });

  it('carries none of the class in the scan result, as `scan --format json` saves it', () => {
    assertClean('scan result', JSON.parse(JSON.stringify(results)));
  });

  it('carries none of the class in SARIF', () => {
    assertClean('SARIF', toSarif(collectFindings(results)));
  });

  it('carries none of the class in any CBOM format, including the git metadata', () => {
    const cbom = generateCbom(results, analyzeOffline(toLibraryInventory(results)), `fixture${IN_TEXT}`, root);
    if (gitReached) {
      assert.ok(cbom.metadata.gitBranch?.startsWith('main'), 'the fixture branch did not reach the CBOM');
      assert.match(cbom.metadata.gitRepo || '', /example\.invalid/);
    }
    assertClean('CBOM', cbom);
    assertClean('CycloneDX', toCycloneDx(cbom));
    assertClean('SPDX', toSpdx(cbom));
    assertClean('native CBOM JSON', toNativeJson(cbom));
  });

  it('carries none of the class in any document a command writes', () => {
    for (const args of [
      ['scan', root, '--format', 'json', '--binary'],
      ['scan', root, '--format', 'sarif', '--binary'],
      ['gate', root, '--format', 'json'],
      ['gate', root, '--format', 'sarif'],
      ['cbom', root, '--format', 'cyclonedx'],
      ['cbom', root, '--format', 'spdx'],
      ['cbom', root, '--format', 'json'],
      ['pqc', root, '--format', 'json'],
    ]) {
      assertClean(args.filter(a => a !== root).join(' '), JSON.parse(run(args)));
    }
  });

  it('carries none of the class in the terminal report', () => {
    for (const args of [['scan', root, '--binary'], ['gate', root], ['pqc', root]]) {
      const out = run(args);
      const lines = out.split('\n').filter(l => STEERING.test(l));
      assert.deepEqual(lines.map(show), [], `${args[0]} printed a terminal-steering character`);
    }
  });

  it('keeps every path naming the file it came from', () => {
    // Stripping would print `weak.js` for a file that is not called that. The
    // printable form decodes back to the real name.
    const paths = [
      ...results.certFiles, ...results.privateKeyFiles,
      ...Object.values(results).filter(Array.isArray).flat().map(e => e?.file).filter(Boolean),
      ...results.libraries.map(l => l.source).filter(s => s !== 'source-code'),
    ];
    assert.ok(paths.some(fromHostileName));
    for (const p of paths) {
      assert.ok(existsSync(join(root, decodeURIComponent(p))), `"${show(p)}" does not name a file in the tree`);
    }
  });

  it('still reads the source context of a file whose name is not printable', () => {
    // `--emit-findings` re-opens each file by its finding's path. An encoded
    // path that it could not open would leave the record with no context.
    const records = buildFindingRecords(results, root).filter(r => fromHostileName(r.file));
    assert.ok(records.length > 0, 'no corpus record for the hostile source file');
    for (const r of records) {
      assert.notEqual(r.context.line, '', `record for "${show(r.file)}" at line ${r.line} lost its source context`);
    }
  });
});

describe('printablePath', () => {
  it('encodes each character of the class as printable ASCII', () => {
    assert.equal(printablePath(`a${String.fromCodePoint(0x202e)}b.js`), 'a%E2%80%AEb.js');
    assert.equal(printablePath(`a${String.fromCodePoint(0x9b)}b.js`), 'a%C2%9Bb.js');
    assert.equal(printablePath(`a${String.fromCodePoint(0x7f)}\nb.js`), 'a%7F%0Ab.js');
  });

  it('encodes a literal percent sign, so a name holding one prints apart from an encoded name', () => {
    const rlo = `a${String.fromCodePoint(0x202e)}b.js`;
    assert.equal(printablePath(rlo), 'a%E2%80%AEb.js');
    assert.equal(printablePath('a%E2%80%AEb.js'), 'a%25E2%2580%25AEb.js');
    assert.equal(printablePath('src/100% done.js'), 'src/100%25 done.js');
    assert.equal(printablePath(`100%${String.fromCodePoint(0x202e)}.js`), '100%25%E2%80%AE.js');
  });

  it('decodes back to the name it was given', () => {
    const failures = [];
    const check = (name) => {
      let back;
      try { back = decodeURIComponent(printablePath(name)); } catch (e) { back = e.message; }
      if (back !== name) failures.push(`"${show(name)}" came back as "${show(back)}"`);
    };
    // Each code point of the Basic Multilingual Plane outside the surrogates,
    // alone and between two letters.
    for (let cp = 0; cp <= 0xffff; cp++) {
      if (cp >= 0xd800 && cp <= 0xdfff) continue;
      check(String.fromCodePoint(cp));
      check(`a${String.fromCodePoint(cp)}b.js`);
    }
    // A literal percent sign beside the class, and text that is already an
    // escape, which is exactly what decoding would otherwise misread.
    for (const name of [
      '%', '%%', '100%', 'a%E2%80%AEb.js', 'a%25b.js', `100%${String.fromCodePoint(0x202e)}.js`,
      `%${IN_NAME}%0A%`, `src/${IN_NAME}/100% done.js`,
    ]) check(name);
    assert.deepEqual(failures, []);
  });

  it('leaves an ordinary path exactly as it was', () => {
    // Including what a careless sanitiser would also touch: a tab, a Windows
    // separator, and letters that are not ASCII.
    for (const p of ['src/app.js', 'a\tb.js', 'src\\win.js', 'données/ü.js', 'שלום/مرحبا.py']) {
      assert.equal(printablePath(p), p);
    }
  });
});

describe('a file name that holds a literal percent sign', () => {
  // Two names that printed the same path while `%` was left unencoded: one
  // holds U+202E, the other holds the escape of U+202E as text. Each makes an
  // MD5 call on line 2. `x%.js` makes a SHA-1 call and prints as `x%25.js`,
  // which is the name of another file here, so a path opened as printed rather
  // than decoded reads the wrong file. Line 2 of each ends in a marker that
  // differs per file.
  const RLO_NAME = `a${String.fromCodePoint(0x202e)}b.js`;
  const PCT_NAME = 'a%E2%80%AEb.js';
  const NAMES = [RLO_NAME, PCT_NAME, 'x%.js'];
  const HASHES = ['md5', 'md5', 'sha1'];
  let root;

  before(() => {
    root = mkdtempSync(join(tmpdir(), 'cryptoserve-percent-'));
    NAMES.forEach((name, i) => {
      writeFileSync(join(root, name),
        `const crypto = require('crypto');\ncrypto.createHash('${HASHES[i]}'); // marker-${i}\n`);
    });
    writeFileSync(join(root, 'x%25.js'), 'module.exports = 1;\n');
  });

  after(() => { if (root) rmSync(root, { recursive: true, force: true }); });

  // Compared in their shown form, so a failure cannot print U+202E itself.
  const SHOWN = NAMES.map(show);

  /** The file a printed path decodes to, shown, or a description of why it names none. */
  const named = (p) => {
    let decoded;
    try { decoded = decodeURIComponent(p); } catch { return `"${show(p)}" does not decode`; }
    return NAMES.includes(decoded) ? show(decoded) : `"${show(p)}" decodes to "${show(decoded)}"`;
  };
  const sorted = (list) => [...list].sort();

  it('prints a different path for each file in `scan --format json`', () => {
    const paths = new Set(JSON.parse(run(['scan', root, '--format', 'json'])).weakPatterns.map(w => w.file));
    assert.equal(paths.size, 3, `${paths.size} distinct paths: ${[...paths].map(show).join(', ')}`);
    assert.deepEqual(sorted([...paths].map(named)), sorted(SHOWN));
  });

  it('gives each file a SARIF uri that decodes to exactly that file', () => {
    const sarif = JSON.parse(run(['scan', root, '--format', 'sarif']));
    const uris = new Set(sarif.runs[0].results.flatMap(r => r.locations.map(l => l.physicalLocation.artifactLocation.uri)));
    assert.equal(uris.size, 3, `${uris.size} distinct uris: ${[...uris].map(show).join(', ')}`);
    assert.deepEqual(sorted([...uris].map(named)), sorted(SHOWN));
  });

  it('keeps the MD5 calls in the two files as two `gate` violations', () => {
    const { violations } = JSON.parse(run(['gate', root, '--format', 'json']));
    const md5 = violations.filter(v => /^md5$/i.test(v.algorithm) && v.file !== undefined);
    assert.deepEqual(sorted(md5.map(v => named(v.file))), sorted([RLO_NAME, PCT_NAME].map(show)));
  });

  it('reads the source context of each record from the file it names', () => {
    const records = buildFindingRecords(scanProject(root), root);
    assert.ok(records.some(r => named(r.file) === 'x%.js'), 'no record for x%.js');
    for (const r of records) {
      const name = named(r.file);
      assert.ok(SHOWN.includes(name), name);
      assert.match(r.context.line, new RegExp(`marker-${SHOWN.indexOf(name)}$`),
        `record for "${show(r.file)}" read "${show(r.context.line)}"`);
    }
  });
});
