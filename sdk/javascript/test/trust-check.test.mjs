/**
 * The trust check in `scan` and `gate`: a certificate whose key is one of the
 * eight compromised eMudhra intermediate keys (trust/compromised-ca-key), or
 * that is or chains to emSign ECC Root CA - G3 (trust/distrusted-root).
 *
 * The fixtures are public certificates committed under testdata/trust-keys;
 * its README says where each came from. Every expected value below is
 * recomputed here from those certificates, not read from the code under test.
 * Nothing here reaches the network.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { X509Certificate, createHash } from 'node:crypto';
import { readFileSync, readdirSync, mkdtempSync, writeFileSync, existsSync, copyFileSync, cpSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { checkCertificateText } from '../lib/trust-check.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = join(__dirname, '..', 'bin', 'cryptoserve.mjs');
const REPO = join(__dirname, '..', '..', '..');
const FIXTURES = join(REPO, 'testdata', 'trust-keys');
const SCAN_FIXTURE = join(FIXTURES, 'scan');
const CONTROL = join(FIXTURES, 'control');
const LISTED = join(FIXTURES, 'listed');

function run(argv, options = {}) {
  const r = spawnSync(process.execPath, [CLI, ...argv], { encoding: 'utf-8', timeout: 60000, ...options });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const cert = (rel) => new X509Certificate(readFileSync(join(FIXTURES, rel)));
const certSha = (x) => sha256(x.raw);
const spkiSha = (x) => sha256(x.publicKey.export({ type: 'spki', format: 'der' }));

/** 1-based line of each `-----BEGIN CERTIFICATE-----` header in a file. */
function headerLines(path) {
  return readFileSync(path, 'utf8').split('\n')
    .map((l, i) => (l.startsWith('-----BEGIN CERTIFICATE-----') ? i + 1 : 0))
    .filter(Boolean);
}

const FIX = {
  tls: 'Replace the chain with one issued by a CA none of whose keys is listed, and remove this certificate from any bundle or pin set you ship.',
  codeSigning: 'Re-sign the artifacts with a certificate from a CA none of whose keys is listed and republish; a verifier that checks revocation can reject signatures under this key.',
  root: "Move the chain to a CA whose root stays trusted, and remove emSign ECC Root CA - G3 from any bundle you ship; Chrome's removal date for all devices is 2026-10-27.",
};
const ISSUE = {
  1: 'Certificate uses a publicly compromised CA key (eMudhra intermediate, Mozilla Bug 2083449)',
  2: 'Certificate is signed by a publicly compromised CA key (eMudhra intermediate, Mozilla Bug 2083449)',
  3: "Certificate is emSign ECC Root CA - G3, removed from Mozilla's root store on 2026-10-20",
  4: "Chain anchors on emSign ECC Root CA - G3, removed from Mozilla's root store on 2026-10-20",
};
const PAGE = {
  'trust/compromised-ca-key': 'https://github.com/ecolibria/cryptoserve/blob/main/docs/findings/trust-compromised-key.md',
  'trust/distrusted-root': 'https://github.com/ecolibria/cryptoserve/blob/main/docs/findings/trust-distrusted-root.md',
};
const SPKI_CMD = "openssl x509 -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \\n'";
const CERT_CMD = "openssl x509 -outform DER | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \\n'";

// The keys of a trustFindings entry, in the order `scan --format json` writes
// them; a key that does not apply is null, never absent.
const ENTRY_KEYS = ['id', 'kind', 'issue', 'severity', 'file', 'line', 'matchedValue', 'valueType',
  'issuerSpkiSha256', 'keyUse', 'trustRule', 'distrustDate', 'verify', 'fix', 'references'];
// The data a SARIF trust result carries in `properties`, under the same names.
const PROPERTY_KEYS = ['kind', 'matchedValue', 'valueType', 'issuerSpkiSha256', 'keyUse', 'trustRule', 'distrustDate'];

// A distrustedRoot finding carries the distrustDate of the removed root's row
// in the key table, and null when the row has none.
const LIB = join(__dirname, '..', 'lib');
const ROOT_ROW = JSON.parse(readFileSync(join(LIB, 'trust-keys.json'), 'utf8')).keys.find((k) => k.use === 'root');
const ROOT_DATE = ROOT_ROW.distrustDate ?? null;

// The certificates the scan fixture is built from.
const LEAF = cert('leaves/crtsh-29977124910/cert.crt');
const OV_G3C = cert('listed/cb6e15165ac802e9b3f993f16c25d41f4e81c21ebde71ae1b012ac00bf9c7c3f/cert.crt');
const ANCHORED = cert('anchored/crtsh-14658191778/cert.crt');
const ROOT = cert('root/emsign-ecc-root-ca-g3.crt');

function expectedScanFindings() {
  const [, anchoredLine] = headerLines(join(SCAN_FIXTURE, 'chain.crt'));
  const [, rootLine] = headerLines(join(SCAN_FIXTURE, 'ca-bundle.crt'));
  return [
    {
      id: 'trust/distrusted-root', kind: 'distrustedRoot', issue: ISSUE[3], severity: 'high', file: 'ca-bundle.crt', line: rootLine,
      matchedValue: spkiSha(ROOT), valueType: 'spkiSha256', issuerSpkiSha256: null, keyUse: 'root', trustRule: 3, distrustDate: ROOT_DATE,
      verify: `awk 'NR>=${rootLine}' ca-bundle.crt | ${SPKI_CMD}`, fix: FIX.root, references: [PAGE['trust/distrusted-root']],
    },
    {
      id: 'trust/compromised-ca-key', kind: 'compromisedCaKey', issue: ISSUE[2], severity: 'critical', file: 'cert.crt', line: 1,
      matchedValue: certSha(LEAF), valueType: 'certSha256', issuerSpkiSha256: spkiSha(OV_G3C), keyUse: 'tls', trustRule: 2, distrustDate: null,
      verify: `openssl x509 -in cert.crt -outform DER | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \\n'`,
      fix: FIX.tls, references: [PAGE['trust/compromised-ca-key']],
    },
    {
      id: 'trust/compromised-ca-key', kind: 'compromisedCaKey', issue: ISSUE[1], severity: 'critical', file: 'chain.crt', line: 1,
      matchedValue: spkiSha(OV_G3C), valueType: 'spkiSha256', issuerSpkiSha256: null, keyUse: 'tls', trustRule: 1, distrustDate: null,
      verify: `openssl x509 -in chain.crt -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \\n'`,
      fix: FIX.tls, references: [PAGE['trust/compromised-ca-key']],
    },
    {
      id: 'trust/distrusted-root', kind: 'distrustedRoot', issue: ISSUE[4], severity: 'high', file: 'chain.crt', line: anchoredLine,
      matchedValue: certSha(ANCHORED), valueType: 'certSha256', issuerSpkiSha256: spkiSha(ROOT), keyUse: 'root', trustRule: 4, distrustDate: ROOT_DATE,
      verify: `awk 'NR>=${anchoredLine}' chain.crt | ${CERT_CMD}`, fix: FIX.root, references: [PAGE['trust/distrusted-root']],
    },
  ];
}

const byPlace = (a, b) => a.file.localeCompare(b.file) || a.line - b.line;
const byValue = (a, b) => a.matchedValue.localeCompare(b.matchedValue);

/** What a SARIF trust result carries in `properties`: the finding's data, a null value left out. */
const sarifProperties = (findings) => findings.map((f) =>
  Object.fromEntries(PROPERTY_KEYS.filter((k) => f[k] !== null).map((k) => [k, f[k]])));

function scanJson(dir) {
  const r = run(['scan', dir, '--format', 'json']);
  assert.equal(r.code, 0, r.stderr);
  return JSON.parse(r.stdout);
}

const HAVE_OPENSSL = spawnSync('openssl', ['version'], { encoding: 'utf-8' }).status === 0;
const NO_OPENSSL = !HAVE_OPENSSL && 'openssl is not on PATH, so a printed Verify command cannot be run here';

describe('trust check fixtures', () => {
  it('hold the removed root with the certificate and SPKI SHA-256 the advisory gives', () => {
    assert.equal(certSha(ROOT), '86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b');
    assert.equal(spkiSha(ROOT), '8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782');
  });

  it('hold 16 listed certificates, each named by its own SHA-256, for eight keys', () => {
    const dirs = readdirSync(LISTED);
    assert.equal(dirs.length, 16);
    const keys = new Set();
    for (const d of dirs) {
      const x = cert(join('listed', d, 'cert.crt'));
      assert.equal(certSha(x), d, `listed/${d}/cert.crt is not the certificate its directory names`);
      keys.add(spkiSha(x));
    }
    assert.equal(keys.size, 8);
  });
});

describe('scan reports the trust findings', () => {
  it('carries both kinds in trustFindings, one entry per certificate block, with every ruled field', () => {
    const results = scanJson(SCAN_FIXTURE);
    assert.ok(Array.isArray(results.trustFindings), 'scan --format json has no trustFindings array');
    assert.deepEqual([...results.trustFindings].sort(byPlace), expectedScanFindings());
    assert.deepEqual(
      [...new Set(results.trustFindings.map((f) => f.id))].sort(),
      ['trust/compromised-ca-key', 'trust/distrusted-root'],
    );
  });

  it('writes every entry with the same keys in the same order, a key that does not apply set to null', () => {
    for (const dir of [SCAN_FIXTURE, LISTED]) {
      for (const f of scanJson(dir).trustFindings) {
        assert.deepEqual(Object.keys(f), ENTRY_KEYS, `${f.file}:${f.line}`);
      }
    }
  });

  it('pairs each rule id with one kind, and each kind with one rule id', () => {
    const findings = [...scanJson(SCAN_FIXTURE).trustFindings, ...scanJson(LISTED).trustFindings];
    assert.deepEqual(
      [...new Set(findings.map((f) => `${f.id} ${f.kind}`))].sort(),
      ['trust/compromised-ca-key compromisedCaKey', 'trust/distrusted-root distrustedRoot'],
    );
  });

  it('carries the removed root row\'s distrustDate on each distrustedRoot finding, and null on each compromisedCaKey finding', async () => {
    // A copy of the library whose key table gives the root's row a date, so a
    // date read back can only have come from the row. Any date does.
    const date = '2000-01-01';
    const base = mkdtempSync(join(tmpdir(), 'trust-date-'));
    try {
      const lib = join(base, 'lib');
      cpSync(LIB, lib, { recursive: true });
      const table = JSON.parse(readFileSync(join(lib, 'trust-keys.json'), 'utf8'));
      table.keys.find((k) => k.use === 'root').distrustDate = date;
      writeFileSync(join(lib, 'trust-keys.json'), JSON.stringify(table));
      const { checkCertificateText } = await import(pathToFileURL(join(lib, 'trust-check.mjs')).href);
      const findings = ['ca-bundle.crt', 'cert.crt', 'chain.crt'].flatMap((name) =>
        checkCertificateText(readFileSync(join(SCAN_FIXTURE, name), 'utf8'), { file: name, path: name }).findings);
      assert.deepEqual(findings.map((f) => [f.kind, f.trustRule, f.distrustDate]).sort(), [
        ['compromisedCaKey', 1, null], ['compromisedCaKey', 2, null],
        ['distrustedRoot', 3, date], ['distrustedRoot', 4, date],
      ]);
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  });

  it('leaves `rule` one type beside a misuse finding: the string id a waiver pragma names', () => {
    const dir = mkdtempSync(join(tmpdir(), 'trust-mixed-'));
    writeFileSync(join(dir, 'client.js'), 'const agent = { rejectUnauthorized: false };\n');
    copyFileSync(join(SCAN_FIXTURE, 'cert.crt'), join(dir, 'cert.pem'));
    const results = scanJson(dir);
    assert.equal(results.weakPatterns.length, 1, JSON.stringify(results.weakPatterns));
    assert.equal(results.trustFindings.length, 1);
    const types = new Set();
    const walk = (v) => {
      if (Array.isArray(v)) v.forEach(walk);
      else if (v !== null && typeof v === 'object') {
        if (Object.hasOwn(v, 'rule')) types.add(typeof v.rule);
        Object.values(v).forEach(walk);
      }
    };
    walk(results);
    assert.deepEqual([...types], ['string']);
    assert.equal(results.trustFindings[0].trustRule, 2);
  });

  it('matches every listed certificate by its key (rule 1), with the Fix chosen by the key\'s use', () => {
    const results = scanJson(LISTED);
    const findings = results.trustFindings || [];
    assert.equal(findings.length, 16, JSON.stringify(findings.map((f) => f.file)));
    for (const f of findings) {
      const x = new X509Certificate(readFileSync(join(LISTED, f.file)));
      const use = (x.keyUsage || []).includes('1.3.6.1.5.5.7.3.3') ? 'codeSigning' : 'tls';
      assert.equal(f.trustRule, 1);
      assert.equal(f.id, 'trust/compromised-ca-key');
      assert.equal(f.kind, 'compromisedCaKey');
      assert.equal(f.distrustDate, null);
      assert.equal(f.matchedValue, spkiSha(x));
      assert.equal(f.keyUse, use);
      assert.equal(f.fix, FIX[use]);
    }
    assert.equal(findings.filter((f) => f.keyUse === 'codeSigning').length, 4);
  });

  it('reports nothing, and prints no all-clear line, for the control root of the same CA', () => {
    const results = scanJson(CONTROL);
    assert.deepEqual(results.trustFindings, []);
    const text = run(['scan', CONTROL]);
    assert.equal(text.code, 0);
    // The markers a trust finding prints; the fixture's own path says "trust".
    assert.doesNotMatch(text.stdout, /TRUST\]|compromised CA key|emSign ECC Root CA - G3|Verify:|Trust findings/);
  });

  it('does not match a certificate that only carries the removed root\'s name', { skip: NO_OPENSSL }, () => {
    const dir = mkdtempSync(join(tmpdir(), 'trust-name-only-'));
    const made = spawnSync('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', '/dev/null', '-days', '1',
      '-subj', '/C=IN/OU=emSign PKI/O=eMudhra Technologies Limited/CN=emSign ECC Root CA - G3',
      '-out', join(dir, 'root.pem'),
    ], { encoding: 'utf-8' });
    assert.equal(made.status, 0, made.stderr);
    assert.deepEqual(scanJson(dir).trustFindings, []);
  });

  it('prints each finding under its file in the Certificate/Key Files section, with its Fix, and counts it', () => {
    const r = run(['scan', SCAN_FIXTURE]);
    assert.equal(r.code, 0, r.stderr);
    // The lines from each file's own line to the next file's, within the
    // section. Walk order is the file system's, so no order between files is
    // assumed.
    const lines = r.stdout.replace(/\x1b\[[0-9;]*m/g, '').split('\n').map((l) => l.trim().replace(/^\*\s+/, ''));
    const from = lines.findIndex((l) => l.includes('Certificate/Key Files'));
    const to = lines.findIndex((l, i) => i > from && l === 'Summary');
    assert.ok(from >= 0 && to > from, 'no Certificate/Key Files section before Summary');
    const files = ['ca-bundle.crt', 'cert.crt', 'chain.crt'];
    const starts = files.map((f) => lines.indexOf(f, from)).sort((a, b) => a - b);
    const block = (f) => {
      const at = lines.indexOf(f, from);
      const next = starts.find((s) => s > at) ?? to;
      return lines.slice(at, next).join('\n');
    };
    assert.ok(block('cert.crt').includes(ISSUE[2]));
    assert.ok(block('cert.crt').includes(`Fix: ${FIX.tls}`));
    assert.ok(block('chain.crt').includes(ISSUE[1]));
    assert.ok(block('chain.crt').includes(ISSUE[4]));
    assert.ok(block('chain.crt').includes(`Fix: ${FIX.root}`));
    assert.ok(block('ca-bundle.crt').includes(ISSUE[3]));
    assert.ok(block('ca-bundle.crt').includes(`Fix: ${FIX.root}`));
    assert.match(r.stdout, /Trust findings\D+4/);
  });

  it('prints a Verify command that, run as printed, prints the finding\'s value', { skip: NO_OPENSSL }, () => {
    const r = run(['scan', SCAN_FIXTURE]);
    for (const f of expectedScanFindings()) {
      assert.ok(r.stdout.includes(`Verify: ${f.verify}`), `text output lacks: Verify: ${f.verify}`);
      const out = spawnSync('sh', ['-c', f.verify], { cwd: SCAN_FIXTURE, encoding: 'utf-8' });
      assert.equal(out.status, 0, out.stderr);
      assert.equal(out.stdout, f.matchedValue, `${f.file}:${f.line}`);
    }
  });

  it('quotes a hostile file name in the Verify command so the shell runs nothing from it', { skip: NO_OPENSSL }, () => {
    const dir = mkdtempSync(join(tmpdir(), 'trust-hostile-'));
    const names = ["it's $(touch PWNED).pem", '-leaf.pem', 'a\u{202e}b.pem', 'line\nbreak.pem'];
    for (const name of names) copyFileSync(join(SCAN_FIXTURE, 'cert.crt'), join(dir, name));
    const findings = scanJson(dir).trustFindings;
    assert.equal(findings.length, names.length);
    for (const f of findings) {
      assert.doesNotMatch(f.verify, /[\u0000-\u001f\u007f-\u009f\u{202a}-\u{202e}\u{2066}-\u{2069}]/u);
      const out = spawnSync('sh', ['-c', f.verify], { cwd: dir, encoding: 'utf-8' });
      assert.equal(out.stdout, certSha(LEAF), `${JSON.stringify(f.verify)}: ${out.stderr}`);
    }
    assert.equal(existsSync(join(dir, 'PWNED')), false, 'a printed Verify command ran a command substitution');
  });

  it('finds a certificate after text and other blocks, at the line of its header', { skip: NO_OPENSSL }, () => {
    const dir = mkdtempSync(join(tmpdir(), 'trust-bundle-'));
    const text = '# CA bundle\n\n'
      + readFileSync(join(FIXTURES, 'control', 'emsign-root-ca-g1.crt'), 'utf8')
      + '\n=== emSign ECC Root CA - G3\nsubject and fingerprint lines\n'
      + readFileSync(join(FIXTURES, 'root', 'emsign-ecc-root-ca-g3.crt'), 'utf8');
    writeFileSync(join(dir, 'cert.pem'), text);
    const [f] = scanJson(dir).trustFindings;
    assert.equal(f.trustRule, 3);
    assert.equal(f.line, headerLines(join(dir, 'cert.pem'))[1]);
    const out = spawnSync('sh', ['-c', f.verify], { cwd: dir, encoding: 'utf-8' });
    assert.equal(out.stdout, spkiSha(ROOT));
  });

  it('reads a header followed by a long run of line breaks and no END line in linear time', () => {
    // Every certificate-extension file is read whole, and its contents are
    // chosen by whoever committed it.
    for (const lineBreak of ['\n', '\r\n', '\r']) {
      const text = `-----BEGIN CERTIFICATE-----${lineBreak.repeat(131072 / lineBreak.length)}`;
      const started = process.hrtime.bigint();
      const result = checkCertificateText(text, { file: 'cert.pem', path: 'cert.pem' });
      const ms = Number(process.hrtime.bigint() - started) / 1e6;
      assert.deepEqual(result, { checked: 0, findings: [] });
      assert.ok(ms < 1000, `${JSON.stringify(lineBreak)}: ${ms.toFixed(0)} ms for ${text.length} characters`);
    }
  });

  it('carries the findings into SARIF under one rule id per kind', () => {
    const r = run(['scan', SCAN_FIXTURE, '--format', 'sarif']);
    const results = JSON.parse(r.stdout).runs[0].results;
    const trust = results.filter((x) => x.ruleId.startsWith('cryptoserve/trust/'));
    assert.deepEqual(
      trust.map((x) => x.ruleId).sort(),
      ['cryptoserve/trust/compromised-ca-key', 'cryptoserve/trust/compromised-ca-key',
        'cryptoserve/trust/distrusted-root', 'cryptoserve/trust/distrusted-root'],
    );
    for (const x of trust) assert.equal(x.level, 'error');
  });

  it('carries each finding\'s data in its SARIF result\'s properties, under the JSON names, a null value left out', () => {
    const r = run(['scan', SCAN_FIXTURE, '--format', 'sarif']);
    const trust = JSON.parse(r.stdout).runs[0].results.filter((x) => x.ruleId.startsWith('cryptoserve/trust/'));
    const properties = trust.map((x) => x.properties ?? null);
    assert.ok(properties.every(Boolean), 'a SARIF trust result has no properties');
    assert.deepEqual([...properties].sort(byValue), sarifProperties(expectedScanFindings()).sort(byValue));
    for (const p of properties) assert.deepEqual(Object.keys(p), PROPERTY_KEYS.filter((k) => k in p));
    assert.deepEqual([...new Set(properties.map((p) => p.kind))].sort(), ['compromisedCaKey', 'distrustedRoot']);
  });
});

describe('gate fails on the trust findings', () => {
  it('exits 1 on the fixture and names each finding as a TRUST violation', () => {
    const r = run(['gate', SCAN_FIXTURE, '--format', 'json']);
    assert.equal(r.code, 1, r.stderr);
    const g = JSON.parse(r.stdout);
    assert.equal(g.status, 'fail');
    const trust = g.violations.filter((v) => v.type === 'trust');
    assert.equal(trust.length, 4);
    assert.deepEqual(trust.map((v) => v.severity).sort(), ['critical', 'critical', 'high', 'high']);
    assert.equal(g.summary.trust, 4);
    const text = run(['gate', SCAN_FIXTURE]);
    assert.equal(text.code, 1);
    assert.match(text.stdout, /\[CRITICAL TRUST\]/);
    assert.match(text.stdout, /\[HIGH TRUST\]/);
  });

  it('carries kind, trustRule and distrustDate on each trust violation, and no rule, with the scan entry\'s values', () => {
    const g = JSON.parse(run(['gate', SCAN_FIXTURE, '--format', 'json']).stdout);
    const trust = g.violations.filter((v) => v.type === 'trust').sort(byPlace);
    const expected = expectedScanFindings();
    assert.equal(trust.length, expected.length);
    trust.forEach((v, i) => {
      const at = `${v.file}:${v.line}`;
      assert.equal(Object.hasOwn(v, 'rule'), false, `${at} carries rule, the key a waiver pragma names`);
      for (const k of PROPERTY_KEYS) {
        assert.ok(Object.hasOwn(v, k), `${at} has no ${k}`);
        assert.equal(v[k], expected[i][k], `${at} ${k}`);
      }
    });
  });

  it('cannot be waived by --max-severity or --allow-secrets', () => {
    for (const flags of [['--max-severity', 'none'], ['--max-severity', 'low'], ['--max-severity', 'medium'], ['--allow-secrets']]) {
      const r = run(['gate', SCAN_FIXTURE, ...flags, '--format', 'json']);
      assert.equal(r.code, 1, `gate exited ${r.code}, not 1, with ${flags.join(' ')}`);
      assert.equal(JSON.parse(r.stdout).violations.filter((v) => v.type === 'trust').length, 4);
    }
  });

  it('exits 0 on the control directory, which holds another root of the same CA', () => {
    const r = run(['gate', CONTROL, '--format', 'json']);
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(JSON.parse(r.stdout).status, 'pass');
  });

  it('carries the violations into the gate SARIF', () => {
    const r = run(['gate', SCAN_FIXTURE, '--format', 'sarif']);
    assert.equal(r.code, 1);
    const ids = JSON.parse(r.stdout).runs[0].results.map((x) => x.ruleId);
    assert.ok(ids.includes('cryptoserve/trust/compromised-ca-key'));
    assert.ok(ids.includes('cryptoserve/trust/distrusted-root'));
  });

  it('carries each violation\'s data in its gate SARIF result\'s properties, as scan does', () => {
    const r = run(['gate', SCAN_FIXTURE, '--format', 'sarif']);
    assert.equal(r.code, 1);
    const trust = JSON.parse(r.stdout).runs[0].results.filter((x) => x.ruleId.startsWith('cryptoserve/trust/'));
    const properties = trust.map((x) => x.properties ?? null);
    assert.ok(properties.every(Boolean), 'a gate SARIF trust result has no properties');
    assert.deepEqual([...properties].sort(byValue), sarifProperties(expectedScanFindings()).sort(byValue));
  });
});

describe('the key table', () => {
  const ENGINE_COPY = join(REPO, 'backend', 'app', 'core', 'trust_keys.json');
  const CLI_COPY = join(__dirname, '..', 'lib', 'trust-keys.json');

  it('is byte-equal in the certificate engine and in the CLI', () => {
    assert.ok(readFileSync(ENGINE_COPY).equals(readFileSync(CLI_COPY)));
  });

  it('is what the committed generator derives from the fixture certificates', () => {
    const r = spawnSync(process.execPath, [join(REPO, 'scripts', 'trust-keys', 'generate.mjs'), '--check'], { encoding: 'utf-8' });
    assert.equal(r.status, 0, r.stderr);
  });

  // The CryptoScan table lives in another repository, so the comparison reads
  // it from a path named by CRYPTOSCAN_TRUST_KEYS. It compares the values both
  // tools match on, whatever the file's format: every SPKI SHA-256 and
  // certificate SHA-256 (64 hex digits), and every base64 SPKI DER.
  it('equals the CryptoScan key table', {
    skip: !process.env.CRYPTOSCAN_TRUST_KEYS && 'CRYPTOSCAN_TRUST_KEYS is not set; set it to the CryptoScan key table to compare',
  }, () => {
    const ours = JSON.parse(readFileSync(CLI_COPY, 'utf8')).keys;
    const theirs = readFileSync(process.env.CRYPTOSCAN_TRUST_KEYS, 'utf8');
    const hex = new Set((theirs.match(/\b[0-9a-fA-F]{64}\b/g) || []).map((h) => h.toLowerCase()));
    const b64 = new Set(theirs.match(/MH[A-Za-z0-9+/]{100,}={0,2}/g) || []);
    const ourHex = new Set(ours.flatMap((k) => [k.spkiSha256, ...k.certSha256]));
    assert.deepEqual([...hex].sort(), [...ourHex].sort(), 'the SPKI and certificate SHA-256 values differ');
    assert.deepEqual([...b64].sort(), ours.map((k) => k.spkiDer).sort(), 'the SPKI DER values differ');
  });
});
