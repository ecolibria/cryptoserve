import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = join(__dirname, '..', 'bin', 'cryptoserve.mjs');
const TEST_DIR = join(tmpdir(), 'cryptoserve-gate-test-' + Date.now());

function setup() { mkdirSync(TEST_DIR, { recursive: true }); }
function cleanup() { if (existsSync(TEST_DIR)) rmSync(TEST_DIR, { recursive: true, force: true }); }

function runGate(args = '') {
  try {
    const output = execSync(`${process.execPath} ${CLI} gate ${TEST_DIR} ${args}`, {
      encoding: 'utf-8',
      timeout: 30000,
    });
    return { exitCode: 0, output };
  } catch (e) {
    return { exitCode: e.status, output: e.stdout || '' };
  }
}

describe('gate command', () => {
  beforeEach(setup);
  afterEach(cleanup);

  it('passes for project with no crypto', () => {
    writeFileSync(join(TEST_DIR, 'package.json'), JSON.stringify({ name: 'test' }));
    writeFileSync(join(TEST_DIR, 'index.js'), 'console.log("hello");\n');
    const { exitCode } = runGate('--format json');
    assert.equal(exitCode, 0);
  });

  it('returns JSON output with --format json', () => {
    writeFileSync(join(TEST_DIR, 'package.json'), JSON.stringify({ name: 'test' }));
    const { output } = runGate('--format json');
    const result = JSON.parse(output);
    assert.ok(result.status);
    assert.ok(typeof result.score === 'number');
    assert.ok(Array.isArray(result.violations));
    assert.ok(result.summary);
  });

  it('detects quantum-vulnerable algorithms', () => {
    writeFileSync(join(TEST_DIR, 'package.json'), JSON.stringify({
      dependencies: { 'jsonwebtoken': '^9.0.0', 'node-rsa': '^1.1.0' },
    }));
    const { output } = runGate('--format json --max-risk low');
    const result = JSON.parse(output);
    assert.equal(result.status, 'fail');
    assert.ok(result.violations.length > 0);
  });

  it('enforces minimum score threshold', () => {
    writeFileSync(join(TEST_DIR, 'package.json'), JSON.stringify({
      dependencies: { 'jsonwebtoken': '^9.0.0' },
    }));
    const { exitCode } = runGate('--format json --min-score 99');
    assert.equal(exitCode, 1);
  });

  it('detects weak algorithms with --fail-on-weak', () => {
    // Rewritten: the previous version wrapped its assertion in
    // `if (result.violations.some(v => v.weak))`, so it passed vacuously if the
    // flag stopped working. AES-ECB is weak in the algorithm database, so the
    // violation is asserted unconditionally.
    writeFileSync(join(TEST_DIR, 'package.json'), JSON.stringify({ name: 'weak' }));
    writeFileSync(join(TEST_DIR, 'app.js'),
      'const c = require("crypto");\nconst ci = c.createCipheriv("aes-256-ecb", k, iv);\n');
    const { exitCode, output } = runGate('--format json --min-score 0 --fail-on-weak');
    const result = JSON.parse(output);
    assert.equal(result.status, 'fail');
    assert.equal(exitCode, 1);
    assert.ok(result.violations.some(v => v.weak), output);
  });

  it('exits 2 with status=error when path does not exist', () => {
    // A typo in CI (`cryptoserve gate ./srcc`) must not silently pass.
    const missing = join(tmpdir(), 'cryptoserve-gate-missing-' + Date.now());
    let exitCode = 0;
    let output = '';
    try {
      output = execSync(
        `${process.execPath} ${CLI} gate ${missing} --format json`,
        { encoding: 'utf-8', timeout: 10000 },
      );
    } catch (e) {
      exitCode = e.status;
      output = e.stdout || '';
    }
    assert.equal(exitCode, 2);
    const result = JSON.parse(output);
    assert.equal(result.status, 'error');
    assert.ok(/does not exist/i.test(result.error));
  });
});

/**
 * Two axes, two flags (issue #58).
 *
 * `--max-risk` bounds QUANTUM risk. `--max-severity` bounds the SECURITY
 * severity `scan` reports. Before 0.6.0 only the first existed, which meant the
 * strictest available setting failed a correct modern project (SHA-256 carries
 * quantum risk `low`) and passed a real weakness (unauthenticated CBC, which
 * `scan` rates `medium`), and no flag combination could reach a medium finding
 * at all. `--fail-on-weak` additionally rewrote the `risk` of the findings it
 * took over, so a CI policy filtering `.risk == "high"` saw nothing under the
 * flag whose name sounds strictest.
 */
describe('gate severity axis', () => {
  const DIR = join(tmpdir(), 'cryptoserve-gate-severity-' + Date.now());

  beforeEach(() => { mkdirSync(DIR, { recursive: true }); });
  afterEach(() => { if (existsSync(DIR)) rmSync(DIR, { recursive: true, force: true }); });

  function project(source, name = 'fixture') {
    writeFileSync(join(DIR, 'package.json'), JSON.stringify({ name }));
    writeFileSync(join(DIR, 'app.js'), source);
  }

  function gate(args = '') {
    try {
      const output = execSync(`${process.execPath} ${CLI} gate ${DIR} ${args}`,
        { encoding: 'utf-8', timeout: 30000, stdio: ['pipe', 'pipe', 'pipe'] });
      return { exitCode: 0, output };
    } catch (e) {
      return { exitCode: e.status, output: e.stdout || '' };
    }
  }

  function gateJson(args = '') {
    const { exitCode, output } = gate(`${args} --format json`);
    return { exitCode, result: JSON.parse(output), output };
  }

  const CBC = 'const c = require("crypto");\nconst ci = c.createCipheriv("aes-256-cbc", k, iv);\n';
  const ECB = 'const c = require("crypto");\nconst ci = c.createCipheriv("aes-256-ecb", k, iv);\n';
  const CLEAN = 'const c = require("crypto");\n'
    + 'const ci = c.createCipheriv("aes-256-gcm", k, iv);\n'
    + 'const h = c.createHash("sha256");\n';
  const TLS_OFF = 'const opts = { rejectUnauthorized: false };\n';

  it('reaches a medium-severity finding with --max-severity low', () => {
    // `scan` reports unauthenticated CBC at severity medium. Before 0.6.0 no
    // combination of --max-risk, --fail-on-weak or --min-score could fail the
    // gate on it; it was counted as safe.
    project(CBC);
    const { exitCode, result } = gateJson('--min-score 0 --max-severity low');
    assert.equal(result.status, 'fail', JSON.stringify(result, null, 1));
    assert.equal(exitCode, 1);
    const cbc = result.violations.find(v => /cbc/i.test(v.algorithm));
    assert.ok(cbc, JSON.stringify(result.violations));
    assert.equal(cbc.severity, 'medium');
    assert.equal(cbc.severityBreach, true);
  });

  it('leaves the default verdict on a medium finding unchanged', () => {
    // The defect was unreachability, not laxity. Tightening the DEFAULT would
    // flip verdicts for every existing CI job on upgrade with no code change,
    // which is the same "trains people to ignore it" failure the release gate
    // was just fixed for. Default stays at medium: high and critical fail.
    project(CBC);
    const { exitCode, result } = gateJson('--min-score 0');
    assert.equal(result.status, 'pass', JSON.stringify(result, null, 1));
    assert.equal(exitCode, 0);
  });

  it('refuses a --max-severity that would loosen the floor', () => {
    // high and critical always fail the gate. Accepting `--max-severity high`
    // and silently ignoring it would be a flag that appears to do something and
    // does not; honouring it would turn the flag into an enforcement kill
    // switch for TLS-verification-bypass findings. Both are worse than exit 2.
    project(CBC);
    for (const level of ['high', 'critical']) {
      const { exitCode, result } = gateJson(`--min-score 0 --max-severity ${level}`);
      assert.equal(exitCode, 2, `--max-severity ${level}`);
      assert.equal(result.status, 'error');
      assert.match(result.error, /can only tighten|none, low or medium/i);
    }
  });

  it('keeps a critical misuse failing at every accepted --max-severity', () => {
    // No accepted value of the new flag may waive a critical finding.
    project(TLS_OFF);
    for (const level of ['none', 'low', 'medium']) {
      const { exitCode, result } = gateJson(`--min-score 0 --max-severity ${level}`);
      assert.equal(result.status, 'fail', `--max-severity ${level}: ${JSON.stringify(result)}`);
      assert.equal(exitCode, 1);

      const misuse = result.violations.find(v => v.type === 'misuse');
      assert.ok(misuse, JSON.stringify(result.violations));
      assert.equal(misuse.severity, 'critical');
      // A disabled certificate check is not a statement about quantum
      // resistance. `risk` carried the security severity here, which is the
      // conflation of the two axes in its purest form.
      assert.equal(misuse.risk, null, JSON.stringify(misuse));
    }
  });

  it('reports the same risk and severity whether or not --fail-on-weak is passed', () => {
    // The reported classification of a finding is a property of the finding.
    // Before 0.6.0, AES-ECB went risk high -> none under --fail-on-weak, `type`
    // was dropped, and the actionable fix was replaced by a bare description.
    project(ECB);
    const plain = gateJson('--min-score 0').result;
    const weak = gateJson('--min-score 0 --fail-on-weak').result;

    const find = r => r.violations.find(v => /ecb/i.test(v.algorithm));
    const a = find(plain);
    const b = find(weak);
    assert.ok(a, JSON.stringify(plain.violations));
    assert.ok(b, JSON.stringify(weak.violations));

    assert.equal(a.risk, b.risk, 'quantum risk must not depend on flags');
    assert.equal(a.severity, b.severity, 'security severity must not depend on flags');
    // AES-ECB is structurally broken rather than quantum-broken: no quantum
    // risk, high security severity. Both axes are reported, and neither is the
    // other's label.
    assert.equal(a.risk, 'none');
    assert.equal(a.severity, 'high');
    // The actionable remediation survives the flag.
    assert.match(a.reason, /AES-256-GCM/);
    assert.match(b.reason, /AES-256-GCM/);
  });

  it('does not count an algorithm it just failed on as safe', () => {
    // `safe` counted anything quantum none/low, so AES-ECB -- structurally
    // broken, quantum-irrelevant -- was reported as a safe algorithm in the
    // same summary whose violation list failed the build.
    project(ECB);
    const { result } = gateJson('--min-score 0');
    assert.equal(result.status, 'fail');
    assert.equal(result.summary.safe, 0, JSON.stringify(result.summary));
    assert.equal(result.summary.severityBreaches, 1, JSON.stringify(result.summary));
  });

  it('separates quantum risk from security severity on a clean project', () => {
    // SHA-256 carries quantum risk `low` and no security finding at all. Under
    // one overloaded flag the strictest setting failed this project; the two
    // axes now disagree on purpose.
    project(CLEAN);
    const strictQuantum = gateJson('--min-score 0 --max-risk none').result;
    assert.equal(strictQuantum.status, 'fail');
    assert.ok(strictQuantum.violations.some(v => /sha/i.test(v.algorithm) && v.riskBreach));

    const strictSeverity = gateJson('--min-score 0 --max-severity none').result;
    assert.equal(strictSeverity.status, 'pass', JSON.stringify(strictSeverity, null, 1));
  });

  it('reports a quantum-only violation with no security severity', () => {
    project(CLEAN);
    const { result } = gateJson('--min-score 0 --max-risk none');
    const sha = result.violations.find(v => /sha/i.test(v.algorithm));
    assert.ok(sha);
    assert.equal(sha.risk, 'low');
    // No finding is a dead end. A quantum breach has no per-line fix, so it
    // names the command that plans a migration.
    assert.match(sha.reason, /cryptoserve pqc/);
    // `scan` reports no security finding for SHA-256, so there is no severity
    // to report. Not 'none' -- absent, which is a different claim.
    assert.equal(sha.severity, null);
  });

  it('does not let --max-severity waive credential findings', () => {
    // Secrets fail under their own rule and are waivable only by name, with
    // --allow-secrets. A severity threshold must not become a second waiver.
    writeFileSync(join(DIR, 'package.json'), JSON.stringify({ name: 'creds' }));
    writeFileSync(join(DIR, 'app.js'),
      'const c = require("crypto");\nconst apiKey = "AKIAIOSFODNN7EXAMPLE";\n');
    const { result } = gateJson('--min-score 0 --max-severity medium');
    assert.equal(result.status, 'fail', JSON.stringify(result, null, 1));
    assert.ok(result.violations.some(v => v.type === 'secret'), JSON.stringify(result.violations));
  });

  it('fails on a deprecated TLS protocol the scanner rates critical', () => {
    // The fifth appearance of one fail-open. `scan` reported SSLv3 at critical,
    // `gate` passed the tree, and `gate --format sarif` emitted three
    // level="error" results while exiting 0 -- one command contradicting itself
    // on one tree. Same shape as the secrets, private-key, misuse and AES-ECB
    // fail-opens fixed before it.
    writeFileSync(join(DIR, 'package.json'), JSON.stringify({ name: 'tlsfx' }));
    writeFileSync(join(DIR, 'nginx.conf'), 'server {\n  ssl_protocols SSLv3 TLSv1;\n}\n');
    writeFileSync(join(DIR, 'app.js'), CLEAN);

    const { exitCode, result } = gateJson('--min-score 0');
    assert.equal(result.status, 'fail', JSON.stringify(result, null, 1));
    assert.equal(exitCode, 1);

    const tls = result.violations.filter(v => v.type === 'tls');
    assert.ok(tls.length > 0, JSON.stringify(result.violations));
    assert.ok(tls.some(v => /SSLv3/.test(v.algorithm)), JSON.stringify(tls));
    assert.equal(tls[0].severity, 'critical');
    // A protocol version is not a statement about quantum resistance.
    assert.equal(tls[0].risk, null);
    // The scanner emits SSLv3 twice for one line (a protocol-specific pattern
    // and a generic config pattern). One line is one finding.
    const keys = tls.map(v => `${v.file}:${v.line}:${v.algorithm}`);
    assert.equal(new Set(keys).size, keys.length, `duplicated TLS findings: ${keys}`);
  });

  it('agrees between its own exit code and its own SARIF output', () => {
    // `gate --format sarif` exited 0 while writing three level="error" results.
    // A CI job uploading that report got three code-scanning alerts from a gate
    // that had just told the build it passed.
    writeFileSync(join(DIR, 'package.json'), JSON.stringify({ name: 'tlsfx' }));
    writeFileSync(join(DIR, 'nginx.conf'), 'server {\n  ssl_protocols SSLv3 TLSv1;\n}\n');
    writeFileSync(join(DIR, 'app.js'), CLEAN);

    const { exitCode, output } = gate('--min-score 0 --format sarif');
    const sarif = JSON.parse(output);
    const errors = (sarif.runs[0].results || []).filter(r => r.level === 'error');
    assert.ok(errors.length > 0, 'expected error-level SARIF results for SSLv3');
    assert.equal(exitCode, 1, 'SARIF reported errors, so the gate must not pass');
  });

  it('labels every violation on one severity scale', () => {
    // `[TLS]` and `[MEDIUM]` in the same list gave no way to see that the TLS
    // finding was critical and the other medium: two vocabularies, one column.
    // Severity leads every label that has one, category follows it.
    writeFileSync(join(DIR, 'package.json'), JSON.stringify({ name: 'mixed' }));
    writeFileSync(join(DIR, 'nginx.conf'), 'server {\n  ssl_protocols SSLv3;\n}\n');
    writeFileSync(join(DIR, 'app.js'),
      'const c = require("crypto");\nconst ci = c.createCipheriv("aes-256-cbc", k, iv);\n');

    const { output } = gate('--min-score 0 --max-severity low');
    // eslint-disable-next-line no-control-regex
    const plain = output.replace(/\[[0-9;]*m/g, '');
    assert.match(plain, /\[CRITICAL TLS\] SSLv3 enabled/, plain);
    assert.match(plain, /\[MEDIUM\] aes-cbc/, plain);
    // No label may carry a category without its severity when one exists.
    assert.doesNotMatch(plain, /\[TLS\]/, plain);
  });

  it('says in --help that --max-risk is about quantum risk', () => {
    const help = execSync(`${process.execPath} ${CLI} help gate`, { encoding: 'utf-8' });
    assert.match(help, /--max-risk/);
    assert.match(help, /quantum/i);
    assert.match(help, /--max-severity/);
  });

  it('says in --help that its SARIF is this run, not the whole tree', () => {
    // `gate --format sarif` and `scan --format sarif` used to be the same
    // document. They are now different answers to different questions, and a
    // CI author choosing between them has to be told which is which.
    const help = execSync(`${process.execPath} ${CLI} help gate`, { encoding: 'utf-8' });
    assert.match(help, /--format sarif/);
    assert.match(help, /scan --format sarif/);
  });
});

/**
 * One decision, three renderings.
 *
 * `gate --format sarif` re-ran `collectFindings(scanResults)` instead of
 * reporting the violations `gate` had just decided on, so the document was
 * byte-identical to `scan --format sarif` and no threshold reached it. A CI job
 * failed the build on three manifest violations and uploaded a SARIF naming one
 * source finding; another passed the build and uploaded alerts anyway.
 *
 * The test that shipped in #62 asserted only "SARIF has error results -> exit
 * 1". The converse -- gate failed, so SARIF must say why -- is the half that was
 * missing, and it is the half that was broken.
 */
describe('gate renders one decision in every format', () => {
  let DIR;
  // A fresh directory per test, from mkdtemp rather than a shared name: these
  // trees are what the assertions measure, and a sibling test writing into the
  // same path under a parallel runner would rewrite the measurement.
  beforeEach(() => { DIR = mkdtempSync(join(tmpdir(), 'cryptoserve-gate-format-')); });
  afterEach(() => { if (DIR && existsSync(DIR)) rmSync(DIR, { recursive: true, force: true }); });

  const MD5 = 'const c = require("crypto");\nconst h = c.createHash("md5");\n';
  const RSA = 'const c = require("crypto");\n'
    + 'const kp = c.generateKeyPairSync("rsa", { modulusLength: 2048 });\n';
  const CBC = 'const c = require("crypto");\nconst ci = c.createCipheriv("aes-256-cbc", k, iv);\n';
  const ECB = 'const c = require("crypto");\nconst ci = c.createCipheriv("aes-256-ecb", k, iv);\n';

  function write(name, body) { writeFileSync(join(DIR, name), body); }
  function manifest(deps) { write('package.json', JSON.stringify({ name: 'fmt', ...(deps ? { dependencies: deps } : {}) })); }

  function run(args) {
    try {
      return { exitCode: 0, output: execSync(`${process.execPath} ${CLI} gate ${DIR} ${args}`,
        { encoding: 'utf-8', timeout: 30000, stdio: ['pipe', 'pipe', 'pipe'] }) };
    } catch (e) {
      return { exitCode: e.status, output: e.stdout || '' };
    }
  }

  function asJson(args = '') {
    const { exitCode, output } = run(`${args} --format json`);
    return { exitCode, result: JSON.parse(output), output };
  }

  function asSarif(args = '') {
    const { exitCode, output } = run(`${args} --format sarif`);
    const doc = JSON.parse(output);
    return { exitCode, doc, results: doc.runs[0].results || [], output };
  }

  const uris = (results) => results
    .map(r => r.locations?.[0]?.physicalLocation?.artifactLocation?.uri)
    .sort();

  it('names in SARIF every violation that failed the build', () => {
    // crypto-js 3.1.9-1 puts DES and 3DES in the inventory from the manifest
    // alone; MD5 comes from source. `gate` failed on all three and its SARIF
    // carried the one that happened to be a scanner weakPattern, so the two
    // manifest violations that failed the build were invisible in the report
    // uploaded to explain it.
    manifest({ 'crypto-js': '3.1.9-1' });
    write('app.js', MD5);

    const { result } = asJson('--min-score 0');
    assert.equal(result.status, 'fail', JSON.stringify(result, null, 1));
    assert.ok(result.violations.length >= 3, JSON.stringify(result.violations));

    const { exitCode, results } = asSarif('--min-score 0');
    assert.equal(exitCode, 1);
    assert.equal(results.length, result.violations.length,
      `JSON reported ${result.violations.length} violations, SARIF ${results.length}`);
    for (const v of result.violations) {
      assert.ok(results.some(r => r.message.text.includes(v.algorithm)),
        `SARIF never names ${v.algorithm}: ${results.map(r => r.message.text).join(' | ')}`);
    }
  });

  it('uploads no alert for a tree it passed', () => {
    // Unauthenticated CBC is `medium`, which the default threshold accepts. The
    // gate said PASS and the same invocation emitted a code-scanning alert, so
    // a job that exited 0 still opened an alert nobody could act on -- the
    // reverse of the failure above, from the same cause.
    manifest();
    write('app.js', CBC);

    const { exitCode, result } = asJson('--min-score 0');
    assert.equal(result.status, 'pass', JSON.stringify(result, null, 1));
    assert.equal(exitCode, 0);

    const sarif = asSarif('--min-score 0');
    assert.equal(sarif.exitCode, 0);
    assert.deepEqual(sarif.results, [], `passing gate emitted ${sarif.results.length} SARIF results`);
  });

  it('changes the SARIF when a threshold changes the verdict', () => {
    // Pinned from both sides: the test above fixes the passing end, this one
    // the failing end. A SARIF emitter that reported nothing at all would
    // satisfy the first and fail this one.
    manifest();
    write('app.js', CBC);

    const { exitCode, results } = asSarif('--min-score 0 --max-severity low');
    assert.equal(exitCode, 1);
    assert.ok(results.some(r => /cbc/i.test(r.message.text)),
      `--max-severity low failed the gate but SARIF says: ${JSON.stringify(results)}`);
  });

  it('agrees with its own JSON at every threshold', () => {
    // The property, over the flags that move the verdict: one decision, so the
    // count and the exit code are the same in both formats.
    manifest({ 'crypto-js': '3.1.9-1' });
    write('app.js', MD5);
    write('lib.js', CBC);
    write('nginx.conf', 'server {\n  ssl_protocols SSLv3;\n}\n');

    for (const flags of ['', '--max-severity low', '--max-severity none', '--max-risk none', '--fail-on-weak']) {
      const j = asJson(`--min-score 0 ${flags}`);
      const s = asSarif(`--min-score 0 ${flags}`);
      assert.equal(s.exitCode, j.exitCode, `exit codes differ for "${flags}"`);
      assert.equal(s.results.length, j.result.violations.length,
        `"${flags}": ${j.result.violations.length} violations, ${s.results.length} SARIF results`);
    }
  });

  it('says in SARIF why a build failed on the score alone', () => {
    // The shape of the whole defect, on the one axis that raises no violation:
    // red build, empty document, nothing in the Security tab to explain it.
    manifest();
    write('app.js', RSA);

    const { exitCode, result } = asJson('--min-score 99');
    assert.equal(exitCode, 1);
    assert.equal(result.violations.length, 0, 'fixture must fail on score only');

    const sarif = asSarif('--min-score 99');
    assert.equal(sarif.exitCode, 1);
    assert.equal(sarif.results.length, 1, JSON.stringify(sarif.results));
    assert.match(sarif.results[0].message.text, /score .* below the minimum 99/i);
    assert.equal(sarif.results[0].level, 'error');
    // Anchored, or code scanning renders no alert for it at all.
    assert.deepEqual(uris(sarif.results), ['package.json'], JSON.stringify(sarif.results));
  });

  it('anchors a score failure even with no manifest to anchor it to', () => {
    // The score is computed from source-detected libraries too, so a tree with
    // no manifest can fail on it. `locations: []` is schema-valid and invisible
    // in the Security tab, which is the defect this release is fixing.
    write('app.js', RSA);

    const { results } = asSarif('--min-score 99');
    assert.equal(results.length, 1, JSON.stringify(results));
    assert.deepEqual(uris(results), ['app.js'], JSON.stringify(results));
    // The anchor is a place to start reading, not the file that caused it.
    assert.match(results[0].message.text, /verdict on the project, not on this file/);
  });

  it('ranks a quantum-risk breach by its risk, not by a default', () => {
    // A quantum-only violation has no security severity -- that is the point of
    // the two axes -- so the SARIF level was falling to the "unknown severity"
    // default. A critical breach that failed the build was filed as a warning.
    manifest();
    write('app.js', RSA);

    const { results } = asSarif('--min-score 0 --max-risk low');
    const rsa = results.find(r => /rsa/i.test(r.message.text));
    assert.ok(rsa, JSON.stringify(results));
    assert.equal(rsa.level, 'error', JSON.stringify(rsa));
  });

  it('gives a finding the same rule id as scan does', () => {
    // Code scanning groups, deduplicates and tracks alerts by ruleId. Two
    // commands reporting one tree under two ids means an alert that closes and
    // reopens depending on which one ran.
    write('.env', `AWS_ACCESS_KEY_ID=${'AKIA' + 'EXAMPLEKEY0000FF'}\n`);
    // The manifest matters: the package database spells the algorithm `MD5`
    // and the source scanner canonicalizes the same one to `md5`, so a gate
    // reporting the dependency filed it under an id `scan` never emits.
    manifest({ 'crypto-js': '3.1.9-1' });
    write('app.js', MD5);
    write('nginx.conf', 'server {\n  ssl_protocols SSLv3;\n}\n');

    const scanned = JSON.parse(execSync(
      `${process.execPath} ${CLI} scan ${DIR} --format sarif`,
      { encoding: 'utf-8', timeout: 30000 },
    )).runs[0].results.map(r => r.ruleId);

    const mine = asSarif('--min-score 0').results.map(r => r.ruleId);

    // MD5, the secret and the protocol are in both reports, so both must file
    // them under one id. (DES and 3DES are in the gate's alone: they come from
    // the dependency, which `scan` never saw used. Two reports of different
    // things is not disagreement.)
    for (const id of ['cryptoserve/weak-algorithm/md5', 'cryptoserve/secret/aws-access', 'cryptoserve/tls/SSLv3']) {
      assert.ok(scanned.includes(id), `scan lost ${id}: ${scanned.join(', ')}`);
      assert.ok(mine.includes(id), `gate says ${mine.join(', ')}, not ${id}`);
    }

    // And nothing may agree only up to spelling: an id that differs by case is
    // a second rule as far as code scanning is concerned.
    const byCase = new Map(scanned.map(id => [id.toLowerCase(), id]));
    for (const id of mine) {
      const twin = byCase.get(id.toLowerCase());
      if (twin) assert.equal(id, twin, 'gate and scan spell one rule id two ways');
    }
  });

  it('gives a manifest violation an action the reader can actually take', () => {
    // Two failures, one line of text. It said "56-bit key is trivially
    // brutable", a description rather than a step. Answering it with the
    // scanner's step, "Replace with AES-256-GCM", is worse: crypto-js lists DES
    // in its catalogue whether or not anything calls it, so a user who has
    // fixed every line of their own code still fails the gate and is told to
    // edit a call site that does not exist. The remediation loop has to
    // terminate, and for a dependency it terminates at the dependency.
    manifest({ 'crypto-js': '3.1.9-1' });
    write('app.js', 'const c = require("crypto");\nconst ci = c.createCipheriv("des-ede3-cbc", k, iv);\n');

    const { result } = asJson('--min-score 0');
    const fromManifest = result.violations.find(v => /^des$/i.test(v.algorithm));
    const fromSource = result.violations.find(v => /3des|des-ede3/i.test(v.algorithm));
    assert.ok(fromManifest, JSON.stringify(result.violations, null, 1));
    assert.ok(fromSource, JSON.stringify(result.violations, null, 1));

    // The algorithm the scanner read in a file: edit that line.
    assert.match(fromSource.reason, /^Replace with AES-256-GCM/, fromSource.reason);
    assert.ok(fromSource.file, JSON.stringify(fromSource));

    // The algorithm reached only through the manifest: the same replacement is
    // named, and so is the fact that this one is about the dependency.
    assert.ok(fromManifest.manifest, JSON.stringify(fromManifest));
    assert.match(fromManifest.reason, /AES-256-GCM/, fromManifest.reason);
    assert.match(fromManifest.reason, /dependency/, fromManifest.reason);
    assert.match(fromManifest.reason, /not seen in the scanned source/, fromManifest.reason);
  });

  it('gives every SARIF result a location code scanning can render', () => {
    // A result with no physical location is dropped by GitHub code scanning, so
    // a manifest violation with nowhere to point would fail the build and still
    // show up nowhere. A dependency has a location: the manifest that declares
    // it.
    manifest({ 'crypto-js': '3.1.9-1' });
    write('app.js', MD5);

    const { results } = asSarif('--min-score 0');
    assert.ok(results.length > 0);
    for (const r of results) {
      const uri = r.locations?.[0]?.physicalLocation?.artifactLocation?.uri;
      assert.ok(uri, `no location on ${r.ruleId}: ${r.message.text}`);
    }
    assert.ok(uris(results).includes('package.json'),
      `manifest violations do not point at the manifest: ${uris(results)}`);
  });
});

/**
 * One algorithm in three files is three places to fix.
 *
 * `byAlgorithm` was keyed on the algorithm name and `locations` kept the first
 * hit, so MD5 in `a.js`, `b.js` and `c.js` was one violation naming `a.js`. A CI
 * user fixed that file, re-ran, and was shown `b.js` -- N cycles for N files --
 * while `scan` and the SARIF path reported all three from the start.
 *
 * The root cause is one level down: `scanProject` deduplicates
 * `sourceAlgorithms` on `algorithm:language` across the WHOLE tree, so the gate
 * could not have seen the second file. That is why the quantum-risk case below
 * matters: it has no weakPattern to fall back on.
 *
 * The dedup itself stays. The 0.4.0 bug it was added for was one call site
 * emitting a risk row and a weakness row for the SAME line, which the last test
 * here pins.
 */
describe('gate reports every place an algorithm is used', () => {
  let DIR;
  beforeEach(() => { DIR = mkdtempSync(join(tmpdir(), 'cryptoserve-gate-sites-')); });
  afterEach(() => { if (DIR && existsSync(DIR)) rmSync(DIR, { recursive: true, force: true }); });

  const MD5 = 'const c = require("crypto");\nconst h = c.createHash("md5");\n';
  const RSA = 'const c = require("crypto");\n'
    + 'const kp = c.generateKeyPairSync("rsa", { modulusLength: 2048 });\n';
  const ECB = 'const c = require("crypto");\nconst ci = c.createCipheriv("aes-256-ecb", k, iv);\n';

  function spread(body, files = ['a.js', 'b.js', 'c.js']) {
    writeFileSync(join(DIR, 'package.json'), JSON.stringify({ name: 'sites' }));
    for (const f of files) writeFileSync(join(DIR, f), body);
  }

  function run(args) {
    try {
      return { exitCode: 0, output: execSync(`${process.execPath} ${CLI} gate ${DIR} ${args}`,
        { encoding: 'utf-8', timeout: 30000, stdio: ['pipe', 'pipe', 'pipe'] }) };
    } catch (e) {
      return { exitCode: e.status, output: e.stdout || '' };
    }
  }

  const asJson = (args = '') => JSON.parse(run(`${args} --format json`).output);
  const asSarif = (args = '') => JSON.parse(run(`${args} --format sarif`).output).runs[0].results || [];

  it('reports a weak algorithm once per file, not once per name', () => {
    spread(MD5);
    const result = asJson('--min-score 0');
    const md5 = result.violations.filter(v => /md5/i.test(v.algorithm));
    assert.deepEqual(md5.map(v => v.file).sort(), ['a.js', 'b.js', 'c.js'],
      JSON.stringify(result.violations, null, 1));
  });

  it('reports a quantum-risk breach once per file too', () => {
    // No weakPattern exists for RSA -- it is not a weak algorithm, it is a
    // quantum-vulnerable one -- so this case cannot be fixed by reading the
    // scanner's weakness list. It pins the deduplication in `scanProject`.
    spread(RSA);
    const result = asJson('--min-score 0 --max-risk medium');
    const rsa = result.violations.filter(v => /rsa/i.test(v.algorithm));
    assert.deepEqual(rsa.map(v => v.file).sort(), ['a.js', 'b.js', 'c.js'],
      JSON.stringify(result.violations, null, 1));
  });

  it('names all three files in SARIF as well as JSON', () => {
    spread(MD5);
    const violations = asJson('--min-score 0').violations;
    const results = asSarif('--min-score 0');
    const uris = results
      .map(r => r.locations?.[0]?.physicalLocation?.artifactLocation?.uri)
      .sort();
    assert.deepEqual(uris, ['a.js', 'b.js', 'c.js'], JSON.stringify(results));
    assert.equal(results.length, violations.length);
  });

  it('still counts one algorithm at one location once', () => {
    // The 0.4.0 defect, kept red-proofed: `gate --fail-on-weak` emitted a row
    // for the risk breach and a row for the weakness from a single call site,
    // doubling the violation count. Splitting on location must not bring that
    // back -- one file, one violation, under the flag that used to double it.
    spread(ECB, ['a.js']);
    for (const flags of ['', '--fail-on-weak', '--max-risk none --fail-on-weak']) {
      const result = asJson(`--min-score 0 ${flags}`);
      const ecb = result.violations.filter(v => /ecb/i.test(v.algorithm));
      assert.equal(ecb.length, 1, `"${flags}" raised ${ecb.length} violations for one call site: `
        + JSON.stringify(ecb, null, 1));
    }
  });

  it('does not multiply a per-file violation by the flags that reach it', () => {
    spread(MD5);
    for (const flags of ['', '--fail-on-weak', '--max-risk none']) {
      const result = asJson(`--min-score 0 ${flags}`);
      const md5 = result.violations.filter(v => /md5/i.test(v.algorithm));
      assert.equal(md5.length, 3, `"${flags}": ${JSON.stringify(md5.map(v => `${v.file}:${v.line}`))}`);
    }
  });
});

/**
 * `gate --help` promises it fails on "critical API misuse such as a disabled
 * TLS certificate check". It knew one spelling of that, so a tree that turns
 * verification off in two languages and pins TLSv1 scored 100/100 and exited 0
 * (#66). Reproduced on released 0.5.0 too: pre-existing, not a regression.
 */
describe('gate fails a tree with TLS verification disabled', () => {
  let DIR;
  beforeEach(() => { DIR = mkdtempSync(join(tmpdir(), 'cryptoserve-gate-tls-')); });
  afterEach(() => { if (DIR && existsSync(DIR)) rmSync(DIR, { recursive: true, force: true }); });

  function run(args = '') {
    try {
      return { exitCode: 0, output: execSync(`${process.execPath} ${CLI} gate ${DIR} ${args}`,
        { encoding: 'utf-8', timeout: 30000, stdio: ['pipe', 'pipe', 'pipe'] }) };
    } catch (e) {
      return { exitCode: e.status, output: e.stdout || '' };
    }
  }

  it('exits non-zero on the tree the help text describes', () => {
    writeFileSync(join(DIR, 'package.json'), JSON.stringify({ name: 'tls' }));
    writeFileSync(join(DIR, 'app.js'),
      "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n"
      + "const a = new https.Agent({ secureProtocol: 'TLSv1_method' });\n");
    writeFileSync(join(DIR, 'app.py'),
      'import ssl\n'
      + 'ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\n'
      + 'ctx.check_hostname = False\n'
      + 'ctx.verify_mode = ssl.CERT_NONE\n');

    const { exitCode, output } = run('--format json');
    assert.equal(exitCode, 1, output);
    const result = JSON.parse(output);
    assert.equal(result.status, 'fail');

    // Every file that disables verification is named. One of the two would let
    // a user fix a file, re-run, and be shown the next one.
    const files = new Set(result.violations.map(v => v.file));
    assert.ok(files.has('app.js'), JSON.stringify(result.violations, null, 1));
    assert.ok(files.has('app.py'), JSON.stringify(result.violations, null, 1));
  });

  it('fails on each spelling ALONE, at default thresholds', () => {
    // One tree carrying every spelling cannot pin any of them: the others keep
    // the gate red. A pattern whose severity drops below the default
    // --max-severity is a finding `scan` prints and `gate` can never reach --
    // the same unreachability that made medium-severity findings invisible
    // before 0.6.0 -- and a shared fixture hides it completely.
    const spellings = {
      'node-tls.js': "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n",
      'identity.js': 'const a = new https.Agent({ checkServerIdentity: () => undefined });\n',
      'protocol.js': "const a = new https.Agent({ secureProtocol: 'TLSv1_method' });\n",
      'cert-none.py': 'import ssl\nctx.verify_mode = ssl.CERT_NONE\n',
      'hostname.py': 'import ssl\nctx.check_hostname = False\n',
      'unverified.py': 'import ssl\nctx = ssl._create_unverified_context()\n',
      'protocol.py': 'import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\n',
    };
    for (const [file, body] of Object.entries(spellings)) {
      rmSync(DIR, { recursive: true, force: true });
      mkdirSync(DIR, { recursive: true });
      writeFileSync(join(DIR, 'package.json'), JSON.stringify({ name: 'tls' }));
      writeFileSync(join(DIR, file), body);
      const { exitCode, output } = run('--format json');
      assert.equal(exitCode, 1, `${file} alone did not fail the gate: ${output}`);
      const violations = JSON.parse(output).violations;
      assert.equal(violations.length, 1, `${file}: ${JSON.stringify(violations, null, 1)}`);
      assert.equal(violations[0].file, file, JSON.stringify(violations[0]));
    }
  });

  it('passes the same tree once verification is restored', () => {
    // The other direction. A gate that fails everything is not a gate, and this
    // is the shape of the fixed file.
    writeFileSync(join(DIR, 'package.json'), JSON.stringify({ name: 'tls' }));
    writeFileSync(join(DIR, 'app.js'),
      "const a = new https.Agent({ secureProtocol: 'TLSv1_2_method' });\n");
    writeFileSync(join(DIR, 'app.py'),
      'import ssl\n'
      + 'ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)\n'
      + 'ctx.check_hostname = True\n');

    const { exitCode, output } = run('--format json');
    assert.equal(exitCode, 0, output);
  });
});

/**
 * A library must not be named as the source of a call it cannot have made.
 *
 * The gate indexed sites on the algorithm NAME alone, dropping the language the
 * scanner recorded, then paired every inventory library with every site of any
 * algorithm it declares. `crypto-js` declares MD5, so a Python `hashlib.md5()`
 * was reported with `source: crypto-js@3.1.9` -- and manifest libraries are
 * pushed before source ones, so the wrong owner won the first-writer race.
 * SHA-1 stayed correct only because `crypto-js` does not declare it.
 *
 * Barring foreign-ecosystem claims is not sufficient on its own: a C site has no
 * owning library at all, so the language check alone would leave it unclaimed
 * and silently drop the violation. The synthetic owner is what keeps it, which
 * is why both halves are pinned here together.
 */
describe('gate attributes a site to a library of that language', () => {
  let DIR;
  beforeEach(() => { DIR = mkdtempSync(join(tmpdir(), 'cryptoserve-gate-attr-')); });
  afterEach(() => { if (DIR && existsSync(DIR)) rmSync(DIR, { recursive: true, force: true }); });

  const CRYPTO_JS = JSON.stringify({ name: 'attr', dependencies: { 'crypto-js': '^3.1.9' } });

  function run(args) {
    try {
      return { exitCode: 0, output: execSync(`${process.execPath} ${CLI} gate ${DIR} ${args}`,
        { encoding: 'utf-8', timeout: 30000, stdio: ['pipe', 'pipe', 'pipe'] }) };
    } catch (e) {
      return { exitCode: e.status, output: e.stdout || '' };
    }
  }
  const asJson = (args = '') => JSON.parse(run(`${args} --format json`).output);
  const at = (violations, file) => violations.filter(v => v.file === file);

  it('does not name an npm package as the source of a Python call', () => {
    writeFileSync(join(DIR, 'package.json'), CRYPTO_JS);
    writeFileSync(join(DIR, 'auth.py'),
      'import hashlib\nh = hashlib.md5(b"pw")\ns = hashlib.sha1(b"pw")\n');

    const violations = asJson('--min-score 0').violations;
    const md5 = at(violations, 'auth.py').filter(v => /md5/i.test(v.algorithm));
    assert.equal(md5.length, 1, JSON.stringify(violations, null, 1));
    assert.equal(md5[0].source, 'hashlib@builtin', JSON.stringify(md5[0]));

    // The asymmetry that made the real cause hard to see: SHA-1 was already
    // right, because `crypto-js` does not declare it. It stays right.
    const sha1 = at(violations, 'auth.py').filter(v => /sha1/i.test(v.algorithm));
    assert.equal(sha1.length, 1, JSON.stringify(violations, null, 1));
    assert.equal(sha1[0].source, 'hashlib@builtin');
  });

  it('keeps the dependency violation the manifest declares', () => {
    // Barring the foreign claim must not lose the dependency finding: crypto-js
    // still declares MD5, and with no JavaScript site to point at, the manifest
    // that declares it is where the violation belongs.
    writeFileSync(join(DIR, 'package.json'), CRYPTO_JS);
    writeFileSync(join(DIR, 'auth.py'), 'import hashlib\nh = hashlib.md5(b"pw")\n');

    const violations = asJson('--min-score 0').violations;
    const declared = violations.filter(v => v.source === 'crypto-js@3.1.9'
      && /md5/i.test(v.algorithm));
    assert.equal(declared.length, 1, JSON.stringify(violations, null, 1));
    assert.equal(declared[0].manifest, 'package.json');
    assert.equal(declared[0].file, undefined);

    // And it says what a dependency finding says. A manifest has no scanner
    // finding of its own, so the only way this row could carry "Replace with
    // SHA-256" is by borrowing the fix from a Python call site in another
    // file -- the same cross-attribution by algorithm name, one field over.
    // The user has no line in `package.json` to apply that to.
    assert.match(declared[0].reason, /declared by this dependency/,
      JSON.stringify(declared[0]));
  });

  it('still raises a violation for a site no library owns', () => {
    // `#include <openssl/md5.h>` produces no source library, and `crypto/md5`
    // is Go. Nothing in the inventory is a C library, so this site is the one a
    // language check alone would silently drop.
    writeFileSync(join(DIR, 'package.json'), CRYPTO_JS);
    writeFileSync(join(DIR, 'hash.c'), '#include <openssl/md5.h>\nvoid f(void){MD5_CTX c;MD5_Init(&c);}\n');
    writeFileSync(join(DIR, 'main.go'), 'package main\n\nimport "crypto/md5"\n\nfunc main(){ _ = md5.New() }\n');

    const result = asJson('--min-score 0');
    assert.equal(result.status, 'fail');

    const c = at(result.violations, 'hash.c');
    assert.equal(c.length, 1, `C site lost its violation: ${JSON.stringify(result.violations, null, 1)}`);
    // The EXACT owner, not merely "not the wrong one". Asserting the negative
    // let the gate fall through to the weak-pattern sweep, which raises a
    // `type: 'misuse'` row whose `source` is the FILE -- a different finding
    // that happens to satisfy `!== crypto-js`. It carries the same risk and CWE
    // (both come from the algorithm database), so only `source` and the row
    // type tell the two apart.
    assert.equal(c[0].source, 'c:md5', JSON.stringify(c[0]));
    assert.equal(c[0].type, undefined, `fell through to the misuse sweep: ${JSON.stringify(c[0])}`);
    assert.equal(c[0].algorithm.toLowerCase(), 'md5', JSON.stringify(c[0]));
    assert.equal(c[0].risk, 'critical', JSON.stringify(c[0]));
    assert.equal(c[0].cwe, 'CWE-328', JSON.stringify(c[0]));

    const go = at(result.violations, 'main.go');
    assert.equal(go.length, 1, JSON.stringify(result.violations, null, 1));
    assert.equal(go[0].source, 'crypto/md5@builtin', JSON.stringify(go[0]));
  });

  it('does not turn a failing gate green by attributing more precisely', () => {
    // The dangerous direction, and the one an attribution change is least
    // expected to reach. `jose` declares `AES-GCM`; the Python site is
    // `aes-gcm`. Counting the Python site as its own inventory row adds a
    // second SAFE classification -- the two spellings differ and that
    // deduplication is case-sensitive -- which RAISES `safe / total`. This tree
    // scored 25/100 and failed; it must not start passing because the gate got
    // better at naming owners.
    writeFileSync(join(DIR, 'package.json'),
      JSON.stringify({ name: 'flip', dependencies: { jose: '^5.0.0' } }));
    writeFileSync(join(DIR, 'a.py'), 'c = AESGCM(key)\n');

    const { exitCode, output } = run('--min-score 30 --format json');
    assert.equal(exitCode, 1, `gate went green on a tree that was failing: ${output}`);
    assert.equal(JSON.parse(output).score, 25, output);
  });

  it('lets a JavaScript library keep its own JavaScript site', () => {
    // The change must not overshoot: an npm package does own the JS call.
    writeFileSync(join(DIR, 'package.json'), CRYPTO_JS);
    writeFileSync(join(DIR, 'app.js'),
      'const CryptoJS = require("crypto-js");\nconst h = CryptoJS.MD5("pw");\n');

    const violations = asJson('--min-score 0').violations;
    const js = at(violations, 'app.js').filter(v => /md5/i.test(v.algorithm));
    assert.equal(js.length, 1, JSON.stringify(violations, null, 1));
    assert.equal(js[0].source, 'crypto-js@3.1.9', JSON.stringify(js[0]));
  });
});

/**
 * A PASS with waivers behind it is a different claim from a clean PASS, and the
 * gate must say which one it is on every surface it reports through. JSON is
 * the one a CI job parses, and it carried only a count until adversarial review
 * pointed out that a reviewer reading it could not tell WHAT had been
 * suppressed.
 */
describe('gate reports what a waiver cleared', () => {
  beforeEach(setup);
  afterEach(cleanup);

  // Assembled so this file's own source does not read as a live pragma.
  const IGNORE = 'cryptoserve' + '-ignore';
  const RULE = 'misuse/node-tls-reject-unauthorized';
  const DEFECT = "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n";

  const write = (body) => {
    writeFileSync(join(TEST_DIR, 'package.json'), '{}');
    writeFileSync(join(TEST_DIR, 'app.js'), body);
  };

  it('fails the tree, then passes it once the finding is waived', () => {
    // Both directions in one test, on one tree. A gate going GREEN is the thing
    // that needs proving, and it only means something beside the red run.
    write(DEFECT);
    assert.equal(runGate('--format json').exitCode, 1);

    write(`// ${IGNORE} ${RULE} -- the test harness uses a self-signed cert\n${DEFECT}`);
    assert.equal(runGate('--format json').exitCode, 0);
  });

  it('names the waived finding in the JSON a CI job parses', () => {
    write(`// ${IGNORE} ${RULE} -- the test harness uses a self-signed cert\n${DEFECT}`);
    const doc = JSON.parse(runGate('--format json').output);
    assert.equal(doc.status, 'pass');
    assert.equal(doc.summary.waived, 1);
    assert.equal(doc.waived.length, 1);
    assert.equal(doc.waived[0].rule, RULE);
    assert.equal(doc.waived[0].file, 'app.js');
    assert.equal(doc.waived[0].line, 2);
    assert.match(doc.waived[0].reason, /self-signed cert/);
  });

  it('reports a waived finding in SARIF as a suppressed result', () => {
    // Present and dismissed, not absent. An alert that is missing and an alert
    // that was deliberately cleared are different claims to a reviewer reading
    // the Security tab weeks later.
    write(`// ${IGNORE} ${RULE} -- the test harness uses a self-signed cert\n${DEFECT}`);
    const { output, exitCode } = runGate('--format sarif');
    assert.equal(exitCode, 0);
    const results = JSON.parse(output).runs[0].results;
    assert.equal(results.length, 1, output);
    assert.equal(results[0].suppressions[0].kind, 'inSource');
    assert.match(results[0].suppressions[0].justification, new RegExp(RULE));
  });

  it('does not let a waiver hide a second defect below it', () => {
    write(`// ${IGNORE} ${RULE} -- the first one is deliberate\n${DEFECT}const x = 1;\n${DEFECT}`);
    const { exitCode, output } = runGate('--format json');
    assert.equal(exitCode, 1);
    const doc = JSON.parse(output);
    assert.equal(doc.waived.length, 1);
    assert.equal(doc.violations.filter(v => v.type === 'misuse').length, 1);
  });

  it('does not waive on a typo in the rule id', () => {
    write(`// ${IGNORE} misuse/nod-tls-reject -- typo\n${DEFECT}`);
    const { exitCode, output } = runGate('--format json');
    assert.equal(exitCode, 1);
    const doc = JSON.parse(output);
    assert.equal(doc.summary.waiverProblems, 1);
    assert.equal(doc.waiverWarnings[0].kind, 'unknown-rule');
  });

  it('does not waive without a reason', () => {
    write(`// ${IGNORE} ${RULE}\n${DEFECT}`);
    const { exitCode, output } = runGate('--format json');
    assert.equal(exitCode, 1);
    assert.equal(JSON.parse(output).waiverWarnings[0].kind, 'malformed');
  });

  it('does not let one pragma waive a whole file that has no newline in it', () => {
    // A CR-only file arrives at the parser as a single line, so every finding
    // in it is line 1 and one pragma reaches all of them. Measured: a tree
    // disabling TLS verification 400 lines below an unrelated waiver exited 0
    // with `live misuse 0, waived 1`. The gate going from red to green is the
    // one direction a waiver must never be able to produce.
    const body = [`// ${IGNORE} ${RULE} -- unrelated, and 400 lines away`]
      .concat(Array.from({ length: 400 }, (_, i) => `const f${i} = ${i};`))
      .concat([DEFECT.trim()])
      .join('\r');
    write(body);
    const { exitCode, output } = runGate('--format json');
    assert.equal(exitCode, 1, output);
    const doc = JSON.parse(output);
    assert.equal(doc.waived.length, 0, output);
    assert.equal(doc.violations.filter(v => v.type === 'misuse').length, 1, output);
  });

  it('does not print a control character a scanned file put in a reason', () => {
    // The reason is file content on its way to a terminal. Left raw, a file in
    // the scanned tree rewrites the scanner's own output. Nothing before this
    // feature printed file text at all, so the surface arrived with it.
    write(`// ${IGNORE} ${RULE} -- ok\x1b[2K\rFORGED\n${DEFECT}`);
    const { exitCode, output } = runGate();
    assert.equal(exitCode, 1, output);
    assert.ok(!output.includes('\x1b[2K'), JSON.stringify(output));
  });
});

/**
 * The TEXT renderings, which the JSON and SARIF tests above do not cover.
 *
 * Mutation testing found that deleting the whole waiver section from `scan`'s
 * and `gate`'s text output killed no test at all: the surfaces this change
 * exists to produce were the ones nothing checked.
 */
describe('waivers are visible in the text output', () => {
  beforeEach(setup);
  afterEach(cleanup);

  const IGNORE = 'cryptoserve' + '-ignore';
  const RULE = 'misuse/node-tls-reject-unauthorized';
  const DEFECT = "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n";
  const CLI_DIR = join(__dirname, '..');

  const runScan = (args = '') => {
    try {
      return execSync(`${process.execPath} ${join(CLI_DIR, 'bin', 'cryptoserve.mjs')} scan ${TEST_DIR} ${args}`,
        { encoding: 'utf-8', timeout: 30000 });
    } catch (e) { return e.stdout || ''; }
  };

  const write = (body) => {
    writeFileSync(join(TEST_DIR, 'package.json'), '{}');
    writeFileSync(join(TEST_DIR, 'app.js'), body);
  };

  it('gate names the rule, the location and the reason it was waived', () => {
    write(`// ${IGNORE} ${RULE} -- the harness uses a self-signed cert\n${DEFECT}`);
    const { output } = runGate();
    assert.match(output, /waived by a cryptoserve-ignore pragma/);
    assert.match(output, /app\.js:2/);
    assert.match(output, new RegExp(RULE));
    assert.match(output, /self-signed cert/);
  });

  it('scan lists the waived finding and counts it in the summary', () => {
    write(`// ${IGNORE} ${RULE} -- the harness uses a self-signed cert\n${DEFECT}`);
    const output = runScan();
    assert.match(output, /Waived Findings/);
    assert.match(output, new RegExp(RULE));
    assert.match(output, /self-signed cert/);
    assert.match(output, /Waived\s+.*1/);
  });

  it('scan says nothing about waivers on a tree that has none', () => {
    // The other direction: a clean tree must not grow a section telling the
    // reader that nothing was suppressed.
    write(DEFECT);
    const output = runScan();
    assert.ok(!/Waived Findings/.test(output), output);
    assert.ok(!/Waiver Problems/.test(output), output);
  });

  it('tells a user the placement that always works, not just the id', () => {
    // A pragma that is not the first thing in its comment is ignored in
    // silence, and this module cannot diagnose that without a real parse. The
    // instruction printed next to a live finding is therefore the only thing
    // standing between a user and a waiver that does nothing, so it has to name
    // the placement as well as the rule id.
    write(DEFECT);
    const { exitCode, output } = runGate();
    assert.equal(exitCode, 1);
    assert.match(output, /own line above/);
    assert.match(runScan(), /own line above/);
  });

  it('leaves the finding red when a pragma is not the first thing in its comment', () => {
    // The end of the same story: the limitation costs a waiver, never a
    // finding. Ignoring it in silence is only acceptable while it fails in this
    // direction.
    write(`const u = "http://x"; // ${IGNORE} ${RULE} -- why\n${DEFECT}`);
    const { exitCode, output } = runGate('--format json');
    assert.equal(exitCode, 1, output);
    const doc = JSON.parse(output);
    assert.equal(doc.waived.length, 0);
    assert.equal(doc.violations.filter(v => v.type === 'misuse').length, 1);
  });
});

/**
 * A finding a user believes is wrong needs a next step. For a misuse that step
 * is the pragma, so the rule id has to be reachable from the failing output.
 * It was carried only by `scan --format json`, which meant the remediation path
 * for a false positive was a dead end everywhere a user would actually look.
 */
describe('a live misuse finding names the rule you would waive', () => {
  beforeEach(setup);
  afterEach(cleanup);

  const write = () => {
    writeFileSync(join(TEST_DIR, 'package.json'), '{}');
    writeFileSync(join(TEST_DIR, 'app.js'), "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n");
  };

  it('prints the rule id and the pragma to write, in the gate text', () => {
    write();
    const { output, exitCode } = runGate();
    assert.equal(exitCode, 1);
    assert.match(output, /misuse\/node-tls-reject-unauthorized/);
    assert.match(output, /waive with: cryptoserve-ignore/);
  });

  it('carries the rule id in the gate JSON', () => {
    write();
    const doc = JSON.parse(runGate('--format json').output);
    const misuse = doc.violations.filter(v => v.type === 'misuse');
    assert.equal(misuse.length, 1, JSON.stringify(doc.violations));
    assert.equal(misuse[0].rule, 'misuse/node-tls-reject-unauthorized');
  });

  it('round-trips: the id the gate prints is the id that waives it', () => {
    // The property that matters. A rule id a user copies out of the output and
    // pastes into a pragma has to be the one the parser matches, or the whole
    // remediation path is decoration.
    write();
    const doc = JSON.parse(runGate('--format json').output);
    const rule = doc.violations.find(v => v.type === 'misuse').rule;

    const IGNORE = 'cryptoserve' + '-ignore';
    writeFileSync(join(TEST_DIR, 'app.js'),
      `// ${IGNORE} ${rule} -- copied from the gate output\n`
      + "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n");
    assert.equal(runGate().exitCode, 0);
  });
});
