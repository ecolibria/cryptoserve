import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
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
});
