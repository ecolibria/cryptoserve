/**
 * What the CLI does with an argument it cannot act on.
 *
 * Every test here was confirmed RED against the code as it shipped in 0.4.0.
 * The five defects share one shape: an unusable argument was carried into the
 * work instead of stopping it, and the command then reported a confident
 * result about something it had not measured.
 *
 *   gate --min-score abc   NaN, and `score < NaN` is false, so the threshold
 *                          was not lax — it was absent, and a failing gate
 *                          exited 0.
 *   cbom <missing path>    a valid CBOM asserting quantumReadiness 100 / none.
 *   pqc <path>             the path was ignored and the cwd analysed instead.
 *   init --insecure-storage a ReferenceError, on the exact recovery the
 *                          previous error recommends.
 *   <prompt> with no TTY   a Node "unsettled top-level await" diagnostic.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, realpathSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = join(__dirname, '..', 'bin', 'cryptoserve.mjs');

/**
 * Run the CLI with stdin as a pipe, never a TTY — the shape every CI job has,
 * and the one that produced the unsettled-await diagnostic.
 */
function run(args, { cwd, env, input = '' } = {}) {
  // spawnSync, not execFileSync: execFileSync discards stderr on a zero exit,
  // and several of these assertions are about what a SUCCEEDING command says
  // on stderr.
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 120000,
    cwd: cwd ?? __dirname,
    input,
    env: { ...process.env, NO_COLOR: '1', ...env },
  });
  return {
    code: r.status,
    stdout: r.stdout ?? '',
    stderr: r.stderr ?? '',
    signal: r.signal ?? null,
  };
}

function tempDir(prefix) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), `cryptoserve-${prefix}-`)));
  process.on('exit', () => { try { rmSync(dir, { recursive: true, force: true }); } catch { /* gone */ } });
  return dir;
}

/**
 * A project whose ONLY gate failure is the score. `jsonwebtoken` scores 40
 * against the default minimum of 50 and raises no violation at the default
 * --max-risk, so `--min-score` is the single condition under test. A fixture
 * scoring 100, or one that also breaches --max-risk, exits the same way with
 * and without the defect and proves nothing about the threshold.
 */
function scoreOnlyFixture() {
  const dir = tempDir('gate');
  writeFileSync(join(dir, 'package.json'), JSON.stringify({
    name: 'score-only', dependencies: { jsonwebtoken: '^9.0.0' },
  }));
  writeFileSync(join(dir, 'index.js'), 'const jwt = require("jsonwebtoken");\n');
  return dir;
}

// ---------------------------------------------------------------------------
// gate: an unusable threshold must stop the gate, not disable it
// ---------------------------------------------------------------------------

describe('gate --min-score', () => {
  it('the fixture fails on score alone, so the threshold is the only thing under test', () => {
    const { code, stdout } = run(['gate', scoreOnlyFixture(), '--format', 'json']);
    const result = JSON.parse(stdout);
    assert.equal(code, 1, 'fixture must fail its own baseline');
    assert.equal(result.status, 'fail');
    assert.equal(result.violations.length, 0, 'no violation may be failing it');
    assert.ok(result.score < 50, `score ${result.score} must be under the default minimum`);
  });

  it('rejects a non-numeric value instead of dropping the threshold', () => {
    const { code, stdout } = run(['gate', scoreOnlyFixture(), '--min-score', 'abc', '--format', 'json']);
    assert.equal(code, 2, 'a threshold that cannot be parsed is an error, not a pass');
    const result = JSON.parse(stdout);
    assert.equal(result.status, 'error');
    assert.match(result.error, /--min-score/);
  });

  it('never prints NaN as the minimum it enforced', () => {
    const { stdout } = run(['gate', scoreOnlyFixture(), '--min-score', 'abc']);
    assert.doesNotMatch(stdout, /NaN/);
  });

  it('rejects a value below 0 or above 100', () => {
    for (const bad of ['-5', '500', '101']) {
      const { code } = run(['gate', scoreOnlyFixture(), '--min-score', bad, '--format', 'json']);
      assert.equal(code, 2, `--min-score ${bad} must be rejected`);
    }
  });

  it('rejects a partially numeric value rather than reading a prefix off it', () => {
    // parseInt('40abc') is 40. Number('40abc') is NaN. A CI value of "40abc"
    // must not silently become a threshold of 40.
    const { code } = run(['gate', scoreOnlyFixture(), '--min-score', '40abc', '--format', 'json']);
    assert.equal(code, 2);
  });

  it('rejects the flag with no value at all', () => {
    const { code } = run(['gate', scoreOnlyFixture(), '--min-score']);
    assert.equal(code, 2);
  });

  it('still enforces a threshold that is valid', () => {
    // Guards against a fix that rejects everything: 40 clears 10 and misses 90.
    const dir = scoreOnlyFixture();
    assert.equal(run(['gate', dir, '--min-score', '10', '--format', 'json']).code, 0);
    assert.equal(run(['gate', dir, '--min-score', '90', '--format', 'json']).code, 1);
  });

  it('accepts the boundary values and a decimal', () => {
    const dir = scoreOnlyFixture();
    assert.equal(run(['gate', dir, '--min-score', '0', '--format', 'json']).code, 0);
    assert.equal(run(['gate', dir, '--min-score', '100', '--format', 'json']).code, 1);
    assert.equal(run(['gate', dir, '--min-score', '39.5', '--format', 'json']).code, 0);
  });
});

describe('gate other option values', () => {
  it('rejects an unknown --max-risk instead of treating every algorithm as a breach', () => {
    const { code, stdout } = run(['gate', scoreOnlyFixture(), '--max-risk', 'bogus', '--format', 'json']);
    assert.equal(code, 2);
    assert.match(JSON.parse(stdout).error, /--max-risk/);
  });

  it('rejects an unknown --format instead of falling back to text', () => {
    const { code, stderr } = run(['gate', scoreOnlyFixture(), '--format', 'xml']);
    assert.equal(code, 2);
    assert.match(stderr, /--format/);
  });

  it('reports how many files it scanned, and the number is real', () => {
    // Asserting the LABEL proves nothing -- a hardcoded 0 passes that. The
    // count exists to make a wrong path visible, so it has to track the tree.
    const dir = scoreOnlyFixture();          // package.json + index.js
    const { stdout } = run(['gate', dir, '--min-score', '10']);
    assert.match(stdout, /Files scanned\s+1 source file, 1 manifest/i,
      `gate did not report what it read:\n${stdout}`);

    writeFileSync(join(dir, 'second.js'), 'const crypto = require("crypto");\n');
    const after = run(['gate', dir, '--min-score', '10']).stdout;
    assert.match(after, /Files scanned\s+2 source files, 1 manifest/i,
      'the count did not change when a source file was added');
  });

  it('carries the counts into the JSON a CI job parses', () => {
    // The human surface could distinguish "scanned nothing" from "scanned a
    // manifest-only project"; the machine surface could not, because both
    // reported filesScanned: 0.
    const dir = scoreOnlyFixture();
    const withSource = JSON.parse(run(['gate', dir, '--min-score', '10', '--format', 'json']).stdout);
    assert.equal(withSource.summary.filesScanned, 1);
    assert.equal(withSource.summary.manifestsFound, 1);

    const manifestOnly = tempDir('gate-manifest-only');
    writeFileSync(join(manifestOnly, 'package.json'), JSON.stringify({ name: 'm' }));
    const m = JSON.parse(run(['gate', manifestOnly, '--min-score', '0', '--format', 'json']).stdout);
    assert.equal(m.summary.filesScanned, 0);
    assert.equal(m.summary.manifestsFound, 1, 'a manifest-only tree must be distinguishable from an empty one');

    const empty = tempDir('gate-empty');
    const e = JSON.parse(run(['gate', empty, '--min-score', '0', '--format', 'json']).stdout);
    assert.equal(e.summary.filesScanned, 0);
    assert.equal(e.summary.manifestsFound, 0);
  });
});

// ---------------------------------------------------------------------------
// cbom: a missing path must not become a compliance artifact
// ---------------------------------------------------------------------------

describe('cbom', () => {
  it('refuses a path that does not exist rather than certifying it', () => {
    const missing = join(tempDir('cbom'), 'no-such-tree');
    const { code, stdout, stderr } = run(['cbom', missing]);
    assert.equal(code, 2);
    assert.match(stderr, /does not exist/i);
    assert.doesNotMatch(stdout, /quantumReadiness/,
      'a missing path must produce no CBOM at all');
  });

  it('reports what it scanned, so a wrong path cannot look green', () => {
    // The first version of this asserted /\b1 file|files?\b/i, whose alternation
    // is (\b1 file)|(files?\b) -- so "Scanned 0 source files" matched on the
    // bare word and the number was never read. Assert the number.
    const dir = scoreOnlyFixture();
    const { code, stderr } = run(['cbom', dir]);
    assert.equal(code, 0);
    assert.match(stderr, /Scanned 1 source file, 1 manifest/i,
      `cbom did not report what it read:\n${stderr}`);
    assert.match(stderr, /\d+ components?\./i);

    writeFileSync(join(dir, 'second.js'), 'const crypto = require("crypto");\n');
    assert.match(run(['cbom', dir]).stderr, /Scanned 2 source files, 1 manifest/i,
      'the count did not change when a source file was added');
  });

  it('rejects an unknown --format instead of silently emitting native JSON', () => {
    const { code, stderr } = run(['cbom', scoreOnlyFixture(), '--format', 'xml']);
    assert.equal(code, 2);
    assert.match(stderr, /--format/);
  });
});

// ---------------------------------------------------------------------------
// pqc: the readiness score must describe the tree that was named
// ---------------------------------------------------------------------------

describe('pqc [path]', () => {
  it('analyses the directory it was given, not the current one', () => {
    const weak = scoreOnlyFixture();
    const clean = tempDir('pqc-clean');
    writeFileSync(join(clean, 'package.json'), JSON.stringify({ name: 'clean' }));
    writeFileSync(join(clean, 'index.js'), 'module.exports = 1;\n');

    // Both runs share ONE cwd, so the argument is the only thing that differs.
    // Before the fix both reported that shared cwd's score and the two were
    // identical, which is the whole defect. Giving the runs different cwds
    // would make them differ with or without the defect and prove nothing.
    const elsewhere = tempDir('pqc-cwd');
    const a = JSON.parse(run(['pqc', weak, '--format', 'json'], { cwd: elsewhere }).stdout);
    const b = JSON.parse(run(['pqc', clean, '--format', 'json'], { cwd: elsewhere }).stdout);
    assert.notEqual(a.quantumReadinessScore, b.quantumReadinessScore,
      'two different trees must not produce one score');

    // And the answer must not depend on where the command was invoked from.
    const fromClean = JSON.parse(run(['pqc', weak, '--format', 'json'], { cwd: clean }).stdout);
    assert.equal(fromClean.quantumReadinessScore, a.quantumReadinessScore);
  });

  it('names the path it analysed in its JSON, with a real count', () => {
    // `typeof x === 'number'` admits 0 and NaN, so it would pass against a
    // hardcoded zero. Assert the value and that it tracks the tree.
    const dir = scoreOnlyFixture();
    const result = JSON.parse(run(['pqc', dir, '--format', 'json']).stdout);
    assert.equal(result.scannedPath, resolve(dir));
    assert.equal(result.filesScanned, 1);

    writeFileSync(join(dir, 'second.js'), 'const crypto = require("crypto");\n');
    const after = JSON.parse(run(['pqc', dir, '--format', 'json']).stdout);
    assert.equal(after.filesScanned, 2, 'the count did not change when a source file was added');
  });

  it('names the path it analysed in its text output', () => {
    const dir = scoreOnlyFixture();
    const { stdout } = run(['pqc', dir]);
    assert.ok(stdout.includes(resolve(dir)), 'the analysed directory must be visible');
  });

  it('refuses a path that does not exist rather than scoring the cwd', () => {
    const missing = join(tempDir('pqc'), 'no-such-tree');
    const { code, stdout, stderr } = run(['pqc', missing, '--format', 'json']);
    assert.equal(code, 2);
    assert.match(stderr, /does not exist/i);
    assert.doesNotMatch(stdout, /quantumReadinessScore/);
  });

  it('still analyses the cwd when given no path', () => {
    const dir = scoreOnlyFixture();
    const result = JSON.parse(run(['pqc', '--format', 'json'], { cwd: dir }).stdout);
    assert.equal(result.scannedPath, resolve(dir));
  });
});

// ---------------------------------------------------------------------------
// Password prompts with no terminal to prompt on
// ---------------------------------------------------------------------------

const PROMPTING = [
  { name: 'hash-password', args: ['hash-password'] },
  { name: 'encrypt', args: ['encrypt', 'some text'] },
  { name: 'decrypt', args: ['decrypt', 'some-blob'] },
  { name: 'vault list', args: ['vault', 'list'] },
];

describe('password prompts without a TTY', () => {
  for (const { name, args } of PROMPTING) {
    it(`${name} says what to pass instead of dumping a Node diagnostic`, () => {
      const home = tempDir('home');
      const { code, stderr } = run(args, { env: { CRYPTOSERVE_HOME: home } });
      assert.doesNotMatch(stderr, /unsettled top-level await/,
        'the Node internals diagnostic must never reach a user');
      assert.notEqual(code, 13, 'exit 13 is Node reporting an unsettled await');
      assert.equal(code, 2);
      assert.match(stderr, /--password/, 'the message must name what to pass');
    });
  }

  it('rejects an empty --password rather than falling back to a prompt', () => {
    const home = tempDir('home');
    const { code, stderr } = run(['hash-password', '--password', ''], { env: { CRYPTOSERVE_HOME: home } });
    assert.equal(code, 2);
    assert.doesNotMatch(stderr, /unsettled top-level await/);
    assert.match(stderr, /--password/);
  });

  it('rejects a bare --password with no value', () => {
    const home = tempDir('home');
    const { code } = run(['hash-password', '--password'], { env: { CRYPTOSERVE_HOME: home } });
    assert.equal(code, 2);
  });

  it('still works when --password carries a value', () => {
    const home = tempDir('home');
    const { code, stdout } = run(['hash-password', '--password', 'correct horse battery'], {
      env: { CRYPTOSERVE_HOME: home },
    });
    assert.equal(code, 0);
    assert.match(stdout, /scrypt/);
  });
});

// ---------------------------------------------------------------------------
// init --insecure-storage: the recovery the previous error recommends
// ---------------------------------------------------------------------------

describe('init --insecure-storage', () => {
  it('takes the plaintext branch rather than dying in a temporal dead zone', () => {
    // CRYPTOSERVE_NO_KEYCHAIN is what makes this a gate rather than a
    // coin-flip. The plaintext branch runs only when NO master key is found,
    // so on any machine where `cryptoserve init` has ever succeeded the run
    // takes the `existing` branch and the defect is never touched. The first
    // version of this test accepted "Master key already configured" as a pass,
    // which meant it was inert on most developer machines and green against
    // the unfixed code. Declaring the keychain absent makes the branch
    // reachable on every host.
    const project = tempDir('init-project');
    const home = tempDir('init-home');
    writeFileSync(join(project, 'package.json'), JSON.stringify({ name: 'p' }));

    const { code, stdout, stderr } = run(['init', '--insecure-storage'], {
      cwd: project,
      env: { CRYPTOSERVE_HOME: home, CRYPTOSERVE_NO_KEYCHAIN: '1' },
    });

    assert.doesNotMatch(stdout + stderr, /before initialization|ReferenceError/,
      'the shadowed binding must be gone');
    assert.equal(code, 0);
    assert.match(stdout, /Master key stored as plaintext/,
      'the plaintext branch did not run, so this asserted nothing');
    // The branch's whole job: a key on disk under CRYPTOSERVE_HOME.
    assert.ok(existsSync(join(home, 'master.key')),
      'no master key was written, so the branch reported success without doing its work');
  });
});

describe('secrets do not have to go on the command line', () => {
  it('--password-stdin round-trips a secret that never touches argv', () => {
    // `--password <value>` is visible in ps, /proc/<pid>/cmdline and shell
    // history. For a credential tool that cannot be the only non-interactive
    // option, and before this it was: the old prompt registered a stdin `data`
    // listener but never settled, so piping a password produced Node's
    // unsettled-await diagnostic and exit 13.
    const home = tempDir('stdin-home');
    const env = { CRYPTOSERVE_HOME: home };
    assert.equal(run(['vault', 'init', '--password', 'vaultpw'], { env }).code, 0);
    assert.equal(run(['vault', 'set', 'K', 'the-secret', '--password', 'vaultpw'], { env }).code, 0);

    const got = run(['vault', 'get', 'K', '--password-stdin'], { env, input: 'vaultpw' });
    assert.equal(got.code, 0, got.stderr);
    assert.equal(got.stdout.trim(), 'the-secret');
  });

  it('refuses --password and --password-stdin together', () => {
    const home = tempDir('stdin-home2');
    const { code, stderr } = run(['hash-password', '--password', 'x', '--password-stdin'],
      { env: { CRYPTOSERVE_HOME: home }, input: 'y' });
    assert.equal(code, 2);
    assert.match(stderr, /mutually exclusive/i);
  });

  it('refuses --password-stdin with nothing on stdin', () => {
    const home = tempDir('stdin-home3');
    const { code, stderr } = run(['hash-password', '--password-stdin'],
      { env: { CRYPTOSERVE_HOME: home }, input: '' });
    assert.equal(code, 2);
    assert.match(stderr, /nothing on stdin/i);
  });
});

describe('a path that exists but cannot be scanned', () => {
  // `existsSync` was the wrong predicate: a FILE exists, walks to zero source
  // files, and reports a clean tree. `gate ./package.json --min-score 99`
  // certified 100/100 and exited 0 -- the same fail-open as a missing path,
  // in the command whose entire job is to fail closed.
  for (const cmd of ['scan', 'gate', 'cbom', 'pqc']) {
    it(`${cmd} refuses a file where a directory is required`, () => {
      const dir = scoreOnlyFixture();
      const file = join(dir, 'package.json');
      const { code, stdout, stderr } = run([cmd, file, '--format', 'json']);
      assert.equal(code, 2, `${cmd} accepted a file as a scan target`);
      assert.match(stdout + stderr, /Not a directory/i);
      assert.doesNotMatch(stdout, /"status":\s*"pass"/,
        `${cmd} certified a file as a passing tree`);
    });
  }
});

describe('an option given twice', () => {
  it('is refused rather than silently resolved', () => {
    // indexOf took the first occurrence, so `gate . --min-score 10 $EXTRA_ARGS`
    // discarded a stricter threshold the caller appended and never said so.
    const dir = scoreOnlyFixture();
    for (const args of [['--min-score', '10', '--min-score', '90'],
                        ['--min-score', '90', '--min-score', '10'],
                        ['--min-score', '10', '--min-score', 'abc']]) {
      const { code, stderr } = run(['gate', dir, ...args]);
      assert.equal(code, 2, `${args.join(' ')} was not refused`);
      assert.match(stderr, /more than once/i);
    }
  });
});

describe('pqc --profile', () => {
  it('refuses an unknown profile instead of silently using the default', () => {
    // A transposed letter turned a HIPAA assertion into a general one, and the
    // warning was suppressed in JSON mode, so a CI job asserting healthcare
    // posture got "not vulnerable / medium" on every stream and exit 0.
    const dir = scoreOnlyFixture();
    const { code, stderr } = run(['pqc', dir, '--profile', 'helthcare', '--format', 'json']);
    assert.equal(code, 2);
    assert.match(stderr, /--profile/);
  });

  it('still distinguishes the profiles it accepts', () => {
    const dir = scoreOnlyFixture();
    const health = JSON.parse(run(['pqc', dir, '--profile', 'healthcare', '--format', 'json']).stdout);
    const general = JSON.parse(run(['pqc', dir, '--profile', 'general', '--format', 'json']).stdout);
    assert.notEqual(health.sndlAssessment.riskLevel, general.sndlAssessment.riskLevel,
      'two different profiles produced the same assessment');
  });
});

describe('vault positionals', () => {
  it('does not store a flag name as the secret', () => {
    // `vault set KEY --password PW` read restArgs[1] raw and stored the literal
    // string "--password", exit 0 -- silent corruption through the exact
    // non-interactive form the docs recommend for CI.
    const home = tempDir('vault-pos');
    const env = { CRYPTOSERVE_HOME: home };
    assert.equal(run(['vault', 'init', '--password', 'vp'], { env }).code, 0);

    const noValue = run(['vault', 'set', 'K', '--password', 'vp'], { env });
    assert.notEqual(noValue.code, 0, 'a missing value was accepted');
    assert.doesNotMatch(noValue.stdout, /Stored/, 'a flag name was stored as the secret');

    assert.equal(run(['vault', 'set', 'K', 'real-value', '--password', 'vp'], { env }).code, 0);
    assert.equal(run(['vault', 'get', 'K', '--password', 'vp'], { env }).stdout.trim(), 'real-value');
  });
});
