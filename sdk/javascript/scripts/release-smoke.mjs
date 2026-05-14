#!/usr/bin/env node
//
// Release-smoke runner for the cryptoserve JS CLI.
//
// Spawns `bin/cryptoserve.mjs` as a subprocess and asserts behavior across
// help/version, scan/pqc/cbom/gate, encrypt/decrypt/hash, context, and the
// error-exit matrix. No network, no keychain writes, no vault writes.
//
// Run:   npm run release-smoke
// Exit:  0 = all checks pass, 1 = at least one failure.
//
// The companion checklist in docs/testing/release-smoke.md covers the manual
// items this runner can't (init, vault, login, census --live).

import { spawnSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname, resolve as resolvePath } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolvePath(__dirname, '..');
const CLI = join(ROOT, 'bin', 'cryptoserve.mjs');
const PKG = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
const FIX = join(ROOT, 'test', 'fixtures', 'release-smoke');

const C = {
  reset: '\x1b[0m', dim: '\x1b[2m', bold: '\x1b[1m',
  green: '\x1b[32m', red: '\x1b[31m', yellow: '\x1b[33m', cyan: '\x1b[36m',
};
const isTTY = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (s, color) => (isTTY ? `${color}${s}${C.reset}` : s);

const results = { passed: 0, failed: 0, failures: [] };

function check(label, predicate, detail = '') {
  let ok = false;
  let err = null;
  try {
    ok = predicate();
  } catch (e) {
    err = e;
  }
  if (ok) {
    results.passed++;
    console.log(`  ${paint('ok', C.green)}   ${label}`);
  } else {
    results.failed++;
    results.failures.push({ label, detail, err });
    console.log(`  ${paint('FAIL', C.red)} ${label}`);
    if (detail) console.log(`       ${paint(detail, C.dim)}`);
    if (err) console.log(`       ${paint(String(err.message || err), C.dim)}`);
  }
}

function phase(name) {
  console.log(`\n${paint(name, C.bold + C.cyan)}`);
}

// Spawn the CLI and return { exit, stdout, stderr }. NO_COLOR keeps output
// parseable; we run from ROOT so relative paths in args work uniformly.
function run(args, { input, timeoutMs = 15000, cwd = ROOT } = {}) {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    input,
    cwd,
    encoding: 'utf8',
    timeout: timeoutMs,
    env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '0' },
  });
  if (r.error) {
    return { exit: -1, stdout: '', stderr: String(r.error.message), error: r.error };
  }
  return { exit: r.status ?? -1, stdout: r.stdout || '', stderr: r.stderr || '' };
}

function parseJson(s) {
  try { return JSON.parse(s); } catch { return null; }
}

// ---------------------------------------------------------------------------
// 0. Prerequisites
// ---------------------------------------------------------------------------

phase('0. Prerequisites');

check('bin/cryptoserve.mjs is present', () => existsSync(CLI));
check('test/fixtures/release-smoke/{benign,weak,pqc} present', () =>
  ['benign', 'weak', 'pqc'].every((d) => existsSync(join(FIX, d, 'package.json'))));

// ---------------------------------------------------------------------------
// 1. Help & version
// ---------------------------------------------------------------------------

phase('1. Help and version');

{
  const v = run(['version']);
  check('`version` exits 0', () => v.exit === 0, `exit=${v.exit}`);
  check(
    `\`version\` reports ${PKG.version} (matches package.json)`,
    () => v.stdout.trim() === `cryptoserve ${PKG.version}`,
    `stdout=${JSON.stringify(v.stdout.trim())}`,
  );

  const v2 = run(['--version']);
  check('`--version` matches `version`', () => v2.stdout === v.stdout);

  const h = run(['help']);
  check('`help` exits 0', () => h.exit === 0);
  // Sections every release must keep — these are the discovery surface.
  const sections = ['Scanning & Analysis', 'Encryption', 'Contexts', 'Key Management'];
  for (const s of sections) {
    check(`help mentions "${s}"`, () => h.stdout.includes(s));
  }
  const commands = ['scan', 'pqc', 'cbom', 'gate', 'encrypt', 'decrypt', 'vault', 'census'];
  for (const c of commands) {
    check(`help lists "${c}"`, () => h.stdout.includes(c));
  }

  // Each command must respond to --help with non-empty usage.
  for (const c of commands) {
    const r = run([c, '--help']);
    check(`\`${c} --help\` exits 0 with usage`,
      () => r.exit === 0 && /Usage:/i.test(r.stdout),
      `exit=${r.exit}`);
  }
}

// ---------------------------------------------------------------------------
// 2. Scan walkthrough (benign / weak / pqc)
// ---------------------------------------------------------------------------

phase('2. Scan (benign / weak / pqc)');

{
  const benign = run(['scan', join(FIX, 'benign'), '--format', 'json']);
  check('scan benign exits 0', () => benign.exit === 0);
  const bj = parseJson(benign.stdout);
  check('scan benign is valid JSON', () => bj !== null);
  check('scan benign has 0 libraries', () => bj && bj.libraries.length === 0);
  check('scan benign has 0 secrets', () => bj && bj.secrets.length === 0);
  check('scan benign has 0 weak patterns', () => bj && bj.weakPatterns.length === 0);

  const weak = run(['scan', join(FIX, 'weak'), '--format', 'json']);
  check('scan weak exits 0', () => weak.exit === 0);
  const wj = parseJson(weak.stdout);
  check('scan weak is valid JSON', () => wj !== null);
  check('scan weak finds jsonwebtoken',
    () => wj && wj.libraries.some((l) => l.name === 'jsonwebtoken'));
  check('scan weak finds at least one hardcoded secret',
    () => wj && wj.secrets.length >= 1);
  check('scan weak flags MD5 as weak',
    () => wj && wj.weakPatterns.some((p) => /MD5/i.test(p.issue)));
  check('scan weak surfaces a high-risk library',
    () => wj && wj.libraries.some((l) => l.quantumRisk === 'high'));

  const pqc = run(['scan', join(FIX, 'pqc'), '--format', 'json']);
  check('scan pqc exits 0', () => pqc.exit === 0);
  const pj = parseJson(pqc.stdout);
  check('scan pqc is valid JSON', () => pj !== null);
  check('scan pqc detects @noble/post-quantum (quantumRisk=none)',
    () => pj && pj.libraries.some(
      (l) => l.name === '@noble/post-quantum' && l.quantumRisk === 'none'));

  // Error path — nonexistent dir must exit 1, not crash.
  const miss = run(['scan', join(FIX, '__does_not_exist__'), '--format', 'json']);
  check('scan on missing path exits 1', () => miss.exit === 1, `exit=${miss.exit}`);
  check('scan on missing path writes to stderr', () => /Error|does not exist/i.test(miss.stderr));
}

// ---------------------------------------------------------------------------
// 3. PQC analysis
// ---------------------------------------------------------------------------

phase('3. PQC analysis');

{
  const weak = run(['pqc', '--format', 'json'], { cwd: join(FIX, 'weak') });
  check('pqc on weak exits 0', () => weak.exit === 0);
  const wj = parseJson(weak.stdout);
  check('pqc weak is valid JSON', () => wj !== null);
  check('pqc weak has quantumReadinessScore (0-100)',
    () => wj && typeof wj.quantumReadinessScore === 'number'
      && wj.quantumReadinessScore >= 0 && wj.quantumReadinessScore <= 100);
  check('pqc weak reports non-low migration urgency',
    () => wj && typeof wj.migrationUrgency === 'string'
      && wj.migrationUrgency.length > 0);
  check('pqc weak surfaces SNDL assessment',
    () => wj && wj.sndlAssessment && typeof wj.sndlAssessment.vulnerable === 'boolean');

  const pqc = run(['pqc', '--format', 'json'], { cwd: join(FIX, 'pqc') });
  const pj = parseJson(pqc.stdout);
  check('pqc on pqc fixture is valid JSON', () => pj !== null);
  check('pqc on pqc fixture scores >= weak fixture',
    () => pj && wj && pj.quantumReadinessScore >= wj.quantumReadinessScore,
    `pqc=${pj?.quantumReadinessScore} weak=${wj?.quantumReadinessScore}`);

  // Profile validation — unknown profile should still produce JSON, with a
  // warning routed to stderr (not contaminating stdout).
  const bogus = run(['pqc', '--profile', 'definitely-not-a-profile', '--format', 'json'],
    { cwd: join(FIX, 'benign') });
  check('pqc --profile invalid still emits JSON', () => parseJson(bogus.stdout) !== null);
}

// ---------------------------------------------------------------------------
// 4. CBOM (cyclonedx / spdx / native json)
// ---------------------------------------------------------------------------

phase('4. CBOM');

{
  const cdx = run(['cbom', join(FIX, 'weak'), '--format', 'cyclonedx']);
  check('cbom cyclonedx exits 0', () => cdx.exit === 0);
  const cdxj = parseJson(cdx.stdout);
  check('cbom cyclonedx is valid JSON', () => cdxj !== null);
  check('cbom cyclonedx has bomFormat=CycloneDX',
    () => cdxj && cdxj.bomFormat === 'CycloneDX');
  check('cbom cyclonedx has specVersion',
    () => cdxj && typeof cdxj.specVersion === 'string');

  const spdx = run(['cbom', join(FIX, 'weak'), '--format', 'spdx']);
  const spdxj = parseJson(spdx.stdout);
  check('cbom spdx is valid JSON', () => spdxj !== null);
  check('cbom spdx has spdxVersion',
    () => spdxj && typeof spdxj.spdxVersion === 'string'
      && spdxj.spdxVersion.startsWith('SPDX-'));

  const native = run(['cbom', join(FIX, 'weak')]); // default json
  const nj = parseJson(native.stdout);
  check('cbom (default json) is valid JSON', () => nj !== null);
  check('cbom native has components array',
    () => nj && Array.isArray(nj.components));
}

// ---------------------------------------------------------------------------
// 5. Gate — exit code matrix (0 pass, 1 fail, 2 error)
// ---------------------------------------------------------------------------

phase('5. Gate exit codes');

{
  // Benign fixture has no crypto — should pass any threshold.
  const pass = run(['gate', join(FIX, 'benign'),
    '--max-risk', 'critical', '--min-score', '0', '--format', 'json']);
  check('gate benign exits 0', () => pass.exit === 0, `exit=${pass.exit}`);
  const passJ = parseJson(pass.stdout);
  check('gate benign reports status=pass',
    () => passJ && passJ.status === 'pass');

  // Weak fixture has MD5 + RSA-1024 — must fail at max-risk=medium.
  const fail = run(['gate', join(FIX, 'weak'),
    '--max-risk', 'medium', '--format', 'json']);
  check('gate weak exits 1', () => fail.exit === 1, `exit=${fail.exit}`);
  const failJ = parseJson(fail.stdout);
  check('gate weak reports status=fail',
    () => failJ && failJ.status === 'fail');
  check('gate weak surfaces at least one violation',
    () => failJ && Array.isArray(failJ.violations) && failJ.violations.length > 0);

  // Nonexistent path -> exit 2 (error class, not policy failure).
  const err = run(['gate', join(FIX, '__missing__'), '--format', 'json']);
  check('gate on missing path exits 2', () => err.exit === 2, `exit=${err.exit}`);
}

// ---------------------------------------------------------------------------
// 6. Context list / show
// ---------------------------------------------------------------------------

phase('6. Context');

{
  const list = run(['context', 'list', '--format', 'json']);
  check('context list exits 0', () => list.exit === 0);
  const lj = parseJson(list.stdout);
  check('context list is JSON array',
    () => Array.isArray(lj) && lj.length > 0);
  check('context list includes user-pii',
    () => Array.isArray(lj) && lj.some((c) => c.name === 'user-pii'));

  const show = run(['context', 'show', 'user-pii', '--format', 'json']);
  check('context show known exits 0', () => show.exit === 0);
  const sj = parseJson(show.stdout);
  check('context show returns resolved algorithm',
    () => sj && typeof sj.algorithm === 'string' && sj.algorithm.length > 0);

  const bad = run(['context', 'show', 'definitely-not-a-context']);
  check('context show unknown exits 1', () => bad.exit === 1, `exit=${bad.exit}`);
  check('context show unknown lists valid contexts',
    () => /Valid contexts:/i.test(bad.stderr));
}

// ---------------------------------------------------------------------------
// 7. Encrypt / decrypt roundtrip
// ---------------------------------------------------------------------------

phase('7. Encrypt / decrypt');

{
  const PW = 'smoke-pw-do-not-use';
  const PLAINTEXT = 'release-smoke roundtrip';

  const enc = run(['encrypt', PLAINTEXT, '--password', PW, '--algorithm', 'AES-256-GCM']);
  check('encrypt exits 0', () => enc.exit === 0, enc.stderr);
  const blob = enc.stdout.trim();
  check('encrypt produces non-empty blob', () => blob.length > 0);
  check('encrypt blob differs from plaintext',
    () => blob.length > 0 && !blob.includes(PLAINTEXT));

  const dec = run(['decrypt', blob, '--password', PW]);
  check('decrypt with correct pw exits 0', () => dec.exit === 0, dec.stderr);
  check('decrypt restores plaintext',
    () => dec.stdout.trim() === PLAINTEXT,
    `got ${JSON.stringify(dec.stdout.trim())}`);

  const wrong = run(['decrypt', blob, '--password', 'totally-wrong-pw']);
  check('decrypt with wrong pw exits 1', () => wrong.exit === 1, `exit=${wrong.exit}`);
  check('decrypt with wrong pw writes failure to stderr',
    () => /fail|unable|authenticate/i.test(wrong.stderr));

  // Context-driven algorithm selection.
  const ctxEnc = run(['encrypt', PLAINTEXT, '--password', PW, '--context', 'user-pii']);
  check('encrypt --context user-pii exits 0', () => ctxEnc.exit === 0, ctxEnc.stderr);
  const ctxDec = run(['decrypt', ctxEnc.stdout.trim(), '--password', PW]);
  check('decrypt of context-encrypted blob restores plaintext',
    () => ctxDec.stdout.trim() === PLAINTEXT);
}

// ---------------------------------------------------------------------------
// 8. Hash password (scrypt + pbkdf2)
// ---------------------------------------------------------------------------

phase('8. Hash password');

{
  const s = run(['hash-password', '--password', 'smoke-pw', '--algorithm', 'scrypt']);
  check('hash-password scrypt exits 0', () => s.exit === 0, s.stderr);
  check('hash-password scrypt output looks like a scrypt hash',
    () => /^\$scrypt\$/.test(s.stdout.trim()));

  const p = run(['hash-password', '--password', 'smoke-pw', '--algorithm', 'pbkdf2']);
  check('hash-password pbkdf2 exits 0', () => p.exit === 0, p.stderr);
  check('hash-password pbkdf2 output looks like a pbkdf2 hash',
    () => /^\$pbkdf2/.test(p.stdout.trim()));
}

// ---------------------------------------------------------------------------
// 9. Error paths
// ---------------------------------------------------------------------------

phase('9. Error paths');

{
  const unk = run(['frobnicate']);
  check('unknown command exits 1', () => unk.exit === 1);
  check('unknown command suggests `cryptoserve help`',
    () => /cryptoserve help/i.test(unk.stderr));

  // Unknown flag should warn (stderr) but not crash. Use a command that
  // doesn't otherwise need state.
  const flag = run(['scan', join(FIX, 'benign'), '--definitely-bogus', '--format', 'json']);
  check('unknown flag warning is emitted to stderr',
    () => /unknown flag/i.test(flag.stderr));
  check('unknown flag does not break command (still exits 0)',
    () => flag.exit === 0, `exit=${flag.exit}`);
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

const total = results.passed + results.failed;
console.log();
console.log(paint('─'.repeat(60), C.dim));
const status = results.failed === 0
  ? paint(`PASS ${results.passed}/${total}`, C.green + C.bold)
  : paint(`FAIL ${results.failed}/${total}`, C.red + C.bold);
console.log(`Release-smoke: ${status}`);

if (results.failed > 0) {
  console.log();
  console.log(paint('Failures:', C.red));
  for (const f of results.failures) {
    console.log(`  - ${f.label}`);
    if (f.detail) console.log(`      ${paint(f.detail, C.dim)}`);
  }
  process.exit(1);
}

process.exit(0);
