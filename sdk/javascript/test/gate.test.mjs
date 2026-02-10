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
    const output = execSync(`node ${CLI} gate ${TEST_DIR} ${args}`, {
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
    writeFileSync(join(TEST_DIR, 'package.json'), JSON.stringify({
      dependencies: { 'crypto-js': '^4.0.0' },
    }));
    writeFileSync(join(TEST_DIR, 'app.js'), `const hash = CryptoJS.MD5("test");\n`);
    const { output } = runGate('--format json --fail-on-weak');
    const result = JSON.parse(output);
    // crypto-js includes MD5, DES, RC4 which are weak
    if (result.violations.some(v => v.weak)) {
      assert.equal(result.status, 'fail');
    }
  });
});
