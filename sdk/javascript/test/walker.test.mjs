import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { walkProject, DEFAULT_SKIP_DIRS } from '../lib/walker.mjs';

const TEST_DIR = join(tmpdir(), 'cryptoserve-walker-test-' + Date.now());

function setup() { mkdirSync(TEST_DIR, { recursive: true }); }
function cleanup() { if (existsSync(TEST_DIR)) rmSync(TEST_DIR, { recursive: true, force: true }); }

describe('DEFAULT_SKIP_DIRS', () => {
  it('includes node_modules and .git', () => {
    assert.ok(DEFAULT_SKIP_DIRS.has('node_modules'));
    assert.ok(DEFAULT_SKIP_DIRS.has('.git'));
  });

  it('includes Python venvs', () => {
    assert.ok(DEFAULT_SKIP_DIRS.has('__pycache__'));
    assert.ok(DEFAULT_SKIP_DIRS.has('.venv'));
    assert.ok(DEFAULT_SKIP_DIRS.has('venv'));
  });
});

describe('walkProject', () => {
  beforeEach(setup);
  afterEach(cleanup);

  it('classifies JS source files', () => {
    writeFileSync(join(TEST_DIR, 'app.js'), 'console.log("hello")');
    writeFileSync(join(TEST_DIR, 'index.ts'), 'const x: number = 1');

    const result = walkProject(TEST_DIR);
    assert.ok(result.sourceFiles.some(f => f.endsWith('app.js')));
    assert.ok(result.sourceFiles.some(f => f.endsWith('index.ts')));
  });

  it('classifies Go and Python source files', () => {
    writeFileSync(join(TEST_DIR, 'main.go'), 'package main');
    writeFileSync(join(TEST_DIR, 'app.py'), 'print("hello")');

    const result = walkProject(TEST_DIR);
    assert.ok(result.sourceFiles.some(f => f.endsWith('main.go')));
    assert.ok(result.sourceFiles.some(f => f.endsWith('app.py')));
  });

  it('classifies config files', () => {
    writeFileSync(join(TEST_DIR, 'nginx.conf'), 'server {}');
    writeFileSync(join(TEST_DIR, 'config.yaml'), 'key: value');
    writeFileSync(join(TEST_DIR, 'settings.toml'), '[section]');

    const result = walkProject(TEST_DIR);
    assert.ok(result.configFiles.some(f => f.endsWith('nginx.conf')));
    assert.ok(result.configFiles.some(f => f.endsWith('config.yaml')));
    assert.ok(result.configFiles.some(f => f.endsWith('settings.toml')));
  });

  it('classifies Dockerfile as config', () => {
    writeFileSync(join(TEST_DIR, 'Dockerfile'), 'FROM node:18');

    const result = walkProject(TEST_DIR);
    assert.ok(result.configFiles.some(f => f.endsWith('Dockerfile')));
  });

  it('classifies binary files', () => {
    writeFileSync(join(TEST_DIR, 'app.wasm'), Buffer.alloc(100));
    writeFileSync(join(TEST_DIR, 'lib.so'), Buffer.alloc(100));

    const result = walkProject(TEST_DIR);
    assert.ok(result.binaryFiles.some(f => f.endsWith('app.wasm')));
    assert.ok(result.binaryFiles.some(f => f.endsWith('lib.so')));
  });

  it('classifies cert files', () => {
    writeFileSync(join(TEST_DIR, 'server.pem'), 'FAKE CERT');
    writeFileSync(join(TEST_DIR, 'server.key'), 'FAKE KEY');
    writeFileSync(join(TEST_DIR, 'ca.crt'), 'FAKE CA');

    const result = walkProject(TEST_DIR);
    assert.ok(result.certFiles.some(f => f.endsWith('server.pem')));
    assert.ok(result.certFiles.some(f => f.endsWith('server.key')));
    assert.ok(result.certFiles.some(f => f.endsWith('ca.crt')));
  });

  it('skips node_modules', () => {
    mkdirSync(join(TEST_DIR, 'node_modules'), { recursive: true });
    writeFileSync(join(TEST_DIR, 'node_modules', 'lib.js'), 'x');
    writeFileSync(join(TEST_DIR, 'app.js'), 'y');

    const result = walkProject(TEST_DIR);
    assert.equal(result.sourceFiles.length, 1);
    assert.ok(result.sourceFiles[0].endsWith('app.js'));
  });

  it('skips hidden directories', () => {
    mkdirSync(join(TEST_DIR, '.hidden'), { recursive: true });
    writeFileSync(join(TEST_DIR, '.hidden', 'secret.js'), 'x');

    const result = walkProject(TEST_DIR);
    assert.equal(result.sourceFiles.length, 0);
  });

  it('respects maxFileSize for source files', () => {
    writeFileSync(join(TEST_DIR, 'huge.js'), 'x'.repeat(2 * 1024 * 1024));
    writeFileSync(join(TEST_DIR, 'small.js'), 'ok');

    const result = walkProject(TEST_DIR);
    assert.equal(result.sourceFiles.length, 1);
    assert.ok(result.sourceFiles[0].endsWith('small.js'));
  });

  it('respects maxBinaryFiles limit', () => {
    for (let i = 0; i < 5; i++) {
      writeFileSync(join(TEST_DIR, `lib${i}.so`), Buffer.alloc(10));
    }

    const result = walkProject(TEST_DIR, { maxBinaryFiles: 3 });
    assert.equal(result.binaryFiles.length, 3);
  });

  it('accepts extra skipDirs', () => {
    mkdirSync(join(TEST_DIR, 'generated'), { recursive: true });
    writeFileSync(join(TEST_DIR, 'generated', 'output.js'), 'x');
    writeFileSync(join(TEST_DIR, 'app.js'), 'y');

    const result = walkProject(TEST_DIR, { skipDirs: new Set(['generated']) });
    assert.equal(result.sourceFiles.length, 1);
    assert.ok(result.sourceFiles[0].endsWith('app.js'));
  });

  it('accepts extra includeExtensions', () => {
    writeFileSync(join(TEST_DIR, 'contract.sol'), 'pragma solidity');

    const result = walkProject(TEST_DIR);
    assert.equal(result.sourceFiles.length, 0);

    const result2 = walkProject(TEST_DIR, { includeExtensions: new Set(['.sol']) });
    assert.equal(result2.sourceFiles.length, 1);
  });

  it('walks subdirectories', () => {
    mkdirSync(join(TEST_DIR, 'src', 'utils'), { recursive: true });
    writeFileSync(join(TEST_DIR, 'src', 'utils', 'helper.js'), 'export default {}');

    const result = walkProject(TEST_DIR);
    assert.ok(result.sourceFiles.some(f => f.includes('helper.js')));
  });

  it('returns totalFiles and totalBytes', () => {
    writeFileSync(join(TEST_DIR, 'a.js'), 'hello');
    writeFileSync(join(TEST_DIR, 'b.ts'), 'world');

    const result = walkProject(TEST_DIR);
    assert.ok(result.totalFiles >= 2);
    assert.ok(result.totalBytes > 0);
  });

  it('returns empty for empty directory', () => {
    const result = walkProject(TEST_DIR);
    assert.equal(result.sourceFiles.length, 0);
    assert.equal(result.configFiles.length, 0);
    assert.equal(result.binaryFiles.length, 0);
    assert.equal(result.certFiles.length, 0);
  });
});
