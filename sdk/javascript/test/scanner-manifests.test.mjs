import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  parseGoMod, parseRequirementsTxt, parsePyprojectToml,
  parseCargoToml, parsePomXml, scanManifests, CRYPTO_PACKAGES,
} from '../lib/scanner-manifests.mjs';

const TEST_DIR = join(tmpdir(), 'cryptoserve-manifest-test-' + Date.now());

function setup() { mkdirSync(TEST_DIR, { recursive: true }); }
function cleanup() { if (existsSync(TEST_DIR)) rmSync(TEST_DIR, { recursive: true, force: true }); }

describe('parseGoMod', () => {
  it('parses require block', () => {
    const content = `module github.com/example/app

go 1.21

require (
	golang.org/x/crypto v0.17.0
	github.com/cloudflare/circl v1.3.7
)`;
    const deps = parseGoMod(content);
    assert.ok(deps.some(d => d.name === 'golang.org/x/crypto'));
    assert.ok(deps.some(d => d.name === 'github.com/cloudflare/circl'));
    assert.equal(deps.find(d => d.name === 'golang.org/x/crypto').version, 'v0.17.0');
  });

  it('parses single-line require', () => {
    const content = `require golang.org/x/crypto v0.17.0`;
    const deps = parseGoMod(content);
    assert.ok(deps.some(d => d.name === 'golang.org/x/crypto'));
  });
});

describe('parseRequirementsTxt', () => {
  it('parses package==version lines', () => {
    const content = `cryptography==42.0.0
bcrypt>=4.0
argon2-cffi
# comment
-e .`;
    const deps = parseRequirementsTxt(content);
    assert.ok(deps.some(d => d.name === 'cryptography'));
    assert.ok(deps.some(d => d.name === 'bcrypt'));
    assert.ok(deps.some(d => d.name === 'argon2-cffi'));
    assert.equal(deps.length, 3);
  });

  it('handles extras syntax', () => {
    const content = `cryptography[ssh]==42.0.0`;
    const deps = parseRequirementsTxt(content);
    assert.ok(deps.some(d => d.name === 'cryptography'));
  });
});

describe('parsePyprojectToml', () => {
  it('parses [project] dependencies', () => {
    const content = `[project]
name = "myapp"
dependencies = [
    "cryptography>=42.0.0",
    "bcrypt>=4.0",
]`;
    const deps = parsePyprojectToml(content);
    assert.ok(deps.some(d => d.name === 'cryptography'));
    assert.ok(deps.some(d => d.name === 'bcrypt'));
  });

  it('parses poetry dependencies', () => {
    const content = `[tool.poetry.dependencies]
python = "^3.11"
cryptography = "^42.0"
bcrypt = {version = "^4.0", optional = true}`;
    const deps = parsePyprojectToml(content);
    assert.ok(deps.some(d => d.name === 'cryptography'));
    assert.ok(deps.some(d => d.name === 'bcrypt'));
  });
});

describe('parseCargoToml', () => {
  it('parses simple version strings', () => {
    const content = `[dependencies]
aes-gcm = "0.10"
rsa = "0.9"
sha2 = "0.10"
`;
    const deps = parseCargoToml(content);
    assert.ok(deps.some(d => d.name === 'aes-gcm'));
    assert.ok(deps.some(d => d.name === 'rsa'));
    assert.ok(deps.some(d => d.name === 'sha2'));
  });

  it('parses complex version specs', () => {
    const content = `[dependencies]
ring = { version = "0.17", features = ["std"] }
`;
    const deps = parseCargoToml(content);
    assert.ok(deps.some(d => d.name === 'ring'));
  });
});

describe('parsePomXml', () => {
  it('parses dependency blocks', () => {
    const content = `<dependencies>
  <dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-jdk18on</artifactId>
    <version>1.78</version>
  </dependency>
</dependencies>`;
    const deps = parsePomXml(content);
    assert.ok(deps.some(d => d.groupId === 'org.bouncycastle'));
    assert.equal(deps[0].version, '1.78');
  });
});

describe('CRYPTO_PACKAGES', () => {
  it('has npm packages', () => {
    assert.ok(CRYPTO_PACKAGES.npm['jsonwebtoken']);
    assert.ok(CRYPTO_PACKAGES.npm['bcrypt']);
  });

  it('has Go packages', () => {
    assert.ok(CRYPTO_PACKAGES.go['crypto/rsa']);
    assert.ok(CRYPTO_PACKAGES.go['golang.org/x/crypto']);
  });

  it('has Python packages', () => {
    assert.ok(CRYPTO_PACKAGES.pypi['cryptography']);
    assert.ok(CRYPTO_PACKAGES.pypi['bcrypt']);
  });

  it('has Cargo packages', () => {
    assert.ok(CRYPTO_PACKAGES.cargo['aes-gcm']);
    assert.ok(CRYPTO_PACKAGES.cargo['ring']);
  });
});

describe('scanManifests', () => {
  beforeEach(setup);
  afterEach(cleanup);

  it('detects crypto packages in go.mod', () => {
    writeFileSync(join(TEST_DIR, 'go.mod'), `module example.com/app
go 1.21
require (
	golang.org/x/crypto v0.17.0
	github.com/cloudflare/circl v1.3.7
)`);
    const results = scanManifests(TEST_DIR);
    assert.ok(results.some(r => r.name === 'golang.org/x/crypto'));
    assert.ok(results.some(r => r.ecosystem === 'go'));
  });

  it('detects crypto packages in requirements.txt', () => {
    writeFileSync(join(TEST_DIR, 'requirements.txt'), `cryptography==42.0.0
bcrypt>=4.0`);
    const results = scanManifests(TEST_DIR);
    assert.ok(results.some(r => r.name === 'cryptography'));
    assert.ok(results.some(r => r.ecosystem === 'pypi'));
  });

  it('detects crypto packages in Cargo.toml', () => {
    writeFileSync(join(TEST_DIR, 'Cargo.toml'), `[package]
name = "myapp"
[dependencies]
aes-gcm = "0.10"
rsa = "0.9"`);
    const results = scanManifests(TEST_DIR);
    assert.ok(results.some(r => r.name === 'aes-gcm'));
    assert.ok(results.some(r => r.ecosystem === 'cargo'));
  });

  it('returns empty for missing manifests', () => {
    const results = scanManifests(TEST_DIR);
    assert.equal(results.length, 0);
  });

  it('scans multiple manifests in polyglot repos', () => {
    writeFileSync(join(TEST_DIR, 'go.mod'), `module test
require golang.org/x/crypto v0.17.0`);
    writeFileSync(join(TEST_DIR, 'requirements.txt'), `cryptography==42.0.0`);
    const results = scanManifests(TEST_DIR);
    assert.ok(results.some(r => r.ecosystem === 'go'));
    assert.ok(results.some(r => r.ecosystem === 'pypi'));
  });
});
