import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { generateCbom, toCycloneDx, toSpdx, toNativeJson, generatePurl } from '../lib/cbom.mjs';

const CLI = join(dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'cryptoserve.mjs');

const MOCK_SCAN = {
  libraries: [
    { name: 'jsonwebtoken', version: '9.0.0', algorithms: ['RS256', 'HS256'], quantumRisk: 'high', category: 'token', ecosystem: 'npm' },
    { name: 'bcrypt', version: '5.1.0', algorithms: ['bcrypt'], quantumRisk: 'none', category: 'kdf', ecosystem: 'npm' },
  ],
  sourceAlgorithms: [
    { algorithm: 'sha256', category: 'hashing', language: 'go', quantumRisk: 'low' },
  ],
  tlsFindings: [],
};

const MOCK_PQC = {
  quantumReadinessScore: 65,
};

describe('generatePurl', () => {
  it('generates npm purl', () => {
    assert.equal(generatePurl('jsonwebtoken', '9.0.0', 'npm'), 'pkg:npm/jsonwebtoken@9.0.0');
  });

  it('generates Go purl', () => {
    assert.equal(generatePurl('golang.org/x/crypto', 'v0.17.0', 'go'), 'pkg:golang/golang.org/x/crypto@v0.17.0');
  });

  it('generates Cargo purl', () => {
    assert.equal(generatePurl('aes-gcm', '0.10', 'cargo'), 'pkg:cargo/aes-gcm@0.10');
  });

  it('handles unknown version', () => {
    assert.equal(generatePurl('test', 'unknown', 'npm'), 'pkg:npm/test');
  });

  it('handles builtin version', () => {
    assert.equal(generatePurl('node:crypto', 'builtin', 'npm'), 'pkg:npm/node:crypto');
  });
});

describe('generateCbom', () => {
  it('produces valid CBOM structure', () => {
    const cbom = generateCbom(MOCK_SCAN, MOCK_PQC, 'test-project');
    assert.ok(cbom.id);
    assert.ok(cbom.createdAt);
    assert.equal(cbom.projectName, 'test-project');
    assert.ok(cbom.components.length > 0);
    assert.ok(cbom.quantumReadiness);
    assert.ok(cbom.metadata);
  });

  it('includes all libraries as components', () => {
    const cbom = generateCbom(MOCK_SCAN, MOCK_PQC, 'test');
    const libComponents = cbom.components.filter(c => c.type === 'library');
    assert.ok(libComponents.length >= 2);
    assert.ok(libComponents.some(c => c.name === 'jsonwebtoken'));
  });

  it('includes source algorithms as algorithm components', () => {
    const cbom = generateCbom(MOCK_SCAN, MOCK_PQC, 'test');
    const algoComponents = cbom.components.filter(c => c.type === 'algorithm');
    assert.ok(algoComponents.some(c => c.name === 'sha256'));
  });

  it('calculates quantum readiness', () => {
    const cbom = generateCbom(MOCK_SCAN, MOCK_PQC, 'test');
    assert.equal(cbom.quantumReadiness.score, 65);
    assert.ok(typeof cbom.quantumReadiness.vulnerableCount === 'number');
    assert.ok(typeof cbom.quantumReadiness.safeCount === 'number');
  });

  it('includes content hash', () => {
    const cbom = generateCbom(MOCK_SCAN, MOCK_PQC, 'test');
    assert.ok(cbom.metadata.contentHash);
    assert.equal(cbom.metadata.contentHash.length, 64); // SHA-256 hex
  });

  it('does not let a foreign-language library absorb a source algorithm', () => {
    // Same name-only match that misattributed a Python `hashlib.md5()` to
    // `crypto-js` in the gate (#67): an `md5` read from a .c file was dropped
    // from the CBOM entirely because an npm package in the same tree listed it.
    // A component that exists in the tree must not disappear from the bill of
    // materials because something in another ecosystem shares the name.
    const scan = {
      libraries: [
        { name: 'crypto-js', version: '3.1.9', algorithms: ['md5'], quantumRisk: 'critical', category: 'general', ecosystem: 'npm' },
      ],
      sourceAlgorithms: [
        { algorithm: 'md5', category: 'hashing', language: 'c', quantumRisk: 'critical' },
      ],
      tlsFindings: [],
    };
    const cbom = generateCbom(scan, MOCK_PQC, 'test');
    const algoComponents = cbom.components.filter(c => c.type === 'algorithm');
    assert.ok(algoComponents.some(c => c.name === 'md5'),
      `C md5 dropped from the CBOM: ${JSON.stringify(cbom.components.map(c => `${c.type}:${c.name}`))}`);
  });

  it('still emits an algorithm no same-language library declares by name', () => {
    // Constrains the NAME half of the suppression. With only the cross-language
    // cases asserted, dropping the name comparison entirely would let any
    // same-language library suppress EVERY source algorithm of that language
    // and the suite would stay green.
    const scan = {
      libraries: [
        { name: 'crypto-js', version: '3.1.9', algorithms: ['aes'], quantumRisk: 'none', category: 'general', ecosystem: 'npm' },
      ],
      sourceAlgorithms: [
        { algorithm: 'md5', category: 'hashing', language: 'javascript', quantumRisk: 'critical' },
      ],
      tlsFindings: [],
    };
    const cbom = generateCbom(scan, MOCK_PQC, 'test');
    const algoComponents = cbom.components.filter(c => c.type === 'algorithm');
    assert.deepEqual(algoComponents.map(c => c.name), ['md5'],
      'a JavaScript library declaring only AES must not absorb a JavaScript md5');
  });

  it('still folds a source algorithm into a library of the same language', () => {
    // The other direction: an npm package DOES own the JavaScript call, so the
    // algorithm is not standalone and must not be duplicated as its own
    // component beside the library that provides it.
    const scan = {
      libraries: [
        { name: 'crypto-js', version: '3.1.9', algorithms: ['md5'], quantumRisk: 'critical', category: 'general', ecosystem: 'npm' },
      ],
      sourceAlgorithms: [
        { algorithm: 'md5', category: 'hashing', language: 'javascript', quantumRisk: 'critical' },
      ],
      tlsFindings: [],
    };
    const cbom = generateCbom(scan, MOCK_PQC, 'test');
    const algoComponents = cbom.components.filter(c => c.type === 'algorithm');
    assert.equal(algoComponents.length, 0,
      `duplicated an owned algorithm: ${JSON.stringify(algoComponents.map(c => c.name))}`);
  });
});

describe('toCycloneDx', () => {
  it('produces valid CycloneDX 1.5 format', () => {
    const cbom = generateCbom(MOCK_SCAN, MOCK_PQC, 'test');
    const cdx = toCycloneDx(cbom);
    assert.equal(cdx.bomFormat, 'CycloneDX');
    assert.equal(cdx.specVersion, '1.5');
    assert.ok(cdx.serialNumber.startsWith('urn:uuid:'));
    assert.equal(cdx.version, 1);
  });

  it('includes metadata with tools', () => {
    const cbom = generateCbom(MOCK_SCAN, MOCK_PQC, 'test');
    const cdx = toCycloneDx(cbom);
    assert.equal(cdx.metadata.tools[0].vendor, 'CryptoServe');
    assert.equal(cdx.metadata.tools[0].name, 'crypto-inventory');
  });

  it('includes quantum readiness properties', () => {
    const cbom = generateCbom(MOCK_SCAN, MOCK_PQC, 'test');
    const cdx = toCycloneDx(cbom);
    const props = cdx.metadata.properties;
    assert.ok(props.some(p => p.name === 'cbom:quantum-readiness-score'));
    assert.ok(props.some(p => p.name === 'cbom:risk-level'));
    assert.ok(props.some(p => p.name === 'cbom:migration-urgency'));
  });

  it('includes components with bom-ref', () => {
    const cbom = generateCbom(MOCK_SCAN, MOCK_PQC, 'test');
    const cdx = toCycloneDx(cbom);
    assert.ok(cdx.components.length > 0);
    for (const comp of cdx.components) {
      assert.ok(comp['bom-ref']);
      assert.ok(comp.type);
      assert.ok(comp.name);
    }
  });
});

describe('toSpdx', () => {
  it('produces valid SPDX 2.3 format', () => {
    const cbom = generateCbom(MOCK_SCAN, MOCK_PQC, 'test');
    const spdx = toSpdx(cbom);
    assert.equal(spdx.spdxVersion, 'SPDX-2.3');
    assert.equal(spdx.dataLicense, 'CC0-1.0');
    assert.equal(spdx.SPDXID, 'SPDXRef-DOCUMENT');
  });

  it('includes creation info', () => {
    const cbom = generateCbom(MOCK_SCAN, MOCK_PQC, 'test');
    const spdx = toSpdx(cbom);
    assert.ok(spdx.creationInfo.created);
    assert.ok(spdx.creationInfo.creators.length > 0);
  });

  it('includes packages with SPDXID', () => {
    const cbom = generateCbom(MOCK_SCAN, MOCK_PQC, 'test');
    const spdx = toSpdx(cbom);
    assert.ok(spdx.packages.length > 0);
    for (const pkg of spdx.packages) {
      assert.ok(pkg.SPDXID.startsWith('SPDXRef-'));
      assert.ok(pkg.name);
    }
  });

  it('includes DESCRIBES relationships', () => {
    const cbom = generateCbom(MOCK_SCAN, MOCK_PQC, 'test');
    const spdx = toSpdx(cbom);
    assert.ok(spdx.relationships.length > 0);
    assert.equal(spdx.relationships[0].relationshipType, 'DESCRIBES');
  });
});

describe('toNativeJson', () => {
  it('returns the full CBOM unchanged', () => {
    const cbom = generateCbom(MOCK_SCAN, MOCK_PQC, 'test');
    const native = toNativeJson(cbom);
    assert.deepEqual(native, cbom);
  });
});

// ---------------------------------------------------------------------------
// gitRepo: the origin remote, without the userinfo of its URL
// ---------------------------------------------------------------------------

// A clone made with a credential in its URL keeps it in the origin remote, and
// a CBOM is a document people pass around. Every URL below that carries
// userinfo is assembled here at runtime, so none is ever a literal in this
// file, and no part of one is a credential for anything.
const USER = ['fixture', 'user'].join('-');
const SECRET = ['fixture', 'pass', 'word'].join('-');
const USERINFO = `${USER}:${SECRET}@`;
const HOST = 'example.test';
const PATH = '/org/repo.git';
// Built from code points, never written as literals: an override is invisible
// in a diff. RLO, and the one-byte CSI.
const RLO = String.fromCodePoint(0x202e);
const CSI = String.fromCodePoint(0x9b);
// A link-local IPv6 host with a zone: git reaches it, `new URL()` refuses it.
const ZONED_HOST = '[fe80::1%25en0]';

const remoteDirs = [];
after(() => {
  for (const dir of remoteDirs) rmSync(dir, { recursive: true, force: true });
});

function tempDir() {
  const dir = mkdtempSync(join(tmpdir(), 'cryptoserve-cbom-remote-'));
  remoteDirs.push(dir);
  return dir;
}

function git(cwd, ...args) {
  return execFileSync('git', args, { cwd, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] });
}

/** A repository whose origin remote is `url`, stored exactly as given. */
function repoWithOrigin(url) {
  const dir = tempDir();
  git(dir, 'init', '-q');
  git(dir, 'remote', 'add', 'origin', url);
  // A url.<base>.insteadOf rule in the git config would rewrite the remote
  // before the CBOM reads it, and the cells below would test that instead.
  assert.equal(git(dir, 'remote', 'get-url', 'origin').trim(), url, 'git did not keep the remote as given');
  return dir;
}

const gitRepoOf = (url) => generateCbom(MOCK_SCAN, MOCK_PQC, 'test', repoWithOrigin(url)).metadata.gitRepo;

describe('gitRepo', () => {
  it('drops the userinfo of the origin remote URL', () => {
    const gitRepo = gitRepoOf(`https://${USERINFO}${HOST}${PATH}`);
    assert.equal(gitRepo, `https://${HOST}${PATH}`);
    assert.doesNotMatch(gitRepo, /\/\/[^/]*@/);
  });

  it('drops a userinfo that is a user name alone, over https and over ssh', () => {
    // A token is often the whole userinfo, with no password after it.
    assert.equal(gitRepoOf(`https://${SECRET}@${HOST}${PATH}`), `https://${HOST}${PATH}`);
    assert.equal(gitRepoOf(`ssh://${USER}@${HOST}${PATH}`), `ssh://${HOST}${PATH}`);
  });

  it('adds no trailing slash the remote did not have', () => {
    assert.equal(gitRepoOf(`https://${USERINFO}${HOST}`), `https://${HOST}`);
    assert.equal(gitRepoOf(`https://${USERINFO}${HOST}/org/repo/`), `https://${HOST}/org/repo/`);
  });

  it('writes a remote without userinfo byte for byte', () => {
    // The host's case and the default port are both things `new URL()` would
    // rewrite. Nothing here is userinfo, so nothing may change.
    const remote = `https://Example.Test:443${PATH}`;
    assert.equal(gitRepoOf(remote), remote);
  });

  it('leaves the scp-like form as it is', () => {
    // `user@host:path` names an account to log in as and has no password field.
    const remote = `${USER}@${HOST}:org/repo.git`;
    assert.equal(gitRepoOf(remote), remote);
  });

  it('drops both the userinfo and a bidi override in the same remote', () => {
    // `new URL()` refuses the override in a host name, so this remote is cut
    // by the fallback and then cleaned of the override: each step has to
    // leave the other's work in place.
    assert.equal(gitRepoOf(`https://${USERINFO}exa${RLO}mple.test${PATH}`), `https://${HOST}${PATH}`);
  });

  it('drops the userinfo and writes a C1 character in the path percent-encoded', () => {
    // Once the userinfo goes, the remote is written as the URL serializes
    // it, which encodes the character rather than dropping it: the path still
    // names the same repository, and nothing raw reaches a terminal.
    assert.equal(gitRepoOf(`https://${USERINFO}${HOST}/org/re${CSI}po.git`), `https://${HOST}/org/re%C2%9Bpo.git`);
  });

  it('cuts the userinfo out of a remote that new URL() refuses', () => {
    assert.equal(gitRepoOf(`https://${USERINFO}${ZONED_HOST}${PATH}`), `https://${ZONED_HOST}${PATH}`);
  });

  it('cuts a refused remote at its last @, so a password holding one goes whole', () => {
    // The userinfo ends at the last `@` before the path, the one `new URL()`
    // splits on. Cutting at the first would leave the rest of the password.
    const secret = [SECRET, 'tail'].join('@');
    assert.equal(gitRepoOf(`https://${USER}:${secret}@${ZONED_HOST}${PATH}`), `https://${ZONED_HOST}${PATH}`);
  });
});

describe('cbom command: the origin remote', () => {
  function cli(...args) {
    // NO_COLOR, so the summary matched below is its text and not its styling.
    const r = spawnSync(process.execPath, [CLI, ...args], {
      encoding: 'utf-8', timeout: 60000, env: { ...process.env, NO_COLOR: '1' },
    });
    return { code: r.status, stdout: r.stdout, stderr: r.stderr };
  }

  const holdsNoUserinfo = (...outputs) => {
    for (const out of outputs) {
      assert.ok(!out.includes(USER) && !out.includes(SECRET), 'a part of the userinfo reached the output');
    }
  };

  it('says on stderr that it removed the userinfo, and never what it was', () => {
    const { code, stdout, stderr } = cli('cbom', repoWithOrigin(`https://${USERINFO}${HOST}${PATH}`));
    assert.equal(code, 0, stderr);
    assert.equal(JSON.parse(stdout).metadata.gitRepo, `https://${HOST}${PATH}`);
    assert.ok(stderr.endsWith(': 0 components. Origin remote written without its userinfo.\n'), stderr);
    holdsNoUserinfo(stdout, stderr);
  });

  it('says nothing about userinfo for a remote that had none', () => {
    const { code, stdout, stderr } = cli('cbom', repoWithOrigin(`https://${HOST}${PATH}`));
    assert.equal(code, 0, stderr);
    assert.equal(JSON.parse(stdout).metadata.gitRepo, `https://${HOST}${PATH}`);
    assert.ok(stderr.endsWith(': 0 components.\n'), stderr);
  });

  it('says nothing about the remote in a format that does not carry it', () => {
    const { code, stdout, stderr } = cli('cbom', repoWithOrigin(`https://${USERINFO}${HOST}${PATH}`), '--format', 'cyclonedx');
    assert.equal(code, 0, stderr);
    assert.equal(JSON.parse(stdout).bomFormat, 'CycloneDX');
    assert.ok(stderr.endsWith(': 0 components.\n'), stderr);
    holdsNoUserinfo(stdout, stderr);
  });

  it('names the removal in the summary of a CBOM written to a file', () => {
    const output = join(tempDir(), 'cbom.json');
    const { code, stdout, stderr } = cli('cbom', repoWithOrigin(`https://${USERINFO}${HOST}${PATH}`), '--output', output);
    assert.equal(code, 0, stderr);
    assert.ok(stdout.split('\n').includes('  Origin remote        written without its userinfo'), stdout);
    const written = readFileSync(output, 'utf-8');
    assert.equal(JSON.parse(written).metadata.gitRepo, `https://${HOST}${PATH}`);
    holdsNoUserinfo(written, stdout, stderr);
  });
});
