import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateCbom, toCycloneDx, toSpdx, toNativeJson, generatePurl } from '../lib/cbom.mjs';

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
