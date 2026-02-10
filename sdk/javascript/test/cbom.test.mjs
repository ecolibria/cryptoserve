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
