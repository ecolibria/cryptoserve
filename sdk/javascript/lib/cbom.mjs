/**
 * Cryptographic Bill of Materials (CBOM) generator.
 *
 * Generates CBOM in three formats:
 * - CycloneDX 1.5 JSON
 * - SPDX 2.3 JSON
 * - Native JSON with quantum readiness data
 *
 * Ported from backend/app/core/cbom.py.
 * Zero dependencies — uses only node:crypto.
 */

import { randomUUID, createHash } from 'node:crypto';
import { execSync } from 'node:child_process';

const VERSION = '0.2.0';

// ---------------------------------------------------------------------------
// Package URL generation
// ---------------------------------------------------------------------------

/**
 * Generate a Package URL (purl) for a dependency.
 */
export function generatePurl(name, version, ecosystem) {
  const v = version && version !== 'unknown' && version !== 'builtin' ? `@${version}` : '';
  switch (ecosystem) {
    case 'npm':    return `pkg:npm/${name}${v}`;
    case 'go':     return `pkg:golang/${name}${v}`;
    case 'pypi':   return `pkg:pypi/${name}${v}`;
    case 'cargo':  return `pkg:cargo/${name}${v}`;
    case 'maven': {
      const parts = name.split(':');
      if (parts.length === 2) return `pkg:maven/${parts[0]}/${parts[1]}${v}`;
      return `pkg:maven/${name}${v}`;
    }
    default:       return `pkg:generic/${name}${v}`;
  }
}

// ---------------------------------------------------------------------------
// Git metadata
// ---------------------------------------------------------------------------

function getGitMetadata() {
  const result = { gitCommit: null, gitBranch: null, gitRepo: null };
  try {
    result.gitCommit = execSync('git rev-parse HEAD', { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  } catch { /* not a git repo */ }
  try {
    result.gitBranch = execSync('git rev-parse --abbrev-ref HEAD', { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  } catch { /* ignore */ }
  try {
    result.gitRepo = execSync('git remote get-url origin', { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  } catch { /* ignore */ }
  return result;
}

// ---------------------------------------------------------------------------
// CBOM generation
// ---------------------------------------------------------------------------

/**
 * Build internal CBOM from scan results and PQC analysis.
 *
 * @param {Object} scanResults - From scanProject()
 * @param {Object} pqcAnalysis - From analyzeOffline()
 * @param {string} [projectName] - Project name override
 * @returns {Object} Internal CBOM structure
 */
export function generateCbom(scanResults, pqcAnalysis, projectName = null) {
  const components = [];

  // Add libraries as components
  for (const lib of (scanResults.libraries || [])) {
    const ecosystem = lib.ecosystem || 'npm';
    components.push({
      bomRef: randomUUID(),
      type: 'library',
      name: lib.name,
      version: lib.version || null,
      purl: generatePurl(lib.name, lib.version, ecosystem),
      category: lib.category,
      quantumRisk: lib.quantumRisk,
      isDeprecated: lib.isDeprecated || false,
      algorithms: lib.algorithms || [],
      ecosystem,
    });
  }

  // Add standalone algorithms detected in source code (not tied to a library)
  const libAlgos = new Set(components.flatMap(c => c.algorithms));
  for (const algo of (scanResults.sourceAlgorithms || [])) {
    if (!libAlgos.has(algo.algorithm)) {
      components.push({
        bomRef: randomUUID(),
        type: 'algorithm',
        name: algo.algorithm,
        version: null,
        purl: null,
        category: algo.category,
        quantumRisk: algo.quantumRisk || 'unknown',
        isDeprecated: false,
        algorithms: [algo.algorithm],
        ecosystem: null,
      });
    }
  }

  // Add TLS findings as protocol components
  for (const tls of (scanResults.tlsFindings || [])) {
    components.push({
      bomRef: randomUUID(),
      type: 'protocol',
      name: tls.protocol,
      version: null,
      purl: null,
      category: 'protocol',
      quantumRisk: tls.risk,
      isDeprecated: tls.risk === 'critical' || tls.risk === 'high',
      algorithms: [tls.protocol.toLowerCase()],
      ecosystem: null,
    });
  }

  const score = pqcAnalysis?.quantumReadinessScore ?? 100;
  const hasPqc = components.some(c => c.category === 'pqc');
  const vulnerableCount = components.filter(c =>
    c.quantumRisk === 'high' || c.quantumRisk === 'critical'
  ).length;
  const safeCount = components.filter(c =>
    c.quantumRisk === 'none' || c.quantumRisk === 'low'
  ).length;
  const deprecatedCount = components.filter(c => c.isDeprecated).length;

  let riskLevel, migrationUrgency;
  if (score >= 80) { riskLevel = 'low'; migrationUrgency = 'low'; }
  else if (score >= 60) { riskLevel = 'medium'; migrationUrgency = 'medium'; }
  else if (score >= 40) { riskLevel = 'high'; migrationUrgency = 'high'; }
  else { riskLevel = 'critical'; migrationUrgency = 'immediate'; }

  if (vulnerableCount === 0 && deprecatedCount === 0) {
    riskLevel = 'none';
    migrationUrgency = 'none';
  }

  const componentsJson = JSON.stringify(components);
  const contentHash = createHash('sha256').update(componentsJson).digest('hex');

  const git = getGitMetadata();

  return {
    id: randomUUID(),
    version: '1.0.0',
    createdAt: new Date().toISOString(),
    projectName: projectName || 'unknown',
    components,
    quantumReadiness: {
      score,
      hasPqc,
      vulnerableCount,
      safeCount,
      deprecatedCount,
      riskLevel,
      migrationUrgency,
    },
    metadata: {
      ...git,
      scanSource: 'cli',
      contentHash,
      toolVersion: VERSION,
    },
  };
}

// ---------------------------------------------------------------------------
// CycloneDX 1.5 output
// ---------------------------------------------------------------------------

/**
 * Convert internal CBOM to CycloneDX 1.5 JSON format.
 */
export function toCycloneDx(cbom) {
  const components = cbom.components.map(c => {
    const comp = {
      type: c.type === 'algorithm' ? 'library' : (c.type === 'protocol' ? 'framework' : 'library'),
      name: c.name,
      'bom-ref': c.bomRef,
    };
    if (c.version) comp.version = c.version;
    if (c.purl) comp.purl = c.purl;

    comp.properties = [
      { name: 'cbom:category', value: c.category },
      { name: 'cbom:quantum-risk', value: c.quantumRisk },
    ];
    if (c.isDeprecated) {
      comp.properties.push({ name: 'cbom:deprecated', value: 'true' });
    }
    if (c.algorithms.length > 0) {
      comp.properties.push({ name: 'cbom:algorithms', value: c.algorithms.join(', ') });
    }

    return comp;
  });

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${cbom.id}`,
    version: 1,
    metadata: {
      timestamp: cbom.createdAt,
      tools: [{
        vendor: 'CryptoServe',
        name: 'crypto-inventory',
        version: VERSION,
      }],
      component: {
        type: 'application',
        name: cbom.projectName,
        'bom-ref': randomUUID(),
      },
      properties: [
        { name: 'cbom:quantum-readiness-score', value: String(cbom.quantumReadiness.score) },
        { name: 'cbom:risk-level', value: cbom.quantumReadiness.riskLevel },
        { name: 'cbom:migration-urgency', value: cbom.quantumReadiness.migrationUrgency },
        { name: 'cbom:has-pqc', value: String(cbom.quantumReadiness.hasPqc) },
      ],
    },
    components,
  };
}

// ---------------------------------------------------------------------------
// SPDX 2.3 output
// ---------------------------------------------------------------------------

/**
 * Convert internal CBOM to SPDX 2.3 JSON format.
 */
export function toSpdx(cbom) {
  const packages = cbom.components.map(c => {
    const pkg = {
      SPDXID: `SPDXRef-${c.bomRef.replace(/-/g, '')}`,
      name: c.name,
      downloadLocation: c.purl || 'NOASSERTION',
      filesAnalyzed: false,
      primaryPackagePurpose: c.type === 'algorithm' ? 'LIBRARY' : 'LIBRARY',
      annotations: [
        {
          annotationType: 'OTHER',
          annotator: 'Tool: CryptoServe',
          annotationDate: cbom.createdAt,
          comment: `quantum-risk: ${c.quantumRisk}, category: ${c.category}`,
        },
      ],
    };
    if (c.version) pkg.versionInfo = c.version;
    if (c.purl) pkg.externalRefs = [{
      referenceCategory: 'PACKAGE-MANAGER',
      referenceType: 'purl',
      referenceLocator: c.purl,
    }];
    return pkg;
  });

  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `cbom-${cbom.projectName}`,
    documentNamespace: `https://cryptoserve.dev/cbom/${cbom.id}`,
    creationInfo: {
      created: cbom.createdAt,
      creators: [`Tool: CryptoServe-${VERSION}`],
      comment: `Quantum readiness score: ${cbom.quantumReadiness.score}/100`,
    },
    packages,
    relationships: packages.map(p => ({
      spdxElementId: 'SPDXRef-DOCUMENT',
      relatedSpdxElement: p.SPDXID,
      relationshipType: 'DESCRIBES',
    })),
  };
}

// ---------------------------------------------------------------------------
// Native JSON output
// ---------------------------------------------------------------------------

/**
 * Full CBOM with all quantum readiness data.
 */
export function toNativeJson(cbom) {
  return cbom;
}
