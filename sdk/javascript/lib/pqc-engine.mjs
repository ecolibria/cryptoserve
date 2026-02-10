/**
 * Offline PQC analysis engine.
 *
 * Port of sdk/python/cryptoserve/_pqc_engine.py — same data, same logic.
 * Provides air-gapped quantum readiness analysis with zero dependencies.
 */

import { lookupAlgorithm, classifyFromDb } from './algorithm-db.mjs';

// ---------------------------------------------------------------------------
// Embedded intelligence data
// ---------------------------------------------------------------------------

export const QUANTUM_THREAT_TIMELINE = {
  rsa_2048:   { min: 10, median: 15, max: 25 },
  rsa_4096:   { min: 15, median: 20, max: 30 },
  ecdsa_p256: { min: 10, median: 15, max: 25 },
  ecdsa_p384: { min: 12, median: 17, max: 27 },
  ed25519:    { min: 10, median: 15, max: 25 },
  x25519:     { min: 10, median: 15, max: 25 },
  dh_2048:    { min: 10, median: 15, max: 25 },
  aes_128:    { min: 15, median: 25, max: 50 },
  aes_256:    { min: 30, median: 50, max: 100 },
  sha_256:    { min: 30, median: 50, max: 100 },
  chacha20:   { min: 30, median: 50, max: 100 },
};

export const DATA_PROFILES = {
  national_security: {
    name: 'National Security Data',
    lifespanYears: 75,
    urgency: 'critical',
    cryptoNeeds: ['kem', 'signature'],
  },
  healthcare: {
    name: 'Healthcare Records',
    lifespanYears: 100,
    urgency: 'critical',
    cryptoNeeds: ['kem'],
  },
  financial: {
    name: 'Long-term Financial Data',
    lifespanYears: 25,
    urgency: 'high',
    cryptoNeeds: ['kem', 'signature'],
  },
  intellectual_property: {
    name: 'Intellectual Property',
    lifespanYears: 20,
    urgency: 'high',
    cryptoNeeds: ['kem'],
  },
  legal: {
    name: 'Legal Documents',
    lifespanYears: 30,
    urgency: 'high',
    cryptoNeeds: ['kem', 'signature'],
  },
  general: {
    name: 'Personal Data / General',
    lifespanYears: 10,
    urgency: 'medium',
    cryptoNeeds: ['kem'],
  },
  authentication: {
    name: 'Authentication Credentials',
    lifespanYears: 1,
    urgency: 'medium',
    cryptoNeeds: ['kem', 'signature'],
  },
  session_tokens: {
    name: 'Session Tokens',
    lifespanYears: 0,
    urgency: 'low',
    cryptoNeeds: ['signature'],
  },
  ephemeral: {
    name: 'Ephemeral Communications',
    lifespanYears: 1,
    urgency: 'low',
    cryptoNeeds: ['kem'],
  },
  // Backward-compat alias
  short_lived: {
    name: 'Session Tokens',
    lifespanYears: 0,
    urgency: 'low',
    cryptoNeeds: ['signature'],
  },
};

export const PQC_ALGORITHMS = {
  kem: [
    {
      id: 'ml-kem-768',
      name: 'ML-KEM-768',
      fips: 'FIPS 203',
      securityLevel: 3,
      status: 'standardized',
      description: 'Primary NIST KEM standard, balanced security/performance',
      hybridWith: 'X25519Kyber768',
    },
    {
      id: 'ml-kem-1024',
      name: 'ML-KEM-1024',
      fips: 'FIPS 203',
      securityLevel: 5,
      status: 'standardized',
      description: 'Highest security KEM for long-term protection',
      hybridWith: 'X25519Kyber1024',
    },
    {
      id: 'ml-kem-512',
      name: 'ML-KEM-512',
      fips: 'FIPS 203',
      securityLevel: 1,
      status: 'standardized',
      description: 'Smallest/fastest KEM for constrained environments',
      hybridWith: 'X25519Kyber512',
    },
  ],
  signature: [
    {
      id: 'ml-dsa-65',
      name: 'ML-DSA-65',
      fips: 'FIPS 204',
      securityLevel: 3,
      status: 'standardized',
      description: 'Primary NIST signature standard, balanced approach',
    },
    {
      id: 'ml-dsa-87',
      name: 'ML-DSA-87',
      fips: 'FIPS 204',
      securityLevel: 5,
      status: 'standardized',
      description: 'Highest security signatures for critical applications',
    },
    {
      id: 'slh-dsa-128f',
      name: 'SLH-DSA-128f',
      fips: 'FIPS 205',
      securityLevel: 1,
      status: 'standardized',
      description: 'Hash-based signatures, conservative security assumptions',
    },
  ],
};

export const COMPLIANCE_FRAMEWORKS = {
  cnsa_2_0: {
    name: 'CNSA 2.0',
    authority: 'NSA',
    kem: 'ML-KEM-1024 required by 2030',
    sig: 'ML-DSA-87 required by 2033',
  },
  nist_sp_800_208: {
    name: 'NIST SP 800-208',
    authority: 'NIST',
    sig: 'LMS/XMSS/SLH-DSA for firmware signing',
  },
  bsi: {
    name: 'BSI TR-02102',
    authority: 'BSI (Germany)',
    note: 'Hybrid mode recommended until 2030',
  },
  anssi: {
    name: 'ANSSI Guidelines',
    authority: 'ANSSI (France)',
    note: 'Hybrid classical+PQC mandated through 2030',
  },
};

// ---------------------------------------------------------------------------
// Algorithm classification rules
// ---------------------------------------------------------------------------

// [pattern, timelineKey, category] — first match wins
const ALGO_CLASSIFICATION_RULES = [
  // PQC (safe)
  ['Kyber',     'pqc',        'pqc'],
  ['ML-KEM',    'pqc',        'pqc'],
  ['Dilithium', 'pqc',        'pqc'],
  ['ML-DSA',    'pqc',        'pqc'],
  ['Falcon',    'pqc',        'pqc'],
  ['SPHINCS',   'pqc',        'pqc'],
  ['SLH-DSA',   'pqc',        'pqc'],
  // Asymmetric (quantum-vulnerable via Shor's)
  ['RSA',       'rsa_2048',   'asymmetric'],
  ['ECDSA',     'ecdsa_p256', 'asymmetric'],
  ['ECDHE',     'ecdsa_p256', 'asymmetric'],
  ['ECC',       'ecdsa_p256', 'asymmetric'],
  ['Ed25519',   'ed25519',    'asymmetric'],
  ['EdDSA',     'ed25519',    'asymmetric'],
  ['Curve25519','x25519',     'asymmetric'],
  ['X25519',    'x25519',     'asymmetric'],
  ['DH',        'dh_2048',    'asymmetric'],
  // Symmetric (Grover's — key-doubling sufficient)
  ['AES',       'aes_256',    'symmetric'],
  ['ChaCha20',  'chacha20',   'symmetric'],
  ['3DES',      'aes_128',    'symmetric'],
  ['DES',       'aes_128',    'symmetric'],
  ['XSalsa20',  'chacha20',   'symmetric'],
  // Hashing
  ['SHA-256',   'sha_256',    'hash'],
  ['SHA-512',   'sha_256',    'hash'],
  ['SHA-1',     'sha_256',    'hash'],
  ['SHA3',      'sha_256',    'hash'],
  ['Blake2',    'sha_256',    'hash'],
  ['MD5',       'sha_256',    'hash'],
  // KDF / MAC / CSPRNG
  ['HMAC',      'sha_256',    'hash'],
  ['bcrypt',    null,         'kdf'],
  ['Argon2',    null,         'kdf'],
  ['PBKDF2',    null,         'kdf'],
  ['scrypt',    null,         'kdf'],
  ['CSPRNG',    null,         'random'],
  ['Poly1305',  null,         'mac'],
  // Token / TLS wrappers
  ['TLS',       'rsa_2048',   'asymmetric'],
  ['JWS',       'rsa_2048',   'asymmetric'],
  ['JWE',       'rsa_2048',   'asymmetric'],
  ['JWK',       'rsa_2048',   'asymmetric'],
  ['RS256',     'rsa_2048',   'asymmetric'],
  ['ES256',     'ecdsa_p256', 'asymmetric'],
  ['HS256',     'sha_256',    'hash'],
];

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

function classifyAlgorithms(libraries) {
  const seen = new Set();
  const results = [];

  for (const lib of libraries) {
    for (const algoName of (lib.algorithms || [])) {
      if (seen.has(algoName)) continue;
      seen.add(algoName);

      let matched = false;
      const upper = algoName.toUpperCase();

      for (const [pattern, timelineKey, category] of ALGO_CLASSIFICATION_RULES) {
        if (upper.includes(pattern.toUpperCase())) {
          results.push({ algo: algoName, timelineKey, category });
          matched = true;
          break;
        }
      }

      if (!matched) {
        results.push({ algo: algoName, timelineKey: null, category: 'unknown' });
      }
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// Analysis helpers
// ---------------------------------------------------------------------------

function assessSndl(classifications, profile, libraries) {
  const lifespan = profile.lifespanYears;
  const migrationYears = 2;

  const asymmetricTimelines = classifications
    .filter(c => c.category === 'asymmetric' && c.timelineKey in QUANTUM_THREAT_TIMELINE)
    .map(c => QUANTUM_THREAT_TIMELINE[c.timelineKey]);

  let minMedian, minMin, minMax;
  if (asymmetricTimelines.length > 0) {
    minMedian = Math.min(...asymmetricTimelines.map(t => t.median));
    minMin = Math.min(...asymmetricTimelines.map(t => t.min));
    minMax = Math.min(...asymmetricTimelines.map(t => t.max));
  } else {
    minMedian = 50;
    minMin = 30;
    minMax = 100;
  }

  const riskWindow = minMedian - (lifespan + migrationYears);
  const isVulnerable = riskWindow < 0;

  const hasDeprecated = libraries.some(lib => lib.isDeprecated);
  const hasPqc = classifications.some(c => c.category === 'pqc');
  const hasAsymmetric = classifications.some(c => c.category === 'asymmetric');

  let riskLevel;
  if (hasDeprecated) {
    riskLevel = 'critical';
  } else if (isVulnerable && hasAsymmetric && !hasPqc) {
    riskLevel = 'critical';
  } else if (isVulnerable) {
    riskLevel = 'high';
  } else if (riskWindow < 5 && hasAsymmetric) {
    riskLevel = 'medium';
  } else {
    riskLevel = 'low';
  }

  let explanation;
  if (isVulnerable) {
    explanation =
      `Your data (${profile.name}) with ${lifespan}-year lifespan ` +
      `is at risk. Quantum computers (est. ${minMin}-${minMax} years) may ` +
      `decrypt this data before its confidentiality period expires.`;
  } else if (riskWindow < 5) {
    explanation =
      `Only ${riskWindow} years margin before SNDL risk. ` +
      `Data encrypted today may be vulnerable before expiration.`;
  } else if (riskWindow < 10) {
    explanation = `${riskWindow} years margin. Time to plan migration.`;
  } else {
    explanation = `${riskWindow} years margin. Monitor quantum developments.`;
  }

  return {
    vulnerable: isVulnerable,
    protectionYearsRequired: lifespan,
    estimatedQuantumYearsMin: minMin,
    estimatedQuantumYearsMedian: minMedian,
    estimatedQuantumYearsMax: minMax,
    riskWindowYears: riskWindow,
    riskLevel,
    explanation,
  };
}

function scoreAlgorithm(algo, hasCritical) {
  let score = 50.0;
  if (algo.status === 'standardized') score += 25;
  if (hasCritical && algo.securityLevel >= 3) {
    score += 15;
  } else if (algo.securityLevel === 3) {
    score += 10;
  }
  if (algo.id === 'ml-kem-768' || algo.id === 'ml-dsa-65') score += 10;
  return Math.min(100.0, score);
}

function recommendKem(classifications, profile, libraries) {
  const hasAsymmetric = classifications.some(c => c.category === 'asymmetric');
  if (!hasAsymmetric && !(profile.cryptoNeeds || []).includes('kem')) {
    return [];
  }

  const hasCritical = libraries.some(
    lib => lib.quantumRisk === 'high' || lib.quantumRisk === 'critical'
  );

  const currentAlgos = [...new Set(
    classifications.filter(c => c.category === 'asymmetric').map(c => c.algo)
  )].sort();
  const currentDisplay = currentAlgos.length > 0 ? currentAlgos.join(', ') : 'classical algorithms';

  const results = PQC_ALGORITHMS.kem.map(algo => ({
    currentAlgorithm: currentDisplay,
    recommendedAlgorithm: algo.name,
    fipsStandard: algo.fips,
    securityLevel: `NIST Level ${algo.securityLevel}`,
    description: algo.description,
    hybridOption: algo.hybridWith || null,
    score: scoreAlgorithm(algo, hasCritical),
    rationale: `Replaces quantum-vulnerable key exchange with ${algo.fips}-standardized KEM`,
    migrationComplexity: 'medium',
  }));

  results.sort((a, b) => b.score - a.score);
  return results;
}

function recommendSignatures(classifications, profile, libraries) {
  const sigAlgos = new Set(['RSA', 'ECDSA', 'Ed25519', 'EdDSA', 'RS256', 'ES256']);
  const hasSigningAlgo = classifications.some(
    c => sigAlgos.has(c.algo) || c.category === 'asymmetric'
  );
  if (!hasSigningAlgo && !(profile.cryptoNeeds || []).includes('signature')) {
    return [];
  }

  const hasCritical = libraries.some(
    lib => lib.quantumRisk === 'high' || lib.quantumRisk === 'critical'
  );

  const currentAlgos = [...new Set(
    classifications.filter(c => c.category === 'asymmetric').map(c => c.algo)
  )].sort();
  const currentDisplay = currentAlgos.length > 0 ? currentAlgos.join(', ') : 'classical signatures';

  const results = PQC_ALGORITHMS.signature.map(algo => ({
    currentAlgorithm: currentDisplay,
    recommendedAlgorithm: algo.name,
    fipsStandard: algo.fips,
    securityLevel: `NIST Level ${algo.securityLevel}`,
    description: algo.description,
    score: scoreAlgorithm(algo, hasCritical),
    rationale: `Replaces quantum-vulnerable signatures with ${algo.fips}-standardized scheme`,
    migrationComplexity: 'medium',
  }));

  results.sort((a, b) => b.score - a.score);
  return results;
}

function generateMigrationPlan(libraries, classifications, sndl) {
  const steps = [];
  let stepOrder = 1;

  const deprecated = libraries.filter(lib => lib.isDeprecated);
  if (deprecated.length > 0) {
    steps.push({
      step: stepOrder++,
      action: 'Replace deprecated libraries',
      description: `Remove ${deprecated.map(l => l.name).join(', ')} — known vulnerabilities`,
      priority: 'CRITICAL',
      effort: 'medium',
      affected: deprecated.map(l => l.name),
    });
  }

  const hasPqc = classifications.some(c => c.category === 'pqc');
  if (!hasPqc) {
    steps.push({
      step: stepOrder++,
      action: 'Enable cryptographic agility',
      description: 'Refactor to support algorithm negotiation and easy swapping',
      priority: ['critical', 'high'].includes(sndl.riskLevel) ? 'HIGH' : 'MEDIUM',
      effort: 'high',
      affected: [],
    });
  }

  const hasAsymmetric = classifications.some(c => c.category === 'asymmetric');
  if (hasAsymmetric) {
    steps.push({
      step: stepOrder++,
      action: 'Deploy hybrid key exchange',
      description: 'Implement X25519Kyber768 for TLS and key exchange',
      priority: sndl.vulnerable ? 'HIGH' : 'MEDIUM',
      effort: 'medium',
      affected: libraries.filter(l => l.category === 'tls').map(l => l.name),
      targetAlgorithm: 'X25519Kyber768',
    });
  }

  const sigAlgos = new Set(['RSA', 'ECDSA', 'Ed25519', 'EdDSA', 'RS256', 'ES256']);
  const hasSigning = classifications.some(c => sigAlgos.has(c.algo));
  if (hasSigning) {
    steps.push({
      step: stepOrder++,
      action: 'Migrate to PQC signatures',
      description: 'Replace RSA/ECDSA signatures with ML-DSA-65',
      priority: 'MEDIUM',
      effort: 'medium',
      affected: libraries.filter(l => l.category === 'token').map(l => l.name),
      targetAlgorithm: 'ML-DSA-65',
    });
  }

  steps.push({
    step: stepOrder,
    action: 'Complete PQC migration',
    description: 'Remove classical-only crypto, verify quantum resistance',
    priority: 'LOW',
    effort: 'low',
    affected: [],
  });

  return steps;
}

function calculateQuantumScore(libraries, classifications) {
  if (libraries.length === 0) return 100.0;
  if (classifications.length === 0) return 100.0;

  // Score by individual algorithm classifications, not library count.
  // A project with 5 symmetric + 1 asymmetric algorithm is mostly ready, not 0%.
  const safe = classifications.filter(
    c => c.category !== 'asymmetric' || c.category === 'pqc'
  ).length;
  const vulnerable = classifications.filter(
    c => c.category === 'asymmetric'
  ).length;
  const total = safe + vulnerable;

  if (total === 0) return 100.0;

  // Two scoring approaches:
  // - Ratio: safe / total (good for large samples)
  // - Penalty: 100 - 30 per vulnerable (good for small samples)
  // Small samples (≤3 algorithms) produce extreme ratios (1/1 = 0% or 100%),
  // so use whichever approach gives the more representative score.
  const ratioScore = (safe / total) * 100;
  const penaltyScore = Math.max(0, 100 - vulnerable * 30);
  let score = total <= 3 ? Math.max(ratioScore, penaltyScore) : ratioScore;

  if (classifications.some(c => c.category === 'pqc')) {
    score = Math.min(100, score + 20);
  }
  const deprecatedCount = libraries.filter(lib => lib.isDeprecated).length;
  if (deprecatedCount > 0) {
    score = Math.max(0, score - deprecatedCount * 10);
  }

  return Math.round(score * 10) / 10;
}

function getComplianceReferences(urgency) {
  const refs = [];
  const allKeys = ['cnsa_2_0', 'nist_sp_800_208', 'bsi', 'anssi'];
  const mediumKeys = ['cnsa_2_0', 'bsi'];

  const keys = ['critical', 'high'].includes(urgency) ? allKeys
    : urgency === 'medium' ? mediumKeys
    : [];

  for (const key of keys) {
    const fw = COMPLIANCE_FRAMEWORKS[key];
    const detail = fw.kem || fw.sig || fw.note || '';
    refs.push({ framework: fw.name, authority: fw.authority, detail });
  }

  return refs;
}

function generateFindings(libraries, classifications, sndl, profile) {
  const findings = [];

  const vulnerableCount = libraries.filter(
    lib => lib.quantumRisk === 'high' || lib.quantumRisk === 'critical'
  ).length;
  if (vulnerableCount > 0) {
    findings.push(`Found ${vulnerableCount} quantum-vulnerable libraries`);
  }

  const deprecatedCount = libraries.filter(lib => lib.isDeprecated).length;
  if (deprecatedCount > 0) {
    findings.push(`Found ${deprecatedCount} deprecated libraries requiring immediate attention`);
  }

  findings.push(
    `Data profile '${profile.name}' requires ${profile.lifespanYears}-year protection`
  );

  if (sndl.vulnerable) {
    findings.push('SNDL risk: Data may be decryptable before confidentiality period expires');
  }

  if (classifications.some(c => c.category === 'pqc')) {
    findings.push('Post-quantum cryptography already in use');
  } else {
    findings.push('No post-quantum cryptography detected');
  }

  return findings;
}

function generateNextSteps(urgency, migrationPlan, sndl) {
  const steps = [];

  if (migrationPlan.length > 0) {
    steps.push(`Priority: ${migrationPlan[0].action}`);
  }

  if (urgency === 'critical') {
    steps.push('Deploy hybrid crypto (X25519Kyber768) within 90 days');
    steps.push('Identify and re-encrypt sensitive long-term data');
  } else if (urgency === 'high') {
    steps.push('Begin PQC pilot project within 6 months');
    steps.push('Evaluate liboqs or @noble/post-quantum for Node.js integration');
  } else if (urgency === 'medium') {
    steps.push('Include PQC migration in next architecture review');
    steps.push('Train development team on PQC concepts');
  } else {
    steps.push('Monitor NIST PQC standardization updates');
    steps.push('Evaluate crypto agility improvements');
  }

  return steps;
}

function buildThreatTimelines(classifications) {
  const timelines = {};
  for (const c of classifications) {
    const key = c.timelineKey;
    if (key && key in QUANTUM_THREAT_TIMELINE && !(key in timelines)) {
      const t = QUANTUM_THREAT_TIMELINE[key];
      timelines[key] = {
        algorithm: c.algo,
        timelineKey: key,
        minYears: t.min,
        medianYears: t.median,
        maxYears: t.max,
        status: t.median <= 25 ? 'AT RISK' : 'SAFE',
        category: c.category,
      };
    }
  }
  return timelines;
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Confidence calculation
// ---------------------------------------------------------------------------

function calculateConfidence(libraries, classifications, scanMeta = {}) {
  const algorithmsFound = classifications.length;
  const languagesScanned = scanMeta.languagesDetected?.length || 0;
  const filesScanned = scanMeta.filesScanned || 0;
  const manifestsFound = scanMeta.manifestsFound?.length || 0;

  let score = 0;

  // Algorithms contribute up to 40 points
  if (algorithmsFound >= 10) score += 40;
  else if (algorithmsFound >= 5) score += 30;
  else if (algorithmsFound >= 3) score += 20;
  else if (algorithmsFound >= 1) score += 10;

  // Manifests contribute up to 25 points
  if (manifestsFound >= 3) score += 25;
  else if (manifestsFound >= 2) score += 20;
  else if (manifestsFound >= 1) score += 15;

  // Files scanned contribute up to 20 points
  if (filesScanned >= 100) score += 20;
  else if (filesScanned >= 50) score += 15;
  else if (filesScanned >= 20) score += 10;
  else if (filesScanned >= 5) score += 5;

  // Languages contribute up to 15 points
  if (languagesScanned >= 3) score += 15;
  else if (languagesScanned >= 2) score += 10;
  else if (languagesScanned >= 1) score += 5;

  let level;
  if (score >= 70) level = 'high';
  else if (score >= 40) level = 'medium';
  else level = 'low';

  const parts = [];
  if (algorithmsFound > 0) parts.push(`${algorithmsFound} algorithms found`);
  if (languagesScanned > 0) parts.push(`${languagesScanned} languages`);
  if (filesScanned > 0) parts.push(`${filesScanned} files`);
  if (manifestsFound > 0) parts.push(`${manifestsFound} manifests`);

  return {
    level,
    score,
    reason: parts.join(', ') || 'no data scanned',
    algorithmsFound,
    languagesScanned,
    filesScanned,
    manifestsFound,
  };
}

// ---------------------------------------------------------------------------
// Migration urgency mapping
// ---------------------------------------------------------------------------

function getMigrationUrgency(riskLevel) {
  switch (riskLevel) {
    case 'critical': return 'immediate';
    case 'high':     return 'high';
    case 'medium':   return 'medium';
    case 'low':      return 'low';
    default:         return 'none';
  }
}

// ---------------------------------------------------------------------------
// Risk breakdown
// ---------------------------------------------------------------------------

function getRiskBreakdown(classifications) {
  const breakdown = { critical: 0, high: 0, medium: 0, low: 0, none: 0 };

  for (const c of classifications) {
    // Use algorithm-db for per-algorithm risk if available
    const dbEntry = lookupAlgorithm(c.algo);
    if (dbEntry) {
      const risk = dbEntry.quantumRisk || 'none';
      if (risk in breakdown) breakdown[risk]++;
      else breakdown.none++;
    } else if (c.category === 'pqc') {
      breakdown.none++;
    } else if (c.category === 'asymmetric') {
      breakdown.high++;
    } else {
      breakdown.low++;
    }
  }

  return breakdown;
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

export function analyzeOffline(libraries, dataProfile = null, scanMeta = {}) {
  const profileKey = dataProfile || 'general';
  const profile = DATA_PROFILES[profileKey] || DATA_PROFILES.general;

  const classifications = classifyAlgorithms(libraries);
  const sndl = assessSndl(classifications, profile, libraries);
  const kemRecs = recommendKem(classifications, profile, libraries);
  const sigRecs = recommendSignatures(classifications, profile, libraries);
  const migrationPlan = generateMigrationPlan(libraries, classifications, sndl);
  const quantumScore = calculateQuantumScore(libraries, classifications);

  const urgency = sndl.riskLevel;
  const complianceRefs = getComplianceReferences(urgency);
  const findings = generateFindings(libraries, classifications, sndl, profile);
  const nextSteps = generateNextSteps(urgency, migrationPlan, sndl);
  const threatTimelines = buildThreatTimelines(classifications);

  // New in v0.2.0
  const confidence = calculateConfidence(libraries, classifications, scanMeta);
  const migrationUrgency = getMigrationUrgency(urgency);
  const riskBreakdown = getRiskBreakdown(classifications);

  return {
    generatedAt: new Date().toISOString(),
    analysisMode: 'offline',
    sndlAssessment: sndl,
    kemRecommendations: kemRecs,
    signatureRecommendations: sigRecs,
    migrationPlan,
    overallUrgency: urgency,
    migrationUrgency,
    quantumReadinessScore: quantumScore,
    confidence,
    riskBreakdown,
    keyFindings: findings,
    nextSteps,
    complianceReferences: complianceRefs,
    threatTimelines,
    dataProfile: {
      key: profileKey,
      name: profile.name,
      lifespanYears: profile.lifespanYears,
      urgency: profile.urgency,
    },
  };
}

export { classifyAlgorithms, assessSndl, calculateQuantumScore };
