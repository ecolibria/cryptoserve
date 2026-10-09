import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeOffline, DATA_PROFILES, classifyAlgorithms, calculateQuantumScore, scoreContributors } from '../lib/pqc-engine.mjs';

const SAMPLE_LIBRARIES = [
  { name: 'jsonwebtoken', version: '9.0.0', algorithms: ['RS256', 'HS256'], quantumRisk: 'high', category: 'token' },
  { name: 'node:crypto', version: 'builtin', algorithms: ['AES-256-GCM', 'SHA-256'], quantumRisk: 'low', category: 'symmetric' },
];

describe('analyzeOffline', () => {
  it('returns valid result for general profile', () => {
    const result = analyzeOffline(SAMPLE_LIBRARIES, 'general');
    assert.ok(result.generatedAt);
    assert.equal(result.analysisMode, 'offline');
    assert.equal(result.dataProfile.key, 'general');
    assert.ok(typeof result.quantumReadinessScore === 'number');
    assert.ok(result.quantumReadinessScore >= 0 && result.quantumReadinessScore <= 100);
  });

  for (const profileKey of Object.keys(DATA_PROFILES)) {
    it(`returns valid result for ${profileKey} profile`, () => {
      const result = analyzeOffline(SAMPLE_LIBRARIES, profileKey);
      assert.ok(result.dataProfile.name);
      assert.ok(typeof result.quantumReadinessScore === 'number');
      assert.ok(result.quantumReadinessScore >= 0 && result.quantumReadinessScore <= 100);
      assert.ok(['critical', 'high', 'medium', 'low'].includes(result.overallUrgency));
    });
  }

  it('short_lived alias works', () => {
    const result = analyzeOffline([], 'short_lived');
    assert.equal(result.dataProfile.name, 'Session Tokens');
    assert.equal(result.dataProfile.lifespanYears, 0);
  });

  it('falls back to general for unknown profile', () => {
    const result = analyzeOffline([], 'nonexistent');
    assert.equal(result.dataProfile.name, 'Personal Data / General');
  });

  it('returns 100 score for empty libraries', () => {
    const result = analyzeOffline([], 'general');
    assert.equal(result.quantumReadinessScore, 100);
  });

  it('generates migration plan with at least 1 step', () => {
    const result = analyzeOffline(SAMPLE_LIBRARIES, 'healthcare');
    assert.ok(result.migrationPlan.length >= 1);
  });

  it('returns compliance refs for critical urgency', () => {
    const result = analyzeOffline(SAMPLE_LIBRARIES, 'national_security');
    assert.ok(result.complianceReferences.length > 0);
  });

  it('returns no compliance refs for low urgency', () => {
    const result = analyzeOffline([], 'session_tokens');
    assert.equal(result.complianceReferences.length, 0);
  });

  it('detects SNDL risk for healthcare with asymmetric crypto', () => {
    const libs = [
      { name: 'rsa-lib', version: '1.0', algorithms: ['RSA'], quantumRisk: 'high', category: 'asymmetric' },
    ];
    const result = analyzeOffline(libs, 'healthcare');
    assert.equal(result.sndlAssessment.vulnerable, true);
    assert.equal(result.overallUrgency, 'critical');
  });
});

describe('classifyAlgorithms', () => {
  it('classifies RSA as asymmetric', () => {
    const libs = [{ algorithms: ['RSA-2048'] }];
    const result = classifyAlgorithms(libs);
    assert.equal(result[0].category, 'asymmetric');
    assert.equal(result[0].timelineKey, 'rsa_2048');
  });

  it('classifies AES as symmetric', () => {
    const libs = [{ algorithms: ['AES-256-GCM'] }];
    const result = classifyAlgorithms(libs);
    assert.equal(result[0].category, 'symmetric');
  });

  it('classifies ML-KEM as pqc', () => {
    const libs = [{ algorithms: ['ML-KEM-768'] }];
    const result = classifyAlgorithms(libs);
    assert.equal(result[0].category, 'pqc');
    assert.equal(result[0].timelineKey, 'pqc');
  });

  it('deduplicates algorithms', () => {
    const libs = [
      { algorithms: ['RSA'] },
      { algorithms: ['RSA'] },
    ];
    const result = classifyAlgorithms(libs);
    assert.equal(result.length, 1);
  });
});

describe('calculateQuantumScore', () => {
  it('returns 100 for no libraries', () => {
    assert.equal(calculateQuantumScore([], []), 100);
  });

  it('returns lower score for vulnerable classifications', () => {
    const libs = [{ quantumRisk: 'high' }, { quantumRisk: 'low' }];
    const classifications = [
      { category: 'asymmetric' },
      { category: 'asymmetric' },
      { category: 'symmetric' },
    ];
    const score = calculateQuantumScore(libs, classifications);
    assert.ok(score < 100, `expected score < 100, got ${score}`);
    assert.ok(score > 0, `expected score > 0, got ${score}`);
  });

  it('returns high score when only symmetric algorithms found', () => {
    const libs = [{ quantumRisk: 'low' }];
    const classifications = [
      { category: 'symmetric' },
      { category: 'hash' },
    ];
    const score = calculateQuantumScore(libs, classifications);
    assert.equal(score, 100);
  });

  it('does not produce 0% for single asymmetric algorithm', () => {
    const libs = [{ quantumRisk: 'high' }];
    const classifications = [{ category: 'asymmetric' }];
    const score = calculateQuantumScore(libs, classifications);
    assert.ok(score > 0, `expected score > 0 for 1 algo, got ${score}`);
    assert.ok(score < 100, `expected score < 100, got ${score}`);
  });

  it('decreases score as more vulnerable algorithms are found', () => {
    const libs = [{ quantumRisk: 'high' }];
    const score1 = calculateQuantumScore(libs, [{ category: 'asymmetric' }]);
    const score2 = calculateQuantumScore(libs, [{ category: 'asymmetric' }, { category: 'asymmetric' }]);
    const score3 = calculateQuantumScore(libs, [
      { category: 'asymmetric' }, { category: 'asymmetric' },
      { category: 'asymmetric' }, { category: 'asymmetric' },
    ]);
    assert.ok(score1 > score2, `1 vuln (${score1}) should score higher than 2 (${score2})`);
    assert.ok(score2 > score3, `2 vuln (${score2}) should score higher than 4 (${score3})`);
  });

  it('boosts score when PQC is present', () => {
    const libs = [{ quantumRisk: 'high' }];
    const withoutPqc = calculateQuantumScore(libs, [
      { category: 'asymmetric' },
      { category: 'symmetric' },
      { category: 'symmetric' },
      { category: 'symmetric' },
    ]);
    const withPqc = calculateQuantumScore(libs, [
      { category: 'asymmetric' },
      { category: 'symmetric' },
      { category: 'symmetric' },
      { category: 'symmetric' },
      { category: 'pqc' },
    ]);
    assert.ok(withPqc > withoutPqc, `expected ${withPqc} > ${withoutPqc}`);
  });
});

describe('scoreContributors', () => {
  const score = (libs) => calculateQuantumScore(libs, classifyAlgorithms(libs));
  const JOSE = { name: 'jose', version: '^5.3.0', algorithms: ['RS256', 'ES256', 'EdDSA', 'AES-GCM'] };

  it('names the library holding the score down and the quantum-vulnerable algorithms it uses', () => {
    const [jose, ...rest] = scoreContributors([JOSE]);
    assert.deepEqual(rest, []);
    assert.equal(jose.library, 'jose');
    assert.deepEqual(jose.algorithms, ['RS256', 'ES256', 'EdDSA']);
    assert.equal(jose.deprecated, false);
  });

  it('measures the recoverable points by scoring without that library\'s contribution', () => {
    const libs = [JOSE, { name: 'node:crypto', algorithms: ['AES-256-GCM', 'SHA-256'] }];
    const [jose] = scoreContributors(libs);
    const without = [{ ...JOSE, algorithms: ['AES-GCM'] }, libs[1]];
    assert.ok(jose.recoverable > 0, JSON.stringify(jose));
    assert.equal(jose.recoverable, Math.round((score(without) - score(libs)) * 10) / 10);
  });

  it('does not list a library that costs the score nothing', () => {
    const libs = [JOSE, { name: 'node:crypto', algorithms: ['AES-256-GCM', 'SHA-256'] }];
    assert.deepEqual(scoreContributors(libs).map(c => c.library), ['jose']);
  });

  it('lists a deprecated library by the points its deprecation costs', () => {
    const libs = [{ name: 'crypto-js', algorithms: ['AES-256-GCM', 'SHA-256'], isDeprecated: true }];
    assert.deepEqual(scoreContributors(libs), [
      { library: 'crypto-js', algorithms: [], deprecated: true, recoverable: 100 - score(libs) },
    ]);
  });

  it('still names both libraries that share an algorithm, though neither moves the score alone', () => {
    const libs = [
      { name: 'jsonwebtoken', algorithms: ['RS256', 'HS256'] },
      { name: 'node-jose', algorithms: ['RS256', 'AES-256-GCM'] },
    ];
    const contributors = scoreContributors(libs);
    assert.deepEqual(contributors.map(c => c.library), ['jsonwebtoken', 'node-jose']);
    for (const c of contributors) {
      assert.deepEqual(c.algorithms, ['RS256']);
      assert.equal(c.recoverable, 0, JSON.stringify(c));
    }
  });

  it('orders contributors by points recoverable, most first', () => {
    const libs = [
      { name: 'one', algorithms: ['RS256'] },
      { name: 'two', algorithms: ['ES256', 'EdDSA'] },
      { name: 'safe', algorithms: ['AES-256-GCM', 'SHA-256', 'SHA-512'] },
    ];
    const contributors = scoreContributors(libs);
    assert.deepEqual(contributors.map(c => c.library), ['two', 'one']);
    assert.ok(contributors[0].recoverable > contributors[1].recoverable, JSON.stringify(contributors));
  });

  it('leaves the inventory it was given untouched', () => {
    const libs = [structuredClone(JOSE)];
    scoreContributors(libs);
    assert.deepEqual(libs, [JOSE]);
  });
});
