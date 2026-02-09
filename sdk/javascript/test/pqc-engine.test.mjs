import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeOffline, DATA_PROFILES, classifyAlgorithms, calculateQuantumScore } from '../lib/pqc-engine.mjs';

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

  it('returns lower score for vulnerable libraries', () => {
    const libs = [
      { quantumRisk: 'high' },
      { quantumRisk: 'high' },
      { quantumRisk: 'low' },
    ];
    const score = calculateQuantumScore(libs, []);
    assert.ok(score < 100);
    assert.ok(score > 0);
  });

  it('boosts score when PQC is present', () => {
    const libs = [{ quantumRisk: 'high' }, { quantumRisk: 'low' }];
    const withoutPqc = calculateQuantumScore(libs, []);
    const withPqc = calculateQuantumScore(libs, [{ category: 'pqc' }]);
    assert.ok(withPqc > withoutPqc);
  });
});
