import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { NPM_PACKAGES, PYPI_PACKAGES, TIERS, getPackages, getNamesByTier } from '../lib/census/package-catalog.mjs';
import { collectNpmDownloads } from '../lib/census/collectors/npm-downloads.mjs';
import { collectPypiDownloads } from '../lib/census/collectors/pypi-downloads.mjs';
import { collectNvdCves } from '../lib/census/collectors/nvd-cves.mjs';
import { collectGithubAdvisories } from '../lib/census/collectors/github-advisories.mjs';
import { aggregate, formatNumber } from '../lib/census/aggregator.mjs';

// ---------------------------------------------------------------------------
// Package Catalog
// ---------------------------------------------------------------------------

describe('package-catalog', () => {
  it('has npm packages in all three tiers', () => {
    const tiers = new Set(NPM_PACKAGES.map(p => p.tier));
    assert.ok(tiers.has(TIERS.WEAK));
    assert.ok(tiers.has(TIERS.MODERN));
    assert.ok(tiers.has(TIERS.PQC));
  });

  it('has pypi packages in all three tiers', () => {
    const tiers = new Set(PYPI_PACKAGES.map(p => p.tier));
    assert.ok(tiers.has(TIERS.WEAK));
    assert.ok(tiers.has(TIERS.MODERN));
    assert.ok(tiers.has(TIERS.PQC));
  });

  it('getPackages returns correct ecosystem', () => {
    assert.deepStrictEqual(getPackages('npm'), NPM_PACKAGES);
    assert.deepStrictEqual(getPackages('pypi'), PYPI_PACKAGES);
  });

  it('getNamesByTier filters correctly', () => {
    const weakNpm = getNamesByTier('npm', TIERS.WEAK);
    assert.ok(weakNpm.includes('md5'));
    assert.ok(weakNpm.includes('crypto-js'));
    assert.ok(!weakNpm.includes('@noble/curves'));
  });

  it('every entry has required fields', () => {
    for (const pkg of [...NPM_PACKAGES, ...PYPI_PACKAGES]) {
      assert.ok(pkg.name, `missing name`);
      assert.ok(Object.values(TIERS).includes(pkg.tier), `invalid tier: ${pkg.tier}`);
      assert.ok(Array.isArray(pkg.algorithms), `${pkg.name} missing algorithms`);
      assert.ok(typeof pkg.note === 'string', `${pkg.name} missing note`);
    }
  });
});

// ---------------------------------------------------------------------------
// Mock fetch factory
// ---------------------------------------------------------------------------

function createMockFetch(responseMap) {
  return async (url, _opts) => {
    for (const [pattern, response] of Object.entries(responseMap)) {
      if (url.includes(pattern)) {
        return {
          ok: true,
          status: 200,
          json: async () => response,
          headers: { get: () => null },
        };
      }
    }
    return { ok: false, status: 404, json: async () => ({}), headers: { get: () => null } };
  };
}

// ---------------------------------------------------------------------------
// npm Collector
// ---------------------------------------------------------------------------

describe('npm-downloads collector', () => {
  it('collects download counts from mocked API', async () => {
    const mockFetch = createMockFetch({
      'api.npmjs.org/downloads': {
        'crypto-js': { downloads: 53_900_000, start: '2026-01-01', end: '2026-01-31', package: 'crypto-js' },
        'md5': { downloads: 2_100_000, start: '2026-01-01', end: '2026-01-31', package: 'md5' },
      },
    });

    const packages = [
      { name: 'crypto-js', tier: 'weak', algorithms: [], note: '' },
      { name: 'md5', tier: 'weak', algorithms: [], note: '' },
    ];

    const result = await collectNpmDownloads(packages, { fetchFn: mockFetch });
    assert.equal(result.packages.length, 2);
    assert.equal(result.packages[0].downloads, 53_900_000);
    assert.ok(result.collectedAt);
  });

  it('handles API errors gracefully', async () => {
    const mockFetch = async () => ({ ok: false, status: 503, json: async () => ({}), headers: { get: () => null } });

    const packages = [{ name: 'fake-pkg', tier: 'weak', algorithms: [], note: '' }];
    const result = await collectNpmDownloads(packages, { fetchFn: mockFetch });
    assert.equal(result.packages.length, 1);
    assert.equal(result.packages[0].downloads, 0);
  });
});

// ---------------------------------------------------------------------------
// PyPI Collector
// ---------------------------------------------------------------------------

describe('pypi-downloads collector', () => {
  it('collects download counts from mocked API', async () => {
    const mockFetch = createMockFetch({
      'pypistats.org/api/packages/cryptography': {
        data: { last_month: 250_000_000, last_week: 60_000_000, last_day: 8_000_000 },
      },
      'pypistats.org/api/packages/pycrypto': {
        data: { last_month: 500_000, last_week: 100_000, last_day: 15_000 },
      },
    });

    const packages = [
      { name: 'cryptography', tier: 'modern', algorithms: [], note: '' },
      { name: 'pycrypto', tier: 'weak', algorithms: [], note: '' },
    ];

    const result = await collectPypiDownloads(packages, { fetchFn: mockFetch });
    assert.equal(result.packages.length, 2);
    const crypto = result.packages.find(p => p.name === 'cryptography');
    assert.equal(crypto.downloads, 250_000_000);
  });
});

// ---------------------------------------------------------------------------
// NVD Collector
// ---------------------------------------------------------------------------

describe('nvd-cves collector', () => {
  it('collects CVE counts from mocked API', async () => {
    const mockFetch = createMockFetch({
      'cweId=CWE-327': { totalResults: 523 },
      'cweId=CWE-326': { totalResults: 187 },
      'cweId=CWE-328': { totalResults: 89 },
    });

    const result = await collectNvdCves({ fetchFn: mockFetch });
    assert.equal(result.cves.length, 3);
    assert.equal(result.cves[0].totalCount, 523);
    assert.equal(result.cves[0].cweId, 'CWE-327');
  });
});

// ---------------------------------------------------------------------------
// GitHub Advisories Collector
// ---------------------------------------------------------------------------

describe('github-advisories collector', () => {
  it('collects and filters crypto-related advisories', async () => {
    const mockFetch = async (url, _opts) => ({
      ok: true,
      status: 200,
      json: async () => [
        { severity: 'high', cwes: [{ cwe_id: 'CWE-327', name: 'Broken Crypto' }], vulnerabilities: [{ package: { ecosystem: 'npm' } }] },
        { severity: 'critical', cwes: [{ cwe_id: 'CWE-326', name: 'Inadequate Encryption' }], vulnerabilities: [{ package: { ecosystem: 'pip' } }] },
        { severity: 'low', cwes: [{ cwe_id: 'CWE-79', name: 'XSS' }], vulnerabilities: [] }, // non-crypto, should be filtered out
        { severity: 'medium', cwes: [{ cwe_id: 'CWE-328', name: 'Weak Hash' }], vulnerabilities: [{ package: { ecosystem: 'npm' } }] },
      ],
      headers: { get: () => null }, // no next page
    });

    const result = await collectGithubAdvisories({ fetchFn: mockFetch });
    assert.equal(result.advisories.length, 3);
    const cwe327 = result.advisories.find(a => a.cweId === 'CWE-327');
    assert.equal(cwe327.count, 1);
    assert.equal(cwe327.bySeverity.high, 1);
    const cwe326 = result.advisories.find(a => a.cweId === 'CWE-326');
    assert.equal(cwe326.count, 1);
    assert.equal(cwe326.bySeverity.critical, 1);
    const cwe328 = result.advisories.find(a => a.cweId === 'CWE-328');
    assert.equal(cwe328.count, 1);
  });
});

// ---------------------------------------------------------------------------
// Aggregator
// ---------------------------------------------------------------------------

describe('aggregator', () => {
  const mockData = {
    npm: {
      packages: [
        { name: 'crypto-js', downloads: 50_000_000, tier: 'weak' },
        { name: 'md5', downloads: 2_000_000, tier: 'weak' },
        { name: '@noble/curves', downloads: 10_000_000, tier: 'modern' },
        { name: '@noble/post-quantum', downloads: 1_000, tier: 'pqc' },
      ],
      period: { start: '2026-01-01', end: '2026-01-31' },
      collectedAt: '2026-01-31T00:00:00Z',
    },
    pypi: {
      packages: [
        { name: 'pycrypto', downloads: 500_000, tier: 'weak' },
        { name: 'cryptography', downloads: 200_000_000, tier: 'modern' },
        { name: 'liboqs-python', downloads: 500, tier: 'pqc' },
      ],
      period: 'last_month',
      collectedAt: '2026-01-31T00:00:00Z',
    },
    nvd: {
      cves: [
        { cweId: 'CWE-327', cweName: 'Broken Crypto', totalCount: 500 },
        { cweId: 'CWE-326', cweName: 'Inadequate Encryption', totalCount: 200 },
        { cweId: 'CWE-328', cweName: 'Weak Hash', totalCount: 100 },
      ],
      collectedAt: '2026-01-31T00:00:00Z',
    },
    github: {
      advisories: [
        { cweId: 'CWE-327', count: 50, bySeverity: { critical: 5, high: 20, medium: 15, low: 10, unknown: 0 }, byEcosystem: { npm: 30, pip: 20 } },
      ],
      collectedAt: '2026-01-31T00:00:00Z',
    },
  };

  it('computes total downloads by tier', () => {
    const result = aggregate(mockData);
    assert.equal(result.totalWeakDownloads, 52_500_000);
    assert.equal(result.totalModernDownloads, 210_000_000);
    assert.equal(result.totalPqcDownloads, 1_500);
  });

  it('computes weak-to-pqc ratio', () => {
    const result = aggregate(mockData);
    assert.equal(result.weakToPqcRatio, 35_000);
  });

  it('computes percentages', () => {
    const result = aggregate(mockData);
    assert.ok(result.weakPercentage > 0);
    assert.ok(result.modernPercentage > 0);
    assert.ok(result.pqcPercentage >= 0);
    const total = result.weakPercentage + result.modernPercentage + result.pqcPercentage;
    assert.ok(Math.abs(total - 100) < 0.1);
  });

  it('computes CVE totals', () => {
    const result = aggregate(mockData);
    assert.equal(result.totalCryptoCves, 800);
  });

  it('computes advisory severity totals', () => {
    const result = aggregate(mockData);
    assert.equal(result.advisorySeverity.critical, 5);
    assert.equal(result.advisorySeverity.high, 20);
  });

  it('includes NIST deadline info', () => {
    const result = aggregate(mockData);
    assert.ok(result.nistDeadline2030Days > 0);
    assert.ok(result.nistDeadline2035Days > 0);
    assert.ok(result.nistDeadline2030.includes('yr'));
  });

  it('handles null pqc downloads gracefully', () => {
    const noPqc = {
      npm: { packages: [{ name: 'md5', downloads: 1000, tier: 'weak' }], period: {}, collectedAt: '' },
      pypi: { packages: [], period: '', collectedAt: '' },
    };
    const result = aggregate(noPqc);
    assert.equal(result.weakToPqcRatio, null);
  });

  it('produces per-ecosystem breakdowns', () => {
    const result = aggregate(mockData);
    assert.equal(result.npm.weak, 52_000_000);
    assert.equal(result.npm.pqc, 1_000);
    assert.equal(result.pypi.modern, 200_000_000);
  });
});

// ---------------------------------------------------------------------------
// formatNumber
// ---------------------------------------------------------------------------

describe('formatNumber', () => {
  it('formats millions', () => {
    assert.equal(formatNumber(53_900_000), '53.9M');
  });

  it('formats thousands', () => {
    assert.equal(formatNumber(1_500), '1.5K');
  });

  it('formats small numbers', () => {
    assert.equal(formatNumber(42), '42');
  });

  it('formats billions', () => {
    assert.equal(formatNumber(1_200_000_000), '1.2B');
  });
});
