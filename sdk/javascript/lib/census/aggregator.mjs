/**
 * Aggregate raw census data into headline metrics.
 */

import { TIERS } from './package-catalog.mjs';

// NIST Post-Quantum Cryptography deadlines
const NIST_2030 = new Date('2030-01-01T00:00:00Z');
const NIST_2035 = new Date('2035-01-01T00:00:00Z');

/**
 * Sum downloads for a given tier from a packages array.
 */
function sumByTier(packages, tier) {
  return packages
    .filter(p => p.tier === tier)
    .reduce((sum, p) => sum + p.downloads, 0);
}

/**
 * Get top N packages sorted by downloads descending.
 */
function topPackages(packages, n = 10) {
  return [...packages]
    .sort((a, b) => b.downloads - a.downloads)
    .slice(0, n);
}

/**
 * Calculate days remaining until a target date.
 */
function daysUntil(target) {
  const now = new Date();
  const diff = target.getTime() - now.getTime();
  return Math.max(0, Math.ceil(diff / (1000 * 60 * 60 * 24)));
}

/**
 * Format days as "X yrs, Y days".
 */
function formatDaysRemaining(totalDays) {
  const years = Math.floor(totalDays / 365);
  const days = totalDays % 365;
  if (years === 0) return `${days} days`;
  return `${years} yr${years !== 1 ? 's' : ''}, ${days} days`;
}

/**
 * Format a large number with suffix (M, K).
 */
export function formatNumber(n) {
  if (n >= 1_000_000_000) return (n / 1_000_000_000).toFixed(1) + 'B';
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
  if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K';
  return String(n);
}

/**
 * Aggregate all census data into headline metrics.
 *
 * @param {Object} data
 * @param {Object} data.npm - Result from collectNpmDownloads
 * @param {Object} data.pypi - Result from collectPypiDownloads
 * @param {Object} [data.nvd] - Result from collectNvdCves
 * @param {Object} [data.github] - Result from collectGithubAdvisories
 * @returns {Object} Aggregated metrics
 */
export function aggregate(data) {
  const npmPkgs = data.npm?.packages || [];
  const pypiPkgs = data.pypi?.packages || [];
  const allPkgs = [...npmPkgs, ...pypiPkgs];

  // Download totals by tier
  const totalWeakDownloads = sumByTier(allPkgs, TIERS.WEAK);
  const totalModernDownloads = sumByTier(allPkgs, TIERS.MODERN);
  const totalPqcDownloads = sumByTier(allPkgs, TIERS.PQC);
  const totalDownloads = totalWeakDownloads + totalModernDownloads + totalPqcDownloads;

  // Percentages
  const weakPercentage = totalDownloads > 0 ? (totalWeakDownloads / totalDownloads * 100) : 0;
  const modernPercentage = totalDownloads > 0 ? (totalModernDownloads / totalDownloads * 100) : 0;
  const pqcPercentage = totalDownloads > 0 ? (totalPqcDownloads / totalDownloads * 100) : 0;

  // The headline ratio
  const weakToPqcRatio = totalPqcDownloads > 0
    ? Math.round(totalWeakDownloads / totalPqcDownloads)
    : null;

  // Per-ecosystem breakdowns
  const npmWeak = sumByTier(npmPkgs, TIERS.WEAK);
  const npmModern = sumByTier(npmPkgs, TIERS.MODERN);
  const npmPqc = sumByTier(npmPkgs, TIERS.PQC);
  const pypiWeak = sumByTier(pypiPkgs, TIERS.WEAK);
  const pypiModern = sumByTier(pypiPkgs, TIERS.MODERN);
  const pypiPqc = sumByTier(pypiPkgs, TIERS.PQC);

  // CVE totals
  const nvdCves = data.nvd?.cves || [];
  const totalCryptoCves = nvdCves.reduce((sum, c) => sum + c.totalCount, 0);

  // GitHub advisories
  const ghAdvisories = data.github?.advisories || [];
  const totalAdvisories = ghAdvisories.reduce((sum, a) => sum + a.count, 0);

  // Merge severity counts across CWEs
  const advisorySeverity = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const adv of ghAdvisories) {
    for (const [sev, count] of Object.entries(adv.bySeverity || {})) {
      advisorySeverity[sev] = (advisorySeverity[sev] || 0) + count;
    }
  }

  // NIST deadlines
  const nistDeadline2030Days = daysUntil(NIST_2030);
  const nistDeadline2035Days = daysUntil(NIST_2035);

  return {
    // Headline numbers
    totalDownloads,
    totalWeakDownloads,
    totalModernDownloads,
    totalPqcDownloads,
    weakPercentage,
    modernPercentage,
    pqcPercentage,
    weakToPqcRatio,

    // Per-ecosystem
    npm: {
      weak: npmWeak, modern: npmModern, pqc: npmPqc,
      total: npmWeak + npmModern + npmPqc,
      topPackages: topPackages(npmPkgs, 15),
      period: data.npm?.period,
    },
    pypi: {
      weak: pypiWeak, modern: pypiModern, pqc: pypiPqc,
      total: pypiWeak + pypiModern + pypiPqc,
      topPackages: topPackages(pypiPkgs, 15),
      period: data.pypi?.period,
    },

    // Vulnerabilities
    totalCryptoCves,
    cveBreakdown: nvdCves,
    totalAdvisories,
    advisorySeverity,
    advisoryBreakdown: ghAdvisories,

    // Deadlines
    nistDeadline2030: formatDaysRemaining(nistDeadline2030Days),
    nistDeadline2030Days,
    nistDeadline2035: formatDaysRemaining(nistDeadline2035Days),
    nistDeadline2035Days,

    // Metadata
    collectedAt: data.npm?.collectedAt || data.pypi?.collectedAt || new Date().toISOString(),
  };
}
