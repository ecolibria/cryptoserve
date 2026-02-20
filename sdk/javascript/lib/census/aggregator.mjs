/**
 * Aggregate raw census data into headline metrics.
 *
 * Supports all 11 ecosystems: npm, PyPI, Go, Maven, crates.io, Packagist, NuGet,
 * RubyGems, Hex (Elixir), pub.dev (Dart), and CocoaPods (Swift/ObjC).
 * Includes project-level transparency stats when available.
 */

import { TIERS, CATEGORIES, getCatalogSize } from './package-catalog.mjs';

// NIST Post-Quantum Cryptography deadlines
const NIST_2030 = new Date('2030-01-01T00:00:00Z');
const NIST_2035 = new Date('2035-01-01T00:00:00Z');

const ECOSYSTEM_IDS = ['npm', 'pypi', 'go', 'maven', 'crates', 'packagist', 'nuget', 'rubygems', 'hex', 'pub', 'cocoapods'];

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
 * Build a per-ecosystem breakdown from a packages array.
 */
function buildEcosystemBreakdown(pkgs, period) {
  const weak = sumByTier(pkgs, TIERS.WEAK);
  const modern = sumByTier(pkgs, TIERS.MODERN);
  const pqc = sumByTier(pkgs, TIERS.PQC);
  return {
    weak,
    modern,
    pqc,
    total: weak + modern + pqc,
    topPackages: topPackages(pkgs, 15),
    period,
  };
}

/**
 * Build per-category breakdown across all packages.
 * Groups packages by category and computes weak/modern/pqc totals + weak percentage.
 */
function buildCategoryBreakdown(allPkgs) {
  const categoryMap = {};
  for (const cat of CATEGORIES) {
    categoryMap[cat] = { category: cat, weak: 0, modern: 0, pqc: 0, total: 0, weakPercentage: 0, topPackages: [] };
  }

  for (const pkg of allPkgs) {
    const cat = pkg.category || 'general';
    const entry = categoryMap[cat];
    if (!entry) continue;

    const dl = pkg.downloads || 0;
    if (pkg.tier === TIERS.WEAK) entry.weak += dl;
    else if (pkg.tier === TIERS.PQC) entry.pqc += dl;
    else entry.modern += dl;

    entry.total += dl;
    entry.topPackages.push(pkg);
  }

  // Compute weak percentage and sort top packages
  const result = [];
  for (const cat of CATEGORIES) {
    const entry = categoryMap[cat];
    entry.weakPercentage = entry.total > 0
      ? Math.round((entry.weak / entry.total) * 1000) / 10
      : 0;
    entry.topPackages = entry.topPackages
      .sort((a, b) => b.downloads - a.downloads)
      .slice(0, 10);
    if (entry.total > 0) {
      result.push(entry);
    }
  }

  // Sort by total downloads descending
  result.sort((a, b) => b.total - a.total);
  return result;
}

/**
 * Aggregate all census data into headline metrics.
 *
 * @param {Object} data
 * @param {Object} data.npm - Result from collectNpmDownloads
 * @param {Object} data.pypi - Result from collectPypiDownloads
 * @param {Object} [data.go] - Result from collectGoDownloads
 * @param {Object} [data.maven] - Result from collectMavenDownloads
 * @param {Object} [data.crates] - Result from collectCratesDownloads
 * @param {Object} [data.packagist] - Result from collectPackagistDownloads
 * @param {Object} [data.nuget] - Result from collectNugetDownloads
 * @param {Object} [data.rubygems] - Result from collectRubygemsDownloads
 * @param {Object} [data.hex] - Result from collectHexDownloads
 * @param {Object} [data.pub] - Result from collectPubDownloads
 * @param {Object} [data.cocoapods] - Result from collectCocoapodsDownloads
 * @param {Object} [data.nvd] - Result from collectNvdCves
 * @param {Object} [data.github] - Result from collectGithubAdvisories
 * @param {Object} [data.projectDeps] - Result from collectProjectDeps
 * @returns {Object} Aggregated metrics matching CensusData type
 */
export function aggregate(data) {
  // Gather all package arrays
  const npmPkgs = data.npm?.packages || [];
  const pypiPkgs = data.pypi?.packages || [];
  const goPkgs = data.go?.packages || [];
  const mavenPkgs = data.maven?.packages || [];
  const cratesPkgs = data.crates?.packages || [];
  const packagistPkgs = data.packagist?.packages || [];
  const nugetPkgs = data.nuget?.packages || [];
  const rubygemsPkgs = data.rubygems?.packages || [];
  const hexPkgs = data.hex?.packages || [];
  const pubPkgs = data.pub?.packages || [];
  const cocoapodsPkgs = data.cocoapods?.packages || [];
  const allPkgs = [...npmPkgs, ...pypiPkgs, ...goPkgs, ...mavenPkgs, ...cratesPkgs, ...packagistPkgs, ...nugetPkgs, ...rubygemsPkgs, ...hexPkgs, ...pubPkgs, ...cocoapodsPkgs];

  // Download totals by tier
  const totalWeakDownloads = sumByTier(allPkgs, TIERS.WEAK);
  const totalModernDownloads = sumByTier(allPkgs, TIERS.MODERN);
  const totalPqcDownloads = sumByTier(allPkgs, TIERS.PQC);
  const totalDownloads = totalWeakDownloads + totalModernDownloads + totalPqcDownloads;

  // Percentages
  const weakPercentage = totalDownloads > 0
    ? Math.round((totalWeakDownloads / totalDownloads) * 1000) / 10
    : 0;
  const modernPercentage = totalDownloads > 0
    ? Math.round((totalModernDownloads / totalDownloads) * 1000) / 10
    : 0;
  const pqcPercentage = totalDownloads > 0
    ? Math.round((totalPqcDownloads / totalDownloads) * 1000) / 10
    : 0;

  // The headline ratio
  const weakToPqcRatio = totalPqcDownloads > 0
    ? Math.round(totalWeakDownloads / totalPqcDownloads)
    : null;

  // Per-ecosystem breakdowns
  const npm = buildEcosystemBreakdown(npmPkgs, data.npm?.period);
  const pypi = buildEcosystemBreakdown(pypiPkgs, data.pypi?.period);
  const go = buildEcosystemBreakdown(goPkgs, data.go?.period);
  const maven = buildEcosystemBreakdown(mavenPkgs, data.maven?.period);
  const crates = buildEcosystemBreakdown(cratesPkgs, data.crates?.period);
  const packagist = buildEcosystemBreakdown(packagistPkgs, data.packagist?.period);
  const nuget = buildEcosystemBreakdown(nugetPkgs, data.nuget?.period);
  const rubygems = buildEcosystemBreakdown(rubygemsPkgs, data.rubygems?.period);
  const hex = buildEcosystemBreakdown(hexPkgs, data.hex?.period);
  const pub = buildEcosystemBreakdown(pubPkgs, data.pub?.period);
  const cocoapods = buildEcosystemBreakdown(cocoapodsPkgs, data.cocoapods?.period);

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

  // Project-level stats (if collected)
  const projectDeps = data.projectDeps;
  const projectStats = projectDeps?.stats || null;

  // Count active ecosystems
  const activeEcosystems = ECOSYSTEM_IDS.filter(eco => {
    const d = data[eco];
    return d?.packages?.length > 0;
  });

  // Category breakdown
  const categoryBreakdown = buildCategoryBreakdown(allPkgs);

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

    // Category breakdown
    categoryBreakdown,

    // Per-ecosystem
    npm,
    pypi,
    go,
    maven,
    crates,
    packagist,
    nuget,
    rubygems,
    hex,
    pub,
    cocoapods,

    // Project-level transparency
    ...(projectStats ? { projectStats } : {}),

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
    catalogSize: getCatalogSize(),
    ecosystemCount: activeEcosystems.length || ECOSYSTEM_IDS.length,
  };
}
