/**
 * Collect download counts from the Hex.pm API.
 *
 * Endpoint: GET https://hex.pm/api/packages/{name}
 * - Returns downloads with recent breakdown
 * - No authentication required
 */

const HEX_API = 'https://hex.pm/api/packages';
const REQUEST_DELAY_MS = 300;

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Fetch Hex.pm download counts for a list of packages.
 *
 * @param {import('../package-catalog.mjs').CatalogEntry[]} packages
 * @param {Object} [options]
 * @param {Function} [options.fetchFn]
 * @param {boolean} [options.verbose]
 * @returns {Promise<{packages: Array<{name: string, downloads: number, tier: string}>, period: string, collectedAt: string}>}
 */
export async function collectHexDownloads(packages, options = {}) {
  const fetchFn = options.fetchFn || globalThis.fetch;
  const verbose = options.verbose || false;

  const results = [];

  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i];

    if (verbose) {
      process.stderr.write(`  hex ${i + 1}/${packages.length}: ${pkg.name}\n`);
    }

    try {
      const res = await fetchFn(`${HEX_API}/${pkg.name}`, {
        headers: { 'Accept': 'application/json' },
      });

      if (!res.ok) {
        if (verbose) process.stderr.write(`  hex ${pkg.name}: ${res.status}\n`);
        results.push({ name: pkg.name, downloads: 0, tier: pkg.tier, category: pkg.category, replacedBy: pkg.replacedBy, algorithms: pkg.algorithms, note: pkg.note });
      } else {
        const data = await res.json();
        // Hex provides downloads.recent (last 90 days) and downloads.all
        const recentDownloads = data?.downloads?.recent || 0;
        // Estimate monthly from 90-day window
        const monthlyEstimate = Math.round(recentDownloads / 3);
        results.push({ name: pkg.name, downloads: monthlyEstimate, tier: pkg.tier, category: pkg.category, replacedBy: pkg.replacedBy, algorithms: pkg.algorithms, note: pkg.note });
      }
    } catch (err) {
      if (verbose) process.stderr.write(`  hex ${pkg.name} error: ${err.message}\n`);
      results.push({ name: pkg.name, downloads: 0, tier: pkg.tier, category: pkg.category, replacedBy: pkg.replacedBy, algorithms: pkg.algorithms, note: pkg.note });
    }

    if (i < packages.length - 1) {
      await sleep(REQUEST_DELAY_MS);
    }
  }

  return {
    packages: results.sort((a, b) => b.downloads - a.downloads),
    period: 'estimated_monthly',
    collectedAt: new Date().toISOString(),
  };
}
