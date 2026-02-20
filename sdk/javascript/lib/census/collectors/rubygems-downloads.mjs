/**
 * Collect download counts from the RubyGems API.
 *
 * Endpoint: GET https://rubygems.org/api/v1/gems/{name}.json
 * - Returns total downloads (no monthly breakdown)
 * - Estimate monthly = total / 120 (approx 10 years of data)
 * - No authentication required
 */

const RUBYGEMS_API = 'https://rubygems.org/api/v1/gems';
const REQUEST_DELAY_MS = 300;

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Fetch RubyGems download counts for a list of packages.
 *
 * @param {import('../package-catalog.mjs').CatalogEntry[]} packages
 * @param {Object} [options]
 * @param {Function} [options.fetchFn]
 * @param {boolean} [options.verbose]
 * @returns {Promise<{packages: Array<{name: string, downloads: number, tier: string}>, period: string, collectedAt: string}>}
 */
export async function collectRubygemsDownloads(packages, options = {}) {
  const fetchFn = options.fetchFn || globalThis.fetch;
  const verbose = options.verbose || false;

  const results = [];

  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i];

    if (verbose) {
      process.stderr.write(`  rubygems ${i + 1}/${packages.length}: ${pkg.name}\n`);
    }

    try {
      const res = await fetchFn(`${RUBYGEMS_API}/${pkg.name}.json`);

      if (!res.ok) {
        if (verbose) process.stderr.write(`  rubygems ${pkg.name}: ${res.status}\n`);
        results.push({ name: pkg.name, downloads: 0, tier: pkg.tier, category: pkg.category, replacedBy: pkg.replacedBy, algorithms: pkg.algorithms, note: pkg.note });
      } else {
        const data = await res.json();
        // RubyGems only provides total downloads; estimate monthly
        const totalDownloads = data?.downloads || 0;
        const monthlyEstimate = Math.round(totalDownloads / 120);
        results.push({ name: pkg.name, downloads: monthlyEstimate, tier: pkg.tier, category: pkg.category, replacedBy: pkg.replacedBy, algorithms: pkg.algorithms, note: pkg.note });
      }
    } catch (err) {
      if (verbose) process.stderr.write(`  rubygems ${pkg.name} error: ${err.message}\n`);
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
