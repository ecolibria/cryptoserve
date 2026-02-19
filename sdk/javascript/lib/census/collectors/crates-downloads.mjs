/**
 * Collect download counts from the crates.io API.
 *
 * Endpoint: GET https://crates.io/api/v1/crates/{name}
 * - Returns total downloads and recent_downloads (last 90 days)
 * - Requires User-Agent header
 * - No authentication required
 * - Rate limit: 1 request per second recommended
 */

const CRATES_API = 'https://crates.io/api/v1/crates';
const REQUEST_DELAY_MS = 300;
const USER_AGENT = 'crypto-census/1.0 (https://census.cryptoserve.dev)';

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Fetch crates.io download counts for a list of packages.
 *
 * @param {import('../package-catalog.mjs').CatalogEntry[]} packages
 * @param {Object} [options]
 * @param {Function} [options.fetchFn] - Fetch implementation (defaults to globalThis.fetch)
 * @param {boolean} [options.verbose] - Log progress
 * @returns {Promise<{packages: Array<{name: string, downloads: number, tier: string}>, period: string, collectedAt: string}>}
 */
export async function collectCratesDownloads(packages, options = {}) {
  const fetchFn = options.fetchFn || globalThis.fetch;
  const verbose = options.verbose || false;

  const results = [];

  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i];

    if (verbose) {
      process.stderr.write(`  crates ${i + 1}/${packages.length}: ${pkg.name}\n`);
    }

    try {
      const res = await fetchFn(`${CRATES_API}/${pkg.name}`, {
        headers: { 'User-Agent': USER_AGENT },
      });

      if (!res.ok) {
        if (verbose) process.stderr.write(`  crates ${pkg.name}: ${res.status}\n`);
        results.push({ name: pkg.name, downloads: 0, tier: pkg.tier });
      } else {
        const data = await res.json();
        // recent_downloads = last 90 days, divide by 3 for monthly estimate
        const recentDownloads = data?.crate?.recent_downloads || 0;
        const monthlyEstimate = Math.round(recentDownloads / 3);
        results.push({ name: pkg.name, downloads: monthlyEstimate, tier: pkg.tier });
      }
    } catch (err) {
      if (verbose) process.stderr.write(`  crates ${pkg.name} error: ${err.message}\n`);
      results.push({ name: pkg.name, downloads: 0, tier: pkg.tier });
    }

    if (i < packages.length - 1) {
      await sleep(REQUEST_DELAY_MS);
    }
  }

  return {
    packages: results.sort((a, b) => b.downloads - a.downloads),
    period: 'last_month_estimated',
    collectedAt: new Date().toISOString(),
  };
}
