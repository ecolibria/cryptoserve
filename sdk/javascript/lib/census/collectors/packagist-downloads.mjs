/**
 * Collect download counts from the Packagist API.
 *
 * Endpoint: GET https://packagist.org/packages/{name}.json
 * - Returns total downloads and monthly downloads
 * - No authentication required
 * - Rate limit: be polite, 300ms between requests
 */

const PACKAGIST_API = 'https://packagist.org/packages';
const REQUEST_DELAY_MS = 300;

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Fetch Packagist download counts for a list of packages.
 *
 * @param {import('../package-catalog.mjs').CatalogEntry[]} packages
 * @param {Object} [options]
 * @param {Function} [options.fetchFn] - Fetch implementation (defaults to globalThis.fetch)
 * @param {boolean} [options.verbose] - Log progress
 * @returns {Promise<{packages: Array<{name: string, downloads: number, tier: string}>, period: string, collectedAt: string}>}
 */
export async function collectPackagistDownloads(packages, options = {}) {
  const fetchFn = options.fetchFn || globalThis.fetch;
  const verbose = options.verbose || false;

  const results = [];

  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i];

    if (verbose) {
      process.stderr.write(`  packagist ${i + 1}/${packages.length}: ${pkg.name}\n`);
    }

    try {
      const res = await fetchFn(`${PACKAGIST_API}/${pkg.name}.json`);

      if (!res.ok) {
        if (verbose) process.stderr.write(`  packagist ${pkg.name}: ${res.status}\n`);
        results.push({ name: pkg.name, downloads: 0, tier: pkg.tier });
      } else {
        const data = await res.json();
        const monthlyDownloads = data?.package?.downloads?.monthly || 0;
        results.push({ name: pkg.name, downloads: monthlyDownloads, tier: pkg.tier });
      }
    } catch (err) {
      if (verbose) process.stderr.write(`  packagist ${pkg.name} error: ${err.message}\n`);
      results.push({ name: pkg.name, downloads: 0, tier: pkg.tier });
    }

    if (i < packages.length - 1) {
      await sleep(REQUEST_DELAY_MS);
    }
  }

  return {
    packages: results.sort((a, b) => b.downloads - a.downloads),
    period: 'last_month',
    collectedAt: new Date().toISOString(),
  };
}
