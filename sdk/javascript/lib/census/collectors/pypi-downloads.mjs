/**
 * Collect download counts from PyPI Stats API.
 *
 * Endpoint: GET https://pypistats.org/api/packages/{pkg}/recent
 * - Individual requests only (no batch endpoint)
 * - No authentication required
 * - 500ms delay between requests to be polite
 */

const PYPI_API = 'https://pypistats.org/api/packages';
const REQUEST_DELAY_MS = 500;

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Fetch PyPI download counts for a list of packages.
 *
 * @param {import('../package-catalog.mjs').CatalogEntry[]} packages
 * @param {Object} [options]
 * @param {Function} [options.fetchFn] - Fetch implementation (defaults to globalThis.fetch)
 * @param {boolean} [options.verbose] - Log progress
 * @returns {Promise<{packages: Array<{name: string, downloads: number, tier: string}>, period: string, collectedAt: string}>}
 */
export async function collectPypiDownloads(packages, options = {}) {
  const fetchFn = options.fetchFn || globalThis.fetch;
  const verbose = options.verbose || false;

  const results = [];

  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i];
    const url = `${PYPI_API}/${pkg.name}/recent`;

    if (verbose) {
      process.stderr.write(`  pypi ${i + 1}/${packages.length}: ${pkg.name}\n`);
    }

    try {
      const res = await fetchFn(url);
      if (!res.ok) {
        if (verbose) process.stderr.write(`  pypi ${pkg.name}: ${res.status}\n`);
        results.push({ name: pkg.name, downloads: 0, tier: pkg.tier });
      } else {
        const data = await res.json();
        // Response: { data: { last_month: N, last_week: N, last_day: N }, ... }
        const downloads = data?.data?.last_month || 0;
        results.push({ name: pkg.name, downloads, tier: pkg.tier });
      }
    } catch (err) {
      if (verbose) process.stderr.write(`  pypi ${pkg.name} error: ${err.message}\n`);
      results.push({ name: pkg.name, downloads: 0, tier: pkg.tier });
    }

    // Delay between requests
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
