/**
 * Collect download counts from the NuGet API.
 *
 * Endpoint: GET https://api.nuget.org/v3/registration5-semver1/{id}/index.json
 * - Returns per-version download counts
 * - No authentication required
 * - Rate limit: be polite, 300ms between requests
 *
 * Alternative: NuGet search API for total downloads
 * GET https://azuresearch-usnc.nuget.org/query?q=packageid:{name}&take=1
 */

const NUGET_SEARCH = 'https://azuresearch-usnc.nuget.org/query';
const REQUEST_DELAY_MS = 300;

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Fetch NuGet download counts for a list of packages.
 *
 * @param {import('../package-catalog.mjs').CatalogEntry[]} packages
 * @param {Object} [options]
 * @param {Function} [options.fetchFn] - Fetch implementation (defaults to globalThis.fetch)
 * @param {boolean} [options.verbose] - Log progress
 * @returns {Promise<{packages: Array<{name: string, downloads: number, tier: string}>, period: string, collectedAt: string}>}
 */
export async function collectNugetDownloads(packages, options = {}) {
  const fetchFn = options.fetchFn || globalThis.fetch;
  const verbose = options.verbose || false;

  const results = [];

  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i];

    if (verbose) {
      process.stderr.write(`  nuget ${i + 1}/${packages.length}: ${pkg.name}\n`);
    }

    try {
      const url = `${NUGET_SEARCH}?q=packageid:${encodeURIComponent(pkg.name)}&take=1`;
      const res = await fetchFn(url);

      if (!res.ok) {
        if (verbose) process.stderr.write(`  nuget ${pkg.name}: ${res.status}\n`);
        results.push({ name: pkg.name, downloads: 0, tier: pkg.tier, category: pkg.category, replacedBy: pkg.replacedBy, algorithms: pkg.algorithms, note: pkg.note });
      } else {
        const data = await res.json();
        const entry = data?.data?.[0];
        // NuGet returns total downloads, estimate monthly as total / 36 (3 years average)
        const totalDownloads = entry?.totalDownloads || 0;
        const monthlyEstimate = Math.round(totalDownloads / 36);
        results.push({ name: pkg.name, downloads: monthlyEstimate, tier: pkg.tier, category: pkg.category, replacedBy: pkg.replacedBy, algorithms: pkg.algorithms, note: pkg.note });
      }
    } catch (err) {
      if (verbose) process.stderr.write(`  nuget ${pkg.name} error: ${err.message}\n`);
      results.push({ name: pkg.name, downloads: 0, tier: pkg.tier, category: pkg.category, replacedBy: pkg.replacedBy, algorithms: pkg.algorithms, note: pkg.note });
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
