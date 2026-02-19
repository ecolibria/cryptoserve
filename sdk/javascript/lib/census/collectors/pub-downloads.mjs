/**
 * Collect download counts from the pub.dev API.
 *
 * Endpoint: GET https://pub.dev/api/packages/{name}/score
 * - Returns downloadCount30Days (or estimate from likes/popularity)
 * - No authentication required
 */

const PUB_API = 'https://pub.dev/api/packages';
const REQUEST_DELAY_MS = 300;

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Fetch pub.dev download counts for a list of packages.
 *
 * @param {import('../package-catalog.mjs').CatalogEntry[]} packages
 * @param {Object} [options]
 * @param {Function} [options.fetchFn]
 * @param {boolean} [options.verbose]
 * @returns {Promise<{packages: Array<{name: string, downloads: number, tier: string}>, period: string, collectedAt: string}>}
 */
export async function collectPubDownloads(packages, options = {}) {
  const fetchFn = options.fetchFn || globalThis.fetch;
  const verbose = options.verbose || false;

  const results = [];

  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i];

    if (verbose) {
      process.stderr.write(`  pub ${i + 1}/${packages.length}: ${pkg.name}\n`);
    }

    try {
      const res = await fetchFn(`${PUB_API}/${pkg.name}/score`);

      if (!res.ok) {
        if (verbose) process.stderr.write(`  pub ${pkg.name}: ${res.status}\n`);
        results.push({ name: pkg.name, downloads: 0, tier: pkg.tier });
      } else {
        const data = await res.json();
        // pub.dev score endpoint has downloadCount30Days
        const downloads = data?.downloadCount30Days || 0;
        results.push({ name: pkg.name, downloads: downloads, tier: pkg.tier });
      }
    } catch (err) {
      if (verbose) process.stderr.write(`  pub ${pkg.name} error: ${err.message}\n`);
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
