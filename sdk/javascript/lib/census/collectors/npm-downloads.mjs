/**
 * Collect download counts from the npm registry API.
 *
 * Endpoint: GET https://api.npmjs.org/downloads/point/last-month/pkg1,pkg2,...
 * - Supports batching up to 128 scoped + unscoped packages per request
 * - No authentication required
 * - We batch 50 at a time with 1s delay to be polite
 */

const NPM_API = 'https://api.npmjs.org/downloads/point/last-month';
const BATCH_SIZE = 50;
const BATCH_DELAY_MS = 1000;

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Fetch npm download counts for a list of packages.
 *
 * @param {import('../package-catalog.mjs').CatalogEntry[]} packages
 * @param {Object} [options]
 * @param {Function} [options.fetchFn] - Fetch implementation (defaults to globalThis.fetch)
 * @param {boolean} [options.verbose] - Log progress
 * @returns {Promise<{packages: Array<{name: string, downloads: number, tier: string}>, period: {start: string, end: string}, collectedAt: string}>}
 */
export async function collectNpmDownloads(packages, options = {}) {
  const fetchFn = options.fetchFn || globalThis.fetch;
  const verbose = options.verbose || false;

  const results = [];
  let period = { start: '', end: '' };

  // Split into batches
  const batches = [];
  for (let i = 0; i < packages.length; i += BATCH_SIZE) {
    batches.push(packages.slice(i, i + BATCH_SIZE));
  }

  for (let i = 0; i < batches.length; i++) {
    const batch = batches[i];
    const names = batch.map(p => p.name).join(',');
    const url = `${NPM_API}/${names}`;

    if (verbose) {
      process.stderr.write(`  npm batch ${i + 1}/${batches.length} (${batch.length} packages)\n`);
    }

    try {
      const res = await fetchFn(url);
      if (!res.ok) {
        if (verbose) process.stderr.write(`  npm batch ${i + 1} failed: ${res.status}\n`);
        // Fall back to individual requests for this batch
        for (const pkg of batch) {
          try {
            const singleRes = await fetchFn(`${NPM_API}/${pkg.name}`);
            if (singleRes.ok) {
              const data = await singleRes.json();
              if (!period.start && data.start) {
                period = { start: data.start, end: data.end };
              }
              results.push({ name: pkg.name, downloads: data.downloads || 0, tier: pkg.tier });
            } else {
              results.push({ name: pkg.name, downloads: 0, tier: pkg.tier });
            }
          } catch {
            results.push({ name: pkg.name, downloads: 0, tier: pkg.tier });
          }
          await sleep(200);
        }
        continue;
      }

      const data = await res.json();

      // Single-package response has { downloads, start, end, package }
      // Multi-package response has { pkg1: { downloads, ... }, pkg2: { ... } }
      if (batch.length === 1) {
        if (!period.start && data.start) {
          period = { start: data.start, end: data.end };
        }
        results.push({
          name: batch[0].name,
          downloads: data.downloads || 0,
          tier: batch[0].tier,
        });
      } else {
        for (const pkg of batch) {
          const entry = data[pkg.name];
          if (entry) {
            if (!period.start && entry.start) {
              period = { start: entry.start, end: entry.end };
            }
            results.push({ name: pkg.name, downloads: entry.downloads || 0, tier: pkg.tier });
          } else {
            results.push({ name: pkg.name, downloads: 0, tier: pkg.tier });
          }
        }
      }
    } catch (err) {
      if (verbose) process.stderr.write(`  npm batch ${i + 1} error: ${err.message}\n`);
      for (const pkg of batch) {
        results.push({ name: pkg.name, downloads: 0, tier: pkg.tier });
      }
    }

    // Delay between batches
    if (i < batches.length - 1) {
      await sleep(BATCH_DELAY_MS);
    }
  }

  return {
    packages: results.sort((a, b) => b.downloads - a.downloads),
    period,
    collectedAt: new Date().toISOString(),
  };
}
