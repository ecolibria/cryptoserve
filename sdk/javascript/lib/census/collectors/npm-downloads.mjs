/**
 * Collect download counts from the npm registry API.
 *
 * Endpoint: GET https://api.npmjs.org/downloads/point/last-month/pkg1,pkg2,...
 * - Bulk endpoint does NOT support scoped packages (@org/pkg)
 * - Scoped packages must be fetched individually
 * - No authentication required
 */

const NPM_API = 'https://api.npmjs.org/downloads/point/last-month';
const BATCH_SIZE = 50;
const BATCH_DELAY_MS = 1000;
const INDIVIDUAL_DELAY_MS = 200;

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Fetch a single package's download count.
 */
async function fetchSingle(pkg, fetchFn, period, verbose) {
  try {
    const res = await fetchFn(`${NPM_API}/${pkg.name}`);
    if (res.ok) {
      const data = await res.json();
      if (!period.start && data.start) {
        period.start = data.start;
        period.end = data.end;
      }
      return { name: pkg.name, downloads: data.downloads || 0, tier: pkg.tier, category: pkg.category, replacedBy: pkg.replacedBy, algorithms: pkg.algorithms, note: pkg.note };
    }
    if (verbose) process.stderr.write(`  npm ${pkg.name}: HTTP ${res.status}\n`);
  } catch (err) {
    if (verbose) process.stderr.write(`  npm ${pkg.name} error: ${err.message}\n`);
  }
  return { name: pkg.name, downloads: 0, tier: pkg.tier, category: pkg.category, replacedBy: pkg.replacedBy, algorithms: pkg.algorithms, note: pkg.note };
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
  const period = { start: '', end: '' };

  // Separate scoped (@org/pkg) from unscoped packages
  const scoped = packages.filter(p => p.name.startsWith('@'));
  const unscoped = packages.filter(p => !p.name.startsWith('@'));

  // Batch unscoped packages
  const batches = [];
  for (let i = 0; i < unscoped.length; i += BATCH_SIZE) {
    batches.push(unscoped.slice(i, i + BATCH_SIZE));
  }

  for (let i = 0; i < batches.length; i++) {
    const batch = batches[i];
    const names = batch.map(p => p.name).join(',');
    const url = `${NPM_API}/${names}`;

    if (verbose) {
      process.stderr.write(`  npm batch ${i + 1}/${batches.length} (${batch.length} unscoped packages)\n`);
    }

    try {
      const res = await fetchFn(url);
      if (!res.ok) {
        if (verbose) process.stderr.write(`  npm batch ${i + 1} failed: ${res.status}, falling back to individual\n`);
        for (const pkg of batch) {
          results.push(await fetchSingle(pkg, fetchFn, period, verbose));
          await sleep(INDIVIDUAL_DELAY_MS);
        }
        continue;
      }

      const data = await res.json();

      if (batch.length === 1) {
        if (!period.start && data.start) {
          period.start = data.start;
          period.end = data.end;
        }
        results.push({ name: batch[0].name, downloads: data.downloads || 0, tier: batch[0].tier, category: batch[0].category, replacedBy: batch[0].replacedBy, algorithms: batch[0].algorithms, note: batch[0].note });
      } else {
        for (const pkg of batch) {
          const entry = data[pkg.name];
          if (entry) {
            if (!period.start && entry.start) {
              period.start = entry.start;
              period.end = entry.end;
            }
            results.push({ name: pkg.name, downloads: entry.downloads || 0, tier: pkg.tier, category: pkg.category, replacedBy: pkg.replacedBy, algorithms: pkg.algorithms, note: pkg.note });
          } else {
            results.push({ name: pkg.name, downloads: 0, tier: pkg.tier, category: pkg.category, replacedBy: pkg.replacedBy, algorithms: pkg.algorithms, note: pkg.note });
          }
        }
      }
    } catch (err) {
      if (verbose) process.stderr.write(`  npm batch ${i + 1} error: ${err.message}\n`);
      for (const pkg of batch) {
        results.push({ name: pkg.name, downloads: 0, tier: pkg.tier, category: pkg.category, replacedBy: pkg.replacedBy, algorithms: pkg.algorithms, note: pkg.note });
      }
    }

    if (i < batches.length - 1) await sleep(BATCH_DELAY_MS);
  }

  // Fetch scoped packages individually (bulk API doesn't support them)
  if (scoped.length > 0 && verbose) {
    process.stderr.write(`  npm fetching ${scoped.length} scoped packages individually\n`);
  }
  for (let i = 0; i < scoped.length; i++) {
    results.push(await fetchSingle(scoped[i], fetchFn, period, verbose));
    if (i < scoped.length - 1) await sleep(INDIVIDUAL_DELAY_MS);
  }

  return {
    packages: results.sort((a, b) => b.downloads - a.downloads),
    period,
    collectedAt: new Date().toISOString(),
  };
}
