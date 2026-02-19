/**
 * Census orchestrator: run collectors, aggregate, cache results.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

import { NPM_PACKAGES, PYPI_PACKAGES } from './package-catalog.mjs';
import { collectNpmDownloads } from './collectors/npm-downloads.mjs';
import { collectPypiDownloads } from './collectors/pypi-downloads.mjs';
import { collectNvdCves } from './collectors/nvd-cves.mjs';
import { collectGithubAdvisories } from './collectors/github-advisories.mjs';
import { aggregate } from './aggregator.mjs';

const CACHE_DIR = join(homedir(), '.cryptoserve');
const CACHE_FILE = join(CACHE_DIR, 'census-cache.json');
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

/**
 * Load cached data if valid.
 * @returns {Object|null}
 */
function loadCache() {
  try {
    if (!existsSync(CACHE_FILE)) return null;
    const raw = readFileSync(CACHE_FILE, 'utf-8');
    const cached = JSON.parse(raw);
    const age = Date.now() - new Date(cached.collectedAt).getTime();
    if (age < CACHE_TTL_MS) return cached;
    return null;
  } catch {
    return null;
  }
}

/**
 * Save data to cache.
 */
function saveCache(data) {
  try {
    mkdirSync(CACHE_DIR, { recursive: true });
    writeFileSync(CACHE_FILE, JSON.stringify(data, null, 2));
  } catch {
    // Cache write failure is non-fatal
  }
}

/**
 * Run the full census: collect data from all sources and aggregate.
 *
 * @param {Object} [options]
 * @param {boolean} [options.verbose] - Log progress to stderr
 * @param {boolean} [options.noCache] - Skip cache
 * @param {string[]} [options.sources] - Which sources to query (default: all)
 * @param {Function} [options.fetchFn] - Injected fetch for testing
 * @returns {Promise<Object>} Aggregated census data
 */
export async function runCensus(options = {}) {
  const { verbose = false, noCache = false, sources, fetchFn } = options;

  // Check cache first
  if (!noCache) {
    const cached = loadCache();
    if (cached) {
      if (verbose) process.stderr.write('Using cached census data (< 1 hour old)\n');
      return cached;
    }
  }

  const enabledSources = sources || ['npm', 'pypi', 'nvd', 'github'];
  const collectorOpts = { verbose, fetchFn };

  if (verbose) process.stderr.write('Collecting census data...\n');

  // Phase 1: Package downloads (npm + PyPI in parallel)
  const downloadPromises = [];
  if (enabledSources.includes('npm')) {
    if (verbose) process.stderr.write('\nFetching npm download counts...\n');
    downloadPromises.push(collectNpmDownloads(NPM_PACKAGES, collectorOpts));
  } else {
    downloadPromises.push(Promise.resolve({ packages: [], period: {}, collectedAt: new Date().toISOString() }));
  }
  if (enabledSources.includes('pypi')) {
    if (verbose) process.stderr.write('\nFetching PyPI download counts...\n');
    downloadPromises.push(collectPypiDownloads(PYPI_PACKAGES, collectorOpts));
  } else {
    downloadPromises.push(Promise.resolve({ packages: [], period: 'last_month', collectedAt: new Date().toISOString() }));
  }

  const [npmData, pypiData] = await Promise.all(downloadPromises);

  // Phase 2: Vulnerability data (NVD + GitHub in parallel)
  const vulnPromises = [];
  if (enabledSources.includes('nvd')) {
    if (verbose) process.stderr.write('\nFetching NVD CVE data...\n');
    vulnPromises.push(collectNvdCves(collectorOpts));
  } else {
    vulnPromises.push(Promise.resolve({ cves: [], collectedAt: new Date().toISOString() }));
  }
  if (enabledSources.includes('github')) {
    if (verbose) process.stderr.write('\nFetching GitHub advisories...\n');
    vulnPromises.push(collectGithubAdvisories(collectorOpts));
  } else {
    vulnPromises.push(Promise.resolve({ advisories: [], collectedAt: new Date().toISOString() }));
  }

  const [nvdData, githubData] = await Promise.all(vulnPromises);

  // Aggregate
  const result = aggregate({
    npm: npmData,
    pypi: pypiData,
    nvd: nvdData,
    github: githubData,
  });

  // Cache the result
  if (!noCache) {
    saveCache(result);
  }

  return result;
}
