/**
 * Census orchestrator: run collectors, aggregate, cache results.
 *
 * Supports 11 ecosystems: npm, PyPI, Go, Maven, crates.io, Packagist, NuGet,
 * RubyGems, Hex (Elixir), pub.dev (Dart), and CocoaPods (Swift/ObjC).
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { configPath, ensureConfigDir } from '../paths.mjs';

import {
  NPM_PACKAGES, PYPI_PACKAGES, GO_PACKAGES,
  MAVEN_PACKAGES, CRATES_PACKAGES, PACKAGIST_PACKAGES, NUGET_PACKAGES,
  RUBYGEMS_PACKAGES, HEX_PACKAGES, PUB_PACKAGES, COCOAPODS_PACKAGES,
} from './package-catalog.mjs';
import { collectNpmDownloads } from './collectors/npm-downloads.mjs';
import { collectPypiDownloads } from './collectors/pypi-downloads.mjs';
import { collectGoDownloads } from './collectors/go-downloads.mjs';
import { collectMavenDownloads } from './collectors/maven-downloads.mjs';
import { collectCratesDownloads } from './collectors/crates-downloads.mjs';
import { collectPackagistDownloads } from './collectors/packagist-downloads.mjs';
import { collectNugetDownloads } from './collectors/nuget-downloads.mjs';
import { collectRubygemsDownloads } from './collectors/rubygems-downloads.mjs';
import { collectHexDownloads } from './collectors/hex-downloads.mjs';
import { collectPubDownloads } from './collectors/pub-downloads.mjs';
import { collectCocoapodsDownloads } from './collectors/cocoapods-downloads.mjs';
import { collectNvdCves } from './collectors/nvd-cves.mjs';
import { collectGithubAdvisories } from './collectors/github-advisories.mjs';
import { aggregate } from './aggregator.mjs';

const cacheFile = () => configPath('census-cache.json');
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

// A census run fans out to thirteen third-party services. Without a per-request
// deadline one unresponsive registry blocks the whole command indefinitely,
// which is exactly what `cryptoserve census` used to do: no output, no timeout,
// no way to tell a slow run from a hung one.
export const DEFAULT_REQUEST_TIMEOUT_MS = 15_000;

/**
 * fetch with a hard per-request deadline. Returned as a non-ok response shape
 * on timeout so collectors take their existing "registry did not answer" path
 * instead of aborting the run.
 */
export function fetchWithTimeout(timeoutMs = DEFAULT_REQUEST_TIMEOUT_MS, baseFetch = globalThis.fetch) {
  return async (url, options = {}) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      return await baseFetch(url, { ...options, signal: controller.signal });
    } catch (err) {
      if (err?.name === 'AbortError') {
        return { ok: false, status: 408, statusText: `timeout after ${timeoutMs}ms`, json: async () => ({}), text: async () => '' };
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  };
}

/**
 * Load cached data if valid.
 * @returns {Object|null}
 */
function loadCache() {
  try {
    const file = cacheFile();
    if (!existsSync(file)) return null;
    const raw = readFileSync(file, 'utf-8');
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
    ensureConfigDir();
    writeFileSync(cacheFile(), JSON.stringify(data, null, 2));
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
  const {
    verbose = false,
    noCache = false,
    sources,
    fetchFn,
    timeoutMs = DEFAULT_REQUEST_TIMEOUT_MS,
    onProgress,
  } = options;

  // Check cache first
  if (!noCache) {
    const cached = loadCache();
    if (cached) {
      if (verbose) process.stderr.write('Using cached census data (< 1 hour old)\n');
      return cached;
    }
  }

  const enabledSources = sources || [
    'npm', 'pypi', 'go', 'maven', 'crates', 'packagist', 'nuget',
    'rubygems', 'hex', 'pub', 'cocoapods',
    'nvd', 'github',
  ];
  // An explicitly injected fetch (tests) is used as-is; otherwise every
  // collector gets the deadline-bounded fetch rather than a bare global.
  const collectorOpts = { verbose, fetchFn: fetchFn || fetchWithTimeout(timeoutMs) };
  const empty = { packages: [], period: 'last_month', collectedAt: new Date().toISOString() };

  // Progress is reported unconditionally, not only under --verbose. A command
  // that reaches out to thirteen services must never look like it has hung.
  const report = onProgress || (msg => process.stderr.write(msg + '\n'));
  report(`Collecting census data from ${enabledSources.length} sources (timeout ${Math.round(timeoutMs / 1000)}s per request)...`);

  // Phase 1: Package downloads (all 11 ecosystems in parallel)
  const downloadPromises = [
    enabledSources.includes('npm')
      ? (report('  Fetching npm download counts...'), collectNpmDownloads(NPM_PACKAGES, collectorOpts))
      : Promise.resolve(empty),
    enabledSources.includes('pypi')
      ? (report('  Fetching PyPI download counts...'), collectPypiDownloads(PYPI_PACKAGES, collectorOpts))
      : Promise.resolve(empty),
    enabledSources.includes('go')
      ? (report('  Fetching Go module stats...'), collectGoDownloads(GO_PACKAGES, collectorOpts))
      : Promise.resolve(empty),
    enabledSources.includes('maven')
      ? (report('  Fetching Maven Central stats...'), collectMavenDownloads(MAVEN_PACKAGES, collectorOpts))
      : Promise.resolve(empty),
    enabledSources.includes('crates')
      ? (report('  Fetching crates.io download counts...'), collectCratesDownloads(CRATES_PACKAGES, collectorOpts))
      : Promise.resolve(empty),
    enabledSources.includes('packagist')
      ? (report('  Fetching Packagist download counts...'), collectPackagistDownloads(PACKAGIST_PACKAGES, collectorOpts))
      : Promise.resolve(empty),
    enabledSources.includes('nuget')
      ? (report('  Fetching NuGet download counts...'), collectNugetDownloads(NUGET_PACKAGES, collectorOpts))
      : Promise.resolve(empty),
    enabledSources.includes('rubygems')
      ? (report('  Fetching RubyGems download counts...'), collectRubygemsDownloads(RUBYGEMS_PACKAGES, collectorOpts))
      : Promise.resolve(empty),
    enabledSources.includes('hex')
      ? (report('  Fetching Hex.pm download counts...'), collectHexDownloads(HEX_PACKAGES, collectorOpts))
      : Promise.resolve(empty),
    enabledSources.includes('pub')
      ? (report('  Fetching pub.dev download counts...'), collectPubDownloads(PUB_PACKAGES, collectorOpts))
      : Promise.resolve(empty),
    enabledSources.includes('cocoapods')
      ? (report('  Fetching CocoaPods pod counts...'), collectCocoapodsDownloads(COCOAPODS_PACKAGES, collectorOpts))
      : Promise.resolve(empty),
  ];

  const [npmData, pypiData, goData, mavenData, cratesData, packagistData, nugetData,
         rubygemsData, hexData, pubData, cocoapodsData] =
    await Promise.all(downloadPromises);

  // Phase 2: Vulnerability data (NVD + GitHub in parallel)
  const vulnPromises = [
    enabledSources.includes('nvd')
      ? (report('  Fetching NVD CVE data...'), collectNvdCves(collectorOpts))
      : Promise.resolve({ cves: [], collectedAt: new Date().toISOString() }),
    enabledSources.includes('github')
      ? (report('  Fetching GitHub advisories...'), collectGithubAdvisories(collectorOpts))
      : Promise.resolve({ advisories: [], collectedAt: new Date().toISOString() }),
  ];

  const [nvdData, githubData] = await Promise.all(vulnPromises);

  // Aggregate
  const result = aggregate({
    npm: npmData,
    pypi: pypiData,
    go: goData,
    maven: mavenData,
    crates: cratesData,
    packagist: packagistData,
    nuget: nugetData,
    rubygems: rubygemsData,
    hex: hexData,
    pub: pubData,
    cocoapods: cocoapodsData,
    nvd: nvdData,
    github: githubData,
  });

  // Cache the result
  if (!noCache) {
    saveCache(result);
  }

  return result;
}
