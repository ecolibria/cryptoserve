/**
 * Census orchestrator: run collectors, aggregate, cache results.
 *
 * Supports 11 ecosystems: npm, PyPI, Go, Maven, crates.io, Packagist, NuGet,
 * RubyGems, Hex (Elixir), pub.dev (Dart), and CocoaPods (Swift/ObjC).
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

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

  const enabledSources = sources || [
    'npm', 'pypi', 'go', 'maven', 'crates', 'packagist', 'nuget',
    'rubygems', 'hex', 'pub', 'cocoapods',
    'nvd', 'github',
  ];
  const collectorOpts = { verbose, fetchFn };
  const empty = { packages: [], period: 'last_month', collectedAt: new Date().toISOString() };

  if (verbose) process.stderr.write('Collecting census data across 11 ecosystems...\n');

  // Phase 1: Package downloads (all 11 ecosystems in parallel)
  const downloadPromises = [
    enabledSources.includes('npm')
      ? (verbose && process.stderr.write('\nFetching npm download counts...\n'), collectNpmDownloads(NPM_PACKAGES, collectorOpts))
      : Promise.resolve(empty),
    enabledSources.includes('pypi')
      ? (verbose && process.stderr.write('\nFetching PyPI download counts...\n'), collectPypiDownloads(PYPI_PACKAGES, collectorOpts))
      : Promise.resolve(empty),
    enabledSources.includes('go')
      ? (verbose && process.stderr.write('\nFetching Go module stats...\n'), collectGoDownloads(GO_PACKAGES, collectorOpts))
      : Promise.resolve(empty),
    enabledSources.includes('maven')
      ? (verbose && process.stderr.write('\nFetching Maven Central stats...\n'), collectMavenDownloads(MAVEN_PACKAGES, collectorOpts))
      : Promise.resolve(empty),
    enabledSources.includes('crates')
      ? (verbose && process.stderr.write('\nFetching crates.io download counts...\n'), collectCratesDownloads(CRATES_PACKAGES, collectorOpts))
      : Promise.resolve(empty),
    enabledSources.includes('packagist')
      ? (verbose && process.stderr.write('\nFetching Packagist download counts...\n'), collectPackagistDownloads(PACKAGIST_PACKAGES, collectorOpts))
      : Promise.resolve(empty),
    enabledSources.includes('nuget')
      ? (verbose && process.stderr.write('\nFetching NuGet download counts...\n'), collectNugetDownloads(NUGET_PACKAGES, collectorOpts))
      : Promise.resolve(empty),
    enabledSources.includes('rubygems')
      ? (verbose && process.stderr.write('\nFetching RubyGems download counts...\n'), collectRubygemsDownloads(RUBYGEMS_PACKAGES, collectorOpts))
      : Promise.resolve(empty),
    enabledSources.includes('hex')
      ? (verbose && process.stderr.write('\nFetching Hex.pm download counts...\n'), collectHexDownloads(HEX_PACKAGES, collectorOpts))
      : Promise.resolve(empty),
    enabledSources.includes('pub')
      ? (verbose && process.stderr.write('\nFetching pub.dev download counts...\n'), collectPubDownloads(PUB_PACKAGES, collectorOpts))
      : Promise.resolve(empty),
    enabledSources.includes('cocoapods')
      ? (verbose && process.stderr.write('\nFetching CocoaPods pod counts...\n'), collectCocoapodsDownloads(COCOAPODS_PACKAGES, collectorOpts))
      : Promise.resolve(empty),
  ];

  const [npmData, pypiData, goData, mavenData, cratesData, packagistData, nugetData,
         rubygemsData, hexData, pubData, cocoapodsData] =
    await Promise.all(downloadPromises);

  // Phase 2: Vulnerability data (NVD + GitHub in parallel)
  const vulnPromises = [
    enabledSources.includes('nvd')
      ? (verbose && process.stderr.write('\nFetching NVD CVE data...\n'), collectNvdCves(collectorOpts))
      : Promise.resolve({ cves: [], collectedAt: new Date().toISOString() }),
    enabledSources.includes('github')
      ? (verbose && process.stderr.write('\nFetching GitHub advisories...\n'), collectGithubAdvisories(collectorOpts))
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
