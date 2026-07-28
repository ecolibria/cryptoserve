/**
 * Census client: fetch the published census snapshot and cache it locally.
 *
 * This used to collect the census itself -- its own copy of thirteen collectors
 * over its own copy of the catalog. That was a second definition of a published
 * measurement, and the two disagreed: the CLI catalogued 357 packages while the
 * census catalogued 355, and every collector in this package still records a
 * failed request as `downloads: 0`, so anyone running `cryptoserve census` was
 * shown collection failures as measurements of zero. `cryptography` alone really
 * has over a billion downloads a month and was reported as none.
 *
 * The census now publishes from committed dated snapshots, so there is one
 * number and one collection date. This module fetches that and renders it. It
 * does not measure anything, which is why nothing here can disagree with what
 * census.cryptoserve.dev shows.
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { configPath, ensureConfigDir } from '../paths.mjs';

/** Where the published snapshot lives. Overridable for tests and local checks. */
export const CENSUS_URL =
  process.env.CRYPTOSERVE_CENSUS_URL || 'https://census.cryptoserve.dev/api/census';

const cacheFile = () => configPath('census-cache.json');

/**
 * The snapshot is a dated measurement that changes when someone publishes a new
 * one, not a live feed, so the cache is a day rather than an hour. npm and
 * pypistats both report a rolling 30-day window: re-fetching it four times a day
 * advances that window by under a percent and returns the same number.
 */
export const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

export const DEFAULT_REQUEST_TIMEOUT_MS = 15_000;

/**
 * Read the cache. Returns `{ payload, fetchedAt, ageMs }` or null.
 *
 * Age is measured from when this machine fetched the snapshot, never from the
 * snapshot's own `collectedAt` -- that is the date of the measurement, which is
 * legitimately weeks old and would expire every cache entry the moment it was
 * written.
 */
function loadCache() {
  try {
    const file = cacheFile();
    if (!existsSync(file)) return null;
    const cached = JSON.parse(readFileSync(file, 'utf-8'));
    if (!cached?.payload || !cached?.fetchedAt) return null;
    const ageMs = Date.now() - new Date(cached.fetchedAt).getTime();
    if (!Number.isFinite(ageMs) || ageMs < 0) return null;
    return { payload: cached.payload, fetchedAt: cached.fetchedAt, ageMs };
  } catch {
    return null;
  }
}

function saveCache(payload) {
  try {
    ensureConfigDir();
    writeFileSync(cacheFile(), JSON.stringify({
      fetchedAt: new Date().toISOString(),
      source: CENSUS_URL,
      payload,
    }, null, 2));
  } catch {
    // A cache we could not write is not a reason to fail a read-only command.
  }
}

/** A payload that is missing its headline is a fetch that went somewhere else. */
function looksLikeCensus(payload) {
  return Boolean(
    payload &&
    typeof payload === 'object' &&
    typeof payload.totalDownloads === 'number' &&
    typeof payload.collectedAt === 'string' &&
    payload.npm && typeof payload.npm === 'object'
  );
}

export function describeAge(ms) {
  const days = Math.floor(ms / 86_400_000);
  if (days >= 1) return `${days} day${days === 1 ? '' : 's'} old`;
  const hours = Math.floor(ms / 3_600_000);
  if (hours >= 1) return `${hours} hour${hours === 1 ? '' : 's'} old`;
  return 'under an hour old';
}

/**
 * Fetch the published census snapshot.
 *
 * @param {Object}   [options]
 * @param {boolean}  [options.noCache]   Ignore any cached copy
 * @param {boolean}  [options.verbose]   Narrate to stderr
 * @param {Function} [options.fetchFn]   Injected fetch, for tests
 * @param {number}   [options.timeoutMs]
 * @returns {Promise<{data: Object, source: 'network'|'cache'|'stale-cache', fetchedAt: string}>}
 */
export async function fetchCensus(options = {}) {
  const {
    noCache = false,
    verbose = false,
    fetchFn = globalThis.fetch,
    timeoutMs = DEFAULT_REQUEST_TIMEOUT_MS,
  } = options;

  const note = (msg) => { if (verbose) process.stderr.write(`${msg}\n`); };

  if (!noCache) {
    const cached = loadCache();
    if (cached && cached.ageMs < CACHE_TTL_MS) {
      note(`Using cached snapshot (${describeAge(cached.ageMs)})`);
      return { data: cached.payload, source: 'cache', fetchedAt: cached.fetchedAt };
    }
  }

  note(`Fetching ${CENSUS_URL}`);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let payload = null;
  let failure = null;
  try {
    const res = await fetchFn(CENSUS_URL, {
      signal: controller.signal,
      headers: { accept: 'application/json' },
    });
    if (!res.ok) {
      failure = `${CENSUS_URL} returned HTTP ${res.status}`;
    } else {
      const body = await res.json();
      if (!looksLikeCensus(body)) {
        failure = `${CENSUS_URL} returned something that is not a census snapshot`;
      } else {
        payload = body;
      }
    }
  } catch (err) {
    const cause = err?.cause?.code || err?.cause?.message;
    const reason = err?.name === 'AbortError'
      ? `no response within ${Math.round(timeoutMs / 1000)}s`
      : `${err?.message || err}${cause ? ` (${cause})` : ''}`;
    failure = `could not reach ${CENSUS_URL}: ${reason}`;
  } finally {
    clearTimeout(timer);
  }

  if (payload) {
    saveCache(payload);
    return { data: payload, source: 'network', fetchedAt: new Date().toISOString() };
  }

  // A stale local copy beats no answer, but it is announced as stale rather
  // than passed off as current. Serving it silently is how a snapshot from
  // months ago gets read as today's number.
  const cached = loadCache();
  if (cached) {
    return {
      data: cached.payload,
      source: 'stale-cache',
      fetchedAt: cached.fetchedAt,
      failure,
    };
  }

  const error = new Error(failure || 'census snapshot unavailable');
  error.censusUnavailable = true;
  throw error;
}
