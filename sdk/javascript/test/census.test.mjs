/**
 * Guards the census client.
 *
 * This file used to test the CLI's own collectors, catalog and aggregator.
 * Those are gone: they were a second definition of a published measurement, and
 * the two disagreed. What matters now is that this package renders the
 * published snapshot faithfully and never invents one.
 *
 * Every assertion corresponds to a way the old command misled someone:
 *
 *   - Each collector recorded a failed request as `downloads: 0`, so a
 *     rate-limited run reported real packages as having no downloads at all.
 *     pypistats.org rate-limits at the rate the collector asked, and
 *     `cryptography` (over a billion downloads a month) was printed as 0.
 *   - The CLI carried its own catalog, which drifted to 357 entries against the
 *     census's 355, so the two disagreed on the denominator of every share.
 *   - The text report called toFixed on each percentage without checking it,
 *     so a snapshot without them printed no report, only `Cannot read
 *     properties of undefined (reading 'toFixed')`, and exited 1, while
 *     `--format json` and `--format html` exited 0 on the same snapshot.
 */

import { describe, it, mock } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

import { formatNumber } from '../lib/census/format.mjs';
import { renderTerminal } from '../lib/census/report-terminal.mjs';
import * as style from '../lib/cli-style.mjs';

/** A payload with the fields the client validates and the renderers read. */
function snapshot(overrides = {}) {
  return {
    totalDownloads: 7_103_335_621,
    measuredDownloads: 6_360_204_128,
    modelledDownloads: 743_131_493,
    measuredShareOfTotal: 89.5,
    totalWeakDownloads: 1_027_777_533,
    totalModernDownloads: 6_071_142_439,
    totalPqcDownloads: 4_415_649,
    weakPercentage: 14.5,
    modernPercentage: 85.5,
    pqcPercentage: 0.1,
    weakToPqcRatio: 233,
    totalCryptoCves: 735,
    totalAdvisories: 7,
    nistDeadline2030: '3 yrs, 158 days',
    nistDeadline2035: '8 yrs, 159 days',
    collectedAt: '2026-07-28T04:34:38.416Z',
    catalogSize: 355,
    ecosystemCount: 11,
    npm: { weak: 0, modern: 0, pqc: 0, total: 0, topPackages: [], period: {} },
    cveBreakdown: [],
    advisoryBreakdown: [],
    ...overrides,
  };
}

const response = (status, body) => ({
  ok: status >= 200 && status < 300,
  status,
  json: async () => body,
});

/**
 * Load the client against an isolated state directory, so a test never reads or
 * writes the developer's real ~/.cryptoserve cache. The module is cache-busted
 * because CENSUS_URL is resolved at import time.
 */
let loadCounter = 0;
async function loadClient(home) {
  process.env.CRYPTOSERVE_HOME = home;
  process.env.CRYPTOSERVE_CENSUS_URL = 'https://census.example.test/api/census';
  return import(`../lib/census/index.mjs?t=${++loadCounter}`);
}

const libFile = (rel) => fileURLToPath(new URL(`../lib/census/${rel}`, import.meta.url));

const CLI = fileURLToPath(new URL('../bin/cryptoserve.mjs', import.meta.url));

/** The text report for `data`, without colour codes. */
function renderText(data) {
  return style.unstyled(renderTerminal(data, style));
}

/** A PyPI section with one package, which snapshot() leaves out. */
const pypi = (pkg = { name: 'cryptography', downloads: 1_200_000_000, tier: 'modern' }) => ({
  weak: 5, modern: 1_500_000, pqc: 0, total: 1_500_005, topPackages: [pkg],
});

describe('format', () => {
  it('abbreviates at each threshold', () => {
    assert.equal(formatNumber(999), '999');
    assert.equal(formatNumber(1_500), '1.5K');
    assert.equal(formatNumber(2_500_000), '2.5M');
    assert.equal(formatNumber(7_103_335_621), '7.1B');
  });
});

describe('census client', () => {
  it('returns the published snapshot as fetched, computing nothing', async () => {
    const home = mkdtempSync(join(tmpdir(), 'cs-census-'));
    const { fetchCensus } = await loadClient(home);
    const published = snapshot();

    const result = await fetchCensus({
      noCache: true,
      fetchFn: async () => response(200, published),
    });

    assert.equal(result.source, 'network');
    assert.deepEqual(result.data, published,
      'the client altered the published payload; it must render it, not recompute it');
    rmSync(home, { recursive: true, force: true });
  });

  it('refuses a response that is not a census snapshot', async () => {
    // A captive portal, a redirected CDN or a wrong URL all answer 200 with
    // something. Rendering that as a census is worse than failing.
    const home = mkdtempSync(join(tmpdir(), 'cs-census-'));
    const { fetchCensus } = await loadClient(home);

    await assert.rejects(
      () => fetchCensus({ noCache: true, fetchFn: async () => response(200, { hello: 'world' }) }),
      /not a census snapshot/);

    await assert.rejects(
      () => fetchCensus({ noCache: true, fetchFn: async () => response(503, {}) }),
      /HTTP 503/);
    rmSync(home, { recursive: true, force: true });
  });

  it('names the transport failure rather than reporting a bare error', async () => {
    // Node reports every transport failure as "fetch failed" and puts the
    // reason on the cause. Without it, a typo in a hostname and a firewall look
    // identical to whoever has to fix it.
    const home = mkdtempSync(join(tmpdir(), 'cs-census-'));
    const { fetchCensus } = await loadClient(home);

    const err = await fetchCensus({
      noCache: true,
      fetchFn: async () => {
        const e = new Error('fetch failed');
        e.cause = { code: 'ENOTFOUND' };
        throw e;
      },
    }).then(() => null, (e) => e);

    assert.ok(err, 'an unreachable host resolved successfully');
    assert.match(err.message, /ENOTFOUND/, 'the reason was discarded');
    rmSync(home, { recursive: true, force: true });
  });

  it('never invents a snapshot when it has none', async () => {
    const home = mkdtempSync(join(tmpdir(), 'cs-census-'));
    const { fetchCensus } = await loadClient(home);

    const err = await fetchCensus({
      noCache: true,
      fetchFn: async () => { throw new Error('offline'); },
    }).then(() => null, (e) => e);

    assert.ok(err?.censusUnavailable, 'a failed fetch produced a result instead of an error');
    rmSync(home, { recursive: true, force: true });
  });

  it('serves a stale cache only when it says so', async () => {
    const home = mkdtempSync(join(tmpdir(), 'cs-census-'));
    const { fetchCensus } = await loadClient(home);
    const published = snapshot();

    await fetchCensus({ noCache: true, fetchFn: async () => response(200, published) });

    const cache = join(home, 'census-cache.json');
    assert.ok(existsSync(cache), 'a successful fetch did not populate the cache');
    const cached = JSON.parse(readFileSync(cache, 'utf-8'));
    cached.fetchedAt = new Date(Date.now() - 40 * 24 * 3600 * 1000).toISOString();
    writeFileSync(cache, JSON.stringify(cached));

    const result = await fetchCensus({ fetchFn: async () => { throw new Error('offline'); } });
    assert.equal(result.source, 'stale-cache',
      'a month-old cached snapshot was returned as if it were current');
    assert.match(result.failure, /offline/, 'the reason for falling back was not recorded');
    assert.equal(result.data.totalDownloads, published.totalDownloads);
    rmSync(home, { recursive: true, force: true });
  });

  it('measures cache age from the fetch, not from the snapshot date', async () => {
    // The snapshot's own collectedAt is the date of the measurement. Keying the
    // TTL on it expires every entry the moment it is written, because a
    // published snapshot is legitimately weeks old.
    const home = mkdtempSync(join(tmpdir(), 'cs-census-'));
    const { fetchCensus } = await loadClient(home);
    const old = snapshot({ collectedAt: '2026-03-18T00:00:00.000Z' });

    await fetchCensus({ noCache: true, fetchFn: async () => response(200, old) });

    const fetchFn = mock.fn(async () => response(200, old));
    const result = await fetchCensus({ fetchFn });
    assert.equal(result.source, 'cache',
      'a snapshot collected months ago was treated as an expired cache entry');
    assert.equal(fetchFn.mock.callCount(), 0, 'the cache was not used');
    rmSync(home, { recursive: true, force: true });
  });

  it('carries no package catalog, collectors or aggregator of its own', () => {
    // The one that drifted to 357 against the census's 355. There is now one
    // catalog and it is not in this package.
    for (const gone of ['package-catalog.mjs', 'collectors', 'aggregator.mjs']) {
      assert.equal(existsSync(libFile(gone)), false,
        `lib/census/${gone} is back; the CLI is measuring the census again`);
    }
  });
});

describe('census text report', () => {
  it('prints each figure of a complete snapshot as published', () => {
    const out = renderText(snapshot({ pypi: pypi() }));

    assert.match(out, /Weak crypto downloads +1\.0B\/month \(14\.5%\)/);
    assert.match(out, /Modern crypto downloads +6\.1B\/month \(85\.5%\)/);
    assert.match(out, /PQC crypto downloads +4\.4M\/month \(0\.1%\)/);
    assert.match(out, /Weak-to-PQC ratio +1 PQC for every 233 weak/);
    assert.match(out, /cryptography +1\.2B +MODERN/);
    assert.doesNotMatch(out, /not in this snapshot|\babsent\b/i,
      'a complete snapshot was reported as lacking a figure');
  });

  it('shows the counts of a snapshot that lacks the percentages, and names them', () => {
    // Each percentage was read with toFixed unchecked: this snapshot printed
    // no report, only Node's TypeError, and exited 1.
    const data = snapshot({ pypi: pypi(), modernPercentage: null });
    delete data.weakPercentage;
    delete data.pqcPercentage;

    const out = renderText(data);

    assert.match(out, /Weak crypto downloads +1\.0B\/month \(share not in this snapshot\)/);
    assert.match(out, /Modern crypto downloads +6\.1B\/month \(share not in this snapshot\)/);
    assert.match(out, /PQC crypto downloads +4\.4M\/month \(share not in this snapshot\)/);
    assert.match(out, /^ {2}Not in this snapshot: weakPercentage, modernPercentage, pqcPercentage$/m);
    assert.doesNotMatch(out, /undefined|NaN/);
  });

  it('marks a table cell or date the snapshot lacks instead of stopping the report', () => {
    // A package without a tier stopped the report at `pkg.tier.toUpperCase()`
    // and an advisory without bySeverity at `adv.bySeverity.critical`. A
    // snapshot without collectedAt printed no collection date and said nothing.
    const data = snapshot({
      pypi: pypi({ name: 'cryptography', downloads: 1_200_000_000 }),
      advisoryBreakdown: [{ cweId: 'CWE-327', count: 7 }],
      weakToPqcRatio: null,
    });
    delete data.collectedAt;

    const out = renderText(data);

    assert.match(out, /Snapshot collected +not in this snapshot/);
    assert.match(out, /cryptography +1\.2B +absent/);
    assert.match(out, /CWE-327 +7 +absent +absent +absent +absent/);
    assert.match(out, /Weak-to-PQC ratio +No PQC downloads detected/,
      'a null ratio no longer reads as no PQC downloads');
    assert.match(out, new RegExp('^ {2}Not in this snapshot: collectedAt, pypi\\.topPackages\\[\\]\\.tier, ' +
      'advisoryBreakdown\\[\\]\\.bySeverity\\.critical, advisoryBreakdown\\[\\]\\.bySeverity\\.high, ' +
      'advisoryBreakdown\\[\\]\\.bySeverity\\.medium, advisoryBreakdown\\[\\]\\.bySeverity\\.low$', 'm'));
    assert.doesNotMatch(out, /undefined|NaN/);
  });

  it('renders a cached snapshot that lacks most figures, on stdout and to --output, and exits 0', () => {
    // The payload the `census --output` tests carried until #108 gave them
    // every field the text report reads. `cryptoserve census` printed
    // `Error: Cannot read properties of undefined (reading 'toFixed')` and
    // exited 1 on it, and `census --output` wrote no file.
    const home = mkdtempSync(join(tmpdir(), 'cs-census-'));
    writeFileSync(join(home, 'census-cache.json'), JSON.stringify({
      fetchedAt: new Date().toISOString(),
      source: 'test',
      payload: {
        totalDownloads: 100,
        collectedAt: '2026-07-28T04:34:38.416Z',
        npm: { weak: 0, modern: 0, pqc: 0, total: 0, topPackages: [], period: {} },
      },
    }));

    // A closed local port: a run that did not use the cache fails at once
    // instead of reaching the network.
    const census = (...args) => spawnSync(process.execPath, [CLI, 'census', ...args], {
      encoding: 'utf-8',
      timeout: 60_000,
      env: {
        ...process.env,
        NO_COLOR: '1',
        CRYPTOSERVE_HOME: home,
        CRYPTOSERVE_CENSUS_URL: 'http://127.0.0.1:9/api/census',
      },
    });
    const r = census();
    const report = join(home, 'report.txt');
    const written = census('--output', report);
    const file = existsSync(report) ? readFileSync(report, 'utf-8') : null;
    rmSync(home, { recursive: true, force: true });

    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stderr, '');
    assert.match(r.stdout, /Snapshot collected +2026-07-28/);
    assert.match(r.stdout, /Weak crypto downloads +not in this snapshot/);
    assert.match(r.stdout, /PQC Readiness\n {2}not in this snapshot/);
    assert.match(r.stdout, new RegExp('^ {2}Not in this snapshot: totalWeakDownloads, weakPercentage, ' +
      'totalModernDownloads, modernPercentage, totalPqcDownloads, pqcPercentage, weakToPqcRatio, ' +
      'totalCryptoCves, totalAdvisories, nistDeadline2030, nistDeadline2035, pypi, cveBreakdown, ' +
      'advisoryBreakdown$', 'm'));
    assert.doesNotMatch(r.stdout, /undefined|NaN/);

    assert.equal(written.status, 0, written.stderr);
    assert.equal(written.stdout.trim(), `Census report written to ${report}`);
    assert.equal(file, r.stdout, 'census --output wrote another report than census printed');
  });
});
