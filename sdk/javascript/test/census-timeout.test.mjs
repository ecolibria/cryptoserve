/**
 * Guards the deadline on the census fetch.
 *
 * The original defect: no collector set a deadline, so a registry that accepted
 * the connection and never answered blocked `cryptoserve census` indefinitely --
 * no output, no timeout, no way to tell a slow run from a hung one. The command
 * now makes one request instead of thirteen, but a single hung request is still
 * a hung command, so the deadline moved rather than went away.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { DEFAULT_REQUEST_TIMEOUT_MS } from '../lib/census/index.mjs';

let loadCounter = 0;
async function loadClient(home) {
  process.env.CRYPTOSERVE_HOME = home;
  process.env.CRYPTOSERVE_CENSUS_URL = 'https://census.example.test/api/census';
  return import(`../lib/census/index.mjs?t=timeout${++loadCounter}`);
}

/** A server that accepts the connection and never answers. */
const hang = (_url, options) => new Promise((_resolve, reject) => {
  options.signal.addEventListener('abort', () => {
    const err = new Error('This operation was aborted');
    err.name = 'AbortError';
    reject(err);
  });
});

describe('census fetch deadline', () => {
  it('has a non-zero default deadline', () => {
    assert.ok(DEFAULT_REQUEST_TIMEOUT_MS > 0);
    assert.ok(DEFAULT_REQUEST_TIMEOUT_MS <= 60_000);
  });

  it('gives up on a hung server instead of blocking the command', async () => {
    const home = mkdtempSync(join(tmpdir(), 'cs-census-t-'));
    const { fetchCensus } = await loadClient(home);

    const started = Date.now();
    const err = await fetchCensus({ noCache: true, timeoutMs: 50, fetchFn: hang })
      .then(() => null, (e) => e);
    const elapsed = Date.now() - started;

    assert.ok(err, 'a hung server produced a result');
    assert.ok(elapsed < 2000, `should have given up quickly, took ${elapsed}ms`);
    rmSync(home, { recursive: true, force: true });
  });

  it('says it timed out rather than reporting an abort', async () => {
    // "This operation was aborted" describes our own AbortController, not the
    // problem. The reader needs to know the server did not answer.
    const home = mkdtempSync(join(tmpdir(), 'cs-census-t-'));
    const { fetchCensus } = await loadClient(home);

    const err = await fetchCensus({ noCache: true, timeoutMs: 50, fetchFn: hang })
      .then(() => null, (e) => e);

    assert.match(err.message, /no response within 0s|no response within \d+s/,
      `unhelpful timeout message: ${err.message}`);
    assert.doesNotMatch(err.message, /aborted/i);
    rmSync(home, { recursive: true, force: true });
  });
});
