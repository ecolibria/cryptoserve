import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { fetchWithTimeout, DEFAULT_REQUEST_TIMEOUT_MS, runCensus } from '../lib/census/index.mjs';

describe('fetchWithTimeout', () => {
  it('passes a successful response through unchanged', async () => {
    const stub = async () => ({ ok: true, status: 200, json: async () => ({ downloads: 42 }) });
    const res = await fetchWithTimeout(1000, stub)('https://example.invalid');
    assert.equal(res.ok, true);
    assert.deepEqual(await res.json(), { downloads: 42 });
  });

  it('turns a hung request into a non-ok response instead of hanging', async () => {
    // Regression: no collector set a deadline, so a registry that accepted the
    // connection and never answered blocked the whole census indefinitely.
    const hang = (_url, options) => new Promise((_resolve, reject) => {
      options.signal.addEventListener('abort', () => {
        const err = new Error('aborted');
        err.name = 'AbortError';
        reject(err);
      });
    });

    const started = Date.now();
    const res = await fetchWithTimeout(50, hang)('https://example.invalid');
    const elapsed = Date.now() - started;

    assert.equal(res.ok, false);
    assert.equal(res.status, 408);
    assert.match(res.statusText, /timeout after 50ms/);
    assert.ok(elapsed < 2000, `should have given up quickly, took ${elapsed}ms`);
  });

  it('gives a timed-out response the shape collectors expect', async () => {
    const hang = (_url, options) => new Promise((_resolve, reject) => {
      options.signal.addEventListener('abort', () => {
        const err = new Error('aborted');
        err.name = 'AbortError';
        reject(err);
      });
    });
    const res = await fetchWithTimeout(20, hang)('https://example.invalid');
    // Collectors branch on res.ok then call res.json(); both must be safe.
    assert.equal(typeof res.json, 'function');
    assert.deepEqual(await res.json(), {});
    assert.equal(await res.text(), '');
  });

  it('propagates non-timeout errors', async () => {
    const boom = async () => { throw new Error('DNS failure'); };
    await assert.rejects(() => fetchWithTimeout(1000, boom)('https://example.invalid'), /DNS failure/);
  });

  it('has a non-zero default deadline', () => {
    assert.ok(DEFAULT_REQUEST_TIMEOUT_MS > 0);
    assert.ok(DEFAULT_REQUEST_TIMEOUT_MS <= 60_000);
  });
});

describe('runCensus progress', () => {
  it('reports progress without requiring --verbose', async () => {
    const messages = [];
    const stubFetch = async () => ({ ok: true, status: 200, json: async () => ({ downloads: 0 }) });

    await runCensus({
      noCache: true,
      sources: ['npm'],
      fetchFn: stubFetch,
      onProgress: msg => messages.push(msg),
    });

    assert.ok(messages.length > 0, 'a silent multi-minute command reads as hung');
    assert.ok(messages.some(m => /npm/i.test(m)), `no npm progress line in ${JSON.stringify(messages)}`);
  });
});
