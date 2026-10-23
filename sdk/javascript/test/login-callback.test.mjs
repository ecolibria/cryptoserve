/**
 * The `cryptoserve login` callback listener.
 *
 * The listener binds 127.0.0.1 only, and stores a token only from a GET to
 * /callback whose `state` equals the random value the CLI put in the
 * authorization URL. Any other request is answered with an error, stores
 * nothing, and leaves the listener waiting for the right callback.
 *
 * Each case runs a real login on port 9876 with a scratch CRYPTOSERVE_HOME
 * (so the token store is a temp file) and a no-op browser launcher, and reads
 * the state from the printed authorization URL. Each case ends by completing
 * the login with the issued state, which is also the check that the listener
 * was still waiting after the requests it refused.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { request } from 'node:http';
import { connect } from 'node:net';
import { networkInterfaces, tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { login } from '../lib/client.mjs';
import { loadToken, tokenStorePath } from '../lib/credentials.mjs';

const PORT = 9876;
const SERVER = 'https://example.invalid';
const CELL = { timeout: 60000 };

const delay = (ms) => new Promise((res) => setTimeout(res, ms));

/** A token value assembled at run time from fragments. */
function makeToken(label) {
  return ['cs', 'login', label, randomBytes(12).toString('hex')].join('.');
}

function callbackQuery(params) {
  return new URLSearchParams(params).toString();
}

/** One request to the callback port on 127.0.0.1, on its own connection. */
function send(method, path) {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port: PORT, method, path, agent: false }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    // A listener that never answers fails the case instead of holding the
    // connection, and with it this test file, open.
    req.setTimeout(5000, () => {
      req.destroy(new Error(`no response to ${method} ${path.split('?')[0]} within 5 seconds`));
    });
    req.on('error', reject);
    req.end();
  });
}

/** 'connected', or why a TCP connection to host:PORT was not made. */
function probe(host) {
  return new Promise((resolve) => {
    const socket = connect({ host, port: PORT });
    socket.setTimeout(2000, () => { socket.destroy(); resolve('timeout'); });
    socket.once('connect', () => { socket.destroy(); resolve('connected'); });
    socket.once('error', (err) => resolve(err.code ?? 'error'));
  });
}

function nonLoopbackIPv4() {
  return Object.values(networkInterfaces()).flat()
    .filter((a) => a && !a.internal && (a.family === 'IPv4' || a.family === 4))
    .map((a) => a.address);
}

async function until(predicate, what, ms = 10000) {
  const deadline = Date.now() + ms;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await delay(5);
  }
}

async function withTimeout(promise, what, ms = 5000) {
  let timer;
  const expired = new Promise((_, rej) => {
    timer = setTimeout(() => rej(new Error(`timed out waiting for ${what}`)), ms);
  });
  try {
    return await Promise.race([promise, expired]);
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// One scratch home and one capture of console.log per test; every login a
// test starts is completed before the home is removed and the environment
// restored, so no token can land in a real credential store.
// ---------------------------------------------------------------------------

const contexts = new WeakMap();

function testContext(t) {
  let ctx = contexts.get(t);
  if (ctx) return ctx;
  const home = realpathSync(mkdtempSync(join(tmpdir(), 'cryptoserve-login-callback-')));
  const previousHome = process.env.CRYPTOSERVE_HOME;
  process.env.CRYPTOSERVE_HOME = home;
  const lines = [];
  t.mock.method(console, 'log', (...args) => { lines.push(args.join(' ')); });
  ctx = { home, lines, runs: [] };
  contexts.set(t, ctx);
  t.after(async () => {
    for (const run of ctx.runs) await endLogin(run);
    if (previousHome === undefined) delete process.env.CRYPTOSERVE_HOME;
    else process.env.CRYPTOSERVE_HOME = previousHome;
    rmSync(home, { recursive: true, force: true });
  });
  return ctx;
}

function authUrlIn(lines) {
  const match = lines.join('\n').match(/https?:\/\/\S+\/auth\/cli\?\S+/);
  return match ? match[0] : null;
}

/**
 * Start a login and wait until its listener is up (the authorization URL is
 * printed from the listen callback). Test files run in parallel and
 * cli-argument-contracts.test.mjs holds the same port for a moment, so a busy
 * port is retried rather than failed.
 */
async function startLogin(t) {
  const ctx = testContext(t);
  for (let attempt = 0; ; attempt++) {
    const from = ctx.lines.length;
    const run = { settled: false };
    run.done = login(SERVER, { openBrowser: () => {} })
      .then((value) => ({ value }), (error) => ({ error }))
      .then((outcome) => { run.settled = true; return outcome; });
    await until(() => run.settled || authUrlIn(ctx.lines.slice(from)) !== null,
      'the login listener to start');

    if (!run.settled) {
      run.authUrl = authUrlIn(ctx.lines.slice(from));
      run.state = new URL(run.authUrl).searchParams.get('state');
      ctx.runs.push(run);
      return run;
    }
    const { error } = await run.done;
    if (error && /already in use/.test(error.message) && attempt < 200) {
      await delay(50);
      continue;
    }
    throw error ?? new Error('login resolved before its listener started');
  }
}

/** Complete a login that is still waiting, with the state it issued. */
async function endLogin(run) {
  if (!run.settled) {
    const query = callbackQuery({ state: run.state ?? '', token: makeToken('cleanup') });
    try { await send('GET', `/callback?${query}`); } catch { /* listener already closed */ }
  }
  await withTimeout(run.done, 'login to end').catch(() => { /* reported by the case itself */ });
}

/** The refused request stored nothing and the login is still waiting. */
async function assertNothingStoredAndWaiting(run) {
  await new Promise((res) => setImmediate(res));
  assert.equal(existsSync(tokenStorePath()), false, 'a token was stored');
  assert.equal(run.settled, false, 'the login ended instead of waiting for the issued state');
}

/** A GET to /callback with the issued state stores the token and resolves login. */
async function assertCompletes(run, token = makeToken('control'), param = 'token') {
  const res = await send('GET', `/callback?${callbackQuery({ state: run.state ?? '', [param]: token })}`);
  assert.equal(res.status, 200, `the issued state was refused: ${res.status} ${res.body}`);
  const outcome = await withTimeout(run.done, 'login to resolve');
  assert.ifError(outcome.error);
  assert.deepEqual(outcome.value, { success: true, server: SERVER });
  const stored = loadToken();
  assert.ok(stored, 'no token was stored');
  assert.ok(Buffer.from(stored.token).equals(Buffer.from(token)), 'the stored token differs from the one sent');
  assert.equal(stored.server, SERVER);
}

// ---------------------------------------------------------------------------

describe('login callback listener', () => {
  it('listens on 127.0.0.1 only', CELL, async (t) => {
    const run = await startLogin(t);
    // The loopback address accepts, so a refusal below is the bind address,
    // not a listener that is down.
    assert.equal(await probe('127.0.0.1'), 'connected');
    const others = nonLoopbackIPv4();
    if (others.length === 0) {
      t.diagnostic('this host has no non-loopback IPv4 address; probed ::1 only');
    }
    const accepting = [];
    for (const host of [...others, '::1']) {
      if (await probe(host) === 'connected') accepting.push(host);
    }
    assert.deepEqual(accepting, [], `the listener accepts connections on ${accepting.join(', ')}`);
    await assertCompletes(run);
  });

  it('prints an authorization URL with the loopback redirect and a new random state', CELL, async (t) => {
    const first = await startLogin(t);
    const query = new URL(first.authUrl).search;
    assert.match(query, /[?&]redirect=http%3A%2F%2F127\.0\.0\.1%3A9876%2Fcallback(&|$)/,
      `the redirect is not the encoded loopback callback: ${first.authUrl}`);
    assert.match(first.state ?? '', /^[A-Za-z0-9_-]{43}$/,
      `the state is not 32 random bytes in base64url: ${first.authUrl}`);
    await assertCompletes(first);

    const second = await startLogin(t);
    assert.notEqual(second.state, first.state, 'two logins issued the same state');
    await assertCompletes(second);
  });

  it('answers 400 to a callback with no state, stores nothing, and keeps waiting', CELL, async (t) => {
    const run = await startLogin(t);
    const res = await send('GET', `/callback?${callbackQuery({ token: makeToken('nostate') })}`);
    assert.equal(res.status, 400);
    await assertNothingStoredAndWaiting(run);
    await assertCompletes(run);
  });

  it('answers 400 to a callback with another state, stores nothing, and keeps waiting', CELL, async (t) => {
    const run = await startLogin(t);
    const issued = run.state ?? '';
    const others = [
      randomBytes(32).toString('base64url'), // same length, other value
      issued.slice(0, -1),                   // a prefix
      `${issued}A`,                          // an extension
    ];
    for (const state of others) {
      const res = await send('GET', `/callback?${callbackQuery({ state, token: makeToken('wrongstate') })}`);
      assert.equal(res.status, 400, `state ${JSON.stringify(state)} answered ${res.status}`);
    }
    await assertNothingStoredAndWaiting(run);
    await assertCompletes(run);
  });

  it('answers 404 on another path even with the issued state, and stores nothing', CELL, async (t) => {
    const run = await startLogin(t);
    for (const path of ['/', '/callback/', '/other']) {
      const query = callbackQuery({ state: run.state ?? '', token: makeToken('path') });
      const res = await send('GET', `${path}?${query}`);
      assert.equal(res.status, 404, `${path} answered ${res.status}`);
    }
    await assertNothingStoredAndWaiting(run);
    await assertCompletes(run);
  });

  it('stores the token from a GET to /callback carrying the issued state, and resolves', CELL, async (t) => {
    const run = await startLogin(t);
    await assertCompletes(run);
  });

  it('answers 405 to a POST to /callback even with the issued state, and stores nothing', CELL, async (t) => {
    const run = await startLogin(t);
    const query = callbackQuery({ state: run.state ?? '', token: makeToken('post') });
    const res = await send('POST', `/callback?${query}`);
    assert.equal(res.status, 405);
    assert.equal(res.headers.allow, 'GET');
    await assertNothingStoredAndWaiting(run);
    await assertCompletes(run);
  });

  it('answers 400 to a token longer than 8192 characters and accepts one of 8192', CELL, async (t) => {
    const run = await startLogin(t);
    const tooLong = makeToken('long').padEnd(8193, 'x');
    const res = await send('GET', `/callback?${callbackQuery({ state: run.state ?? '', token: tooLong })}`);
    assert.equal(res.status, 400);
    await assertNothingStoredAndWaiting(run);
    await assertCompletes(run, makeToken('max').padEnd(8192, 'x'));
  });

  it('answers 400 to a request target that does not parse as a URL, and keeps waiting', CELL, async (t) => {
    const run = await startLogin(t);
    const query = callbackQuery({ state: run.state ?? '', token: makeToken('target') });
    const res = await send('GET', `//[?${query}`);
    assert.equal(res.status, 400);
    await assertNothingStoredAndWaiting(run);
    await assertCompletes(run);
  });

  it('takes the token from the session parameter, as before', CELL, async (t) => {
    const run = await startLogin(t);
    await assertCompletes(run, makeToken('session'), 'session');
  });
});
