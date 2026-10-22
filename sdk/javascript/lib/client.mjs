/**
 * HTTP client for CryptoServe server API.
 *
 * Uses global fetch (Node 18+) — zero dependencies.
 * Used only when connected to a server; all scanning/PQC/crypto work offline.
 */

import { loadToken, saveToken } from './credentials.mjs';
import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';

const DEFAULT_SERVER = 'https://localhost:8003';
const CALLBACK_PORT = 9876;
// A loopback IP literal rather than "localhost" (RFC 8252 section 7.3): the
// listener is reachable from this machine only, and no resolver decides which
// interface the redirect lands on.
const CALLBACK_HOST = '127.0.0.1';
const MAX_TOKEN_LENGTH = 8192;

// ---------------------------------------------------------------------------
// URL validation (SSRF protection)
// ---------------------------------------------------------------------------

const BLOCKED_HOSTS = [
  '169.254.169.254',            // AWS metadata
  'metadata.google.internal',   // GCP metadata
  '100.100.100.200',            // Alibaba metadata
  'fd00::',                     // IPv6 link-local
];

function validateServerUrl(url) {
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      throw new Error('Server URL must use http or https');
    }
    if (BLOCKED_HOSTS.some(h => parsed.hostname === h || parsed.hostname.includes(h))) {
      throw new Error('Server URL points to a blocked address');
    }
    return parsed.toString().replace(/\/$/, '');
  } catch (e) {
    if (e.message.includes('blocked') || e.message.includes('must use')) throw e;
    throw new Error(`Invalid server URL: ${url}`);
  }
}

// ---------------------------------------------------------------------------
// API client
// ---------------------------------------------------------------------------

export async function apiCall(method, path, body = null, options = {}) {
  const creds = loadToken();
  if (!creds) throw new Error('Not logged in. Run "cryptoserve login" first.');

  const server = validateServerUrl(options.server || creds.server || DEFAULT_SERVER);
  const url = `${server}${path}`;

  const headers = {
    'Content-Type': 'application/json',
    'Cookie': `session=${creds.token}`,
  };

  const fetchOpts = {
    method,
    headers,
    signal: AbortSignal.timeout(options.timeout || 30000),
  };

  if (body) fetchOpts.body = JSON.stringify(body);

  const response = await fetch(url, fetchOpts);

  if (!response.ok) {
    if (response.status === 401) {
      throw new Error('Session expired. Run "cryptoserve login" again.');
    }
    throw new Error(`API error ${response.status}: ${await response.text()}`);
  }

  return response.json();
}

export async function getStatus(server = null) {
  const creds = loadToken();
  const url = validateServerUrl(server || creds?.server || DEFAULT_SERVER);

  try {
    const start = Date.now();
    const response = await fetch(`${url}/health`, {
      signal: AbortSignal.timeout(10000),
    });
    const latency = Date.now() - start;
    const data = await response.json();
    return { connected: true, latency, ...data };
  } catch (e) {
    return { connected: false, error: e.message };
  }
}

// ---------------------------------------------------------------------------
// Login flow (browser OAuth with a loopback callback)
// ---------------------------------------------------------------------------

function launchBrowser(url) {
  // Use spawn with array args to prevent command injection
  import('node:child_process').then(m => {
    const cmd = process.platform === 'darwin' ? 'open'
      : process.platform === 'win32' ? 'start'
      : 'xdg-open';
    m.spawn(cmd, [url], { stdio: 'ignore', detached: true }).unref();
  });
}

/** Constant-time comparison. A value of another length is a mismatch. */
function stateMatches(received, expected) {
  if (typeof received !== 'string') return false;
  const a = Buffer.from(received);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Browser login against an explicit server.
 *
 * No default. It used to fall back to https://localhost:8003, so a new user
 * running `cryptoserve login` was sent to an address where nothing runs on
 * their machine, and the flow could only ever time out. The CLI cannot know
 * the operator's server, and a guess that is wrong for everyone is worse than
 * an error that names what to pass.
 *
 * The callback listener binds 127.0.0.1 only. The authorization URL carries a
 * random `state`, and the listener stores a token only from a GET to /callback
 * that returns that `state` unchanged. Any other request is answered with an
 * error and stores nothing, and the listener keeps waiting for the right
 * callback or the timeout.
 *
 * `openBrowser` replaces the browser launch; tests pass a no-op.
 */
export async function login(serverUrl, { openBrowser = launchBrowser } = {}) {
  if (!serverUrl) {
    throw new Error('login requires a server URL. Pass --server <url>.');
  }
  const server = validateServerUrl(serverUrl);
  const redirectUri = `http://${CALLBACK_HOST}:${CALLBACK_PORT}/callback`;
  const state = randomBytes(32).toString('base64url');

  // Start local callback server
  return new Promise((resolve, reject) => {
    let settled = false;
    let timer = null;
    const finish = (fn, arg) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      try { httpServer.close(); } catch { /* already closed */ }
      fn(arg);
    };

    // Every refusal answers and returns without calling finish, so the
    // listener keeps waiting for the right callback or the timeout.
    const refuse = (res, status, message, headers = {}) => {
      res.writeHead(status, headers);
      res.end(message);
    };

    const httpServer = createServer((req, res) => {
      let url;
      try {
        url = new URL(req.url, `http://${CALLBACK_HOST}:${CALLBACK_PORT}`);
      } catch {
        // A request target such as `//[` is accepted by the HTTP parser and
        // throws here; uncaught, it would end the login.
        return refuse(res, 400, 'Bad request');
      }
      if (url.pathname !== '/callback') return refuse(res, 404, 'Not found');
      if (req.method !== 'GET') return refuse(res, 405, 'Method not allowed', { Allow: 'GET' });
      if (!stateMatches(url.searchParams.get('state'), state)) {
        return refuse(res, 400, 'Missing or wrong state');
      }

      const token = url.searchParams.get('token') || url.searchParams.get('session');
      if (!token) return refuse(res, 400, 'Missing token');
      if (token.length > MAX_TOKEN_LENGTH) return refuse(res, 400, 'Token too long');

      saveToken(token, server);
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><body><h2>Login successful</h2><p>You can close this tab.</p></body></html>');
      finish(resolve, { success: true, server });
    });

    // Without this the http server emits an unhandled 'error' and the process
    // dies with a raw Node stack trace. EADDRINUSE is the ordinary case: a
    // previous login left the port held.
    httpServer.on('error', (err) => {
      const message = err.code === 'EADDRINUSE'
        ? `The login callback port ${CALLBACK_PORT} is already in use. `
          + 'Another cryptoserve login is probably still running; close it and try again.'
        : `Could not start the login callback listener on port ${CALLBACK_PORT}: ${err.message}`;
      finish(reject, new Error(message));
    });

    httpServer.listen(CALLBACK_PORT, CALLBACK_HOST, () => {
      const authUrl = `${server}/auth/cli?redirect=${encodeURIComponent(redirectUri)}&state=${state}`;
      console.log(`\nOpen this URL to log in:\n  ${authUrl}\n`);
      openBrowser(authUrl);
    });

    // Timeout after 120 seconds
    timer = setTimeout(() => {
      finish(reject, new Error('Login timed out after 120 seconds'));
    }, 120000);
  });
}
