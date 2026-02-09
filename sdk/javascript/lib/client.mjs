/**
 * HTTP client for CryptoServe server API.
 *
 * Uses global fetch (Node 18+) — zero dependencies.
 * Used only when connected to a server; all scanning/PQC/crypto work offline.
 */

import { loadToken, saveToken } from './credentials.mjs';
import { createServer } from 'node:http';

const DEFAULT_SERVER = 'https://localhost:8003';
const CALLBACK_PORT = 9876;

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
// Login flow (browser OAuth with localhost callback)
// ---------------------------------------------------------------------------

export async function login(serverUrl = DEFAULT_SERVER) {
  const server = validateServerUrl(serverUrl);

  // Start local callback server
  return new Promise((resolve, reject) => {
    const httpServer = createServer((req, res) => {
      const url = new URL(req.url, `http://localhost:${CALLBACK_PORT}`);
      const token = url.searchParams.get('token') || url.searchParams.get('session');

      if (token) {
        saveToken(token, server);
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<html><body><h2>Login successful</h2><p>You can close this tab.</p></body></html>');
        httpServer.close();
        resolve({ success: true, server });
      } else {
        res.writeHead(400);
        res.end('Missing token');
      }
    });

    httpServer.listen(CALLBACK_PORT, () => {
      const authUrl = `${server}/auth/cli?redirect=http://localhost:${CALLBACK_PORT}/callback`;
      console.log(`\nOpen this URL to log in:\n  ${authUrl}\n`);

      // Try to open browser
      const { exec } = import('node:child_process').then(m => {
        const cmd = process.platform === 'darwin' ? 'open'
          : process.platform === 'win32' ? 'start'
          : 'xdg-open';
        m.exec(`${cmd} "${authUrl}"`);
      });
    });

    // Timeout after 120 seconds
    setTimeout(() => {
      httpServer.close();
      reject(new Error('Login timed out after 120 seconds'));
    }, 120000);
  });
}
