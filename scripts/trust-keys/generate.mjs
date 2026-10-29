#!/usr/bin/env node
/**
 * Build the key table that the certificate engine and `cryptoserve scan` check
 * certificates against, from the certificates committed under testdata/trust-keys.
 *
 * Every key value in the table is recomputed here from a committed certificate,
 * so a reviewer can re-derive any row with openssl. A new advisory adds a
 * directory of certificates and an entry in GROUPS, not code.
 *
 * Outputs, all derived from the same reading:
 *   - backend/app/core/trust_keys.json and sdk/javascript/lib/trust-keys.json,
 *     byte-equal. Two copies because the backend image and the npm package
 *     each ship only their own directory.
 *   - testdata/trust-keys/scan/*.crt, the layouts a repository commits
 *     (a leaf alone, a chain file, a CA bundle), built from the certificates
 *     above so the scan fixture cannot drift from them.
 *   - The key table on docs/findings/trust-compromised-key.md and
 *     docs/findings/trust-distrusted-root.md, between the trust-keys markers.
 *
 * Usage:
 *   node scripts/trust-keys/generate.mjs           write the outputs
 *   node scripts/trust-keys/generate.mjs --check   exit 1 if any output differs
 *
 * Zero dependencies: node:crypto, node:fs and node:path only.
 */

import { X509Certificate, createHash } from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const FIXTURES = join(ROOT, 'testdata', 'trust-keys');

const BUG_2083449 = 'https://bugzilla.mozilla.org/show_bug.cgi?id=2083449';
const CHROME_REMOVAL = 'https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/';

// One entry per directory of certificates. `reported` is the date of the public
// record named in `source`: the creation date of Mozilla bug 2083449, and the
// publication date of the Chrome root program's post.
const GROUPS = [
  { dir: 'listed', status: 'compromised', source: BUG_2083449, reported: '2026-10-18' },
  { dir: 'root', use: 'root', status: 'distrusted', source: CHROME_REMOVAL, reported: '2026-10-20' },
];

const USE_ORDER = ['tls', 'codeSigning', 'root'];
const EKU_SERVER_AUTH = '1.3.6.1.5.5.7.3.1';
const EKU_CODE_SIGNING = '1.3.6.1.5.5.7.3.3';

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

/** Every .crt file under `dir`, one level of subdirectories deep. */
function pemFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      for (const inner of readdirSync(path)) {
        if (inner.endsWith('.crt')) out.push(join(path, inner));
      }
    } else if (entry.name.endsWith('.crt')) {
      out.push(path);
    }
  }
  return out.sort();
}

function commonName(x509) {
  const line = x509.subject.split('\n').find((l) => l.startsWith('CN='));
  return line ? line.slice(3) : null;
}

function useFromEku(x509, file) {
  const eku = x509.keyUsage || [];
  if (eku.includes(EKU_SERVER_AUTH)) return 'tls';
  if (eku.includes(EKU_CODE_SIGNING)) return 'codeSigning';
  throw new Error(`${file}: no serverAuth or codeSigning extended key usage, so its use cannot be derived`);
}

export function buildTable() {
  const bySpki = new Map();
  for (const group of GROUPS) {
    for (const file of pemFiles(join(FIXTURES, group.dir))) {
      const x509 = new X509Certificate(readFileSync(file));
      const spkiDer = x509.publicKey.export({ type: 'spki', format: 'der' });
      const spkiSha256 = sha256(spkiDer);
      const use = group.use || useFromEku(x509, file);
      const name = commonName(x509);
      const row = bySpki.get(spkiSha256) || {
        name,
        use,
        spkiSha256,
        certSha256: [],
        spkiDer: spkiDer.toString('base64'),
        source: group.source,
        reported: group.reported,
        status: group.status,
      };
      // Two certificates for one key must agree on what the key is. The name
      // is a label only; it never decides a match.
      if (row.name !== name || row.use !== use || row.status !== group.status) {
        throw new Error(`${file}: disagrees with another certificate for key ${spkiSha256}`);
      }
      row.certSha256.push(sha256(x509.raw));
      bySpki.set(spkiSha256, row);
    }
  }
  const keys = [...bySpki.values()];
  for (const k of keys) k.certSha256.sort();
  keys.sort((a, b) => USE_ORDER.indexOf(a.use) - USE_ORDER.indexOf(b.use) || a.name.localeCompare(b.name));
  return {
    generatedBy: 'scripts/trust-keys/generate.mjs from the certificates in testdata/trust-keys',
    keys,
  };
}

const read = (rel) => readFileSync(join(FIXTURES, rel), 'utf8');

// The files a repository commits, built from the certificates above:
// a leaf alone (the cert.pem beside chain.pem layout), a chain file holding an
// intermediate and the CA certificate above it, and a CA bundle whose second
// certificate is the removed root.
function scanFixtures() {
  return {
    'scan/cert.crt': read('leaves/crtsh-29977124910/cert.crt'),
    'scan/chain.crt': read('listed/cb6e15165ac802e9b3f993f16c25d41f4e81c21ebde71ae1b012ac00bf9c7c3f/cert.crt')
      + read('anchored/crtsh-14658191778/cert.crt'),
    'scan/ca-bundle.crt': read('control/emsign-root-ca-g1.crt') + read('root/emsign-ecc-root-ca-g3.crt'),
  };
}

const USE_LABEL = { tls: 'TLS intermediate', codeSigning: 'code-signing intermediate', root: 'root' };

export function renderKeyTable(table, uses) {
  const rows = table.keys.filter((k) => uses.includes(k.use));
  const lines = [
    '| Key | Use | SPKI SHA-256 | Certificate SHA-256 | Source | Reported |',
    '|---|---|---|---|---|---|',
  ];
  for (const k of rows) {
    lines.push(`| ${k.name} | ${USE_LABEL[k.use]} | \`${k.spkiSha256}\` | ${k.certSha256.map((c) => `\`${c}\``).join('<br>')} | ${k.source} | ${k.reported} |`);
  }
  return lines.join('\n');
}

const PAGES = {
  'docs/findings/trust-compromised-key.md': ['tls', 'codeSigning'],
  'docs/findings/trust-distrusted-root.md': ['root'],
};
const BEGIN = '<!-- trust-keys:begin (generated by scripts/trust-keys/generate.mjs) -->';
const END = '<!-- trust-keys:end -->';

function withTable(pageText, table, uses, page) {
  const start = pageText.indexOf(BEGIN);
  const end = pageText.indexOf(END);
  if (start < 0 || end < start) throw new Error(`${page}: the trust-keys markers are missing`);
  return `${pageText.slice(0, start + BEGIN.length)}\n${renderKeyTable(table, uses)}\n${pageText.slice(end)}`;
}

function outputs() {
  const table = buildTable();
  const json = `${JSON.stringify(table, null, 2)}\n`;
  const files = {
    'backend/app/core/trust_keys.json': json,
    'sdk/javascript/lib/trust-keys.json': json,
  };
  for (const [rel, text] of Object.entries(scanFixtures())) files[join('testdata/trust-keys', rel)] = text;
  for (const [page, uses] of Object.entries(PAGES)) {
    files[page] = withTable(readFileSync(join(ROOT, page), 'utf8'), table, uses, page);
  }
  return files;
}

function main() {
  const check = process.argv.includes('--check');
  const differing = [];
  for (const [rel, text] of Object.entries(outputs())) {
    const path = join(ROOT, rel);
    const current = existsSync(path) ? readFileSync(path, 'utf8') : null;
    if (current === text) continue;
    if (check) {
      differing.push(rel);
    } else {
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, text);
      console.log(`wrote ${rel}`);
    }
  }
  if (check && differing.length > 0) {
    console.error(`Out of date, run node scripts/trust-keys/generate.mjs: ${differing.join(', ')}`);
    process.exit(1);
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
