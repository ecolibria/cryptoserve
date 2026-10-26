/**
 * The trust check: a certificate whose key is a publicly compromised CA key
 * (trust/compromised-ca-key), or that is or chains to a root browsers removed
 * (trust/distrusted-root).
 *
 * The keys come from trust-keys.json, which scripts/trust-keys/generate.mjs
 * writes from the certificates in testdata/trust-keys; the certificate engine
 * in the backend reads a byte-equal copy. A match is by key, never by name.
 * Each PEM certificate block of a file is checked on its own:
 *   1. its SPKI SHA-256 is a listed intermediate key            (kind A)
 *   2. its signature verifies under a listed intermediate key   (kind A)
 *   3. its SPKI SHA-256 is the removed root's key               (kind B)
 *   4. its signature verifies under the removed root's key      (kind B)
 * Rule 2 is skipped for a block rule 1 matched and rule 4 for a block rule 3
 * matched, so one block yields at most one finding of each kind.
 *
 * Zero dependencies: node:crypto's X509Certificate.
 */

import { X509Certificate, createHash, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { newlineOffsets, lineAt } from './scanner-languages.mjs';

const TABLE = JSON.parse(readFileSync(new URL('./trust-keys.json', import.meta.url), 'utf8'));

const KEYS = TABLE.keys.map((k) => ({
  spkiSha256: k.spkiSha256,
  use: k.use,
  publicKey: createPublicKey({ key: Buffer.from(k.spkiDer, 'base64'), format: 'der', type: 'spki' }),
}));
const BY_SPKI = new Map(KEYS.map((k) => [k.spkiSha256, k]));

// One Fix per key use. The certificate engine and the finding pages use the
// same words.
export const TRUST_FIX = {
  tls: 'Replace the chain with one issued by a CA none of whose keys is listed, and remove this certificate from any bundle or pin set you ship.',
  codeSigning: 'Re-sign the artifacts with a certificate from a CA none of whose keys is listed and republish; a verifier that checks revocation can reject signatures under this key.',
  root: "Move the chain to a CA whose root stays trusted, and remove emSign ECC Root CA - G3 from any bundle you ship; Chrome's removal date for all devices is 2026-10-27.",
};

const ISSUE = {
  1: 'Certificate uses a publicly compromised CA key (eMudhra intermediate, Mozilla Bug 2083449)',
  2: 'Certificate is signed by a publicly compromised CA key (eMudhra intermediate, Mozilla Bug 2083449)',
  3: "Certificate is emSign ECC Root CA - G3, removed from Mozilla's root store on 2026-10-20",
  4: "Chain anchors on emSign ECC Root CA - G3, removed from Mozilla's root store on 2026-10-20",
};

const KIND = {
  A: {
    id: 'trust/compromised-ca-key',
    severity: 'critical',
    references: ['https://github.com/ecolibria/cryptoserve/blob/main/docs/findings/trust-compromised-key.md'],
  },
  B: {
    id: 'trust/distrusted-root',
    severity: 'high',
    references: ['https://github.com/ecolibria/cryptoserve/blob/main/docs/findings/trust-distrusted-root.md'],
  },
};

// What each value is, for a reader of the text report.
export const VALUE_LABEL = { spkiSha256: 'SPKI SHA-256', certSha256: 'certificate SHA-256' };
export const KEY_LABEL = {
  tls: 'a listed TLS intermediate key',
  codeSigning: 'a listed code-signing intermediate key',
  root: "the removed root's key",
};

// The tail of each Verify command: from a PEM block on stdin to the bare
// lowercase hex value, which OpenSSL and LibreSSL print byte for byte alike.
const TO_VALUE = {
  spkiSha256: "openssl x509 -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \\n'",
  certSha256: "openssl x509 -outform DER | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \\n'",
};

// At the start of a line, as openssl reads them: a header anywhere else is not
// one the printed Verify command would find.
const PEM_CERTIFICATE = /^-----BEGIN CERTIFICATE-----[\r\n]+[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----/gm;
const PEM_HEADER = /^-----BEGIN [^\r\n]*-----/m;

// The characters `printablePath` percent-encodes for the terminal, less `%`.
const TERMINAL_UNSAFE = /[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩]/u;

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

function signedBy(x509, publicKey) {
  try {
    return x509.verify(publicKey);
  } catch {
    return false;
  }
}

/**
 * A path as one word of a POSIX shell command. A file name in a scanned tree
 * is chosen by whoever committed it, and the Verify command is meant to be
 * pasted: nothing in the name may run. Single quotes when the name is
 * printable; otherwise `printf` with octal escapes, which rebuilds the bytes of
 * the name without printing a character the terminal would act on.
 */
export function shellPath(path) {
  const p = path.startsWith('-') ? `./${path}` : path;
  if (/^[A-Za-z0-9_./-]+$/.test(p)) return p;
  if (!TERMINAL_UNSAFE.test(p)) return `'${p.replaceAll("'", "'\\''")}'`;
  const escaped = [...Buffer.from(p, 'utf8')]
    .map((b) => (b >= 0x20 && b < 0x7f && b !== 0x25 && b !== 0x27 && b !== 0x5c
      ? String.fromCharCode(b)
      : `\\${b.toString(8).padStart(3, '0')}`))
    .join('');
  return `"$(printf '${escaped}')"`;
}

function verifyCommand(valueType, path, line, firstHeaderLine) {
  const file = shellPath(path);
  // `openssl x509 -in FILE` reads the file's first PEM block, so the shorter
  // form names the same certificate only when this block is that one.
  if (line === firstHeaderLine) {
    return `openssl x509 -in ${file} ${TO_VALUE[valueType].slice('openssl x509 '.length)}`;
  }
  return `awk 'NR>=${line}' ${file} | ${TO_VALUE[valueType]}`;
}

/**
 * Check every PEM certificate block in one file's text.
 *
 * @param {string} text - the file's contents
 * @param {{file: string, path: string}} where - `file` is the printable path a
 *   finding reports; `path` is the real relative path the Verify command opens
 * @returns {{checked: number, findings: object[]}} `checked` counts the blocks
 *   that decoded as certificates
 */
export function checkCertificateText(text, { file, path }) {
  const findings = [];
  let checked = 0;
  if (!text.includes('-----BEGIN CERTIFICATE-----')) return { checked, findings };

  const offsets = newlineOffsets(text);
  const firstHeader = text.search(PEM_HEADER);
  const firstHeaderLine = firstHeader >= 0 ? lineAt(offsets, firstHeader) : 0;

  for (const match of text.matchAll(PEM_CERTIFICATE)) {
    let x509;
    try {
      x509 = new X509Certificate(match[0]);
    } catch {
      continue; // not a certificate this runtime can decode: nothing to compare
    }
    checked++;
    const line = lineAt(offsets, match.index);
    const certSha256 = sha256(x509.raw);
    let spkiSha256 = null;
    try {
      spkiSha256 = sha256(x509.publicKey.export({ type: 'spki', format: 'der' }));
    } catch {
      // A key type this runtime cannot export is not one of the listed keys.
    }

    const finding = (kind, rule, matchedValue, valueType, issuerSpkiSha256, keyUse) => {
      const { id, severity, references } = KIND[kind];
      findings.push({
        id,
        kind,
        issue: ISSUE[rule],
        severity,
        file,
        line,
        matchedValue,
        valueType,
        issuerSpkiSha256,
        keyUse,
        rule,
        verify: verifyCommand(valueType, path, line, firstHeaderLine),
        fix: TRUST_FIX[keyUse],
        references,
      });
    };

    const own = spkiSha256 ? BY_SPKI.get(spkiSha256) : undefined;
    if (own && own.use === 'root') {
      finding('B', 3, spkiSha256, 'spkiSha256', null, 'root');
      continue;
    }
    if (own) {
      finding('A', 1, spkiSha256, 'spkiSha256', null, own.use);
    } else {
      const signer = KEYS.find((k) => k.use !== 'root' && signedBy(x509, k.publicKey));
      if (signer) finding('A', 2, certSha256, 'certSha256', signer.spkiSha256, signer.use);
    }
    const root = KEYS.find((k) => k.use === 'root' && signedBy(x509, k.publicKey));
    if (root) finding('B', 4, certSha256, 'certSha256', root.spkiSha256, 'root');
  }
  return { checked, findings };
}
