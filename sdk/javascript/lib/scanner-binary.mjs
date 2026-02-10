/**
 * Binary crypto signature scanner.
 *
 * Detects compiled crypto by searching for known byte patterns
 * (S-boxes, round constants, initial hash values) in binary files.
 * Ported from backend/app/core/binary_scanner.py.
 * Zero dependencies — uses only node:fs and node:path.
 */

import { readFileSync, statSync, openSync, readSync, closeSync } from 'node:fs';
import { join, extname, basename } from 'node:path';
import { walkProject } from './walker.mjs';

// ---------------------------------------------------------------------------
// Binary signatures — byte patterns for compiled crypto
// ---------------------------------------------------------------------------

export const BINARY_SIGNATURES = [
  {
    name: 'AES S-box',
    algorithm: 'aes',
    severity: 'info',
    bytes: Buffer.from([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76]),
  },
  {
    name: 'AES round constant',
    algorithm: 'aes',
    severity: 'info',
    bytes: Buffer.from([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]),
  },
  {
    name: 'DES initial permutation',
    algorithm: 'des',
    severity: 'high',
    bytes: Buffer.from([58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4]),
  },
  {
    name: 'DES S-box 1',
    algorithm: 'des',
    severity: 'high',
    bytes: Buffer.from([14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7]),
  },
  {
    name: 'SHA-256 initial values',
    algorithm: 'sha256',
    severity: 'info',
    bytes: Buffer.from([0x6A, 0x09, 0xE6, 0x67, 0xBB, 0x67, 0xAE, 0x85, 0x3C, 0x6E, 0xF3, 0x72, 0xA5, 0x4F, 0xF5, 0x3A]),
  },
  {
    name: 'SHA-1 initial values',
    algorithm: 'sha1',
    severity: 'high',
    bytes: Buffer.from([0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB, 0x89, 0x98, 0xBA, 0xDC, 0xFE, 0x10, 0x32, 0x54, 0x76]),
  },
  {
    name: 'MD5 initial values',
    algorithm: 'md5',
    severity: 'critical',
    bytes: Buffer.from([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10]),
  },
  {
    name: 'ChaCha20 sigma constant',
    algorithm: 'chacha20',
    severity: 'info',
    bytes: Buffer.from('expand 32-byte k'),
  },
  {
    name: 'Blowfish P-array',
    algorithm: 'blowfish',
    severity: 'high',
    bytes: Buffer.from([0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3, 0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x44]),
  },
  {
    name: 'RSA public exponent 65537',
    algorithm: 'rsa',
    severity: 'info',
    bytes: Buffer.from([0x01, 0x00, 0x01]),
  },
];

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

// ---------------------------------------------------------------------------
// Scanner functions
// ---------------------------------------------------------------------------

/**
 * Scan a single binary file for crypto byte patterns.
 * Returns array of matches: [{ name, algorithm, severity, offset }]
 */
export function scanBinary(filePath) {
  let buf;
  try {
    const size = statSync(filePath).size;
    if (size > MAX_FILE_SIZE) {
      const fd = openSync(filePath, 'r');
      buf = Buffer.alloc(MAX_FILE_SIZE);
      readSync(fd, buf, 0, MAX_FILE_SIZE, 0);
      closeSync(fd);
    } else {
      buf = readFileSync(filePath);
    }
  } catch {
    return [];
  }

  const matches = [];
  for (const sig of BINARY_SIGNATURES) {
    const offset = buf.indexOf(sig.bytes);
    if (offset !== -1) {
      matches.push({
        name: sig.name,
        algorithm: sig.algorithm,
        severity: sig.severity,
        offset,
      });
    }
  }
  return matches;
}

/**
 * Scan binary files for crypto byte signatures.
 *
 * @param {string} projectDir - Root directory for relative path calculation
 * @param {string[]|undefined} preFilteredFiles - Pre-walked binary file list.
 *   If omitted, walks the directory internally for backward compat.
 * @returns {Array<{name: string, algorithm: string, severity: string, offset: number, file: string}>}
 */
export function scanBinaries(projectDir, preFilteredFiles) {
  const results = [];
  let files;
  if (Array.isArray(preFilteredFiles)) {
    files = preFilteredFiles;
  } else {
    const walked = walkProject(projectDir);
    files = walked.binaryFiles;
  }

  for (const filePath of files) {
    const matches = scanBinary(filePath);
    for (const match of matches) {
      results.push({
        ...match,
        file: filePath.replace(projectDir + '/', ''),
      });
    }
  }

  return results;
}
