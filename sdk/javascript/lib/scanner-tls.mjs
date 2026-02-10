/**
 * TLS version scanner — detects deprecated TLS/SSL in config and source files.
 *
 * Scans nginx, Apache, Node.js, Go, Java configs and source files for
 * deprecated TLS versions (SSLv2, SSLv3, TLSv1.0, TLSv1.1).
 * Zero dependencies.
 */

import { readFileSync } from 'node:fs';
import { extname, relative } from 'node:path';
import { walkProject } from './walker.mjs';

// ---------------------------------------------------------------------------
// TLS version risk levels
// ---------------------------------------------------------------------------

const TLS_RISK = {
  'SSLv2':   { risk: 'critical', recommendation: 'Remove immediately — completely broken' },
  'SSLv3':   { risk: 'critical', recommendation: 'Remove immediately — POODLE attack' },
  'TLSv1':   { risk: 'critical', recommendation: 'Remove — deprecated by RFC 8996' },
  'TLSv1.0': { risk: 'critical', recommendation: 'Remove — deprecated by RFC 8996' },
  'TLSv1.1': { risk: 'high', recommendation: 'Remove — deprecated by RFC 8996' },
  'TLSv1.2': { risk: 'none', recommendation: 'Current standard, safe to use' },
  'TLSv1.3': { risk: 'none', recommendation: 'Best available, recommended' },
};

// ---------------------------------------------------------------------------
// Detection patterns by file type
// ---------------------------------------------------------------------------

const PATTERNS = [
  // Nginx: ssl_protocols directive
  {
    filePatterns: ['nginx.conf', '*.nginx', '*.nginx.conf'],
    extensions: ['.conf'],
    regex: /ssl_protocols\s+([^;]+);/g,
    extract: (match) => {
      const protocols = match[1].split(/\s+/);
      return protocols
        .filter(p => p.match(/^(SSLv[23]|TLSv1(\.[0-3])?)$/))
        .map(p => ({ protocol: p, context: 'nginx ssl_protocols' }));
    },
  },
  // Apache: SSLProtocol directive
  {
    filePatterns: ['httpd.conf', 'apache2.conf', 'ssl.conf', '*.apache.conf'],
    extensions: ['.conf'],
    regex: /SSLProtocol\s+([^\n]+)/g,
    extract: (match) => {
      const parts = match[1].split(/\s+/);
      return parts
        .filter(p => p.match(/^[+-]?(SSLv[23]|TLSv1(\.[0-3])?)$/))
        .filter(p => !p.startsWith('-'))
        .map(p => ({ protocol: p.replace(/^\+/, ''), context: 'Apache SSLProtocol' }));
    },
  },
  // Node.js: tls.createServer minVersion
  {
    extensions: ['.js', '.ts', '.mjs', '.cjs'],
    regex: /minVersion:\s*['"]([^'"]+)['"]/g,
    extract: (match) => {
      const version = match[1];
      return [{ protocol: version, context: 'Node.js TLS minVersion' }];
    },
  },
  // Go: tls.Config MinVersion
  {
    extensions: ['.go'],
    regex: /MinVersion:\s*tls\.(VersionSSL30|VersionTLS1[0-3])/g,
    extract: (match) => {
      const versionMap = {
        'VersionSSL30': 'SSLv3',
        'VersionTLS10': 'TLSv1.0',
        'VersionTLS11': 'TLSv1.1',
        'VersionTLS12': 'TLSv1.2',
        'VersionTLS13': 'TLSv1.3',
      };
      const protocol = versionMap[match[1]] || match[1];
      return [{ protocol, context: 'Go tls.Config MinVersion' }];
    },
  },
  // Java: SSLContext.getInstance
  {
    extensions: ['.java', '.kt', '.scala'],
    regex: /SSLContext\.getInstance\s*\(\s*["'](TLS(?:v1(?:\.[0-3])?)?|SSL(?:v[23])?)["']\s*\)/g,
    extract: (match) => {
      return [{ protocol: match[1], context: 'Java SSLContext' }];
    },
  },
  // Docker / env: SSL_MIN_VERSION or similar
  {
    filePatterns: ['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml', '.env'],
    regex: /(?:SSL_MIN_VERSION|TLS_MIN_VERSION|MIN_TLS_VERSION)\s*[=:]\s*['"]?([^\s'"]+)/gi,
    extract: (match) => {
      return [{ protocol: match[1], context: 'Environment variable' }];
    },
  },
  // Generic: TLS version strings in any config
  {
    extensions: ['.conf', '.cfg', '.ini', '.toml', '.yaml', '.yml', '.json', '.xml'],
    regex: /\b(SSLv[23]|TLSv1\.0|TLSv1\.1)\b/g,
    extract: (match) => {
      return [{ protocol: match[1], context: 'Config file reference' }];
    },
  },
];

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

/**
 * Scan project for deprecated TLS/SSL versions.
 *
 * @param {string} projectDir - Root directory for relative path calculation
 * @param {string[]|undefined} preFilteredFiles - Pre-walked file list (source+config).
 *   If omitted, walks the directory internally for backward compat.
 * @returns {Array<{file: string, line: number, protocol: string, risk: string, recommendation: string}>}
 */
export function scanTlsConfigs(projectDir, preFilteredFiles) {
  const findings = [];
  let files;
  if (Array.isArray(preFilteredFiles)) {
    files = preFilteredFiles;
  } else {
    const walked = walkProject(projectDir);
    files = [...walked.sourceFiles, ...walked.configFiles];
  }

  for (const filePath of files) {
    let content;
    try { content = readFileSync(filePath, 'utf-8'); }
    catch { continue; }

    const ext = extname(filePath).toLowerCase();
    const name = filePath.split('/').pop();
    const relPath = relative(projectDir, filePath);

    for (const pattern of PATTERNS) {
      // Check if pattern applies to this file
      const extMatch = pattern.extensions && pattern.extensions.includes(ext);
      const nameMatch = pattern.filePatterns && pattern.filePatterns.some(p => {
        if (p.startsWith('*')) return name.endsWith(p.slice(1));
        return name === p;
      });

      if (!extMatch && !nameMatch) continue;

      pattern.regex.lastIndex = 0;
      let match;
      while ((match = pattern.regex.exec(content)) !== null) {
        const detected = pattern.extract(match);
        for (const { protocol, context } of detected) {
          const riskInfo = TLS_RISK[protocol];
          if (riskInfo && riskInfo.risk !== 'none') {
            // Find line number
            const lineNum = content.substring(0, match.index).split('\n').length;
            findings.push({
              file: relPath,
              line: lineNum,
              protocol,
              risk: riskInfo.risk,
              recommendation: riskInfo.recommendation,
              context,
            });
          }
        }
      }
    }
  }

  return findings;
}
