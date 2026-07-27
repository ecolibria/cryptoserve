/**
 * Cryptographic dependency and secret scanner — orchestrates all sub-scanners.
 *
 * Scans projects for:
 * 1. Cryptographic dependencies (package.json, go.mod, requirements.txt, etc.)
 * 2. Source code crypto patterns (JS/TS, Go, Python, Java, Rust, C/C++)
 * 3. Hardcoded secrets (API keys, passwords — patterns from secretless-ai)
 * 4. Certificate/key files (.pem, .key, .crt, .p12)
 * 5. TLS version issues in config files
 * 6. Binary crypto signatures (optional, via --binary flag)
 *
 * Output matches the library inventory format used by pqc-engine.mjs.
 * Zero dependencies — uses only node:fs and node:path.
 */

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, relative, extname, basename } from 'node:path';
import { LANGUAGE_PATTERNS, scanSourceFile, scanWeakKeySizes, detectLanguage, MULTI_LANG_EXTENSIONS } from './scanner-languages.mjs';
import { scanManifests } from './scanner-manifests.mjs';
import { scanTlsConfigs } from './scanner-tls.mjs';
import { lookupAlgorithm } from './algorithm-db.mjs';
import { lookupNpmPackage } from './crypto-registry.mjs';
import { walkProject } from './walker.mjs';
import { loadScannerConfig } from './config.mjs';

// ---------------------------------------------------------------------------
// API misuse patterns
//
// These are distinct from weak *algorithms* (which come from the algorithm
// database via the language pattern tables). A misuse is a correct algorithm
// used incorrectly, so it cannot be derived from an algorithm name.
// ---------------------------------------------------------------------------

const MISUSE_PATTERNS = [
  {
    languages: ['javascript'],
    pattern: /createCipher\s*\(\s*['"`]/g,
    issue: 'createCipher derives an IV from the key (use createCipheriv)',
    severity: 'critical',
    fix: 'crypto.createCipheriv(algorithm, key, crypto.randomBytes(16))',
  },
  {
    languages: ['javascript'],
    pattern: /Math\.random\s*\(\s*\)[^\n]{0,40}(?:token|secret|key|nonce|salt|iv|password)/gi,
    issue: 'Math.random() is not a CSPRNG',
    severity: 'high',
    fix: 'crypto.randomBytes(n) or crypto.getRandomValues(...)',
  },
  {
    languages: ['python'],
    pattern: /\brandom\s*\.\s*(?:random|randint|choice)\s*\([^\n]{0,40}(?:token|secret|key|nonce|salt|password)/gi,
    issue: 'random module is not a CSPRNG',
    severity: 'high',
    fix: 'secrets.token_bytes(n)',
  },
  {
    languages: ['javascript', 'python', 'go', 'java'],
    pattern: /(?:rejectUnauthorized\s*:\s*false|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true)/g,
    issue: 'TLS certificate verification disabled',
    severity: 'critical',
    fix: 'Remove the override and trust the system CA store',
  },
];

// Modes that are not weak on their own but carry a caveat worth surfacing.
const MODE_ADVISORIES = {
  'aes-cbc': {
    issue: 'CBC mode needs an authenticated construction (prefer GCM)',
    severity: 'medium',
    fix: 'Use aes-256-gcm, or pair CBC with a separate MAC',
  },
};

// ---------------------------------------------------------------------------
// Hardcoded secret detection (borrowed from secretless-ai patterns)
// ---------------------------------------------------------------------------

export const SECRET_PATTERNS = [
  { id: 'anthropic',     regex: /sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/g,                      name: 'Anthropic API Key',     envVar: 'ANTHROPIC_API_KEY' },
  { id: 'openai-proj',   regex: /sk-proj-[a-zA-Z0-9]{20,}/g,                                 name: 'OpenAI Project Key',    envVar: 'OPENAI_API_KEY' },
  { id: 'openai-legacy', regex: /sk-[a-zA-Z0-9]{48,}/g,                                       name: 'OpenAI Legacy Key',     envVar: 'OPENAI_API_KEY' },
  { id: 'aws-access',    regex: /AKIA[0-9A-Z]{16}/g,                                          name: 'AWS Access Key',        envVar: 'AWS_ACCESS_KEY_ID' },
  { id: 'github-pat',    regex: /ghp_[a-zA-Z0-9]{36}/g,                                       name: 'GitHub PAT',            envVar: 'GITHUB_TOKEN' },
  { id: 'github-fine',   regex: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/g,                name: 'GitHub Fine-grained',   envVar: 'GITHUB_TOKEN' },
  { id: 'slack',         regex: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/g,      name: 'Slack Token',           envVar: 'SLACK_TOKEN' },
  { id: 'google',        regex: /AIza[0-9A-Za-z_-]{35}/g,                                     name: 'Google API Key',        envVar: 'GOOGLE_API_KEY' },
  { id: 'stripe',        regex: /sk_live_[0-9a-zA-Z]{24,}/g,                                  name: 'Stripe Secret Key',     envVar: 'STRIPE_SECRET_KEY' },
  { id: 'sendgrid',      regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,                 name: 'SendGrid Key',          envVar: 'SENDGRID_API_KEY' },
  { id: 'npm',           regex: /npm_[a-zA-Z0-9]{36}/g,                                       name: 'npm Token',             envVar: 'NPM_TOKEN' },
  { id: 'private-key',   regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,    name: 'Private Key',           envVar: null },
];

// File patterns for cert/key discovery
const CERT_EXTENSIONS = new Set(['.pem', '.key', '.crt', '.p12', '.pfx', '.jks', '.keystore']);

/** 1-based line number for a byte offset. */
function lineNumberAt(content, index) {
  let line = 1;
  for (let i = content.indexOf('\n'); i !== -1 && i < index; i = content.indexOf('\n', i + 1)) line++;
  return line;
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

export function scanProject(projectDir, options = {}) {
  const results = {
    libraries: [],
    secrets: [],
    weakPatterns: [],
    certFiles: [],
    filesScanned: 0,   // source files matched to a language and analyzed
    filesWalked: 0,    // every file the walker examined, analyzed or not
    // New in v0.2.0
    sourceAlgorithms: [],
    tlsFindings: [],
    binaryFindings: [],
    languagesDetected: new Set(),
    manifestsFound: [],
  };

  // 1. Scan package.json for crypto dependencies (root + monorepo workspaces)
  const pkgPaths = [join(projectDir, 'package.json')];
  const monorepoGlobs = ['apps', 'packages', 'libs', 'modules', 'services'];
  for (const sub of monorepoGlobs) {
    const subDir = join(projectDir, sub);
    try {
      const entries = readdirSync(subDir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory()) {
          const nested = join(subDir, entry.name, 'package.json');
          if (existsSync(nested)) pkgPaths.push(nested);
        }
      }
    } catch { /* dir doesn't exist */ }
  }

  const seenPkgs = new Set();
  for (const pkgPath of pkgPaths) {
    if (!existsSync(pkgPath)) continue;
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
      const allDeps = {
        ...(pkg.dependencies || {}),
        ...(pkg.devDependencies || {}),
      };

      for (const [name, version] of Object.entries(allDeps)) {
        const info = lookupNpmPackage(name);
        if (info && !seenPkgs.has(name)) {
          seenPkgs.add(name);
          results.libraries.push({
            name,
            version: version.replace(/^[\^~]/, ''),
            algorithms: info.algorithms,
            quantumRisk: info.quantumRisk,
            category: info.category,
            source: pkgPath.replace(projectDir + '/', ''),
            ecosystem: 'npm',
          });
        }
      }
      results.manifestsFound.push('package.json');
    } catch { /* invalid package.json */ }
  }

  // 2. Scan non-npm manifests (go.mod, requirements.txt, Cargo.toml, etc.)
  const manifestLibs = scanManifests(projectDir);
  for (const lib of manifestLibs) {
    if (!seenPkgs.has(lib.name)) {
      seenPkgs.add(lib.name);
      results.libraries.push(lib);
      if (!results.manifestsFound.includes(lib.source)) {
        results.manifestsFound.push(lib.source);
      }
    }
  }

  // 3. Walk source files (single-pass unified walker with config overrides)
  const scannerConfig = loadScannerConfig(projectDir);
  const walked = walkProject(projectDir, {
    skipDirs: scannerConfig.skipDirs.length > 0 ? new Set(scannerConfig.skipDirs) : undefined,
    includeExtensions: scannerConfig.includeExtensions.length > 0 ? new Set(scannerConfig.includeExtensions) : undefined,
    maxFiles: scannerConfig.maxFiles,
    maxBytes: scannerConfig.maxBytes,
    maxFileSize: scannerConfig.maxFileSize,
    maxBinaryFiles: scannerConfig.binary.maxFiles,
    maxBinaryFileSize: scannerConfig.binary.maxFileSize,
  });
  results.filesWalked = walked.totalFiles;
  const seenSourceAlgos = new Set();
  const sourceLibraries = new Map(); // library name -> algorithm set

  // Cert files from walker
  for (const certPath of walked.certFiles) {
    results.certFiles.push(relative(projectDir, certPath));
  }

  for (const filePath of walked.sourceFiles) {
    const relPath = relative(projectDir, filePath);

    // Every supported language, JS/TS included, goes through one detection
    // path. Keeping JS on a separate path is what previously let 3DES and
    // Blowfish through and collapsed SHA-1 onto the SHA-256 label.
    const language = detectLanguage(filePath);
    if (!language) continue;

    results.filesScanned++;
    results.languagesDetected.add(language);

    let content;
    try { content = readFileSync(filePath, 'utf-8'); }
    catch { continue; }

    const langResult = scanSourceFile(filePath, content, language);

    // Same unambiguity rule as the library table: attribute only when the file
    // imports exactly one crypto library.
    const attributedLibrary = langResult.imports.length === 1 ? langResult.imports[0].library : '';

    for (const algo of langResult.algorithms) {
      const dbEntry = lookupAlgorithm(algo.algorithm);
      const sourceAlgoKey = `${algo.algorithm}:${language}`;
      if (!seenSourceAlgos.has(sourceAlgoKey)) {
        seenSourceAlgos.add(sourceAlgoKey);
        results.sourceAlgorithms.push({
          algorithm: algo.algorithm,
          category: algo.category,
          language,
          file: relPath,
          line: algo.line,
          evidence: algo.evidence,
          library: attributedLibrary,
          quantumRisk: dbEntry?.quantumRisk || 'unknown',
          isWeak: dbEntry?.isWeak || false,
        });
      }

      // A weak algorithm is a weak algorithm in every language. Deriving the
      // finding from the database instead of per-language regexes is what
      // gives Go, Python, Java, Rust and C the same coverage JS used to have.
      if (dbEntry?.isWeak) {
        results.weakPatterns.push({
          file: relPath,
          line: algo.line,
          algorithm: algo.algorithm,
          issue: `${algo.algorithm.toUpperCase()}: ${dbEntry.weaknessReason}`,
          severity: dbEntry.quantumRisk === 'critical' ? 'critical' : 'high',
          cwe: dbEntry.cwe,
          fix: dbEntry.replacement ? `Replace with ${dbEntry.replacement}` : undefined,
          evidence: algo.evidence,
        });
      } else if (MODE_ADVISORIES[algo.algorithm]) {
        const advisory = MODE_ADVISORIES[algo.algorithm];
        results.weakPatterns.push({
          file: relPath,
          line: algo.line,
          algorithm: algo.algorithm,
          issue: advisory.issue,
          severity: advisory.severity,
          fix: advisory.fix,
          evidence: algo.evidence,
        });
      }
    }

    // Attribute algorithms to an imported library only when the file imports
    // exactly one crypto library. With two or more, which call belongs to which
    // import is not decidable without dataflow analysis, and a guess here would
    // print a wrong algorithm list next to a real package name.
    for (const imp of langResult.imports) {
      if (!sourceLibraries.has(imp.library)) sourceLibraries.set(imp.library, new Set());
    }
    if (langResult.imports.length === 1) {
      const only = sourceLibraries.get(langResult.imports[0].library);
      for (const algo of langResult.algorithms) only.add(algo.algorithm);
    }

    // Keys generated below the current minimum size.
    for (const weakKey of scanWeakKeySizes(content)) {
      const key = `${weakKey.algorithm}:${language}`;
      if (!seenSourceAlgos.has(key)) {
        seenSourceAlgos.add(key);
        results.sourceAlgorithms.push({
          algorithm: weakKey.algorithm,
          category: weakKey.category,
          language,
          file: relPath,
          line: weakKey.line,
          quantumRisk: 'critical',
          isWeak: true,
        });
      }
      results.weakPatterns.push({
        file: relPath,
        line: weakKey.line,
        algorithm: weakKey.algorithm,
        issue: `${weakKey.algorithm.toUpperCase()}: ${weakKey.weaknessReason}`,
        severity: 'critical',
        cwe: weakKey.cwe,
        fix: 'Generate keys at 3072 bits or move to ML-KEM / ML-DSA',
      });
    }

    // API misuse (correct algorithm, incorrect usage).
    for (const { languages, pattern, issue, severity, fix } of MISUSE_PATTERNS) {
      if (!languages.includes(language)) continue;
      pattern.lastIndex = 0;
      const m = pattern.exec(content);
      if (m) {
        results.weakPatterns.push({
          file: relPath,
          line: lineNumberAt(content, m.index),
          issue,
          severity,
          fix,
          evidence: m[0].slice(0, 80),
        });
      }
    }

    // Hardcoded secrets
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.length > 4096) continue; // ReDoS protection
      // Skip env var references
      if (/\$\{[A-Z_]+\}/.test(line) || /process\.env\.[A-Z_]+/.test(line)) continue;

      for (const { id, regex, name, envVar } of SECRET_PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          results.secrets.push({
            type: id,
            name,
            file: relPath,
            line: i + 1,
            envVar,
            severity: 'critical',
          });
        }
      }
    }
  }

  // Source-detected libraries (node:crypto, hashlib, openssl, ...) become
  // inventory entries carrying the algorithms actually observed in that file
  // set, rather than a hardcoded guess derived from which helper was imported.
  for (const [name, algoSet] of sourceLibraries) {
    if (seenPkgs.has(name)) continue; // already inventoried from a manifest
    const algorithms = [...algoSet];
    const risks = algorithms.map(a => lookupAlgorithm(a)?.quantumRisk).filter(Boolean);
    const quantumRisk = risks.includes('critical') ? 'critical'
      : risks.includes('high') ? 'high'
      : risks.includes('low') ? 'low'
      : 'none';
    const hasAsymmetric = algorithms.some(a => {
      const c = lookupAlgorithm(a)?.category;
      return c === 'signing' || c === 'key_exchange' || a.startsWith('rsa');
    });
    results.libraries.push({
      name,
      version: 'builtin',
      algorithms,
      quantumRisk,
      category: hasAsymmetric ? 'asymmetric' : 'symmetric',
      source: 'source-code',
      ecosystem: 'source',
    });
  }

  // 4. TLS scanning — pass pre-walked source+config files
  const tlsFiles = [...walked.sourceFiles, ...walked.configFiles];
  results.tlsFindings = scanTlsConfigs(projectDir, tlsFiles);

  // 5. Binary scanning moved to CLI layer (lazy-loaded via dynamic import)

  // Convert sets to arrays for JSON serialization
  results.languagesDetected = [...results.languagesDetected];

  return results;
}

// ---------------------------------------------------------------------------
// Format results as library inventory (for PQC engine input)
// ---------------------------------------------------------------------------

export function toLibraryInventory(scanResults) {
  const inventory = scanResults.libraries.map(lib => {
    const entry = {
      name: lib.name,
      version: lib.version,
      algorithms: lib.algorithms,
      quantumRisk: lib.quantumRisk,
      category: lib.category,
      isDeprecated: lib.isDeprecated || false,
    };
    // Enrich with algorithm-db data
    for (const algoName of lib.algorithms) {
      const dbEntry = lookupAlgorithm(algoName);
      if (dbEntry?.isWeak && !entry.isDeprecated) {
        entry.isDeprecated = true;
      }
    }
    return entry;
  });

  // Also add source-detected algorithms as synthetic library entries
  for (const algo of (scanResults.sourceAlgorithms || [])) {
    const alreadyInLib = inventory.some(lib =>
      lib.algorithms.some(a => a.toLowerCase() === algo.algorithm.toLowerCase())
    );
    if (!alreadyInLib) {
      inventory.push({
        name: `${algo.language}:${algo.algorithm}`,
        version: 'source-code',
        algorithms: [algo.algorithm],
        quantumRisk: algo.quantumRisk || 'unknown',
        category: algo.category,
        isDeprecated: algo.isWeak || false,
      });
    }
  }

  return inventory;
}
