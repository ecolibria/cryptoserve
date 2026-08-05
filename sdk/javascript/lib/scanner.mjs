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
import { parseWaiverPragmas, findWaiver, waiverWarnings } from './waivers.mjs';

// ---------------------------------------------------------------------------
// API misuse patterns
//
// These are distinct from weak *algorithms* (which come from the algorithm
// database via the language pattern tables). A misuse is a correct algorithm
// used incorrectly, so it cannot be derived from an algorithm name.
//
// Every entry carries a stable `id`. It is what a waiver pragma names, so it is
// part of the CLI's contract with a user's source tree: renaming one silently
// un-waives every finding somebody wrote a pragma for. The `issue` text is
// prose and may be reworded; the id may not.
// ---------------------------------------------------------------------------

const MISUSE_PATTERNS = [
  {
    id: 'misuse/create-cipher',
    languages: ['javascript'],
    pattern: /createCipher\s*\(\s*['"`]/g,
    issue: 'createCipher derives an IV from the key (use createCipheriv)',
    severity: 'critical',
    fix: 'crypto.createCipheriv(algorithm, key, crypto.randomBytes(16))',
  },
  {
    id: 'misuse/insecure-random-js',
    languages: ['javascript'],
    pattern: /Math\.random\s*\(\s*\)[^\n]{0,40}(?:token|secret|key|nonce|salt|iv|password)/gi,
    issue: 'Math.random() is not a CSPRNG',
    severity: 'high',
    fix: 'crypto.randomBytes(n) or crypto.getRandomValues(...)',
  },
  {
    id: 'misuse/insecure-random-python',
    languages: ['python'],
    pattern: /\brandom\s*\.\s*(?:random|randint|choice)\s*\([^\n]{0,40}(?:token|secret|key|nonce|salt|password)/gi,
    issue: 'random module is not a CSPRNG',
    severity: 'high',
    fix: 'secrets.token_bytes(n)',
  },
  {
    id: 'misuse/tls-verify-disabled',
    languages: ['javascript', 'python', 'go', 'java'],
    pattern: /(?:rejectUnauthorized\s*:\s*false|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true)/g,
    issue: 'TLS certificate verification disabled',
    severity: 'critical',
    fix: 'Remove the override and trust the system CA store',
  },
  // `gate --help` promises to fail on "critical API misuse such as a disabled
  // TLS certificate check", and the entry above was the only spelling of that
  // it knew. A tree turning verification off in JavaScript and in Python scored
  // 100/100 and exited 0 (#66). Each defect is listed in both languages,
  // because a project that disables a check in one of them is not safer than
  // one that disables it in the other.
  //
  // Separate entries rather than one alternation on purpose: the loop that
  // applies these runs `exec` ONCE per pattern per file, so folding them
  // together would report whichever spelling appeared first and hide the rest
  // of the file.
  {
    // Anchored on an ASSIGNMENT, not on the bare name. Matching the name alone
    // flagged every mention of it -- including this rule's own `issue:` string
    // one screen up, so `gate` reported a critical finding against the
    // definition of the check. A security tool that fails its own source
    // teaches people to ignore it.
    //
    // Scoped to `process.env`, and deliberately NOT widened beyond it.
    //
    // Widening this to any receiver (`\w\s*\.\s*NAME = 0`) plus an object
    // property (`NAME: 0`) does catch five more real spellings -- destructured
    // `env`, an aliased `process.env`, `Bun.env`, a spread into a spawn env,
    // and `Object.assign`. Measured, it also flags all of these, none of which
    // is a defect:
    //
    //     // Never write NODE_TLS_REJECT_UNAUTHORIZED: 0 anywhere.
    //     module.exports = { rules: { NODE_TLS_REJECT_UNAUTHORIZED: 0 } };
    //     const SEVERITY = { NODE_TLS_REJECT_UNAUTHORIZED: 0, OTHER: 2 };
    //     counts.NODE_TLS_REJECT_UNAUTHORIZED = 0;
    //     this.NODE_TLS_REJECT_UNAUTHORIZED = 0;
    //
    // 8/8 detected against 6/6 false positives, versus 3/8 against 1/6 here.
    //
    // The `cryptoserve-ignore` pragma now makes every one of those clearable,
    // which removes the ORIGINAL objection to widening. It stays narrow anyway,
    // for a second reason found by adversarial review: on this repository's own
    // tree the widened form makes all eight remaining criticals fixture strings
    // in the test suite, so the scanner fails its own gate. A rule that forces
    // 39 pragmas onto its own author is not ready. Reaching those spellings
    // wants the scanner to be able to tell code from prose, and a hand-written
    // comment tokenizer was measured mis-reading ordinary JSX and minified
    // bundles badly enough to LOSE real findings. Tracked in
    // `todo/roadmap/gate-tls-verification-spellings.md`.
    //
    // The value ends with `(?![\w.])`. Without it a bare `0` with optional
    // quotes prefix-matches longer values: `= 0.5`, `= 0x1` and `= '00'` all
    // reported the disabling literal, and none of them is it.
    id: 'misuse/node-tls-reject-unauthorized',
    languages: ['javascript'],
    pattern: /process\s*\.\s*env\s*(?:\.\s*NODE_TLS_REJECT_UNAUTHORIZED|\[\s*['"`]NODE_TLS_REJECT_UNAUTHORIZED['"`]\s*\])\s*(?:\|\|)?=\s*['"`]?0['"`]?(?![\w.])/g,
    issue: 'TLS certificate verification disabled process-wide (NODE_TLS env override set to 0)',
    severity: 'critical',
    fix: 'Remove the assignment; pass a CA with the `ca` option if the certificate is private',
  },
  {
    id: 'misuse/python-cert-none',
    languages: ['python'],
    pattern: /(?:verify_mode|cert_reqs)\s*=\s*ssl\.CERT_NONE/g,
    issue: 'TLS certificate verification disabled (ssl.CERT_NONE)',
    severity: 'critical',
    fix: 'Use ssl.CERT_REQUIRED, or ssl.create_default_context() which sets it',
  },
  {
    // Both spellings. Assigning it to `_create_default_https_context` is the
    // canonical process-wide Python bypass and never calls the function here,
    // so requiring the opening parenthesis missed exactly the worst form.
    id: 'misuse/python-unverified-context',
    languages: ['python'],
    pattern: /ssl\._create_unverified_context\s*\(|_create_default_https_context\s*=\s*ssl\._create_unverified_context/g,
    issue: 'TLS certificate verification disabled (ssl._create_unverified_context)',
    severity: 'critical',
    fix: 'Use ssl.create_default_context()',
  },
  {
    id: 'misuse/python-check-hostname',
    languages: ['python'],
    pattern: /check_hostname\s*=\s*False/g,
    issue: 'TLS hostname verification disabled (check_hostname = False)',
    severity: 'critical',
    fix: 'Leave check_hostname True; a certificate for another host is not a certificate for yours',
  },
  {
    // The JavaScript spelling of the same defect: an override that returns
    // nothing accepts every certificate for every host. A real implementation
    // calls back into `tls.checkServerIdentity`, so only the empty bodies match.
    id: 'misuse/js-check-server-identity',
    languages: ['javascript'],
    pattern: /checkServerIdentity\s*:\s*(?:function\s*)?\([^)]*\)\s*(?:=>\s*)?(?:undefined\b|null\b|true\b|\{\s*\}|\{\s*return\s*(?:undefined|null|true)?\s*;?\s*\})/g,
    issue: 'TLS hostname verification disabled (checkServerIdentity overridden with a no-op)',
    severity: 'critical',
    fix: 'Remove the override, or return tls.checkServerIdentity(host, cert)',
  },
];

/**
 * Every rule id a waiver pragma can legitimately name.
 *
 * Exported so a pragma naming something that is not a rule is reported as a
 * warning rather than silently doing nothing. A typo in an off switch that
 * looks like it worked is worse than no off switch.
 */
export const MISUSE_RULE_IDS = new Set(MISUSE_PATTERNS.map(p => p.id));

/**
 * The security severity `scan` reports for a weak algorithm.
 *
 * Exported because `gate` needs the same answer for algorithms it only ever
 * sees named in a dependency manifest, where no source line was read and so no
 * weakPattern exists to carry a severity. Restating the rule in the gate would
 * let the two commands drift into rating the same algorithm differently, which
 * is the class of disagreement issue #58 is about.
 *
 * Returns null for an algorithm that is not weak: absence of a security finding
 * is not the same claim as a finding of severity `none`.
 */
export function weakAlgorithmSeverity(dbEntry) {
  if (!dbEntry || !dbEntry.isWeak) return null;
  return dbEntry.quantumRisk === 'critical' ? 'critical' : 'high';
}

/** The severity ladder, lowest to highest. */
export const SEVERITY_ORDER = ['none', 'low', 'medium', 'high', 'critical'];

/**
 * Does a finding's severity exceed a threshold?
 *
 * Unknown severities fail CLOSED. `SEVERITY_ORDER.indexOf` returns -1 for a
 * value the ladder does not know, and `-1 > anything` is false, so comparing
 * indices directly means a typo in one pattern definition -- `severity:
 * 'moderate'` -- makes that finding silently unable to breach any threshold.
 * The gate would report the tree clean and never mention the finding it could
 * not classify. A gate must not be disarmed by a misspelling.
 *
 * A null severity means the scanner reported no security finding at all, which
 * is a different claim from a finding of severity `none`, and never breaches.
 */
export function exceedsSeverity(severity, threshold) {
  if (severity === null || severity === undefined) return false;
  const idx = SEVERITY_ORDER.indexOf(severity);
  if (idx === -1) return true;
  return idx > SEVERITY_ORDER.indexOf(threshold);
}

// ---------------------------------------------------------------------------
// Which languages a library can own a call site in
// ---------------------------------------------------------------------------

/**
 * The source languages each manifest ecosystem can produce call sites in.
 *
 * A library must not be named as the source of a call it cannot have made.
 * `crypto-js` declares MD5, so a Python `hashlib.md5()` was reported with
 * `source: crypto-js@3.1.9` (#67): every consumer paired libraries with sites on
 * the algorithm NAME alone and dropped the language the scanner had recorded.
 *
 * `source` libraries have no ecosystem to derive this from, so they carry the
 * languages of the files their import was actually read in -- see the
 * `languages` field `scanProject` records.
 *
 * No manifest ecosystem produces C, and that gap is load-bearing rather than an
 * omission: a `#include <openssl/md5.h>` site has no owning library at all, so
 * it depends on the synthetic owner `toOwnershipInventory` mints for it.
 * Narrowing the claim without that fallback would delete the violation instead
 * of re-attributing it.
 */
export const ECOSYSTEM_LANGUAGES = Object.freeze({
  npm: Object.freeze(['javascript']),
  go: Object.freeze(['go']),
  pypi: Object.freeze(['python']),
  cargo: Object.freeze(['rust']),
  maven: Object.freeze(['java']),
  source: Object.freeze([]), // recorded per library, from the files the import was seen in
});

/**
 * The languages a library can own a call site in.
 *
 * Returns a COPY. Handing out the table's own array made an exported constant
 * writable through any inventory entry that derived from it -- one
 * `entry.languages.push(...)` would have rewritten `ECOSYSTEM_LANGUAGES.npm`
 * process-wide, for every library and both inventories at once. Nothing mutates
 * it today; the frozen table and the copy mean nothing can start to.
 */
export function libraryLanguages(lib) {
  if (!lib) return [];
  if (Array.isArray(lib.languages)) return [...lib.languages];
  return [...(ECOSYSTEM_LANGUAGES[lib.ecosystem] || [])];
}

/**
 * One predicate, because three consumers ask this question and disagreeing
 * answers are what the fail-open is made of: the gate pairing libraries with
 * sites, the inventory deciding whether a site already has an owner, and the
 * CBOM deciding whether an algorithm is standalone. If the gate stops letting a
 * library claim a site but the inventory still counts it as claimed, the site
 * loses its only claimant and the violation disappears.
 */
export function libraryCoversLanguage(lib, language) {
  if (!language) return false;
  return libraryLanguages(lib).includes(language);
}

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

/**
 * Record every hardcoded secret in one file's contents.
 *
 * Extracted from the source-file loop so config files can be scanned with the
 * identical rules: one definition, so the two surfaces cannot drift.
 */
/**
 * Variables whose VALUE is a credential even though the value itself carries no
 * recognisable prefix.
 *
 * Prefix patterns (AKIA, ghp_, sk-) catch an identifier and miss its secret
 * half: `AWS_SECRET_ACCESS_KEY` is 40 characters of base64 alphabet with
 * nothing to key on. The variable it is assigned to is the signal, so the
 * length and alphabet of the value are what qualify it.
 */
const SECRET_ASSIGNMENTS = [
  { id: 'aws-secret', name: 'AWS Secret Access Key', envVar: 'AWS_SECRET_ACCESS_KEY',
    key: /AWS_SECRET_ACCESS_KEY/i, value: /^[A-Za-z0-9/+=]{40}$/ },
  { id: 'generic-secret-key', name: 'Secret Key', envVar: 'SECRET_KEY',
    key: /^(?:[A-Z0-9_]*_)?SECRET_KEY$/i, value: /^[A-Fa-f0-9]{32,}$|^[A-Za-z0-9/+=]{32,}$/ },
];

/** Values that are obviously stand-ins rather than credentials. */
const PLACEHOLDER_VALUE = /^(?:$|<.*>$|your[-_ ]|xxx+$|changeme$|placeholder$|todo$|example$|dummy$|test$|\.\.\.$)/i;

/**
 * Record every hardcoded secret in one file's contents.
 *
 * Extracted from the source-file loop so config files can be scanned with the
 * identical rules: one definition, so the two surfaces cannot drift.
 */
function collectSecrets(content, relPath, results) {
  const lines = content.split('\n');
  const seen = new Set();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 4096) continue; // ReDoS protection
    // An indirection is not a secret. `.env` files legitimately hold
    // `KEY=${OTHER}` and source holds `process.env.KEY`.
    if (/\$\{[A-Z_]+\}/.test(line) || /\$[A-Z_]{2,}/.test(line) || /process\.env\.[A-Z_]+/.test(line)) continue;

    const record = (id, name, envVar) => {
      const key = `${id}:${i + 1}`;
      if (seen.has(key)) return;
      seen.add(key);
      results.secrets.push({ type: id, name, file: relPath, line: i + 1, envVar, severity: 'critical' });
    };

    for (const { id, regex, name, envVar } of SECRET_PATTERNS) {
      regex.lastIndex = 0;
      if (regex.test(line)) record(id, name, envVar);
    }

    // Assignment-shaped credentials, judged by the value rather than a prefix.
    const assignment = /^\s*(?:export\s+)?([A-Za-z0-9_.]+)\s*[:=]\s*["']?([^"'\s#]*)["']?\s*(?:#.*)?$/.exec(line);
    if (!assignment) continue;
    const [, varName, rawValue] = assignment;
    if (PLACEHOLDER_VALUE.test(rawValue)) continue;
    for (const { id, name, envVar, key, value } of SECRET_ASSIGNMENTS) {
      if (key.test(varName) && value.test(rawValue)) record(id, name, envVar);
    }
  }
}

export function scanProject(projectDir, options = {}) {
  const results = {
    libraries: [],
    secrets: [],
    weakPatterns: [],
    // Findings a `cryptoserve-ignore` pragma cleared. They leave `weakPatterns`
    // -- so they do not fail a gate -- but they are not deleted: `scan`, `gate`
    // and the JSON output all report them, with the reason the author gave.
    // Suppression nobody can see is indistinguishable from a missed check.
    waivedFindings: [],
    // Pragmas that are malformed, name a rule that does not exist, or waived
    // nothing. Each one is an off switch that is not doing what its author
    // believes it is doing.
    waiverWarnings: [],
    certFiles: [],
    filesScanned: 0,   // source files matched to a language and analyzed
    configFilesScanned: 0, // config/dotenv files read for secrets
    privateKeyFiles: [], // cert files whose contents are a PRIVATE key
    filesWalked: 0,    // every file the walker examined, analyzed or not
    // New in v0.2.0
    sourceAlgorithms: [],
    // Every place an algorithm was seen, as opposed to `sourceAlgorithms`,
    // which is the deduplicated inventory: one row per algorithm:language for
    // the whole tree. Both are wanted, by different callers. A CBOM component
    // list must not repeat a component once per file; a gate reporting a
    // violation must name every file the reader has to change. Before this
    // existed the gate read the inventory, so MD5 in three files was one
    // violation naming the first, and the user found the second only after
    // fixing the first.
    algorithmSites: [],
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
  // library name -> { algorithms: Set, languages: Set }. Keyed by name across
  // the whole tree, so the languages are a set: `openssl` read from a .c file
  // and a .py file is one entry that owns sites in both.
  const sourceLibraries = new Map();

  // Cert files from walker. A public certificate and the private key that
  // signs it were reported in one undifferentiated list, so a committed
  // `server.key` looked exactly like a published `server.crt`. Publishing a
  // certificate is routine; publishing its key is the incident.
  for (const certPath of walked.certFiles) {
    const rel = relative(projectDir, certPath);
    results.certFiles.push(rel);
    let head = '';
    try { head = readFileSync(certPath, 'utf-8').slice(0, 4096); }
    catch { continue; }
    if (/-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/.test(head)) {
      results.privateKeyFiles.push(rel);
    }
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
      // Recorded before the inventory deduplication, and never subject to it:
      // this is the list of places, and the second and third file are exactly
      // what the deduplication drops.
      results.algorithmSites.push({
        algorithm: algo.algorithm,
        category: algo.category,
        language,
        file: relPath,
        line: algo.line,
      });
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
          severity: weakAlgorithmSeverity(dbEntry),
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
    //
    // The LANGUAGE is recorded for every import, not only the unambiguous ones.
    // Which algorithm belongs to which of two imports is undecidable here, but
    // which language the file is written in is not, and it is what stops a
    // library from being named as the source of a call in another language.
    for (const imp of langResult.imports) {
      if (!sourceLibraries.has(imp.library)) {
        sourceLibraries.set(imp.library, { algorithms: new Set(), languages: new Set() });
      }
      sourceLibraries.get(imp.library).languages.add(language);
    }
    if (langResult.imports.length === 1) {
      const only = sourceLibraries.get(langResult.imports[0].library);
      for (const algo of langResult.algorithms) only.algorithms.add(algo.algorithm);
    }

    // Keys generated below the current minimum size.
    for (const weakKey of scanWeakKeySizes(content)) {
      results.algorithmSites.push({
        algorithm: weakKey.algorithm,
        category: weakKey.category,
        language,
        file: relPath,
        line: weakKey.line,
      });
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
    const applicable = MISUSE_PATTERNS.filter(p => p.languages.includes(language));
    const { waivers, malformed, refused } = parseWaiverPragmas(content, language);

    for (const { id, pattern, issue, severity, fix } of applicable) {
      pattern.lastIndex = 0;
      let m;
      // Keeps reading after a WAIVED match rather than stopping at the first
      // one. This loop reports only the first match per pattern per file, so
      // stopping at a waived one would let a pragma on line 3 hide a real
      // defect on line 40 of the same file -- a waiver that silently widens
      // itself to the rest of the file. Behaviour is unchanged where no pragma
      // applies: the first unwaived match is reported, and the loop stops.
      while ((m = pattern.exec(content)) !== null) {
        const line = lineNumberAt(content, m.index);
        const evidence = m[0].slice(0, 80);
        const waiver = findWaiver(waivers, id, line);
        if (waiver) {
          results.waivedFindings.push({
            rule: id, file: relPath, line, issue, severity, reason: waiver.reason, evidence,
          });
          // A zero-length match would spin here forever. None of these patterns
          // can produce one, and this costs one comparison to guarantee it.
          if (m.index === pattern.lastIndex) pattern.lastIndex++;
          continue;
        }
        results.weakPatterns.push({
          file: relPath,
          line,
          rule: id,
          issue,
          severity,
          fix,
          evidence,
        });
        break;
      }
    }

    // Appended one at a time rather than spread. `push(...arr)` passes every
    // element as an argument, so a file with enough pragmas throws RangeError
    // on the argument limit instead of reporting them. Not reachable at the
    // default 1MB maxFileSize, but `.cryptoserve.json` can raise that and a
    // scanner must not crash on a file it was configured to read.
    for (const w of waiverWarnings(waivers, malformed, refused, MISUSE_RULE_IDS, relPath)) {
      results.waiverWarnings.push(w);
    }

    // Hardcoded secrets
    collectSecrets(content, relPath, results);
  }

  // Config files are scanned for secrets too. They were walked and then used
  // only for TLS settings, so a committed .env holding a live key reported
  // "Secrets found: 0" while the SAME literal in a .js file was found. That is
  // a false negative on the highest-value target the scanner has, on a
  // capability both help surfaces advertise.
  for (const filePath of walked.configFiles) {
    let content;
    try { content = readFileSync(filePath, 'utf-8'); }
    catch { continue; }
    results.configFilesScanned++;
    collectSecrets(content, relative(projectDir, filePath), results);
  }

  // Source-detected libraries (node:crypto, hashlib, openssl, ...) become
  // inventory entries carrying the algorithms actually observed in that file
  // set, rather than a hardcoded guess derived from which helper was imported.
  for (const [name, seen] of sourceLibraries) {
    if (seenPkgs.has(name)) continue; // already inventoried from a manifest
    const algorithms = [...seen.algorithms];
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
      // A source library has no ecosystem to derive its languages from, so it
      // carries the ones it was actually read in. Without this every consumer
      // has to fall back to matching on the algorithm name alone.
      languages: [...seen.languages],
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

function inventoryEntries(scanResults) {
  return scanResults.libraries.map(lib => {
    const entry = {
      name: lib.name,
      version: lib.version,
      algorithms: lib.algorithms,
      quantumRisk: lib.quantumRisk,
      category: lib.category,
      // Carried through because ownership is decided from the INVENTORY, and
      // `ecosystem` does not survive this mapping. Without it there is nothing
      // to decide ownership on but the algorithm name.
      languages: libraryLanguages(lib),
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
}

/**
 * The CENSUS: what cryptography this project contains. Feeds `analyzeOffline`,
 * and through it every score.
 *
 * A source algorithm gets a synthetic entry only when NO library lists that
 * name, in any language. That is deliberately a weaker test than the ownership
 * one below, and the two must not be merged: this list decides SCORES, and
 * `calculateQuantumScore` counts ROWS -- `deprecatedCount * 10`, uncapped --
 * while `classifyAlgorithms` deduplicates by algorithm name. So one row per
 * language for the same algorithm moves the score without changing the set of
 * algorithms present, in both directions:
 *
 *   - down: `md5` used from Python and C costs 20 points rather than 10, and a
 *     tree with four such pairs saturates at 0, where the score stops
 *     discriminating at all.
 *   - UP: a library declaring `AES-GCM` beside a Python `aes-gcm` site adds a
 *     second SAFE classification (the two spellings differ, and that dedup is
 *     case-sensitive), raising `safe / total`. A gate at `--min-score 30` on
 *     such a tree went 25/100 FAIL to 40/100 PASS -- a security gate turning
 *     green because attribution got more precise.
 *
 * Neither is a real change in exposure. Measured on this repository:
 * `classifyAlgorithms` returns the same 56 entries either way. So the census
 * keeps the name-only rule it has always had, and ownership is answered
 * separately, by the function below.
 */
export function toLibraryInventory(scanResults) {
  const inventory = inventoryEntries(scanResults);

  for (const algo of (scanResults.sourceAlgorithms || [])) {
    const alreadyInLib = inventory.some(lib =>
      lib.algorithms.some(a => a.toLowerCase() === algo.algorithm.toLowerCase())
    );
    if (!alreadyInLib) {
      inventory.push(syntheticOwner(algo));
    }
  }

  return inventory;
}

/**
 * OWNERSHIP: which library each call site belongs to. Feeds the gate's
 * violations, and nothing that is scored.
 *
 * Here the suppression is language-aware, which is the #67 fix: `crypto-js` is
 * npm and declares MD5, so it does not own a Python `hashlib.md5()` or an `md5`
 * in a `.c` file. Where no same-language library claims a site, a synthetic
 * owner is minted for it.
 *
 * That synthetic owner is the fail-open guard for the whole change. Refusing a
 * foreign library's claim without it leaves a site with no claimant, and what
 * happens next depends on the algorithm:
 *
 *   - a WEAK one is still caught by the weakPatterns sweep at the end of the
 *     gate, but as a `type: 'misuse'` row whose `source` is the FILE and whose
 *     `algorithm` is the issue prose. The violation survives; the attribution
 *     does not.
 *   - one that is only QUANTUM-risky has no weakPattern to fall back on, so it
 *     disappears entirely. The example has to use a call whose header is NOT a
 *     recognised include: `#include <openssl/rsa.h>` mints an `openssl` source
 *     library that owns the site, so it demonstrates nothing. `openssl/md5.h`
 *     and `openssl/sha.h` are the unrecognised ones.
 *
 * Measured twice, and wrong twice before this wording. The first version
 * claimed the synthetic owner is what keeps `md5@hash.c` a violation at all;
 * mutating the gate to iterate the census showed the sweep still reports it.
 * The second claimed the sweep's row carries no risk and no CWE; it carries
 * both, from `lookupAlgorithm`. What actually distinguishes the two is `source`
 * and the row type, which is what the regression test pins.
 */
export function toOwnershipInventory(scanResults) {
  const inventory = inventoryEntries(scanResults);

  for (const algo of (scanResults.sourceAlgorithms || [])) {
    const claimed = inventory.some(lib =>
      libraryCoversLanguage(lib, algo.language)
      && lib.algorithms.some(a => a.toLowerCase() === algo.algorithm.toLowerCase())
    );
    if (!claimed) {
      inventory.push(syntheticOwner(algo));
    }
  }

  return inventory;
}

function syntheticOwner(algo) {
  return {
    name: `${algo.language}:${algo.algorithm}`,
    version: 'source-code',
    algorithms: [algo.algorithm],
    languages: algo.language ? [algo.language] : [],
    quantumRisk: algo.quantumRisk || 'unknown',
    category: algo.category,
    isDeprecated: algo.isWeak || false,
  };
}
