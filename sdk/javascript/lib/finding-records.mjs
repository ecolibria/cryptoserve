/**
 * Corpus finding records: the scanner's contribution to the triage model.
 *
 * The CryptoServe triage SLM is trained on (code context, label) pairs mined
 * from census-sampled package source. That corpus has one structural weakness:
 * it only ever sees packages the census catalog names. Real codebases contain
 * crypto no catalog lists, in shapes no sampler picks.
 *
 * This module lets a scan emit those findings in the corpus record schema, so
 * a scan is not only a report but a contribution. Field records enter the
 * UNLABELED candidate pool only. Three properties make that safe:
 *
 *   1. `labels` is emitted as all-null and this module never fills it. Labels
 *      come from the teacher LLM or a human, never from a scan and never from
 *      the triage model itself. A model that trains on its own filtered output
 *      makes its blind spots permanent.
 *   2. `origin: "field"` marks every record. The eval path admits human-labeled
 *      gold only, and a gold sampler must never draw from field records: they
 *      come from the user's own tree, so a model evaluated on them would be
 *      scored on data it may have trained on.
 *   3. Emission is local and explicit. Records carry up to 10 lines of the
 *      caller's source either side of each finding. That is their code. It is
 *      written to a path they name, and this module has no network path.
 *
 * Schema and constants are kept byte-compatible with triage-slm
 * corpusgen/schema.py and corpusgen/scanner.py. Drift in either direction
 * silently produces records the pipeline will reject at validation.
 *
 * Zero dependencies.
 */

import { createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { join, sep } from 'node:path';
import { VERSION } from './version.mjs';
import { SECRET_PATTERNS } from './scanner.mjs';

// Context is up to 21 lines of the caller's own source. If a credential sits
// within that window, emitting the record verbatim would copy the credential
// into a corpus file. Redaction runs at emission, before the record exists on
// disk, and the version below is recorded truthfully: this is a redaction
// pass, not the corpus pipeline's full sanitizer (strike logic, entropy
// heuristics), which is not ported to the CLI.
const REDACTION_VERSION = 'cryptoserve-cli-redact/1';
const REDACTED = '[REDACTED-CREDENTIAL]';

function redact(line) {
  let out = line;
  for (const { regex } of SECRET_PATTERNS) {
    regex.lastIndex = 0;
    out = out.replace(regex, REDACTED);
  }
  return out;
}

// Kept in lockstep with corpusgen/scanner.py.
const CONTEXT_LINES = 10;
const MAX_CONTEXT_LINE_CHARS = 400;
const IMPORT_BLOCK_CAP = 20;
const FINDING_ID_HEX_LEN = 16;

// Path-flag heuristic: exact match on lowercased path segments only.
// Recorded per finding, never used to filter. Matching the corpus definition
// exactly matters: these are model inputs, so a different segment set here
// would shift the input distribution between corpus and field records.
const TEST_SEGMENTS = new Set(['test', 'tests', '__tests__', 'spec', 'fixtures']);
const DOCS_SEGMENTS = new Set(['docs', 'examples']);
const VENDOR_SEGMENTS = new Set(['vendor', 'node_modules', 'dist', 'compiled']);

// The JS scanner is regex-based throughout, so every field record carries the
// corpus generator's regex prior rather than an AST prior it has not earned.
const REGEX_CONFIDENCE_PRIOR = 0.8;

const IMPORT_LINE_PATTERNS = {
  javascript: /^\s*(?:import\b|export\s+.*\bfrom\b)|\brequire\s*\(\s*['"]/,
  python: /^\s*(?:import\s+\w|from\s+[.\w]+\s+import\b)/,
  go: /^\s*import\b|^\s*(?:[\w.]+\s+)?"[A-Za-z0-9_.~/-]+"\s*(?:\/\/.*)?$/,
  java: /^\s*import\s+[\w.]/,
  rust: /^\s*(?:pub(?:\([^)]*\))?\s+)?use\s+|^\s*(?:pub\s+)?extern\s+crate\s+/,
  c: /^\s*#\s*include\b/,
};

function clip(line) {
  // Redact before clipping: clipping first could split a credential and leave
  // a usable prefix behind.
  const safe = redact(line);
  return safe.length > MAX_CONTEXT_LINE_CHARS
    ? safe.slice(0, MAX_CONTEXT_LINE_CHARS) + '...[TRUNCATED]'
    : safe;
}

/**
 * Path flags for a package-relative path. Exact segment match, lowercased.
 */
export function pathFlags(relPath) {
  const parts = new Set(relPath.split(/[\\/]/).map(p => p.toLowerCase()));
  const has = set => [...parts].some(p => set.has(p));
  return {
    isTestLike: has(TEST_SEGMENTS),
    isVendoredLike: has(VENDOR_SEGMENTS),
    isDocsLike: has(DOCS_SEGMENTS),
  };
}

/**
 * The file's import block: first lines matching the language's import form,
 * in file order, capped.
 */
export function extractImportBlock(lines, language) {
  const pattern = IMPORT_LINE_PATTERNS[language];
  if (!pattern) return [];
  const imports = [];
  for (const line of lines) {
    if (pattern.test(line)) {
      imports.push(clip(line));
      if (imports.length >= IMPORT_BLOCK_CAP) break;
    }
  }
  return imports;
}

/**
 * Up to CONTEXT_LINES either side of a 1-based line, plus the import block.
 */
export function wideContext(lines, line, language) {
  const importBlock = extractImportBlock(lines, language);
  const idx = line - 1;
  if (idx < 0 || idx >= lines.length) {
    return { before: [], line: '', after: [], imports: importBlock };
  }
  return {
    before: lines.slice(Math.max(0, idx - CONTEXT_LINES), idx).map(clip),
    line: clip(lines[idx]),
    after: lines.slice(idx + 1, idx + 1 + CONTEXT_LINES).map(clip),
    imports: importBlock,
  };
}

/**
 * Stable id: two detections of the same algorithm at the same location are the
 * same logical finding. Same construction as corpusgen/schema.py finding_id.
 */
export function findingId({ name, ecosystem, version }, file, line, algorithm) {
  const key = `${ecosystem}:${name}:${version}:${file}:${line}:${algorithm}`;
  return createHash('sha256').update(key, 'utf-8').digest('hex').slice(0, FINDING_ID_HEX_LEN);
}

/**
 * Identify the scanned project. A local tree is not a registry package, so the
 * ecosystem is "local" and the identity is whatever the manifest declares.
 * Guessing a registry identity here would let a private fork be recorded under
 * a public package's name.
 */
export function projectIdentity(projectDir) {
  const fallbackName = projectDir.split(sep).filter(Boolean).pop() || 'unknown';
  const pkgPath = join(projectDir, 'package.json');
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
      return {
        name: pkg.name || fallbackName,
        ecosystem: 'local',
        version: pkg.version || '0.0.0',
      };
    } catch { /* unparseable manifest falls through to the directory name */ }
  }
  return { name: fallbackName, ecosystem: 'local', version: '0.0.0' };
}

/**
 * Build corpus records for a scan result.
 *
 * @param {object} scanResults - output of scanProject()
 * @param {string} projectDir - the scanned root
 * @returns {Array<object>} one record per source algorithm, labels all null
 */
export function buildFindingRecords(scanResults, projectDir) {
  const pkg = projectIdentity(projectDir);
  const records = [];
  const seen = new Set();
  const fileCache = new Map();

  function linesOf(relPath) {
    if (fileCache.has(relPath)) return fileCache.get(relPath);
    let lines = [];
    try {
      lines = readFileSync(join(projectDir, relPath), 'utf-8').split('\n');
    } catch { /* file moved or unreadable since the scan */ }
    fileCache.set(relPath, lines);
    return lines;
  }

  // Weak-pattern findings carry the CWE; index it so records keep the
  // classification the report showed.
  const cweByLocation = new Map();
  for (const w of scanResults.weakPatterns || []) {
    if (w.file && w.line && w.cwe) cweByLocation.set(`${w.file}:${w.line}:${w.algorithm}`, w.cwe);
  }

  for (const algo of scanResults.sourceAlgorithms || []) {
    if (!algo.file || !algo.line) continue;

    const id = findingId(pkg, algo.file, algo.line, algo.algorithm);
    if (seen.has(id)) continue;
    seen.add(id);

    const lines = linesOf(algo.file);

    records.push({
      findingId: id,
      package: { ...pkg },
      file: algo.file.split(sep).join('/'),
      line: algo.line,
      column: 0,                       // regex detection has no column
      language: algo.language,
      detector: 'regex',
      algorithm: algo.algorithm,
      category: algo.category,
      // The corpus generator attributes a library per finding via AST. The CLI
      // is regex-based and can only attribute when a file imports exactly one
      // crypto library, so the rest are explicitly unattributed rather than
      // guessed. Treat this field as weaker on field records than on corpus
      // records.
      library: algo.library || 'unattributed',
      functionCall: redact(algo.evidence || ''),
      confidencePrior: REGEX_CONFIDENCE_PRIOR,
      cwe: cweByLocation.get(`${algo.file}:${algo.line}:${algo.algorithm}`) || null,
      pathFlags: pathFlags(algo.file),
      context: wideContext(lines, algo.line, algo.language),
      // Never filled here. Labels come from a teacher LLM or a human; a scan
      // has no ground truth and the triage model must not label its own
      // training data.
      labels: {
        realVsNoise: null,
        algorithmClass: null,
        quantumStatus: null,
        migrationPriority: null,
      },
      // Marks the record as collected from a user's own tree rather than from
      // census-sampled package source. The eval path must exclude these.
      origin: 'field',
      generatorVersion: `cryptoserve-cli/${VERSION}`,
      sanitizerVersion: REDACTION_VERSION,
    });
  }

  return records;
}

/** Serialize records as JSONL. */
export function toJsonl(records) {
  return records.map(r => JSON.stringify(r)).join('\n');
}
