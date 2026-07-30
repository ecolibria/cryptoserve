#!/usr/bin/env node

/**
 * CryptoServe CLI — zero-dependency Node.js CLI.
 *
 * Usage:
 *   cryptoserve help
 *   cryptoserve version
 *   cryptoserve init [--insecure-storage]
 *   cryptoserve pqc [path] [--profile P] [--format json] [--verbose]
 *   cryptoserve scan [path] [--format json]
 *   cryptoserve encrypt "text" [--context C | --algorithm A] [--password P]
 *   cryptoserve decrypt "blob" [--password P]
 *   cryptoserve encrypt --file in --output out [--context C | --algorithm A] [--password P]
 *   cryptoserve decrypt --file in --output out [--password P]
 *   cryptoserve hash-password [--password P] [--algorithm scrypt|pbkdf2]
 *   cryptoserve context list | show NAME [--verbose] [--format json]
 *   cryptoserve cbom [path] [--format cyclonedx|spdx|json] [--output file]
 *   cryptoserve gate [path] [--max-risk R] [--min-score N] [--fail-on-weak] [--format json]
 *   cryptoserve vault init|set|get|list|delete|run|import|export [--password P]
 *   cryptoserve login [--server URL]
 *   cryptoserve status
 *   cryptoserve census [--format json|html] [--output file] [--no-cache] [--verbose]
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname, join, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf-8'));

// ---------------------------------------------------------------------------
// Arg parsing helpers
// ---------------------------------------------------------------------------

const OPTIONS_WITH_VALUES = new Set([
  '--password', '--algorithm', '--profile', '--format', '--file',
  '--output', '--server', '--context', '--max-risk', '--min-score',
  '--emit-findings',
]);

const KNOWN_FLAGS = new Set([
  '--insecure-storage', '--verbose', '--binary', '--fail-on-weak',
  '--help', '--version', '--no-cache', '--live', '--password-stdin',
  '--allow-secrets',
]);

/**
 * Render a finding's location as `file:line`, so every finding can be opened
 * directly. Falls back to the file alone when a finding has no line.
 */
function location(finding) {
  if (!finding?.file) return 'unknown location';
  return finding.line ? `${finding.file}:${finding.line}` : finding.file;
}

function getFlag(args, name) {
  const idx = args.indexOf(name);
  return idx !== -1;
}

function getOption(args, name, defaultValue = null) {
  const idx = args.indexOf(name);
  if (idx === -1 || idx + 1 >= args.length) return defaultValue;
  return args[idx + 1];
}

/**
 * Three outcomes rather than two, because `getOption` collapses "you did not
 * pass this" and "you passed it with nothing after it" into the same default —
 * which is how `--min-score` with no value quietly became 50 and `--password ""`
 * quietly became an interactive prompt.
 *
 * Returns `undefined` when absent, `null` when present with no value.
 */
function optionValue(args, name) {
  const idx = args.indexOf(name);
  if (idx === -1) return undefined;
  // Two occurrences are ambiguous, and `indexOf` silently picked the first --
  // so `gate . --min-score 10 $EXTRA_ARGS` discarded a stricter threshold the
  // caller appended, and never reported the one it ignored. Neither first-wins
  // nor last-wins is guessable; refusing is.
  if (args.indexOf(name, idx + 1) !== -1) {
    usageError(`${name} was given more than once.`, `${name} <value>  (exactly once)`);
  }
  if (idx + 1 >= args.length) return null;
  return args[idx + 1];
}

/**
 * Stop on an argument the command cannot act on. Exit 2 throughout: 1 means the
 * command ran and reported a failure, 2 means it could not run as invoked, so a
 * mistyped flag in CI can never be read as a result.
 */
function usageError(message, usage) {
  console.error(`Error: ${message}`);
  if (usage) console.error(`Usage: ${usage}`);
  process.exit(2);
}

/**
 * A numeric option, or a stop.
 *
 * `parseInt` is the wrong tool twice over: `parseInt('abc')` is NaN, and every
 * comparison against NaN is false — so an unchecked threshold is not a lax
 * threshold, it is no threshold at all. `parseInt('40abc')` is 40, which reads
 * a prefix off a value the user did not mean. `Number` rejects both.
 */
function numericOption(args, name, defaultValue, { min, max, onError = usageError }) {
  const raw = optionValue(args, name);
  if (raw === undefined) return defaultValue;
  if (raw === null || String(raw).trim() === '') {
    return onError(`${name} expects a number, but no value followed it.`,
      `${name} <number between ${min} and ${max}>`);
  }
  // A plain decimal only. `Number` alone accepts 0x10 (=16), 0b101 (=5) and
  // 1e-3, silently reinterpreting a value the usage line says is a number
  // between 0 and 100 -- the same class of quiet reinterpretation this
  // validation exists to end.
  if (!/^[+-]?(\d+\.?\d*|\.\d+)$/.test(String(raw).trim())) {
    return onError(`${name} expects a number, but received "${raw}".`,
      `${name} <number between ${min} and ${max}>`);
  }
  const value = Number(raw);
  if (!Number.isFinite(value)) {
    return onError(`${name} expects a number, but received "${raw}".`,
      `${name} <number between ${min} and ${max}>`);
  }
  if (value < min || value > max) {
    return onError(`${name} must be between ${min} and ${max}, but received ${value}.`,
      `${name} <number between ${min} and ${max}>`);
  }
  return value;
}

/**
 * One of a fixed set, or a stop. An unrecognised value used to fall through to
 * a default — `--format xml` silently produced text, and `--max-risk bogus`
 * scored -1 in the risk order so every algorithm counted as a breach.
 */
function choiceOption(args, name, defaultValue, allowed, { onError = usageError } = {}) {
  const raw = optionValue(args, name);
  if (raw === undefined) return defaultValue;
  if (raw === null || !allowed.includes(raw)) {
    return onError(`${name} expects one of: ${allowed.join(', ')}. Received ${raw === null ? 'no value' : `"${raw}"`}.`,
      `${name} <${allowed.join('|')}>`);
  }
  return raw;
}

/** What to do instead of typing a password, for every command that takes one. */
const HINT_PASSWORD =
  'Pass --password-stdin and pipe it in (printf %s "$PW" | cryptoserve ...), '
  + 'or --password <value>, or run the command in an interactive terminal.';

/**
 * Read a password from stdin, for `--password-stdin`.
 *
 * This exists because the alternative the CLI used to offer was worse:
 * `--password <value>` puts the secret in argv, where it is visible in `ps`,
 * /proc/<pid>/cmdline and shell history. `docker login --password-stdin` is the
 * established shape for exactly this reason, and a tool whose job is keeping
 * credentials out of places they should not be ought not to insist on the one
 * place they are most exposed.
 *
 * A trailing newline is stripped -- `printf '%s\n'` and `echo` both add one and
 * neither user means it to be part of the password.
 */
async function readPasswordFromStdin() {
  if (process.stdin.isTTY) {
    usageError(
      '--password-stdin expects a password on stdin, but stdin is a terminal.',
      'printf %s "$PASSWORD" | cryptoserve <command> --password-stdin'
    );
  }
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const value = Buffer.concat(chunks).toString('utf-8').replace(/\r?\n$/, '');
  if (value === '') {
    usageError(
      '--password-stdin was given nothing on stdin.',
      'printf %s "$PASSWORD" | cryptoserve <command> --password-stdin'
    );
  }
  return value;
}

/**
 * The password from `--password`, or null to prompt for it.
 *
 * `--password ""` and a bare `--password` are both falsy, and the old code read
 * falsy as "not supplied" and answered with an interactive prompt. A CI job
 * whose password variable resolved empty therefore blocked on a prompt that
 * could never be answered instead of saying the value was empty.
 */
async function passwordOption(args) {
  const fromStdin = getFlag(args, '--password-stdin');
  const raw = optionValue(args, '--password');
  if (fromStdin && raw !== undefined) {
    usageError('--password and --password-stdin are mutually exclusive.',
      '--password <value>  OR  --password-stdin');
  }
  if (fromStdin) return readPasswordFromStdin();
  if (raw === undefined) return null;
  if (raw === null || raw === '') {
    usageError('--password was given no value.', '--password <value>');
  }
  return raw;
}

/**
 * A directory this command is willing to work on, or a stop. Reporting a
 * confident result about a path that does not exist is the defect this closes:
 * `cbom ./typo` emitted a CBOM asserting perfect quantum readiness, and
 * `pqc ./typo` scored the current directory instead.
 */
async function requireDirectory(pathArg) {
  const { existsSync, statSync } = await import('node:fs');
  const target = pathArg ? resolve(pathArg) : process.cwd();
  if (!existsSync(target)) {
    usageError(`Path does not exist: ${target}`);
  }
  if (!statSync(target).isDirectory()) {
    usageError(`Not a directory: ${target}`);
  }
  return target;
}

/**
 * What was actually read, in one line.
 *
 * "Files scanned: 0" beside a confident readiness score reads as a broken run
 * when it is often correct: a project whose crypto is declared in package.json
 * and nowhere else has no source files to count. Naming both populations keeps
 * an empty tree distinguishable from a manifest-only one.
 */
function scannedSummary(scanResults) {
  const files = scanResults.filesScanned ?? 0;
  const manifests = scanResults.manifestsFound?.length ?? 0;
  const configs = scanResults.configFilesScanned ?? 0;
  const parts = [`${files} source ${files === 1 ? 'file' : 'files'}`];
  if (manifests > 0) parts.push(`${manifests} ${manifests === 1 ? 'manifest' : 'manifests'}`);
  if (configs > 0) parts.push(`${configs} config ${configs === 1 ? 'file' : 'files'}`);
  return parts.join(', ');
}

function getPositional(args) {
  const result = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith('--')) {
      if (OPTIONS_WITH_VALUES.has(args[i])) i++;
      continue;
    }
    result.push(args[i]);
  }
  return result;
}

/**
 * Stop on a flag this CLI does not know.
 *
 * This used to warn and continue, which is a fail-open in flag-name form:
 * `gate . --min-scoree 95` warned, silently fell back to the default threshold,
 * printed "(min: 50)" and exited 0. A typo must not loosen a gate. An
 * unparseable option VALUE already exits 2; an unknown option NAME is the same
 * class of mistake and now does too.
 */
function rejectUnknownFlags(args) {
  const unknown = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('--') && !OPTIONS_WITH_VALUES.has(arg) && !KNOWN_FLAGS.has(arg)) {
      unknown.push(arg);
    }
    if (OPTIONS_WITH_VALUES.has(arg)) i++; // skip value
  }
  if (unknown.length > 0) {
    usageError(`unknown ${unknown.length === 1 ? 'flag' : 'flags'}: ${unknown.join(', ')}`,
      'run "cryptoserve help <command>" for the flags this command accepts');
  }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

async function cmdHelp() {
  const { compactHeader, dim, bold, info } = await import('../lib/cli-style.mjs');
  console.log(compactHeader());
  console.log(`  ${bold('CryptoServe CLI')} v${PKG.version}`);
  console.log(`  ${dim('Cryptographic scanning, PQC analysis, encryption, and key management')}\n`);
  console.log(`  ${bold('Scanning & Analysis')}`);
  console.log(`    ${info('pqc [path] [--profile P] [--format json]')} Post-quantum readiness analysis`);
  console.log(`    ${info('scan [path] [--format json]')}           Scan project for crypto & secrets`);
  console.log(`    ${info('cbom [path] [--format F] [--output O]')} Generate Crypto Bill of Materials`);
  console.log(`    ${info('gate [path] [--max-risk R]')}            CI/CD gate (0=pass, 1=fail, 2=cannot run)`);
  console.log();
  console.log(`  ${bold('Research')}`);
  console.log(`    ${info('census [--format json|html]')}           Published crypto census (11 ecosystems + NVD)`);
  console.log();
  console.log(`  ${bold('Encryption')}`);
  console.log(`    ${info('encrypt "text" [--context C]')}          Encrypt with context-aware algorithm selection`);
  console.log(`    ${info('encrypt "text" [--password P]')}         Encrypt text (interactive password if omitted)`);
  console.log(`    ${info('decrypt "blob" [--password P]')}         Decrypt text`);
  console.log(`    ${info('encrypt --file F --output O')}           Encrypt file`);
  console.log(`    ${info('decrypt --file F --output O')}           Decrypt file`);
  console.log(`    ${info('hash-password [--password P] [--algorithm A]')}  Hash a password (scrypt/pbkdf2)`);
  console.log();
  console.log(`  ${bold('Contexts')}`);
  console.log(`    ${info('context list')}                          List available encryption contexts`);
  console.log(`    ${info('context show NAME [--verbose]')}         Show context details and resolved algorithm`);
  console.log();
  console.log(`  ${bold('Key Management')}`);
  console.log(`    ${info('init [--insecure-storage]')}             Set up master key + AI tool protection`);
  console.log(`    ${info('vault init [--password P]')}              Create encrypted vault`);
  console.log(`    ${info('vault set KEY VALUE [--password P]')}   Store a secret`);
  console.log(`    ${info('vault get KEY [--password P]')}         Retrieve a secret`);
  console.log(`    ${info('vault list [--password P]')}            List stored secrets`);
  console.log(`    ${info('vault delete KEY [--password P]')}      Remove a secret`);
  console.log(`    ${info('vault run [--password P] -- CMD')}      Run command with secrets as env vars`);
  console.log(`    ${info('vault import .env [--password P]')}     Import .env file into vault`);
  console.log();
  console.log(`  ${bold('Platform')}`);
  console.log(`    ${info('login [--server URL]')}                  Authenticate with CryptoServe server`);
  console.log(`    ${info('status')}                                Show configuration and server status`);
  console.log(`    ${info('version')}                               Show version`);
  console.log(`    ${info('help')}                                  Show this help`);
  console.log();
}

async function cmdVersion() {
  console.log(`cryptoserve ${PKG.version}`);
}

async function cmdInit(args) {
  const { compactHeader, success, info, warning, dim, labelValue } = await import('../lib/cli-style.mjs');
  const { initProject } = await import('../lib/init.mjs');

  console.log(compactHeader('init'));

  const insecure = getFlag(args, '--insecure-storage');
  const result = await initProject(process.cwd(), { insecureStorage: insecure });

  // Key storage
  if (result.keyStorage?.storage === 'keychain') {
    console.log(success(`Master key stored in OS keychain (${result.keyStorage.platform})`));
  } else if (result.keyStorage?.storage === 'encrypted-file') {
    console.log(success(`Master key stored in encrypted file`));
  } else if (result.keyStorage?.storage === 'plaintext-file') {
    console.log(warning('Master key stored as plaintext (--insecure-storage)'));
  } else if (result.keyStorage?.storage === 'existing') {
    console.log(info('Master key already configured'));
  }

  // AI tools
  if (result.toolsDetected.length > 0) {
    console.log(`\n  ${dim('Detected AI tools:')}`);
    for (const tool of result.toolsDetected) {
      console.log(`    ${success(tool)}`);
    }
  }

  if (result.toolsConfigured.length > 0) {
    console.log(`\n  ${dim('Configured protections:')}`);
    for (const tool of result.toolsConfigured) {
      console.log(`    ${success(tool)}`);
    }
  }

  if (result.filesCreated.length > 0) {
    console.log(`\n  ${dim('Created:')}`);
    for (const f of result.filesCreated) console.log(`    + ${f}`);
  }
  if (result.filesModified.length > 0) {
    console.log(`\n  ${dim('Modified:')}`);
    for (const f of result.filesModified) console.log(`    ~ ${f}`);
  }

  console.log();
}

async function cmdPqc(args) {
  const { compactHeader, section, labelValue, tableHeader, tableRow, progressBar, statusBadge, divider, success, warning, error, info, dim, bold } = await import('../lib/cli-style.mjs');
  const { analyzeOffline, DATA_PROFILES } = await import('../lib/pqc-engine.mjs');

  const profile = choiceOption(args, '--profile', 'general', Object.keys(DATA_PROFILES));
  const format = choiceOption(args, '--format', 'text', ['text', 'json']);
  const verbose = getFlag(args, '--verbose');

  // `pqc <path>` used to discard the path and analyse the current directory,
  // exit 0, and say nothing — a confident readiness score for the wrong tree.
  const positional = getPositional(args);
  const scanDir = await requireDirectory(positional[0]);

  // Use scanner results if available, otherwise use example libraries
  let libraries = [];
  let scanMeta = {};
  try {
    const { scanProject, toLibraryInventory } = await import('../lib/scanner.mjs');
    const scanResults = scanProject(scanDir);
    libraries = toLibraryInventory(scanResults);
    scanMeta = {
      filesScanned: scanResults.filesScanned,
      languagesDetected: scanResults.languagesDetected,
      manifestsFound: scanResults.manifestsFound,
    };
  } catch { /* scanner not available, empty libraries */ }

  const result = analyzeOffline(libraries, profile, scanMeta);

  if (format === 'json') {
    // Additive: what was analysed, alongside the analysis. A consumer reading
    // only the score cannot otherwise tell which tree it describes.
    console.log(JSON.stringify({
      ...result,
      scannedPath: scanDir,
      filesScanned: scanMeta.filesScanned ?? 0,
    }, null, 2));
    return;
  }

  console.log(compactHeader('pqc'));
  console.log(labelValue('Directory', scanDir));
  console.log(labelValue('Files scanned', scannedSummary(scanMeta)));

  // Data profile
  console.log(section('Data Profile'));
  console.log(labelValue('Profile', result.dataProfile.name));
  console.log(labelValue('Protection needed', `${result.dataProfile.lifespanYears} years`));
  console.log(labelValue('Urgency', result.dataProfile.urgency.toUpperCase()));

  // Quantum readiness score with confidence
  console.log(section('Quantum Readiness'));
  const conf = result.confidence;
  console.log(`  ${progressBar(result.quantumReadinessScore, 100)} ${bold(`${result.quantumReadinessScore}/100`)} ${dim(`(${conf.level} confidence — ${conf.reason})`)}`);
  console.log(labelValue('Migration urgency', result.migrationUrgency.toUpperCase()));

  // Risk breakdown
  if (result.riskBreakdown) {
    const rb = result.riskBreakdown;
    const parts = [];
    if (rb.critical > 0) parts.push(error(`${rb.critical} critical`));
    if (rb.high > 0) parts.push(warning(`${rb.high} high`));
    if (rb.medium > 0) parts.push(`${rb.medium} medium`);
    if (rb.low > 0) parts.push(`${rb.low} low`);
    if (rb.none > 0) parts.push(success(`${rb.none} safe`));
    if (parts.length > 0) console.log(labelValue('Risk breakdown', parts.join(' / ')));
  }

  // Languages detected
  if (scanMeta.languagesDetected?.length > 0) {
    console.log(labelValue('Languages', scanMeta.languagesDetected.join(', ')));
  }

  // SNDL assessment
  const sndl = result.sndlAssessment;
  console.log(section('SNDL Risk Assessment'));
  console.log(labelValue('Risk level', statusBadge(sndl.riskLevel)));
  console.log(labelValue('Vulnerable', sndl.vulnerable ? 'YES' : 'No'));
  console.log(labelValue('Risk window', `${sndl.riskWindowYears} years`));
  console.log(`  ${dim(sndl.explanation)}`);

  // KEM recommendations
  if (result.kemRecommendations.length > 0) {
    console.log(section('KEM Recommendations'));
    console.log(tableHeader(['Algorithm', 'FIPS', 'Level', 'Score'], [20, 12, 14, 8]));
    for (const rec of result.kemRecommendations) {
      console.log(tableRow(
        [rec.recommendedAlgorithm, rec.fipsStandard, rec.securityLevel, `${rec.score}%`],
        [20, 12, 14, 8]
      ));
    }
  }

  // Signature recommendations
  if (result.signatureRecommendations.length > 0) {
    console.log(section('Signature Recommendations'));
    console.log(tableHeader(['Algorithm', 'FIPS', 'Level', 'Score'], [20, 12, 14, 8]));
    for (const rec of result.signatureRecommendations) {
      console.log(tableRow(
        [rec.recommendedAlgorithm, rec.fipsStandard, rec.securityLevel, `${rec.score}%`],
        [20, 12, 14, 8]
      ));
    }
  }

  // Migration plan
  if (result.migrationPlan.length > 0) {
    console.log(section('Migration Plan'));
    for (const step of result.migrationPlan) {
      const icon = step.priority === 'CRITICAL' ? error(step.action)
        : step.priority === 'HIGH' ? warning(step.action)
        : info(step.action);
      console.log(`  ${step.step}. ${icon}`);
      if (verbose) console.log(`     ${dim(step.description)}`);
    }
  }

  // Key findings
  console.log(section('Key Findings'));
  for (const finding of result.keyFindings) {
    console.log(`  ${info(finding)}`);
  }

  // Next steps
  console.log(section('Next Steps'));
  for (const step of result.nextSteps) {
    console.log(`  ${success(step)}`);
  }

  // Compliance (verbose only)
  if (verbose && result.complianceReferences.length > 0) {
    console.log(section('Compliance References'));
    for (const ref of result.complianceReferences) {
      console.log(labelValue(ref.framework, `${ref.authority} — ${ref.detail}`));
    }
  }

  // Threat timelines (verbose only)
  if (verbose && Object.keys(result.threatTimelines).length > 0) {
    console.log(section('Threat Timelines'));
    console.log(tableHeader(['Algorithm', 'Min', 'Median', 'Max', 'Status'], [14, 6, 8, 6, 10]));
    for (const [, t] of Object.entries(result.threatTimelines)) {
      console.log(tableRow(
        [t.algorithm, `${t.minYears}y`, `${t.medianYears}y`, `${t.maxYears}y`, t.status],
        [14, 6, 8, 6, 10]
      ));
    }
  }

  console.log();
}

async function cmdScan(args) {
  const { compactHeader, section, tableHeader, tableRow, success, warning, error, info, dim, bold, labelValue } = await import('../lib/cli-style.mjs');
  const { scanProject } = await import('../lib/scanner.mjs');
  const { existsSync } = await import('node:fs');

  const positional = getPositional(args);
  const format = choiceOption(args, '--format', 'text', ['text', 'json', 'sarif']);
  const binaryFlag = getFlag(args, '--binary');

  // requireDirectory, not existsSync: a path that EXISTS but is a file walks to
  // zero source files and reports a clean tree, so `scan ./package.json` looked
  // like a scan of a project with no crypto in it. Existing is not scannable.
  // Exit 2 throughout: one condition, one code across scan/gate/cbom/pqc.
  const scanDir = await requireDirectory(positional[0]);

  const results = scanProject(scanDir);

  // Binary scanning — lazy-loaded only when requested
  if (binaryFlag) {
    const { scanBinaries } = await import('../lib/scanner-binary.mjs');
    results.binaryFindings = scanBinaries(scanDir);
  }

  // Corpus contribution. Explicit path, local write, no network path.
  const emitFindings = getOption(args, '--emit-findings');
  if (emitFindings) {
    const { buildFindingRecords, toJsonl } = await import('../lib/finding-records.mjs');
    const records = buildFindingRecords(results, scanDir);
    writeFileSync(emitFindings, records.length > 0 ? toJsonl(records) + '\n' : '');
    console.error(`Wrote ${records.length} finding record(s) to ${emitFindings}`);
    console.error('Records contain source context from this tree and are unlabeled. Review before sharing.');
  }

  const outputPath = getOption(args, '--output');

  function emit(document) {
    if (outputPath) {
      writeFileSync(outputPath, document + '\n');
      console.error(`Written to ${outputPath}`);
    } else {
      console.log(document);
    }
  }

  if (format === 'sarif') {
    const { collectFindings, toSarif } = await import('../lib/sarif.mjs');
    emit(JSON.stringify(toSarif(collectFindings(results)), null, 2));
    return;
  }

  if (format === 'json') {
    emit(JSON.stringify(results, null, 2));
    return;
  }

  if (format !== 'text') {
    console.error(`Unknown --format "${format}". Expected one of: text, json, sarif.`);
    process.exit(1);
  }

  console.log(compactHeader('scan'));
  console.log(labelValue('Directory', scanDir));
  console.log(labelValue('Source files', String(results.filesScanned)));
  // Named separately from source files: "Secrets found: 0" means something
  // different when no .env was read than when one was read and was clean.
  console.log(labelValue('Config files', String(results.configFilesScanned ?? 0)));
  if (results.filesWalked > results.filesScanned) {
    console.log(labelValue('Files examined', String(results.filesWalked)));
  }

  // Crypto libraries. A source-detected library with no attributable algorithm
  // list is shown as such rather than with a blank column.
  if (results.libraries.length > 0) {
    console.log(section('Crypto Libraries'));
    console.log(tableHeader(['Library', 'Version', 'Risk', 'Algorithms'], [22, 10, 10, 30]));
    for (const lib of results.libraries) {
      const algos = lib.algorithms.length > 0
        ? lib.algorithms.join(', ')
        : 'see source algorithms';
      console.log(tableRow([lib.name, lib.version, lib.quantumRisk, algos], [22, 10, 10, 30]));
    }
  } else {
    console.log(`\n  ${dim('No crypto libraries detected')}`);
  }

  // Hardcoded secrets
  if (results.secrets.length > 0) {
    console.log(section('Hardcoded Secrets'));
    for (const s of results.secrets) {
      console.log(`  ${error(`[CRIT] ${s.name}`)}`);
      console.log(`         ${dim(location(s))}`);
      if (s.envVar) console.log(`         ${info(`Fix: read from $${s.envVar}`)}`);
    }
  }

  // Weak patterns
  if (results.weakPatterns.length > 0) {
    console.log(section('Weak Crypto Patterns'));
    for (const w of results.weakPatterns) {
      const headline = w.cwe ? `${w.issue} (${w.cwe})` : w.issue;
      console.log(`  ${w.severity === 'critical' ? error(headline) : warning(headline)}`);
      console.log(`    ${dim(location(w))}`);
      if (w.fix) console.log(`    ${info(`Fix: ${w.fix}`)}`);
    }
  }

  // Source algorithms, with the location that produced each one
  if (results.sourceAlgorithms && results.sourceAlgorithms.length > 0) {
    console.log(section('Source Code Crypto'));
    console.log(tableHeader(['Algorithm', 'Category', 'Language', 'Risk', 'Location'], [18, 13, 11, 9, 30]));
    for (const algo of results.sourceAlgorithms) {
      console.log(tableRow(
        [algo.algorithm, algo.category, algo.language, algo.quantumRisk, location(algo)],
        [18, 13, 11, 9, 30]
      ));
    }
  }

  // TLS findings
  if (results.tlsFindings && results.tlsFindings.length > 0) {
    console.log(section('TLS/SSL Issues'));
    for (const tls of results.tlsFindings) {
      const icon = tls.risk === 'critical' ? error(`[CRIT] ${tls.protocol}`) : warning(`[${tls.risk.toUpperCase()}] ${tls.protocol}`);
      console.log(`  ${icon} ${dim(tls.file + ':' + tls.line)}`);
      console.log(`    ${dim(tls.recommendation)}`);
    }
  }

  // Binary findings
  if (results.binaryFindings && results.binaryFindings.length > 0) {
    console.log(section('Binary Crypto Signatures'));
    console.log(tableHeader(['Signature', 'Algorithm', 'Severity', 'File'], [24, 12, 10, 30]));
    for (const bf of results.binaryFindings) {
      console.log(tableRow(
        [bf.name, bf.algorithm, bf.severity, bf.file],
        [24, 12, 10, 30]
      ));
    }
  }

  // Cert files
  if (results.certFiles.length > 0) {
    console.log(section('Certificate/Key Files'));
    for (const f of results.certFiles) {
      console.log(`  ${info(f)}`);
    }
  }

  // Summary
  console.log(section('Summary'));
  console.log(labelValue('Libraries', String(results.libraries.length)));
  if (results.sourceAlgorithms?.length > 0) {
    console.log(labelValue('Source algorithms', String(results.sourceAlgorithms.length)));
  }
  if (results.languagesDetected?.length > 0) {
    console.log(labelValue('Languages', results.languagesDetected.join(', ')));
  }
  if (results.manifestsFound?.length > 0) {
    console.log(labelValue('Manifests', results.manifestsFound.join(', ')));
  }
  console.log(labelValue('Secrets found', results.secrets.length > 0 ? error(String(results.secrets.length)) : success('0')));
  console.log(labelValue('Weak patterns', results.weakPatterns.length > 0 ? warning(String(results.weakPatterns.length)) : success('0')));
  if (results.tlsFindings?.length > 0) {
    console.log(labelValue('TLS issues', warning(String(results.tlsFindings.length))));
  }
  console.log(labelValue('Cert/key files', String(results.certFiles.length)));
  console.log();
}

async function cmdEncrypt(args) {
  const { promptPassword } = await import('../lib/keychain.mjs');
  const { encryptString, encryptFile, ALGORITHMS } = await import('../lib/local-crypto.mjs');

  const file = getOption(args, '--file');
  const output = getOption(args, '--output');
  let password = await passwordOption(args);
  const contextName = getOption(args, '--context');
  const verbose = getFlag(args, '--verbose');
  let algorithm = choiceOption(args, '--algorithm', 'AES-256-GCM', Object.keys(ALGORITHMS));

  // Context-aware algorithm selection
  if (contextName) {
    const { resolveContext } = await import('../lib/context-resolver.mjs');
    const resolved = resolveContext(contextName);
    if (resolved.error) {
      console.error(`${resolved.error}\nValid contexts: ${resolved.validContexts.join(', ')}`);
      process.exit(2);
    }
    algorithm = resolved.algorithm;

    if (verbose) {
      const { dim, success, labelValue } = await import('../lib/cli-style.mjs');
      console.error(labelValue('Context', `${contextName} → ${algorithm}`));
      for (const f of resolved.factors) console.error(`  ${dim(f)}`);
      console.error();
    }
  }

  // Interactive password prompt if not provided
  if (!password) {
    password = await promptPassword('Encryption password: ', { hint: HINT_PASSWORD });
    if (!password) { console.error('Password required.'); process.exit(1); }
  }

  if (file) {
    const outPath = output || file + '.enc';
    encryptFile(file, outPath, password, algorithm, contextName || 'file');
    console.log(`Encrypted: ${outPath}`);
  } else {
    const positional = getPositional(args);
    const text = positional[0];
    if (!text) { usageError('Provide text to encrypt, or use --file.', 'encrypt "text" | encrypt --file F --output O'); }
    console.log(encryptString(text, password, algorithm, contextName || 'cli'));
  }
}

async function cmdDecrypt(args) {
  const { promptPassword } = await import('../lib/keychain.mjs');
  const { decryptString, decryptFile } = await import('../lib/local-crypto.mjs');

  const file = getOption(args, '--file');
  const output = getOption(args, '--output');
  let password = await passwordOption(args);

  if (!password) {
    password = await promptPassword('Decryption password: ', { hint: HINT_PASSWORD });
    if (!password) { console.error('Password required.'); process.exit(1); }
  }

  try {
    if (file) {
      const outPath = output || file.replace(/\.enc$/, '.dec');
      decryptFile(file, outPath, password);
      console.log(`Decrypted: ${outPath}`);
    } else {
      const positional = getPositional(args);
      const blob = positional[0];
      if (!blob) { usageError('Provide encrypted text, or use --file.', 'decrypt "blob" | decrypt --file F --output O'); }
      console.log(decryptString(blob, password));
    }
  } catch (e) {
    console.error(`Decryption failed: ${e.message}`);
    process.exit(1);
  }
}

async function cmdHashPassword(args) {
  const { promptPassword } = await import('../lib/keychain.mjs');
  const { hashPassword, HASH_ALGORITHMS } = await import('../lib/local-crypto.mjs');

  const algorithm = choiceOption(args, '--algorithm', 'scrypt', HASH_ALGORITHMS);
  let password = await passwordOption(args);
  if (!password) {
    const positional = getPositional(args);
    password = positional[0];
  }

  if (!password) {
    password = await promptPassword('Password to hash: ', { hint: HINT_PASSWORD });
    if (!password) { console.error('Password required.'); process.exit(1); }
  }

  console.log(hashPassword(password, algorithm));
}

async function cmdVault(args) {
  const { compactHeader, success, error, warning, info, dim, labelValue, tableHeader, tableRow } = await import('../lib/cli-style.mjs');
  const { promptPassword } = await import('../lib/keychain.mjs');

  const subcommand = args[0];
  const restArgs = args.slice(1);
  // Options filtered out before positionals are read. `vault set KEY --password PW`
  // used to take restArgs[1] literally and store the string "--password" as the
  // secret, exit 0 -- silent corruption through the very form the docs recommend
  // for CI. getPositional already knows which flags carry a value.
  const vaultPositionals = getPositional(restArgs);

  if (!subcommand || subcommand === 'help') {
    console.log(compactHeader('vault'));
    console.log('  vault init               Create new vault');
    console.log('  vault set KEY VALUE      Store a secret');
    console.log('  vault get KEY            Retrieve a secret');
    console.log('  vault list               List stored secrets');
    console.log('  vault delete KEY         Remove a secret');
    console.log('  vault run -- CMD ARGS    Run command with secrets as env vars');
    console.log('  vault import .env        Import .env file');
    console.log('  vault export             Export encrypted bundle');
    console.log('  vault reset              Delete vault');
    console.log();
    return;
  }

  const vault = await import('../lib/vault.mjs');

  // Support --password flag for non-interactive/CI usage
  const flagPassword = await passwordOption(restArgs);

  if (subcommand === 'init') {
    if (vault.vaultExists()) {
      console.log(warning('Vault already exists.'));
      return;
    }
    const pw = flagPassword || await promptPassword('Set vault password: ', { hint: HINT_PASSWORD });
    if (!flagPassword) {
      const pw2 = await promptPassword('Confirm password: ', { hint: HINT_PASSWORD });
      if (pw !== pw2) { console.error('Passwords do not match.'); process.exit(1); }
    }
    vault.initVault(pw);
    const { displayPath } = await import('../lib/paths.mjs');
    console.log(success(`Vault created at ${displayPath(vault.defaultVaultPath())}`));
    return;
  }

  if (subcommand === 'reset') {
    vault.resetVault();
    console.log(success('Vault deleted.'));
    return;
  }

  // All other commands need the vault password
  const pw = flagPassword || await promptPassword('Vault password: ', { hint: HINT_PASSWORD });

  try {
    switch (subcommand) {
      case 'set': {
        const key = vaultPositionals[0];
        let value = vaultPositionals[1];
        if (!key) { console.error('Usage: vault set KEY VALUE'); process.exit(2); }
        if (!value) {
          // Read from stdin if no value provided
          value = await promptPassword(`Value for ${key}: `, {
            hint: `Pass the value as an argument: cryptoserve vault set ${key} <value>`,
          });
        }
        vault.setSecret(pw, key, value);
        console.log(success(`Stored: ${key}`));
        break;
      }
      case 'get': {
        const key = vaultPositionals[0];
        if (!key) { console.error('Usage: vault get KEY'); process.exit(2); }
        const val = vault.getSecret(pw, key);
        if (val === null) { console.error(`Not found: ${key}`); process.exit(1); }
        console.log(val);
        break;
      }
      case 'list': {
        const secrets = vault.listSecrets(pw);
        if (secrets.length === 0) {
          console.log(dim('  Vault is empty'));
        } else {
          console.log(tableHeader(['Key', 'Updated'], [30, 24]));
          for (const s of secrets) {
            const ago = timeSince(new Date(s.updatedAt));
            console.log(tableRow([s.key, ago], [30, 24]));
          }
        }
        break;
      }
      case 'delete': {
        const key = vaultPositionals[0];
        if (!key) { console.error('Usage: vault delete KEY'); process.exit(2); }
        if (vault.deleteSecret(pw, key)) {
          console.log(success(`Deleted: ${key}`));
        } else {
          console.error(`Not found: ${key}`);
          process.exit(1);
        }
        break;
      }
      case 'run': {
        const dashIdx = restArgs.indexOf('--');
        const cmdArgs = dashIdx >= 0 ? restArgs.slice(dashIdx + 1) : restArgs;
        if (cmdArgs.length === 0) {
          console.error('Usage: vault run -- COMMAND [ARGS...]');
          process.exit(1);
        }
        const exitCode = await vault.vaultRun(pw, cmdArgs[0], cmdArgs.slice(1));
        process.exit(exitCode);
        break;
      }
      case 'import': {
        const envFile = vaultPositionals[0] || '.env';
        const count = vault.importEnvFile(pw, envFile);
        console.log(success(`Imported ${count} secrets from ${envFile}`));
        break;
      }
      case 'export': {
        const bundle = vault.exportVault(pw);
        console.log(bundle);
        break;
      }
      default:
        console.error(`Unknown vault command: ${subcommand}`);
        process.exit(2);
    }
  } catch (e) {
    // "There is no terminal to prompt on" is not a vault error and must not be
    // reported as one. It carries its own message and its own exit code.
    if (e?.code === 'ERR_NO_TTY') throw e;
    // node:crypto surfaces a failed GCM tag check as "Unsupported state or
    // unable to authenticate data", which tells a user nothing. For a vault
    // read there is exactly one ordinary cause.
    const message = /unable to authenticate data|Unsupported state/i.test(e.message)
      ? 'Wrong vault password (or the vault file has been modified).'
      : e.message;
    console.error(error(message));
    process.exit(1);
  }
}

async function cmdContext(args) {
  const { compactHeader, section, labelValue, tableHeader, tableRow, success, warning, dim, bold, info, statusBadge } = await import('../lib/cli-style.mjs');
  const { resolveContext, listContexts } = await import('../lib/context-resolver.mjs');

  const subcommand = args[0];
  const format = getOption(args, '--format', 'text');
  const verbose = getFlag(args, '--verbose');

  if (!subcommand || subcommand === 'list') {
    const contexts = listContexts();

    if (format === 'json') {
      console.log(JSON.stringify(contexts, null, 2));
      return;
    }

    console.log(compactHeader('contexts'));
    console.log(tableHeader(['Context', 'Sensitivity', 'Algorithm', 'Compliance'], [20, 12, 20, 20]));
    for (const ctx of contexts) {
      const badge = ctx.custom ? dim('(custom)') : '';
      console.log(tableRow(
        [ctx.name, ctx.sensitivity, ctx.algorithm, ctx.compliance.join(', ') || '—'],
        [20, 12, 20, 20]
      ));
    }
    console.log();
    return;
  }

  if (subcommand === 'show') {
    const name = args[1];
    if (!name) { usageError('context show needs a context name.', 'context show NAME [--verbose]'); }

    const resolved = resolveContext(name);
    if (resolved.error) {
      console.error(`${resolved.error}\nValid contexts: ${resolved.validContexts.join(', ')}`);
      process.exit(2);
    }

    if (format === 'json') {
      console.log(JSON.stringify(resolved, null, 2));
      return;
    }

    console.log(compactHeader('context'));

    // Identity
    console.log(section(resolved.context.displayName));
    console.log(labelValue('Context', resolved.context.name));
    if (resolved.context.description) {
      console.log(labelValue('Description', resolved.context.description));
    }
    if (resolved.context.custom) {
      console.log(labelValue('Source', dim('custom (.cryptoserve.json)')));
    }

    // Resolved algorithm
    console.log(section('Resolved Algorithm'));
    console.log(labelValue('Algorithm', bold(resolved.algorithm)));
    console.log(labelValue('Key size', `${resolved.keyBits} bits`));
    console.log(labelValue('Key rotation', `${resolved.rotationDays} days`));
    if (resolved.quantumRisk) {
      console.log(labelValue('Quantum risk', warning('PQC migration recommended')));
    }

    // 5-layer summary
    console.log(section('Context Layers'));
    console.log(labelValue('1. Sensitivity', resolved.context.sensitivity.toUpperCase()));

    const flags = [];
    if (resolved.context.pii) flags.push('PII');
    if (resolved.context.phi) flags.push('PHI');
    if (resolved.context.pci) flags.push('PCI');
    if (flags.length) console.log(labelValue('   Data flags', flags.join(', ')));

    console.log(labelValue('2. Compliance', resolved.context.compliance.join(', ') || '—'));
    console.log(labelValue('3. Threat model', resolved.context.adversaries.join(', ')));
    console.log(labelValue('   Protection', `${resolved.context.protectionYears} years`));
    console.log(labelValue('4. Access', `${resolved.context.frequency} frequency, ${resolved.context.usage}`));

    // Examples
    if (resolved.context.examples.length > 0) {
      console.log(labelValue('   Examples', resolved.context.examples.join(', ')));
    }

    // Verbose: full rationale
    if (verbose) {
      console.log(section('Resolution Rationale'));
      for (const f of resolved.factors) {
        console.log(`  ${dim(f)}`);
      }

      if (resolved.alternatives.length > 0) {
        console.log(section('Alternatives'));
        for (const alt of resolved.alternatives) {
          console.log(`  ${info(alt.algorithm)}`);
          console.log(`    ${dim(alt.reason)}`);
        }
      }
    }

    // Usage hint
    console.log(section('Usage'));
    console.log(`  ${dim(`cryptoserve encrypt "data" --context ${name} --password P`)}`);
    console.log();
    return;
  }

  console.error(`Unknown context command: ${subcommand}`);
  console.error('Usage: context list | context show NAME');
  process.exit(2);
}

async function cmdCbom(args) {
  const { compactHeader, section, labelValue, success, dim, bold, info } = await import('../lib/cli-style.mjs');
  const { scanProject, toLibraryInventory } = await import('../lib/scanner.mjs');
  const { analyzeOffline } = await import('../lib/pqc-engine.mjs');
  const { generateCbom, toCycloneDx, toSpdx, toNativeJson } = await import('../lib/cbom.mjs');

  const positional = getPositional(args);
  const format = choiceOption(args, '--format', 'json', ['json', 'cyclonedx', 'spdx']);
  const output = getOption(args, '--output');

  // `scan` and `gate` already refuse a path that does not exist; `cbom` did
  // not, and answered a typo with a valid CBOM asserting quantumReadiness 100
  // and riskLevel "none". A compliance artifact certifying a tree nobody read
  // is worse than no artifact.
  const scanDir = await requireDirectory(positional[0]);

  const scanResults = scanProject(scanDir);
  const libraries = toLibraryInventory(scanResults);
  const pqcResult = analyzeOffline(libraries);
  const projectName = basename(scanDir);

  const cbom = generateCbom(scanResults, pqcResult, projectName, scanDir);

  let formatted;
  switch (format) {
    case 'cyclonedx': formatted = JSON.stringify(toCycloneDx(cbom), null, 2); break;
    case 'spdx':      formatted = JSON.stringify(toSpdx(cbom), null, 2); break;
    default:          formatted = JSON.stringify(toNativeJson(cbom), null, 2); break;
  }

  if (output) {
    writeFileSync(output, formatted + '\n');
    console.log(success(`CBOM written to ${output}`));
    console.log(labelValue('Format', format));
    console.log(labelValue('Directory', scanDir));
    console.log(labelValue('Files scanned', scannedSummary(scanResults)));
    console.log(labelValue('Components', String(cbom.components.length)));
    console.log(labelValue('Quantum readiness', `${cbom.quantumReadiness.score}/100`));
    console.log(labelValue('Risk level', cbom.quantumReadiness.riskLevel));
  } else {
    console.log(formatted);
    // To stderr, so the document on stdout stays pipeable. An empty CBOM from a
    // real but wrong directory is indistinguishable from one from a clean
    // project until you can see how much was read.
    console.error(
      `Scanned ${scannedSummary(scanResults)} under ${scanDir}: ` +
      `${cbom.components.length} ${cbom.components.length === 1 ? 'component' : 'components'}.`
    );
  }
}

async function cmdGate(args) {
  const { scanProject, toLibraryInventory } = await import('../lib/scanner.mjs');
  const { analyzeOffline } = await import('../lib/pqc-engine.mjs');
  const { lookupAlgorithm } = await import('../lib/algorithm-db.mjs');
  const { existsSync } = await import('node:fs');

  const positional = getPositional(args);
  const scanDir = positional.length > 0 ? resolve(positional[0]) : process.cwd();
  const failOnWeak = getFlag(args, '--fail-on-weak');
  const { statSync } = await import('node:fs');

  const riskOrder = ['none', 'low', 'medium', 'high', 'critical'];

  // --format decides how every later error is rendered, so it is validated
  // first, and against plain stderr because there is not yet a format to honour.
  const format = choiceOption(args, '--format', 'text', ['text', 'json', 'sarif']);

  /**
   * A gate that cannot run must say so in the caller's own format. A CI job
   * parsing JSON should not have to read stderr to learn that its threshold
   * was rejected.
   */
  function refuse(message, usage) {
    if (format === 'json') {
      console.log(JSON.stringify({ status: 'error', error: message }, null, 2));
    } else {
      console.error(`Error: ${message}`);
      if (usage) console.error(`Usage: ${usage}`);
    }
    process.exit(2);
  }

  // Both thresholds are validated BEFORE any scanning. An unusable threshold is
  // not a weaker gate, it is an absent one: `parseInt('abc')` is NaN and
  // `score < NaN` is false, so a typo'd `--min-score` in CI turned a failing
  // gate green while the report printed `min: NaN`. An unknown `--max-risk`
  // scored -1 in the risk order, which made every algorithm a breach.
  const maxRisk = choiceOption(args, '--max-risk', 'high', riskOrder, { onError: refuse });
  const minScore = numericOption(args, '--min-score', 50, { min: 0, max: 100, onError: refuse });

  // A missing path is an error class (exit 2), not a clean pass. Without this
  // a typo in CI (`cryptoserve gate ./srcc`) silently scores 100 and lets the
  // build through.
  if (!existsSync(scanDir)) {
    refuse(`Path does not exist: ${scanDir}`);
  }
  // Existing is not the same as scannable. `gate ./package.json --min-score 99`
  // walked zero source files, found zero violations and certified 100/100 --
  // the same fail-open as a missing path, in the CI enforcement command.
  if (!statSync(scanDir).isDirectory()) {
    refuse(`Not a directory: ${scanDir}`);
  }

  try {
    const scanResults = scanProject(scanDir);
    const libraries = toLibraryInventory(scanResults);
    const pqcResult = analyzeOffline(libraries);
    const score = pqcResult.quantumReadinessScore;

    // Where each algorithm was actually seen, so a violation points at code
    // rather than at an inventory row.
    const locations = new Map();
    for (const algo of scanResults.sourceAlgorithms || []) {
      if (!algo.file) continue;
      const key = algo.algorithm.toLowerCase();
      if (!locations.has(key)) locations.set(key, { file: algo.file, line: algo.line });
    }

    // Collect violations, one per algorithm. The previous pass emitted a
    // separate row for the risk breach and the weakness, so a single MD5 call
    // printed twice and inflated the violation count.
    const byAlgorithm = new Map();
    const maxRiskIdx = riskOrder.indexOf(maxRisk);

    for (const lib of libraries) {
      for (const algoName of lib.algorithms) {
        const entry = lookupAlgorithm(algoName);
        if (!entry) continue;

        const riskBreach = riskOrder.indexOf(entry.quantumRisk) > maxRiskIdx;
        const weakBreach = failOnWeak && entry.isWeak;
        if (!riskBreach && !weakBreach) continue;

        const key = algoName.toLowerCase();
        const existing = byAlgorithm.get(key);
        const where = locations.get(key);
        const violation = existing || {
          algorithm: algoName,
          risk: entry.quantumRisk,
          source: lib.name + (lib.version && lib.version !== 'source-code' ? `@${lib.version}` : ''),
          ...(where ? { file: where.file, line: where.line } : {}),
        };
        if (riskBreach) violation.riskBreach = true;
        if (weakBreach) {
          violation.weak = true;
          violation.reason = entry.weaknessReason;
          if (entry.cwe) violation.cwe = entry.cwe;
        }
        byAlgorithm.set(key, violation);
      }
    }

    const violations = [...byAlgorithm.values()];

    // A hardcoded secret is the highest-severity thing the scanner reports, and
    // the gate used to ignore it entirely: `scan` printed
    // "[CRIT] AWS Access Key .env:1" while `gate` on the same tree returned
    // PASS 100/100. Two commands reading one tree must not disagree on
    // direction, so secrets fail the gate unless waived by name.
    const allowSecrets = getFlag(args, '--allow-secrets');
    const secretFindings = scanResults.secrets || [];
    if (!allowSecrets) {
      for (const secret of secretFindings) {
        violations.push({
          type: 'secret',
          algorithm: secret.name,
          risk: 'critical',
          source: secret.file,
          file: secret.file,
          line: secret.line,
          reason: secret.envVar ? `read it from $${secret.envVar} instead` : 'hardcoded credential',
        });
      }
    }

    // A gate that read nothing cannot certify anything. An empty tree scored
    // 100/100 PASS, which is a verdict about something never measured -- the
    // same shape as certifying a path that does not exist.
    const readSomething = (scanResults.filesScanned ?? 0) > 0
      || (scanResults.configFilesScanned ?? 0) > 0
      || (scanResults.manifestsFound?.length ?? 0) > 0;
    if (!readSomething) {
      refuse(`Found no files to scan under ${scanDir}. A gate cannot pass a tree it did not read.`);
    }

    const scoreFail = score < minScore;
    const pass = violations.length === 0 && !scoreFail;

    const summary = {
      // How much was actually looked at. A gate that scanned nothing and a gate
      // that scanned a clean tree both report zero violations; only the count
      // tells them apart, which is what makes a wrong path visible.
      filesScanned: scanResults.filesScanned,
      manifestsFound: scanResults.manifestsFound?.length ?? 0,
      total: libraries.reduce((sum, l) => sum + l.algorithms.length, 0),
      safe: libraries.reduce((sum, l) => sum + l.algorithms.filter(a => {
        const e = lookupAlgorithm(a);
        return e && (e.quantumRisk === 'none' || e.quantumRisk === 'low');
      }).length, 0),
      vulnerable: violations.filter(v => !v.weak && v.type !== 'secret').length,
      weak: violations.filter(v => v.weak).length,
      secrets: secretFindings.length,
    };

    const outputPath = getOption(args, '--output');

    if (format === 'sarif') {
      const { collectFindings, toSarif } = await import('../lib/sarif.mjs');
      const document = JSON.stringify(toSarif(collectFindings(scanResults)), null, 2);
      if (outputPath) {
        const { writeFileSync } = await import('node:fs');
        writeFileSync(outputPath, document + '\n');
        console.error(`SARIF written to ${outputPath}`);
      } else {
        console.log(document);
      }
      process.exit(pass ? 0 : 1);
    }

    if (format === 'json') {
      const document = JSON.stringify({
        status: pass ? 'pass' : 'fail',
        score,
        violations,
        summary,
      }, null, 2);
      if (outputPath) {
        const { writeFileSync } = await import('node:fs');
        writeFileSync(outputPath, document + '\n');
        console.error(`JSON written to ${outputPath}`);
      } else {
        console.log(document);
      }
    } else {
      const { compactHeader, success, error, warning, dim, bold, labelValue } = await import('../lib/cli-style.mjs');
      console.log(compactHeader('gate'));
      console.log(labelValue('Status', pass ? success('PASS') : error('FAIL')));
      console.log(labelValue('Directory', scanDir));
      console.log(labelValue('Files scanned', scannedSummary(scanResults)));
      console.log(labelValue('Score', `${score}/100 (min: ${minScore})`));
      console.log(labelValue('Max risk', maxRisk));

      if (violations.length > 0) {
        console.log(`\n  ${bold('Violations:')}`);
        for (const v of violations) {
          const label = v.type === 'secret'
            ? error(`[SECRET] ${v.algorithm}`)
            : v.weak ? warning(`[WEAK] ${v.algorithm}`) : error(`[${v.risk.toUpperCase()}] ${v.algorithm}`);
          const where = v.file ? ` ${dim(location(v))}` : ` ${dim(v.source)}`;
          console.log(`  ${label}${where}${v.reason ? ` ${dim(`(${v.reason})`)}` : ''}`);
        }
      }

      if (scoreFail) {
        console.log(`\n  ${error(`Score ${score} is below minimum ${minScore}`)}`);
      }

      console.log();
    }

    process.exit(pass ? 0 : 1);
  } catch (e) {
    if (format === 'json') {
      console.log(JSON.stringify({ status: 'error', error: e.message }, null, 2));
    } else {
      console.error(`Error: ${e.message}`);
    }
    process.exit(2);
  }
}

async function cmdLogin(args) {
  const { login } = await import('../lib/client.mjs');

  // No default server. The old one was https://localhost:8003, where nothing
  // runs on a user's machine, so the out-of-the-box flow could only time out.
  const server = optionValue(args, '--server');
  if (server === undefined || server === null || server === '') {
    usageError('login requires the server to authenticate against.',
      'login --server https://cryptoserve.example.com');
  }

  // login opens a browser and waits on a localhost callback. With no terminal
  // there is no browser and no one to complete the flow, so it used to print a
  // URL and block for 120 seconds. Every other interactive command refuses
  // immediately; this one hung the job.
  if (!process.stdin.isTTY) {
    console.error('Cannot log in: stdin is not a terminal, and login needs a browser session.');
    console.error('Authenticate on a workstation, then copy the credentials file, or use a');
    console.error('server-issued token in your CI configuration.');
    process.exit(2);
  }

  try {
    await login(server);
    console.log('Login successful.');
  } catch (e) {
    console.error(`Login failed: ${e.message}`);
    process.exit(1);
  }
}

async function cmdStatus() {
  const { compactHeader, section, labelValue, statusBadge, dim } = await import('../lib/cli-style.mjs');
  const { loadToken, maskToken, parseJwtExpiry } = await import('../lib/credentials.mjs');
  const { loadMasterKey, isKeychainAvailable } = await import('../lib/keychain.mjs');
  const { vaultExists } = await import('../lib/vault.mjs');
  const { getStatus } = await import('../lib/client.mjs');

  console.log(compactHeader('status'));

  // Key management
  console.log(section('Key Management'));
  const keychainOk = await isKeychainAvailable();
  console.log(labelValue('OS keychain', keychainOk ? statusBadge('active') : statusBadge('unavailable')));

  let hasKey = false;
  try { hasKey = !!(await loadMasterKey()); } catch { /* no key */ }
  console.log(labelValue('Master key', hasKey ? statusBadge('ready') : statusBadge('not configured')));
  console.log(labelValue('Vault', vaultExists() ? statusBadge('ready') : statusBadge('not initialized')));

  // Server connection
  console.log(section('Server Connection'));
  const creds = loadToken();
  if (creds) {
    console.log(labelValue('Server', creds.server));
    console.log(labelValue('Token', maskToken(creds.token)));
    const expiry = parseJwtExpiry(creds.token);
    if (expiry) {
      if (expiry.expired) {
        console.log(labelValue('Expiry', statusBadge('expired')));
      } else {
        const mins = Math.floor(expiry.remainingMs / 60000);
        console.log(labelValue('Expiry', `${mins} minutes remaining`));
      }
      if (expiry.subject) console.log(labelValue('Subject', expiry.subject));
    }

    const status = await getStatus();
    console.log(labelValue('Connection', status.connected ? statusBadge('healthy') : statusBadge('error')));
    if (status.latency) console.log(labelValue('Latency', `${status.latency}ms`));
  } else {
    console.log(labelValue('Status', dim('Not logged in')));
  }

  console.log();
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function timeSince(date) {
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
  if (seconds < 60) return 'just now';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

// ---------------------------------------------------------------------------
// Census — global crypto adoption survey
// ---------------------------------------------------------------------------

/**
 * Census: render the published census snapshot.
 *
 * This command used to collect the census itself, from its own copy of the
 * collectors and its own copy of the catalog. Two copies of a published
 * measurement disagree, and these did: the CLI catalogued 357 packages against
 * the census's 355, and every collector here recorded a failed request as
 * `downloads: 0`, so a rate-limited run reported real packages as having no
 * downloads at all. It is now a client of the published snapshot, so the number
 * it prints is the number census.cryptoserve.dev serves, by construction.
 */
async function cmdCensus(args) {
  const {
    compactHeader, section, labelValue, tableHeader, tableRow,
    warning, info, dim, bold, divider, progressBar,
  } = await import('../lib/cli-style.mjs');

  const format = choiceOption(args, '--format', 'text', ['text', 'json', 'html']);
  const output = getOption(args, '--output', null);
  const verbose = getFlag(args, '--verbose');
  const noCache = getFlag(args, '--no-cache');

  if (getFlag(args, '--live')) {
    console.error('cryptoserve census --live has been removed.');
    console.error('');
    console.error('It collected its own copy of the download figures, which disagreed with the');
    console.error('published census and recorded a rate-limited request as zero downloads.');
    console.error('The census now publishes dated snapshots and this command renders them;');
    console.error('`cryptoserve census --no-cache` re-fetches the current one.');
    process.exitCode = 2;
    return;
  }

  const { fetchCensus, describeAge } = await import('../lib/census/index.mjs');

  let result;
  try {
    result = await fetchCensus({ noCache, verbose });
  } catch (err) {
    console.error(`Could not load the census snapshot: ${err.message}`);
    console.error('');
    console.error('The published snapshot is at https://census.cryptoserve.dev/api/census');
    console.error('and the full dataset at https://census.cryptoserve.dev/api/download.');
    process.exitCode = 1;
    return;
  }

  const data = result.data;

  if (result.source === 'stale-cache') {
    console.error(`Warning: showing a cached snapshot ${describeAge(Date.now() - new Date(result.fetchedAt).getTime())}.`);
    console.error(`Reason: ${result.failure}`);
    console.error('');
  }

  if (format === 'json') {
    const json = JSON.stringify(data, null, 2);
    if (output) {
      writeFileSync(resolve(output), json);
      console.log(`Census data written to ${output}`);
    } else {
      console.log(json);
    }
    return;
  }

  if (format === 'html') {
    const { generateHtml } = await import('../lib/census/report-html.mjs');
    const html = generateHtml(data);
    const outFile = output || 'crypto-census.html';
    writeFileSync(resolve(outFile), html);
    console.log(`HTML report written to ${outFile}`);
    return;
  }

  const { renderTerminal } = await import('../lib/census/report-terminal.mjs');
  renderTerminal(data, {
    compactHeader, section, labelValue, tableHeader, tableRow,
    warning, info, dim, bold, divider, progressBar,
  });
}

// ---------------------------------------------------------------------------
// Subcommand help text
// ---------------------------------------------------------------------------

const COMMAND_HELP = {
  init: 'cryptoserve init [--insecure-storage]\n\n  Set up master key and AI tool protection for the current project.',
  pqc: 'cryptoserve pqc [path] [--profile P] [--format text|json] [--verbose]\n\n  Analyze post-quantum cryptography readiness of a directory (default: the\n  current one). The report names the directory it analyzed.',
  scan: 'cryptoserve scan [path] [--format text|json|sarif] [--output file] [--binary] [--emit-findings file]\n\n  Scan a project directory for crypto libraries, hardcoded secrets, weak patterns, and certificates.\n  --emit-findings writes unlabeled corpus records (JSONL) for the CryptoServe triage model.\n  Records include source context from the scanned tree and are written locally only.',
  encrypt: 'cryptoserve encrypt "text" [--context C | --algorithm A] [--password P]\ncryptoserve encrypt --file F --output O [--context C | --algorithm A] [--password P]\n\n  Encrypt text or a file with context-aware algorithm selection.',
  decrypt: 'cryptoserve decrypt "blob" [--password P]\ncryptoserve decrypt --file F --output O [--password P]\n\n  Decrypt text or a file.',
  'hash-password': 'cryptoserve hash-password [--password P] [--algorithm scrypt|pbkdf2]\n\n  Hash a password using scrypt or pbkdf2.\n  Use --password for non-interactive/CI usage.',
  context: 'cryptoserve context list [--format json]\ncryptoserve context show NAME [--verbose] [--format json]\n\n  List or inspect encryption contexts.',
  cbom: 'cryptoserve cbom [path] [--format cyclonedx|spdx|json] [--output file]\n\n  Generate a Crypto Bill of Materials. Reports how many files it read, and\n  refuses a path that does not exist rather than certifying an empty tree.',
  gate: 'cryptoserve gate [path] [--max-risk none|low|medium|high|critical]\n        [--min-score 0-100] [--fail-on-weak] [--format text|json|sarif]\n\n  CI/CD gate: exit 0 on pass, 1 on fail, 2 when it could not run — an\n  unreadable path or an option value it cannot enforce.',
  vault: 'cryptoserve vault init|set|get|list|delete|run|import|export|reset [--password P]\n\n  Manage an encrypted secrets vault.\n  Use --password for non-interactive/CI usage.',
  login: 'cryptoserve login [--server URL]\n\n  Authenticate with a CryptoServe server.',
  status: 'cryptoserve status\n\n  Show configuration and server connection status.',
  census: 'cryptoserve census [--format json|html] [--output file] [--no-cache] [--verbose]\n\n  Render the published global crypto adoption census: 11 ecosystems, NVD and\n  GitHub advisories, collected on the date the snapshot carries.\n\n  The snapshot is fetched from census.cryptoserve.dev and cached for a day.\n  --no-cache re-fetches it. This command reports the published measurement and\n  does not collect its own, so its figures match census.cryptoserve.dev exactly.',
};

function showCommandHelp(command) {
  const text = COMMAND_HELP[command];
  if (text) {
    console.log(`\nUsage:\n  ${text}\n`);
  } else {
    console.error(`No help available for "${command}".`);
  }
}

// ---------------------------------------------------------------------------
// Main router
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
const command = args[0];
const commandArgs = args.slice(1);

// Intercept --help / -h for any subcommand
if (command && !['help', '--help', '-h', 'version', '--version', '-v', undefined].includes(command)) {
  if (commandArgs.includes('--help') || commandArgs.includes('-h')) {
    showCommandHelp(command);
    process.exit(0);
  }
}

// Warn about unknown flags (skip for vault/context which have subcommands)
if (command && !['vault', 'context', 'help', '--help', '-h', 'version', '--version', '-v'].includes(command)) {
  rejectUnknownFlags(commandArgs);
}

try {
  switch (command) {
    case 'help':
    case '--help':
    case '-h':
    case undefined:
      // `cryptoserve help census` printed the whole command list, so the
      // per-command help existed but only `census --help` reached it.
      if (commandArgs[0] && COMMAND_HELP[commandArgs[0]]) {
        showCommandHelp(commandArgs[0]);
      } else if (commandArgs[0]) {
        console.error(`No help available for "${commandArgs[0]}".`);
        console.error('Run "cryptoserve help" for the command list.');
        process.exitCode = 1;
      } else {
        await cmdHelp();
      }
      break;
    case 'version':
    case '--version':
    case '-v':
      await cmdVersion();
      break;
    case 'init':
      await cmdInit(commandArgs);
      break;
    case 'pqc':
      await cmdPqc(commandArgs);
      break;
    case 'scan':
      await cmdScan(commandArgs);
      break;
    case 'encrypt':
      await cmdEncrypt(commandArgs);
      break;
    case 'decrypt':
      await cmdDecrypt(commandArgs);
      break;
    case 'hash-password':
      await cmdHashPassword(commandArgs);
      break;
    case 'context':
      await cmdContext(commandArgs);
      break;
    case 'cbom':
      await cmdCbom(commandArgs);
      break;
    case 'gate':
      await cmdGate(commandArgs);
      break;
    case 'vault':
      await cmdVault(commandArgs);
      break;
    case 'login':
      await cmdLogin(commandArgs);
      break;
    case 'status':
      await cmdStatus();
      break;
    case 'census':
      await cmdCensus(commandArgs);
      break;
    default:
      console.error(`Unknown command: ${command}\nRun "cryptoserve help" for usage.`);
      process.exit(2);
  }
} catch (e) {
  // A prompt with no terminal to prompt on is a usage problem, not a runtime
  // one: the message already says what to pass, so it is printed as written and
  // exits 2 like every other "could not run as invoked" case.
  if (e?.code === 'ERR_NO_TTY') {
    console.error(e.message);
    process.exit(2);
  }
  console.error(`Error: ${e.message}`);
  process.exit(1);
}
