#!/usr/bin/env node

/**
 * CryptoServe CLI — zero-dependency Node.js CLI.
 *
 * Usage:
 *   cryptoserve help
 *   cryptoserve version
 *   cryptoserve init [--insecure-storage]
 *   cryptoserve pqc [--profile P] [--format json] [--verbose]
 *   cryptoserve scan [path] [--format json]
 *   cryptoserve encrypt "text" [--context C | --algorithm A] [--password P]
 *   cryptoserve decrypt "blob" [--password P]
 *   cryptoserve encrypt --file in --output out [--context C | --algorithm A] [--password P]
 *   cryptoserve decrypt --file in --output out [--password P]
 *   cryptoserve hash-password [--algorithm scrypt|pbkdf2]
 *   cryptoserve context list | show NAME [--verbose] [--format json]
 *   cryptoserve cbom [path] [--format cyclonedx|spdx|json] [--output file]
 *   cryptoserve gate [path] [--max-risk R] [--min-score N] [--fail-on-weak] [--format json]
 *   cryptoserve vault init|set|get|list|delete|run|import|export
 *   cryptoserve login [--server URL]
 *   cryptoserve status
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname, join, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf-8'));

// ---------------------------------------------------------------------------
// Arg parsing helpers
// ---------------------------------------------------------------------------

function getFlag(args, name) {
  const idx = args.indexOf(name);
  return idx !== -1;
}

function getOption(args, name, defaultValue = null) {
  const idx = args.indexOf(name);
  if (idx === -1 || idx + 1 >= args.length) return defaultValue;
  return args[idx + 1];
}

function getPositional(args, optionsWithValues = ['--password', '--algorithm', '--profile', '--format', '--file', '--output', '--server', '--context', '--max-risk', '--min-score']) {
  const result = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith('--')) {
      // Skip the flag; if it takes a value, skip the next arg too
      if (optionsWithValues.includes(args[i])) i++;
      continue;
    }
    result.push(args[i]);
  }
  return result;
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
  console.log(`    ${info('pqc [--profile P] [--format json]')}     Post-quantum readiness analysis`);
  console.log(`    ${info('scan [path] [--format json]')}           Scan project for crypto & secrets`);
  console.log(`    ${info('cbom [path] [--format F] [--output O]')} Generate Crypto Bill of Materials`);
  console.log(`    ${info('gate [path] [--max-risk R]')}            CI/CD gate (exit 0=pass, 1=fail)`);
  console.log();
  console.log(`  ${bold('Encryption')}`);
  console.log(`    ${info('encrypt "text" [--context C]')}          Encrypt with context-aware algorithm selection`);
  console.log(`    ${info('encrypt "text" [--password P]')}         Encrypt text (interactive password if omitted)`);
  console.log(`    ${info('decrypt "blob" [--password P]')}         Decrypt text`);
  console.log(`    ${info('encrypt --file F --output O')}           Encrypt file`);
  console.log(`    ${info('decrypt --file F --output O')}           Decrypt file`);
  console.log(`    ${info('hash-password [--algorithm A]')}         Hash a password (scrypt/pbkdf2)`);
  console.log();
  console.log(`  ${bold('Contexts')}`);
  console.log(`    ${info('context list')}                          List available encryption contexts`);
  console.log(`    ${info('context show NAME [--verbose]')}         Show context details and resolved algorithm`);
  console.log();
  console.log(`  ${bold('Key Management')}`);
  console.log(`    ${info('init [--insecure-storage]')}             Set up master key + AI tool protection`);
  console.log(`    ${info('vault init')}                            Create encrypted vault`);
  console.log(`    ${info('vault set KEY VALUE')}                   Store a secret`);
  console.log(`    ${info('vault get KEY')}                         Retrieve a secret`);
  console.log(`    ${info('vault list')}                            List stored secrets`);
  console.log(`    ${info('vault delete KEY')}                      Remove a secret`);
  console.log(`    ${info('vault run -- CMD [ARGS]')}               Run command with secrets as env vars`);
  console.log(`    ${info('vault import .env')}                     Import .env file into vault`);
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

  const profile = getOption(args, '--profile', 'general');
  const format = getOption(args, '--format', 'text');
  const verbose = getFlag(args, '--verbose');

  // Validate profile name
  if (!DATA_PROFILES[profile]) {
    const valid = Object.keys(DATA_PROFILES).join(', ');
    if (format !== 'json') {
      console.error(warning(`Unknown profile "${profile}", using default. Valid: ${valid}`));
    }
  }

  // Use scanner results if available, otherwise use example libraries
  let libraries = [];
  let scanMeta = {};
  try {
    const { scanProject, toLibraryInventory } = await import('../lib/scanner.mjs');
    const scanResults = scanProject(process.cwd());
    libraries = toLibraryInventory(scanResults);
    scanMeta = {
      filesScanned: scanResults.filesScanned,
      languagesDetected: scanResults.languagesDetected,
      manifestsFound: scanResults.manifestsFound,
    };
  } catch { /* scanner not available, empty libraries */ }

  const result = analyzeOffline(libraries, profile, scanMeta);

  if (format === 'json') {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  console.log(compactHeader('pqc'));

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

  const positional = getPositional(args);
  const scanDir = positional.length > 0 ? resolve(positional[0]) : process.cwd();
  const format = getOption(args, '--format', 'text');
  const binaryFlag = getFlag(args, '--binary');

  const results = scanProject(scanDir, { binary: binaryFlag });

  if (format === 'json') {
    console.log(JSON.stringify(results, null, 2));
    return;
  }

  console.log(compactHeader('scan'));
  console.log(labelValue('Directory', scanDir));
  console.log(labelValue('Files scanned', String(results.filesScanned)));

  // Crypto libraries
  if (results.libraries.length > 0) {
    console.log(section('Crypto Libraries'));
    console.log(tableHeader(['Library', 'Version', 'Risk', 'Algorithms'], [22, 10, 10, 30]));
    for (const lib of results.libraries) {
      const riskColor = lib.quantumRisk === 'high' ? `\x1b[91m${lib.quantumRisk}\x1b[0m`
        : lib.quantumRisk === 'none' ? `\x1b[92m${lib.quantumRisk}\x1b[0m`
        : lib.quantumRisk;
      console.log(tableRow(
        [lib.name, lib.version, lib.quantumRisk, lib.algorithms.join(', ')],
        [22, 10, 10, 30]
      ));
    }
  } else {
    console.log(`\n  ${dim('No crypto libraries detected')}`);
  }

  // Hardcoded secrets
  if (results.secrets.length > 0) {
    console.log(section('Hardcoded Secrets'));
    for (const s of results.secrets) {
      console.log(`  ${error(`[CRIT] ${s.name}`)}`);
      console.log(`         ${dim(s.file)}`);
      if (s.envVar) console.log(`         ${info(`Use $${s.envVar} instead`)}`);
    }
  }

  // Weak patterns
  if (results.weakPatterns.length > 0) {
    console.log(section('Weak Crypto Patterns'));
    for (const w of results.weakPatterns) {
      const icon = w.severity === 'critical' ? error(w.issue) : warning(w.issue);
      console.log(`  ${icon}`);
      console.log(`    ${dim(w.file)}`);
    }
  }

  // Multi-language source algorithms
  if (results.sourceAlgorithms && results.sourceAlgorithms.length > 0) {
    console.log(section('Source Code Crypto (Multi-Language)'));
    console.log(tableHeader(['Algorithm', 'Category', 'Language', 'Risk'], [20, 14, 12, 10]));
    for (const algo of results.sourceAlgorithms) {
      console.log(tableRow(
        [algo.algorithm, algo.category, algo.language, algo.quantumRisk],
        [20, 14, 12, 10]
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
  const { encryptString, encryptFile } = await import('../lib/local-crypto.mjs');

  const file = getOption(args, '--file');
  const output = getOption(args, '--output');
  let password = getOption(args, '--password');
  const contextName = getOption(args, '--context');
  const verbose = getFlag(args, '--verbose');
  let algorithm = getOption(args, '--algorithm', 'AES-256-GCM');

  // Context-aware algorithm selection
  if (contextName) {
    const { resolveContext } = await import('../lib/context-resolver.mjs');
    const resolved = resolveContext(contextName);
    if (resolved.error) {
      console.error(`${resolved.error}\nValid contexts: ${resolved.validContexts.join(', ')}`);
      process.exit(1);
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
    password = await promptPassword('Encryption password: ');
    if (!password) { console.error('Password required.'); process.exit(1); }
  }

  if (file) {
    const outPath = output || file + '.enc';
    encryptFile(file, outPath, password, algorithm, contextName || 'file');
    console.log(`Encrypted: ${outPath}`);
  } else {
    const positional = getPositional(args);
    const text = positional[0];
    if (!text) { console.error('Provide text to encrypt or use --file.'); process.exit(1); }
    console.log(encryptString(text, password, algorithm, contextName || 'cli'));
  }
}

async function cmdDecrypt(args) {
  const { promptPassword } = await import('../lib/keychain.mjs');
  const { decryptString, decryptFile } = await import('../lib/local-crypto.mjs');

  const file = getOption(args, '--file');
  const output = getOption(args, '--output');
  let password = getOption(args, '--password');

  if (!password) {
    password = await promptPassword('Decryption password: ');
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
      if (!blob) { console.error('Provide encrypted text or use --file.'); process.exit(1); }
      console.log(decryptString(blob, password));
    }
  } catch (e) {
    console.error(`Decryption failed: ${e.message}`);
    process.exit(1);
  }
}

async function cmdHashPassword(args) {
  const { promptPassword } = await import('../lib/keychain.mjs');
  const { hashPassword } = await import('../lib/local-crypto.mjs');

  const algorithm = getOption(args, '--algorithm', 'scrypt');
  const positional = getPositional(args);
  let password = positional[0];

  if (!password) {
    password = await promptPassword('Password to hash: ');
    if (!password) { console.error('Password required.'); process.exit(1); }
  }

  console.log(hashPassword(password, algorithm));
}

async function cmdVault(args) {
  const { compactHeader, success, error, warning, info, dim, labelValue, tableHeader, tableRow } = await import('../lib/cli-style.mjs');
  const { promptPassword } = await import('../lib/keychain.mjs');

  const subcommand = args[0];
  const restArgs = args.slice(1);

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

  if (subcommand === 'init') {
    if (vault.vaultExists()) {
      console.log(warning('Vault already exists.'));
      return;
    }
    const pw = await promptPassword('Set vault password: ');
    const pw2 = await promptPassword('Confirm password: ');
    if (pw !== pw2) { console.error('Passwords do not match.'); process.exit(1); }
    vault.initVault(pw);
    console.log(success('Vault created at ~/.cryptoserve/vault.enc'));
    return;
  }

  if (subcommand === 'reset') {
    vault.resetVault();
    console.log(success('Vault deleted.'));
    return;
  }

  // All other commands need the vault password
  const pw = await promptPassword('Vault password: ');

  try {
    switch (subcommand) {
      case 'set': {
        const key = restArgs[0];
        let value = restArgs[1];
        if (!key) { console.error('Usage: vault set KEY VALUE'); process.exit(1); }
        if (!value) {
          // Read from stdin if no value provided
          value = await promptPassword(`Value for ${key}: `);
        }
        vault.setSecret(pw, key, value);
        console.log(success(`Stored: ${key}`));
        break;
      }
      case 'get': {
        const key = restArgs[0];
        if (!key) { console.error('Usage: vault get KEY'); process.exit(1); }
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
        const key = restArgs[0];
        if (!key) { console.error('Usage: vault delete KEY'); process.exit(1); }
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
        const envFile = restArgs[0] || '.env';
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
        process.exit(1);
    }
  } catch (e) {
    console.error(error(e.message));
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
    if (!name) { console.error('Usage: context show NAME [--verbose]'); process.exit(1); }

    const resolved = resolveContext(name);
    if (resolved.error) {
      console.error(`${resolved.error}\nValid contexts: ${resolved.validContexts.join(', ')}`);
      process.exit(1);
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
  process.exit(1);
}

async function cmdCbom(args) {
  const { compactHeader, section, labelValue, success, dim, bold, info } = await import('../lib/cli-style.mjs');
  const { scanProject, toLibraryInventory } = await import('../lib/scanner.mjs');
  const { analyzeOffline } = await import('../lib/pqc-engine.mjs');
  const { generateCbom, toCycloneDx, toSpdx, toNativeJson } = await import('../lib/cbom.mjs');

  const positional = getPositional(args);
  const scanDir = positional.length > 0 ? resolve(positional[0]) : process.cwd();
  const format = getOption(args, '--format', 'json');
  const output = getOption(args, '--output');

  const scanResults = scanProject(scanDir);
  const libraries = toLibraryInventory(scanResults);
  const pqcResult = analyzeOffline(libraries);
  const projectName = basename(scanDir);

  const cbom = generateCbom(scanResults, pqcResult, projectName);

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
    console.log(labelValue('Components', String(cbom.components.length)));
    console.log(labelValue('Quantum readiness', `${cbom.quantumReadiness.score}/100`));
    console.log(labelValue('Risk level', cbom.quantumReadiness.riskLevel));
  } else {
    console.log(formatted);
  }
}

async function cmdGate(args) {
  const { scanProject, toLibraryInventory } = await import('../lib/scanner.mjs');
  const { analyzeOffline } = await import('../lib/pqc-engine.mjs');
  const { lookupAlgorithm } = await import('../lib/algorithm-db.mjs');

  const positional = getPositional(args);
  const scanDir = positional.length > 0 ? resolve(positional[0]) : process.cwd();
  const maxRisk = getOption(args, '--max-risk', 'high');
  const minScore = parseInt(getOption(args, '--min-score', '50'), 10);
  const failOnWeak = getFlag(args, '--fail-on-weak');
  const format = getOption(args, '--format', 'text');

  const riskOrder = ['none', 'low', 'medium', 'high', 'critical'];

  try {
    const scanResults = scanProject(scanDir);
    const libraries = toLibraryInventory(scanResults);
    const pqcResult = analyzeOffline(libraries);
    const score = pqcResult.quantumReadinessScore;

    // Collect violations
    const violations = [];
    const maxRiskIdx = riskOrder.indexOf(maxRisk);

    for (const lib of libraries) {
      for (const algoName of lib.algorithms) {
        const entry = lookupAlgorithm(algoName);
        if (!entry) continue;

        const algoRiskIdx = riskOrder.indexOf(entry.quantumRisk);
        if (algoRiskIdx > maxRiskIdx) {
          violations.push({
            algorithm: algoName,
            risk: entry.quantumRisk,
            source: lib.name + (lib.version !== 'source-code' ? `@${lib.version}` : ` (${lib.version})`),
          });
        }

        if (failOnWeak && entry.isWeak) {
          violations.push({
            algorithm: algoName,
            risk: entry.quantumRisk,
            source: lib.name,
            weak: true,
            reason: entry.weaknessReason,
          });
        }
      }
    }

    const scoreFail = score < minScore;
    const pass = violations.length === 0 && !scoreFail;

    const summary = {
      total: libraries.reduce((sum, l) => sum + l.algorithms.length, 0),
      safe: libraries.reduce((sum, l) => sum + l.algorithms.filter(a => {
        const e = lookupAlgorithm(a);
        return e && (e.quantumRisk === 'none' || e.quantumRisk === 'low');
      }).length, 0),
      vulnerable: violations.filter(v => !v.weak).length,
      weak: violations.filter(v => v.weak).length,
    };

    if (format === 'json') {
      console.log(JSON.stringify({
        status: pass ? 'pass' : 'fail',
        score,
        violations,
        summary,
      }, null, 2));
    } else {
      const { compactHeader, success, error, warning, dim, bold, labelValue } = await import('../lib/cli-style.mjs');
      console.log(compactHeader('gate'));
      console.log(labelValue('Status', pass ? success('PASS') : error('FAIL')));
      console.log(labelValue('Score', `${score}/100 (min: ${minScore})`));
      console.log(labelValue('Max risk', maxRisk));

      if (violations.length > 0) {
        console.log(`\n  ${bold('Violations:')}`);
        for (const v of violations) {
          const label = v.weak ? warning(`[WEAK] ${v.algorithm}`) : error(`[${v.risk.toUpperCase()}] ${v.algorithm}`);
          console.log(`  ${label} — ${dim(v.source)}${v.reason ? ` (${v.reason})` : ''}`);
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
  const server = getOption(args, '--server', 'https://localhost:8003');
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
// Main router
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
const command = args[0];
const commandArgs = args.slice(1);

// Filter out the command from args for sub-parsers
// Strip flags that belong to the command router
const filteredArgs = commandArgs.filter(a => a !== command);

try {
  switch (command) {
    case 'help':
    case '--help':
    case '-h':
    case undefined:
      await cmdHelp();
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
    default:
      console.error(`Unknown command: ${command}\nRun "cryptoserve help" for usage.`);
      process.exit(1);
  }
} catch (e) {
  console.error(`Error: ${e.message}`);
  process.exit(1);
}
