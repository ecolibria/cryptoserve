/**
 * SARIF 2.1.0 output for the CI gate.
 *
 * SARIF is how findings reach the GitHub Security tab. Every result carries a
 * physical location, which is only possible now that scanner findings carry
 * file and line; before that a SARIF document would have been a list of
 * locationless assertions that no code-scanning UI can render.
 *
 * Spec: OASIS SARIF 2.1.0.
 * Zero dependencies.
 */

import { VERSION, TOOL_NAME, TOOL_URI } from './version.mjs';

const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';

// SARIF levels: error / warning / note / none.
const SEVERITY_TO_LEVEL = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
};

function toLevel(severity) {
  return SEVERITY_TO_LEVEL[severity] || 'warning';
}

/**
 * Build a stable rule id from a finding. Code-scanning deduplicates and tracks
 * alerts by ruleId, so it must not vary between runs for the same defect class.
 */
function ruleIdFor(finding) {
  // One case for one algorithm. The scanner canonicalizes source tokens to
  // lowercase (`md5`), the package database spells the same algorithm as it
  // reads in a datasheet (`MD5`), and a gate reporting the manifest version
  // filed the same defect under a second rule id that no `scan` run ever
  // produced -- so an alert closed and reopened depending on which command had
  // run last.
  const algorithm = String(finding.algorithm || 'unknown').toLowerCase();
  if (finding.kind === 'secret') return `cryptoserve/secret/${finding.type}`;
  if (finding.kind === 'weak-algorithm') return `cryptoserve/weak-algorithm/${algorithm}`;
  if (finding.kind === 'misuse') return 'cryptoserve/api-misuse';
  if (finding.kind === 'tls') return `cryptoserve/tls/${finding.protocol || 'unknown'}`;
  // A committed private key used to fall through to the catch-all id, so it
  // shared one rule with everything else unclassified: code scanning groups by
  // ruleId, and the group took its description from whichever finding arrived
  // first.
  if (finding.kind === 'private-key') return 'cryptoserve/private-key';
  if (finding.kind === 'quantum-risk') return `cryptoserve/quantum-risk/${algorithm}`;
  if (finding.kind === 'score') return 'cryptoserve/quantum-readiness-score';
  return 'cryptoserve/finding';
}

function physicalLocation(finding) {
  if (!finding.file) return [];
  const region = {};
  if (Number.isInteger(finding.line) && finding.line > 0) region.startLine = finding.line;
  return [{
    physicalLocation: {
      artifactLocation: { uri: finding.file.split('\\').join('/') },
      ...(Object.keys(region).length > 0 ? { region } : {}),
    },
  }];
}

/**
 * Normalize a scan result into the flat finding list SARIF wants.
 *
 * @param {object} scanResults - output of scanProject()
 * @returns {Array<object>}
 */
export function collectFindings(scanResults) {
  const findings = [];

  for (const w of scanResults.weakPatterns || []) {
    findings.push({
      kind: w.algorithm ? 'weak-algorithm' : 'misuse',
      algorithm: w.algorithm,
      message: w.issue,
      severity: w.severity,
      file: w.file,
      line: w.line,
      cwe: w.cwe,
      fix: w.fix,
    });
  }

  for (const s of scanResults.secrets || []) {
    findings.push({
      kind: 'secret',
      type: s.type,
      message: `Hardcoded credential: ${s.name}`,
      severity: s.severity || 'critical',
      file: s.file,
      line: s.line,
      cwe: 'CWE-798',
      fix: s.envVar ? `Read from $${s.envVar} instead of embedding the value` : 'Move the value out of source control',
    });
  }

  // Private keys were acted on by `gate` and absent from SARIF, so a CI job
  // uploading the report saw no alert for the finding that failed its build.
  for (const keyFile of scanResults.privateKeyFiles || []) {
    findings.push({
      kind: 'private-key',
      message: 'Private key committed to the repository',
      severity: 'critical',
      file: keyFile,
      cwe: 'CWE-798',
      fix: 'Remove it from the tree and rotate the key',
    });
  }

  for (const t of scanResults.tlsFindings || []) {
    findings.push({
      kind: 'tls',
      protocol: t.protocol,
      message: `${t.protocol}: ${t.recommendation || 'deprecated protocol version'}`,
      severity: t.risk,
      file: t.file,
      line: t.line,
      cwe: 'CWE-326',
    });
  }

  return findings;
}

/**
 * Normalize the GATE's violations into the same flat finding list.
 *
 * `gate --format sarif` used to call collectFindings(scanResults), which is the
 * SCAN's answer to a different question. The document was therefore
 * byte-identical to `scan --format sarif` whatever the gate had decided: a gate
 * that failed the build on three manifest violations uploaded a report naming
 * none of them, and a gate that passed uploaded alerts for findings it had just
 * accepted. Three formats, one decision, so the SARIF is built from the same
 * `violations` array the text and JSON renderings read.
 *
 * Every violation in the list failed the gate, so each result says which
 * threshold it breached. That sentence is the answer to "why is this build
 * red", and it existed in no format before.
 *
 * @param {Array<object>} violations - the gate's violation list
 * @param {{maxRisk?: string, maxSeverity?: string}} thresholds - what the gate enforced
 * @returns {Array<object>} findings, in the shape toSarif() renders
 */
export function violationsToFindings(violations, thresholds = {}) {
  const { maxRisk, maxSeverity } = thresholds;

  return (violations || []).map((v) => {
    const kind = v.type === 'secret' ? 'secret'
      : v.type === 'private-key' ? 'private-key'
      : v.type === 'tls' ? 'tls'
      : v.type === 'misuse' ? 'misuse'
      // An algorithm-level violation raised only by --max-risk is not a
      // statement about how the code is written. Keeping it under its own rule
      // id stops a quantum migration item and a broken hash from sharing an
      // alert group.
      : (v.severity || v.weak) ? 'weak-algorithm'
      : 'quantum-risk';

    const why = [];
    if (v.severityBreach) why.push(`severity ${v.severity} exceeds --max-severity ${maxSeverity}`);
    if (v.riskBreach) why.push(`quantum risk ${v.risk} exceeds --max-risk ${maxRisk}`);
    if (v.weak && !v.severityBreach && !v.riskBreach) why.push('reported weak under --fail-on-weak');
    if (kind === 'secret' || kind === 'private-key') {
      why.push('credential findings fail the gate unless waived with --allow-secrets');
    }

    const headline = kind === 'secret' ? `Hardcoded credential: ${v.algorithm}` : v.algorithm;

    return {
      kind,
      algorithm: v.algorithm,
      // The identity the scanner gave the finding, so one tree gets one rule id
      // whether it was reported by `scan` or by `gate`.
      type: v.secretType,
      protocol: v.protocol,
      title: headline,
      message: why.length > 0 ? `${headline} (${why.join('; ')})` : headline,
      severity: v.severity,
      // Stated rather than derived from `severity`. A violation raised only by
      // --max-risk has no security severity to map -- reporting its quantum
      // risk in a field named severity is the conflation #58 removed -- but it
      // still failed a build and needs a level a reader can rank.
      level: toLevel(v.severity || (v.riskBreach ? v.risk : null)),
      // A dependency named only in a manifest has no source line. The manifest
      // that declares it is a location a reader can open, and a SARIF result
      // with no location at all is dropped by code scanning, so the finding
      // that failed the build would appear nowhere.
      file: v.file || v.manifest,
      line: v.line,
      cwe: v.cwe,
      fix: v.reason,
    };
  });
}

/**
 * Render findings as a SARIF 2.1.0 document.
 *
 * @param {Array<object>} findings - from collectFindings() or violationsToFindings()
 * @returns {object} SARIF log object, ready for JSON.stringify
 */
export function toSarif(findings) {
  const rules = new Map();

  const results = findings.map(finding => {
    const ruleId = ruleIdFor(finding);
    // A rule describes a class of defect; a result describes one instance. The
    // gate's message names the threshold this instance breached, which is true
    // of the result and not of the rule, so the rule keeps the plain title.
    const level = finding.level || toLevel(finding.severity);
    const title = finding.title || finding.message;
    if (!rules.has(ruleId)) {
      const help = [finding.fix ? `Fix: ${finding.fix}` : null, finding.cwe ? `See ${finding.cwe}.` : null]
        .filter(Boolean).join(' ');
      rules.set(ruleId, {
        id: ruleId,
        name: ruleId.split('/').slice(1).join('-') || 'finding',
        shortDescription: { text: title },
        fullDescription: { text: help || title },
        defaultConfiguration: { level },
        ...(help ? { help: { text: help } } : {}),
        ...(finding.cwe ? { properties: { tags: ['security', 'cryptography', finding.cwe] } } : {
          properties: { tags: ['security', 'cryptography'] },
        }),
      });
    }

    const text = finding.fix ? `${finding.message}. Fix: ${finding.fix}` : finding.message;
    return {
      ruleId,
      level,
      message: { text },
      locations: physicalLocation(finding),
    };
  });

  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: TOOL_NAME,
          version: VERSION,
          semanticVersion: VERSION,
          informationUri: TOOL_URI,
          rules: [...rules.values()],
        },
      },
      results,
    }],
  };
}
