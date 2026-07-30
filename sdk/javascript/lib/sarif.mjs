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
  if (finding.kind === 'secret') return `cryptoserve/secret/${finding.type}`;
  if (finding.kind === 'weak-algorithm') return `cryptoserve/weak-algorithm/${finding.algorithm || 'unknown'}`;
  if (finding.kind === 'misuse') return 'cryptoserve/api-misuse';
  if (finding.kind === 'tls') return `cryptoserve/tls/${finding.protocol || 'unknown'}`;
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
 * Render findings as a SARIF 2.1.0 document.
 *
 * @param {Array<object>} findings - from collectFindings()
 * @returns {object} SARIF log object, ready for JSON.stringify
 */
export function toSarif(findings) {
  const rules = new Map();

  const results = findings.map(finding => {
    const ruleId = ruleIdFor(finding);
    if (!rules.has(ruleId)) {
      const help = [finding.fix ? `Fix: ${finding.fix}` : null, finding.cwe ? `See ${finding.cwe}.` : null]
        .filter(Boolean).join(' ');
      rules.set(ruleId, {
        id: ruleId,
        name: ruleId.split('/').slice(1).join('-') || 'finding',
        shortDescription: { text: finding.message },
        fullDescription: { text: help || finding.message },
        defaultConfiguration: { level: toLevel(finding.severity) },
        ...(help ? { help: { text: help } } : {}),
        ...(finding.cwe ? { properties: { tags: ['security', 'cryptography', finding.cwe] } } : {
          properties: { tags: ['security', 'cryptography'] },
        }),
      });
    }

    const text = finding.fix ? `${finding.message}. Fix: ${finding.fix}` : finding.message;
    return {
      ruleId,
      level: toLevel(finding.severity),
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
