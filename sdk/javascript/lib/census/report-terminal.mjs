/**
 * Styled terminal output for census results using cli-style.mjs.
 */

import { formatNumber } from './format.mjs';

/** Printed where the snapshot does not carry the figure a line reports. */
const ABSENT = 'not in this snapshot';

/** The same, in a table column too narrow for the phrase. */
const ABSENT_CELL = 'absent';

/**
 * A date-only rendering in UTC.
 *
 * Not `toLocaleDateString()`: a date-only value formatted in local time shows
 * the previous day everywhere west of Greenwich, which the site hit on this
 * same field.
 */
function formatDate(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso) : d.toISOString().slice(0, 10);
}

/**
 * Render census results as the terminal report. The caller prints it, or
 * writes it to the `--output` file.
 *
 * Each field is checked where it is read, so a snapshot that lacks one still
 * shows the figures it has, as `--format json` and `--format html` do: they
 * pass the snapshot on as it is. Read unchecked, a snapshot without the
 * percentages printed no report, only Node's `Cannot read properties of
 * undefined (reading 'toFixed')`, and exited 1. A field the snapshot lacks,
 * holds as null, or holds as a type other than the one its line reads is named
 * under Data Sources, and a line that reports it prints ABSENT (ABSENT_CELL in
 * a table column), never 0, `undefined` or `NaN`.
 *
 * @param {Object} data - The published census snapshot
 * @param {Object} style - Destructured cli-style exports
 * @returns {string} The report, with the colour codes cli-style adds
 */
export function renderTerminal(data, style) {
  const {
    compactHeader, section, labelValue, tableHeader, tableRow,
    warning, info, dim, bold, divider, progressBar,
  } = style;

  const lines = [];

  // The fields this snapshot does not carry, in the order the report reads them.
  const absent = new Set();
  const figure = (value, field) => {
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    absent.add(field);
    return null;
  };
  const text = (value, field) => {
    if (typeof value === 'string' && value !== '') return value;
    absent.add(field);
    return null;
  };
  const list = (value, field) => {
    if (Array.isArray(value)) return value;
    absent.add(field);
    return [];
  };
  const cell = (value, render = String) => (value === null ? ABSENT_CELL : render(value));

  /** A monthly count and its share of the total, each printed only when present. */
  const downloads = (countField, shareField) => {
    const count = figure(data[countField], countField);
    const share = figure(data[shareField], shareField);
    if (count === null && share === null) return ABSENT;
    const perMonth = count === null ? `count ${ABSENT}` : `${formatNumber(count)}/month`;
    return `${perMonth} (${share === null ? `share ${ABSENT}` : `${share.toFixed(1)}%`})`;
  };

  lines.push(compactHeader('census'));
  lines.push('');

  // --- Headline ---
  //
  // The collection date leads, because this is a dated snapshot and not a live
  // reading. Without it, a figure collected in March reads as today's, which is
  // how "refresh in progress" sat on a public page for four months.
  lines.push(section('Headline'));
  const collectedAt = text(data.collectedAt, 'collectedAt');
  lines.push(labelValue('Snapshot collected', collectedAt === null ? ABSENT : formatDate(collectedAt), 26));
  lines.push(labelValue('Weak crypto downloads', downloads('totalWeakDownloads', 'weakPercentage'), 26));
  lines.push(labelValue('Modern crypto downloads', downloads('totalModernDownloads', 'modernPercentage'), 26));
  lines.push(labelValue('PQC crypto downloads', downloads('totalPqcDownloads', 'pqcPercentage'), 26));

  // A null ratio reads as no PQC downloads to divide by; an absent one does not.
  if (data.weakToPqcRatio === null) {
    lines.push(labelValue('Weak-to-PQC ratio', 'No PQC downloads detected', 26));
  } else {
    const ratio = figure(data.weakToPqcRatio, 'weakToPqcRatio');
    lines.push(labelValue('Weak-to-PQC ratio', ratio === null ? ABSENT : `1 PQC for every ${formatNumber(ratio)} weak`, 26));
  }

  const totalCryptoCves = figure(data.totalCryptoCves, 'totalCryptoCves');
  if (totalCryptoCves !== null && totalCryptoCves > 0) {
    lines.push(labelValue('Crypto CVEs (all time)', String(totalCryptoCves), 26));
  }
  const totalAdvisories = figure(data.totalAdvisories, 'totalAdvisories');
  if (totalAdvisories !== null && totalAdvisories > 0) {
    lines.push(labelValue('GitHub advisories', String(totalAdvisories), 26));
  }

  const deadline2030 = text(data.nistDeadline2030, 'nistDeadline2030');
  const deadline2035 = text(data.nistDeadline2035, 'nistDeadline2035');
  lines.push(labelValue('NIST 2030 deadline', deadline2030 ?? ABSENT, 26));
  lines.push(labelValue('NIST 2035 deadline', deadline2035 ?? ABSENT, 26));
  lines.push('');

  // --- PQC Readiness Bar ---
  lines.push(section('PQC Readiness'));
  const totalDownloads = figure(data.totalDownloads, 'totalDownloads');
  const totalPqcDownloads = figure(data.totalPqcDownloads, 'totalPqcDownloads');
  if (totalDownloads === null || totalPqcDownloads === null) {
    lines.push(`  ${ABSENT}`);
  } else {
    const pqcReadiness = totalDownloads > 0 ? totalPqcDownloads / totalDownloads : 0;
    lines.push(`  ${progressBar(pqcReadiness * 100, 100, 40, true)}`);
  }
  lines.push(dim('  Industry-wide PQC adoption based on package downloads'));
  lines.push('');

  // --- npm and PyPI packages ---
  const ecosystem = (key, title) => {
    const eco = data[key];
    if (eco === null || typeof eco !== 'object') {
      absent.add(key);
      return;
    }
    const packages = list(eco.topPackages, `${key}.topPackages`);
    if (packages.length === 0) return;
    lines.push(section(title(eco)));
    const colWidths = [28, 14, 8];
    lines.push(tableHeader(['Package', 'Downloads', 'Tier'], colWidths));
    for (const pkg of packages) {
      lines.push(tableRow([
        cell(text(pkg?.name, `${key}.topPackages[].name`)),
        cell(figure(pkg?.downloads, `${key}.topPackages[].downloads`), formatNumber),
        cell(text(pkg?.tier, `${key}.topPackages[].tier`), (tier) => tier.toUpperCase()),
      ], colWidths));
    }
    lines.push('');
    for (const tier of ['weak', 'modern', 'pqc']) {
      const count = figure(eco[tier], `${key}.${tier}`);
      lines.push(labelValue(`${key} ${tier}`, count === null ? ABSENT : formatNumber(count), 16));
    }
    lines.push('');
  };
  ecosystem('npm', (npm) => `npm (${npm.period?.start || 'last month'} to ${npm.period?.end || 'now'})`);
  ecosystem('pypi', () => 'PyPI (last month)');

  // --- CVE Breakdown ---
  const cveBreakdown = list(data.cveBreakdown, 'cveBreakdown');
  if (cveBreakdown.length > 0) {
    lines.push(section('CVE Landscape (NVD)'));
    const colWidths = [12, 48, 10];
    lines.push(tableHeader(['CWE', 'Description', 'Count'], colWidths));
    for (const cve of cveBreakdown) {
      lines.push(tableRow([
        cell(text(cve?.cweId, 'cveBreakdown[].cweId')),
        cell(text(cve?.cweName, 'cveBreakdown[].cweName')),
        cell(figure(cve?.totalCount, 'cveBreakdown[].totalCount')),
      ], colWidths));
    }
    lines.push('');
  }

  // --- GitHub Advisories ---
  const advisoryBreakdown = list(data.advisoryBreakdown, 'advisoryBreakdown');
  if (advisoryBreakdown.length > 0) {
    lines.push(section('GitHub Security Advisories'));
    const colWidths = [12, 10, 10, 10, 10, 10];
    lines.push(tableHeader(['CWE', 'Total', 'Critical', 'High', 'Medium', 'Low'], colWidths));
    for (const adv of advisoryBreakdown) {
      lines.push(tableRow([
        cell(text(adv?.cweId, 'advisoryBreakdown[].cweId')),
        cell(figure(adv?.count, 'advisoryBreakdown[].count')),
        ...['critical', 'high', 'medium', 'low'].map((severity) =>
          cell(figure(adv?.bySeverity?.[severity], `advisoryBreakdown[].bySeverity.${severity}`))),
      ], colWidths));
    }
    lines.push('');
  }

  // --- Data Sources ---
  lines.push(divider());
  lines.push(section('Data Sources'));
  lines.push(dim('  Downloads: npm Registry API, PyPI Stats, Go Module Proxy, Maven Central, crates.io,'));
  lines.push(dim('             Packagist, NuGet, RubyGems, Hex.pm, pub.dev, CocoaPods Trunk'));
  lines.push(dim('  CVEs:      NIST NVD (CWE-326, CWE-327, CWE-328)'));
  lines.push(dim('  Advisories: GitHub Advisory Database (reviewed, crypto-CWE filtered)'));

  // Not every registry publishes a monthly download count. NuGet and RubyGems
  // divide a lifetime total by an assumed number of months; CocoaPods publishes
  // nothing. Presenting the combined figure without saying so reports a proxy
  // times a constant as a measurement.
  if (typeof data.measuredDownloads === 'number' && typeof data.modelledDownloads === 'number') {
    lines.push('');
    lines.push(dim(`  Measured:  ${formatNumber(data.measuredDownloads)}/month from registries that publish a count` +
      (typeof data.measuredShareOfTotal === 'number' ? ` (${data.measuredShareOfTotal.toFixed(1)}% of the total)` : '')));
    lines.push(dim(`  Modelled:  ${formatNumber(data.modelledDownloads)}/month derived from lifetime totals or version counts`));
    lines.push(dim('             The percentages above divide by the combined figure. Quote the measured one.'));
  }

  lines.push('');
  lines.push(dim('  Download counts reflect package installs (CI/CD + transitive deps), not direct usage'));
  lines.push(dim('  NIST 2030/2035 deadlines target public-key crypto only (AES, SHA-2, SHA-3 unaffected)'));
  if (collectedAt !== null) {
    lines.push(dim(`  Published snapshot collected ${formatDate(collectedAt)}; not a live reading`));
  }
  if (absent.size > 0) {
    lines.push(dim(`  Not in this snapshot: ${[...absent].join(', ')}`));
    lines.push(dim('  `cryptoserve census --format json` prints the snapshot as fetched'));
  }
  lines.push('');

  // --- Next Steps ---
  lines.push(section('Next Steps'));
  lines.push(info('Run `cryptoserve scan .` to find weak crypto in your code'));
  lines.push(info('Run `cryptoserve census --format html --output report.html` for visual report'));
  lines.push(warning('NIST deprecates quantum-vulnerable public-key crypto by 2030' +
    (deadline2030 === null ? '' : ` -- ${deadline2030} remaining`)));
  lines.push('');

  return lines.join('\n');
}
