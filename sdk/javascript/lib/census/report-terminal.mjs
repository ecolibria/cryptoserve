/**
 * Styled terminal output for census results using cli-style.mjs.
 */

import { formatNumber } from './aggregator.mjs';

/**
 * Render census results to the terminal.
 *
 * @param {Object} data - Aggregated census data from aggregate()
 * @param {Object} style - Destructured cli-style exports
 */
export function renderTerminal(data, style) {
  const {
    compactHeader, section, labelValue, tableHeader, tableRow,
    warning, info, dim, bold, divider, progressBar,
  } = style;

  const lines = [];

  lines.push(compactHeader('census'));
  lines.push('');

  // --- Headline ---
  lines.push(section('Headline'));
  lines.push(labelValue('Weak crypto downloads', `${formatNumber(data.totalWeakDownloads)}/month (${data.weakPercentage.toFixed(1)}%)`, 26));
  lines.push(labelValue('Modern crypto downloads', `${formatNumber(data.totalModernDownloads)}/month (${data.modernPercentage.toFixed(1)}%)`, 26));
  lines.push(labelValue('PQC crypto downloads', `${formatNumber(data.totalPqcDownloads)}/month (${data.pqcPercentage.toFixed(1)}%)`, 26));

  if (data.weakToPqcRatio !== null) {
    lines.push(labelValue('Weak-to-PQC ratio', `1 PQC for every ${formatNumber(data.weakToPqcRatio)} weak`, 26));
  } else {
    lines.push(labelValue('Weak-to-PQC ratio', 'No PQC downloads detected', 26));
  }

  if (data.totalCryptoCves > 0) {
    lines.push(labelValue('Crypto CVEs (all time)', String(data.totalCryptoCves), 26));
  }
  if (data.totalAdvisories > 0) {
    lines.push(labelValue('GitHub advisories', String(data.totalAdvisories), 26));
  }

  lines.push(labelValue('NIST 2030 deadline', data.nistDeadline2030, 26));
  lines.push(labelValue('NIST 2035 deadline', data.nistDeadline2035, 26));
  lines.push('');

  // --- PQC Readiness Bar ---
  lines.push(section('PQC Readiness'));
  const pqcReadiness = data.totalDownloads > 0
    ? data.totalPqcDownloads / data.totalDownloads
    : 0;
  lines.push(`  ${progressBar(pqcReadiness * 100, 100, 40, true)}`);
  lines.push(dim('  Industry-wide PQC adoption based on package downloads'));
  lines.push('');

  // --- npm packages ---
  if (data.npm.topPackages.length > 0) {
    lines.push(section(`npm (${data.npm.period?.start || 'last month'} to ${data.npm.period?.end || 'now'})`));
    const colWidths = [28, 14, 8];
    lines.push(tableHeader(['Package', 'Downloads', 'Tier'], colWidths));
    for (const pkg of data.npm.topPackages) {
      const tierLabel = pkg.tier.toUpperCase();
      lines.push(tableRow([pkg.name, formatNumber(pkg.downloads), tierLabel], colWidths));
    }
    lines.push('');
    lines.push(labelValue('npm weak', formatNumber(data.npm.weak), 16));
    lines.push(labelValue('npm modern', formatNumber(data.npm.modern), 16));
    lines.push(labelValue('npm pqc', formatNumber(data.npm.pqc), 16));
    lines.push('');
  }

  // --- PyPI packages ---
  if (data.pypi.topPackages.length > 0) {
    lines.push(section('PyPI (last month)'));
    const colWidths = [28, 14, 8];
    lines.push(tableHeader(['Package', 'Downloads', 'Tier'], colWidths));
    for (const pkg of data.pypi.topPackages) {
      const tierLabel = pkg.tier.toUpperCase();
      lines.push(tableRow([pkg.name, formatNumber(pkg.downloads), tierLabel], colWidths));
    }
    lines.push('');
    lines.push(labelValue('pypi weak', formatNumber(data.pypi.weak), 16));
    lines.push(labelValue('pypi modern', formatNumber(data.pypi.modern), 16));
    lines.push(labelValue('pypi pqc', formatNumber(data.pypi.pqc), 16));
    lines.push('');
  }

  // --- CVE Breakdown ---
  if (data.cveBreakdown.length > 0) {
    lines.push(section('CVE Landscape (NVD)'));
    const colWidths = [12, 48, 10];
    lines.push(tableHeader(['CWE', 'Description', 'Count'], colWidths));
    for (const cve of data.cveBreakdown) {
      lines.push(tableRow([cve.cweId, cve.cweName, String(cve.totalCount)], colWidths));
    }
    lines.push('');
  }

  // --- GitHub Advisories ---
  if (data.advisoryBreakdown.length > 0) {
    lines.push(section('GitHub Security Advisories'));
    const colWidths = [12, 10, 10, 10, 10, 10];
    lines.push(tableHeader(['CWE', 'Total', 'Critical', 'High', 'Medium', 'Low'], colWidths));
    for (const adv of data.advisoryBreakdown) {
      lines.push(tableRow([
        adv.cweId,
        String(adv.count),
        String(adv.bySeverity.critical),
        String(adv.bySeverity.high),
        String(adv.bySeverity.medium),
        String(adv.bySeverity.low),
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
  lines.push(dim('  Download counts reflect package installs (CI/CD + transitive deps), not direct usage'));
  lines.push(dim('  NIST 2030/2035 deadlines target public-key crypto only (AES, SHA-2, SHA-3 unaffected)'));
  lines.push('');

  // --- Next Steps ---
  lines.push(section('Next Steps'));
  lines.push(info('Run `cryptoserve scan .` to find weak crypto in your code'));
  lines.push(info('Run `cryptoserve census --format html --output report.html` for visual report'));
  lines.push(warning(`NIST deprecates quantum-vulnerable public-key crypto by 2030 -- ${data.nistDeadline2030} remaining`));
  lines.push('');

  console.log(lines.join('\n'));
}
