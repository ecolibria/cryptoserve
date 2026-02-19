/**
 * Generate a self-contained HTML report with Chart.js visualizations.
 * All data is embedded as JSON; charts render client-side.
 */

import { formatNumber } from './aggregator.mjs';

/**
 * Generate the full HTML string for the census report.
 *
 * @param {Object} data - Aggregated census data
 * @returns {string} Complete HTML document
 */
export function generateHtml(data) {
  const dataJson = JSON.stringify(data);

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>State of Cryptography - CryptoServe Census</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"><\/script>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    background: #0a0e17;
    color: #e2e8f0;
    line-height: 1.6;
    min-height: 100vh;
  }
  .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
  .hero {
    text-align: center;
    padding: 4rem 2rem;
    border-bottom: 1px solid #1e293b;
  }
  .hero-brand {
    font-size: 0.875rem;
    text-transform: uppercase;
    letter-spacing: 0.15em;
    color: #06b6d4;
    margin-bottom: 1rem;
  }
  .hero h1 {
    font-size: 2.5rem;
    font-weight: 700;
    color: #f8fafc;
    margin-bottom: 0.5rem;
  }
  .hero-subtitle {
    font-size: 1.125rem;
    color: #94a3b8;
    margin-bottom: 2rem;
  }
  .hero-stat {
    display: inline-block;
    padding: 1rem 2rem;
    background: linear-gradient(135deg, rgba(239,68,68,0.15), rgba(239,68,68,0.05));
    border: 1px solid rgba(239,68,68,0.3);
    border-radius: 12px;
  }
  .hero-stat-number {
    font-size: 3rem;
    font-weight: 800;
    color: #ef4444;
    display: block;
  }
  .hero-stat-label {
    font-size: 0.875rem;
    color: #94a3b8;
  }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
    gap: 1.5rem;
    margin: 2rem 0;
  }
  .card {
    background: #111827;
    border: 1px solid #1e293b;
    border-radius: 12px;
    padding: 1.5rem;
  }
  .card-title {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #64748b;
    margin-bottom: 1rem;
  }
  .metric {
    text-align: center;
    padding: 1rem;
  }
  .metric-value {
    font-size: 2rem;
    font-weight: 700;
  }
  .metric-label {
    font-size: 0.875rem;
    color: #94a3b8;
    margin-top: 0.25rem;
  }
  .color-weak { color: #ef4444; }
  .color-modern { color: #06b6d4; }
  .color-pqc { color: #10b981; }
  .color-warn { color: #f59e0b; }
  .countdown-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
  }
  .countdown-item {
    text-align: center;
    padding: 1.5rem;
    background: rgba(245,158,11,0.08);
    border: 1px solid rgba(245,158,11,0.2);
    border-radius: 8px;
  }
  .countdown-days {
    font-size: 2.5rem;
    font-weight: 800;
    color: #f59e0b;
  }
  .countdown-label {
    font-size: 0.75rem;
    color: #94a3b8;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .chart-container {
    position: relative;
    height: 300px;
    margin: 1rem 0;
  }
  .chart-container-sm {
    position: relative;
    height: 250px;
    margin: 1rem 0;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.875rem;
  }
  th {
    text-align: left;
    padding: 0.5rem 0.75rem;
    color: #64748b;
    font-weight: 600;
    text-transform: uppercase;
    font-size: 0.7rem;
    letter-spacing: 0.05em;
    border-bottom: 1px solid #1e293b;
  }
  td {
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid rgba(30,41,59,0.5);
  }
  .tier-badge {
    display: inline-block;
    padding: 0.125rem 0.5rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
  }
  .tier-weak { background: rgba(239,68,68,0.15); color: #ef4444; }
  .tier-modern { background: rgba(6,182,212,0.15); color: #06b6d4; }
  .tier-pqc { background: rgba(16,185,129,0.15); color: #10b981; }
  .pqc-gap {
    text-align: center;
    padding: 2rem;
  }
  .pqc-gap-bar {
    height: 32px;
    border-radius: 8px;
    overflow: hidden;
    display: flex;
    margin: 1rem 0;
  }
  .pqc-gap-segment {
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.75rem;
    font-weight: 600;
    color: #fff;
    min-width: 2px;
  }
  .cta {
    text-align: center;
    padding: 3rem 2rem;
    border-top: 1px solid #1e293b;
    margin-top: 2rem;
  }
  .cta h2 {
    font-size: 1.5rem;
    color: #f8fafc;
    margin-bottom: 0.5rem;
  }
  .cta p {
    color: #94a3b8;
    margin-bottom: 1.5rem;
  }
  .cta-code {
    display: inline-block;
    background: #1e293b;
    padding: 0.75rem 1.5rem;
    border-radius: 8px;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    color: #06b6d4;
    font-size: 1rem;
    margin: 0.5rem;
  }
  .cta-link {
    display: inline-block;
    margin-top: 1rem;
    color: #06b6d4;
    text-decoration: none;
    font-size: 0.875rem;
  }
  .cta-link:hover { text-decoration: underline; }
  .methodology {
    padding: 2rem;
    border-top: 1px solid #1e293b;
    color: #64748b;
    font-size: 0.75rem;
    text-align: center;
  }
  .section-title {
    font-size: 1.25rem;
    font-weight: 600;
    color: #f8fafc;
    margin: 2rem 0 0.5rem;
  }
  .section-subtitle {
    color: #94a3b8;
    font-size: 0.875rem;
    margin-bottom: 1rem;
  }
</style>
</head>
<body>

<div class="container">
  <!-- Hero -->
  <div class="hero">
    <div class="hero-brand">CryptoServe Census</div>
    <h1>The State of Cryptography</h1>
    <p class="hero-subtitle">Real-time analysis of cryptographic library adoption across npm and PyPI</p>
    <div class="hero-stat">
      <span class="hero-stat-number" id="hero-ratio"></span>
      <span class="hero-stat-label">weak crypto downloads for every 1 PQC download</span>
    </div>
  </div>

  <!-- NIST Deadline Countdown -->
  <h2 class="section-title">NIST Post-Quantum Deadlines</h2>
  <p class="section-subtitle">Time remaining before NIST mandates PQC migration</p>
  <div class="countdown-grid">
    <div class="countdown-item">
      <div class="countdown-days" id="countdown-2030"></div>
      <div class="countdown-label">Days until 2030 (deprecate classical)</div>
    </div>
    <div class="countdown-item">
      <div class="countdown-days" id="countdown-2035"></div>
      <div class="countdown-label">Days until 2035 (disallow classical)</div>
    </div>
  </div>

  <!-- Download Metrics -->
  <div class="grid" style="margin-top: 2rem;">
    <div class="card">
      <div class="card-title">Weak / Deprecated Crypto</div>
      <div class="metric">
        <div class="metric-value color-weak" id="metric-weak"></div>
        <div class="metric-label">downloads / month</div>
      </div>
    </div>
    <div class="card">
      <div class="card-title">Modern Crypto (non-PQC)</div>
      <div class="metric">
        <div class="metric-value color-modern" id="metric-modern"></div>
        <div class="metric-label">downloads / month</div>
      </div>
    </div>
    <div class="card">
      <div class="card-title">Post-Quantum Crypto</div>
      <div class="metric">
        <div class="metric-value color-pqc" id="metric-pqc"></div>
        <div class="metric-label">downloads / month</div>
      </div>
    </div>
  </div>

  <!-- PQC Gap -->
  <div class="card" style="margin: 1.5rem 0;">
    <div class="card-title">The PQC Gap</div>
    <div class="pqc-gap">
      <p style="color: #94a3b8; margin-bottom: 0.5rem;">Download volume by cryptographic tier</p>
      <div class="pqc-gap-bar" id="pqc-gap-bar"></div>
      <div style="display: flex; justify-content: space-between; font-size: 0.75rem; color: #64748b;">
        <span>Weak (<span class="color-weak" id="pqc-pct-weak"></span>)</span>
        <span>Modern (<span class="color-modern" id="pqc-pct-modern"></span>)</span>
        <span>PQC (<span class="color-pqc" id="pqc-pct-pqc"></span>)</span>
      </div>
    </div>
  </div>

  <!-- Ecosystem Charts -->
  <h2 class="section-title">Ecosystem Breakdown</h2>
  <p class="section-subtitle">Download distribution by cryptographic tier</p>
  <div class="grid">
    <div class="card">
      <div class="card-title">npm Ecosystem</div>
      <div class="chart-container-sm">
        <canvas id="chart-npm-donut"></canvas>
      </div>
    </div>
    <div class="card">
      <div class="card-title">PyPI Ecosystem</div>
      <div class="chart-container-sm">
        <canvas id="chart-pypi-donut"></canvas>
      </div>
    </div>
  </div>

  <!-- Top Packages -->
  <h2 class="section-title">Top Packages by Downloads</h2>
  <p class="section-subtitle">Most downloaded cryptographic libraries (last month)</p>
  <div class="card">
    <div class="chart-container">
      <canvas id="chart-top-packages"></canvas>
    </div>
  </div>

  <!-- Vulnerability Landscape -->
  <h2 class="section-title">Vulnerability Landscape</h2>
  <p class="section-subtitle">Crypto-related CVEs and security advisories</p>
  <div class="grid">
    <div class="card">
      <div class="card-title">NVD CVEs by Category</div>
      <table>
        <thead><tr><th>CWE</th><th>Description</th><th style="text-align:right">Count</th></tr></thead>
        <tbody id="cve-table"></tbody>
      </table>
    </div>
    <div class="card">
      <div class="card-title">GitHub Advisories by Severity</div>
      <div class="chart-container-sm">
        <canvas id="chart-advisories"></canvas>
      </div>
    </div>
  </div>

  <!-- CTA -->
  <div class="cta">
    <h2>Find Weak Crypto in Your Code</h2>
    <p>CryptoServe scans your codebase for vulnerable cryptographic implementations</p>
    <div class="cta-code">npx cryptoserve scan .</div>
    <br>
    <a class="cta-link" href="https://github.com/ecolibria/crypto-serve">View on GitHub</a>
  </div>

  <!-- Methodology -->
  <div class="methodology">
    <p><strong>Methodology:</strong> Download counts sourced from npm registry API and PyPI Stats API (last 30 days).
    CVE data from NIST National Vulnerability Database (CWE-326, CWE-327, CWE-328).
    Advisory data from GitHub Advisory Database. Package classification based on NIST SP 800-131A and CNSA 2.0 guidance.</p>
    <p style="margin-top: 0.5rem;">Generated by CryptoServe Census on <span id="collected-at"></span></p>
  </div>
</div>

<script>
const DATA = ${dataJson};

function fmt(n) {
  if (n >= 1e9) return (n / 1e9).toFixed(1) + 'B';
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
  return String(n);
}

// Hero
const ratioEl = document.getElementById('hero-ratio');
ratioEl.textContent = DATA.weakToPqcRatio !== null ? fmt(DATA.weakToPqcRatio) + ':1' : 'N/A';

// Countdowns
document.getElementById('countdown-2030').textContent = DATA.nistDeadline2030Days.toLocaleString();
document.getElementById('countdown-2035').textContent = DATA.nistDeadline2035Days.toLocaleString();

// Metrics
document.getElementById('metric-weak').textContent = fmt(DATA.totalWeakDownloads);
document.getElementById('metric-modern').textContent = fmt(DATA.totalModernDownloads);
document.getElementById('metric-pqc').textContent = fmt(DATA.totalPqcDownloads);

// PQC Gap bar
const gapBar = document.getElementById('pqc-gap-bar');
gapBar.innerHTML = [
  { pct: DATA.weakPercentage, color: '#ef4444', label: 'Weak' },
  { pct: DATA.modernPercentage, color: '#06b6d4', label: 'Modern' },
  { pct: DATA.pqcPercentage, color: '#10b981', label: 'PQC' },
].map(s => '<div class="pqc-gap-segment" style="width:' + Math.max(s.pct, 0.5) + '%;background:' + s.color + '">' + (s.pct >= 5 ? s.label : '') + '</div>').join('');
document.getElementById('pqc-pct-weak').textContent = DATA.weakPercentage.toFixed(1) + '%';
document.getElementById('pqc-pct-modern').textContent = DATA.modernPercentage.toFixed(1) + '%';
document.getElementById('pqc-pct-pqc').textContent = DATA.pqcPercentage.toFixed(2) + '%';

// Colors
const WEAK_COLOR = '#ef4444';
const MODERN_COLOR = '#06b6d4';
const PQC_COLOR = '#10b981';

const chartDefaults = {
  color: '#94a3b8',
  borderColor: '#1e293b',
};
Chart.defaults.color = chartDefaults.color;

// npm donut
new Chart(document.getElementById('chart-npm-donut'), {
  type: 'doughnut',
  data: {
    labels: ['Weak', 'Modern', 'PQC'],
    datasets: [{
      data: [DATA.npm.weak, DATA.npm.modern, DATA.npm.pqc],
      backgroundColor: [WEAK_COLOR, MODERN_COLOR, PQC_COLOR],
      borderWidth: 0,
    }],
  },
  options: {
    cutout: '60%',
    plugins: {
      legend: { position: 'bottom', labels: { padding: 16 } },
      tooltip: {
        callbacks: { label: function(ctx) { return ctx.label + ': ' + fmt(ctx.raw); } }
      }
    }
  }
});

// PyPI donut
new Chart(document.getElementById('chart-pypi-donut'), {
  type: 'doughnut',
  data: {
    labels: ['Weak', 'Modern', 'PQC'],
    datasets: [{
      data: [DATA.pypi.weak, DATA.pypi.modern, DATA.pypi.pqc],
      backgroundColor: [WEAK_COLOR, MODERN_COLOR, PQC_COLOR],
      borderWidth: 0,
    }],
  },
  options: {
    cutout: '60%',
    plugins: {
      legend: { position: 'bottom', labels: { padding: 16 } },
      tooltip: {
        callbacks: { label: function(ctx) { return ctx.label + ': ' + fmt(ctx.raw); } }
      }
    }
  }
});

// Top packages bar chart
const allTop = [...(DATA.npm?.topPackages || []), ...(DATA.pypi?.topPackages || []), ...(DATA.go?.topPackages || []), ...(DATA.maven?.topPackages || []), ...(DATA.crates?.topPackages || []), ...(DATA.packagist?.topPackages || []), ...(DATA.nuget?.topPackages || []), ...(DATA.rubygems?.topPackages || []), ...(DATA.hex?.topPackages || []), ...(DATA.pub?.topPackages || []), ...(DATA.cocoapods?.topPackages || [])]
  .sort((a, b) => b.downloads - a.downloads)
  .slice(0, 15);

new Chart(document.getElementById('chart-top-packages'), {
  type: 'bar',
  data: {
    labels: allTop.map(p => p.name),
    datasets: [{
      data: allTop.map(p => p.downloads),
      backgroundColor: allTop.map(p =>
        p.tier === 'weak' ? WEAK_COLOR : p.tier === 'pqc' ? PQC_COLOR : MODERN_COLOR
      ),
      borderWidth: 0,
      borderRadius: 4,
    }],
  },
  options: {
    indexAxis: 'y',
    plugins: {
      legend: { display: false },
      tooltip: {
        callbacks: { label: function(ctx) { return fmt(ctx.raw) + ' downloads'; } }
      }
    },
    scales: {
      x: {
        grid: { color: '#1e293b' },
        ticks: { callback: function(v) { return fmt(v); } }
      },
      y: {
        grid: { display: false },
        ticks: { font: { family: 'monospace', size: 11 } }
      }
    }
  }
});

// CVE table
const cveTable = document.getElementById('cve-table');
(DATA.cveBreakdown || []).forEach(function(cve) {
  const row = document.createElement('tr');
  row.innerHTML = '<td>' + cve.cweId + '</td><td>' + cve.cweName + '</td><td style="text-align:right;font-weight:600">' + cve.totalCount.toLocaleString() + '</td>';
  cveTable.appendChild(row);
});

// Advisories chart
const sevData = DATA.advisorySeverity || {};
new Chart(document.getElementById('chart-advisories'), {
  type: 'bar',
  data: {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [{
      data: [sevData.critical || 0, sevData.high || 0, sevData.medium || 0, sevData.low || 0],
      backgroundColor: ['#ef4444', '#f59e0b', '#06b6d4', '#64748b'],
      borderWidth: 0,
      borderRadius: 4,
    }],
  },
  options: {
    plugins: { legend: { display: false } },
    scales: {
      x: { grid: { display: false } },
      y: { grid: { color: '#1e293b' }, beginAtZero: true }
    }
  }
});

// Collected at
document.getElementById('collected-at').textContent = new Date(DATA.collectedAt).toLocaleString();
<\/script>
</body>
</html>`;
}
