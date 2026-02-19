/**
 * Collect crypto-related security advisories from the GitHub Advisory Database.
 *
 * Endpoint: GET https://api.github.com/advisories?cwe=CWE-XXX&per_page=100
 * - Free, no authentication required (60 req/hr unauthenticated)
 * - 2s delay between requests
 * - Paginate if needed (Link header), but usually < 100 results per CWE
 */

const GITHUB_API = 'https://api.github.com/advisories';
const REQUEST_DELAY_MS = 2000;

const CRYPTO_CWES = [
  { id: 'CWE-327', name: 'Broken Crypto Algorithm' },
  { id: 'CWE-326', name: 'Inadequate Encryption Strength' },
  { id: 'CWE-328', name: 'Weak Hash' },
];

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Count advisories by severity and ecosystem from a list of advisory objects.
 */
function countAdvisories(advisories) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  const byEcosystem = {};

  for (const adv of advisories) {
    const sev = (adv.severity || 'unknown').toLowerCase();
    if (sev in bySeverity) {
      bySeverity[sev]++;
    } else {
      bySeverity.unknown++;
    }

    // Count affected ecosystems
    const vulnerabilities = adv.vulnerabilities || [];
    for (const vuln of vulnerabilities) {
      const eco = vuln?.package?.ecosystem || 'other';
      byEcosystem[eco] = (byEcosystem[eco] || 0) + 1;
    }
  }

  return { bySeverity, byEcosystem };
}

/**
 * Fetch all pages for a given CWE query.
 */
async function fetchAllPages(cweId, fetchFn, verbose) {
  const allAdvisories = [];
  let url = `${GITHUB_API}?cwe=${cweId}&per_page=100`;

  while (url) {
    const res = await fetchFn(url, {
      headers: { 'Accept': 'application/vnd.github+json' },
    });

    if (!res.ok) {
      if (verbose) process.stderr.write(`  github ${cweId}: HTTP ${res.status}\n`);
      break;
    }

    const data = await res.json();
    if (Array.isArray(data)) {
      allAdvisories.push(...data);
    }

    // Check for next page via Link header
    const linkHeader = res.headers?.get?.('link') || '';
    const nextMatch = linkHeader.match(/<([^>]+)>;\s*rel="next"/);
    url = nextMatch ? nextMatch[1] : null;

    if (url) await sleep(REQUEST_DELAY_MS);
  }

  return allAdvisories;
}

/**
 * Fetch crypto-related advisory counts from GitHub Advisory Database.
 *
 * @param {Object} [options]
 * @param {Function} [options.fetchFn] - Fetch implementation (defaults to globalThis.fetch)
 * @param {boolean} [options.verbose] - Log progress
 * @returns {Promise<{advisories: Array<{cweId: string, count: number, bySeverity: Object, byEcosystem: Object}>, collectedAt: string}>}
 */
export async function collectGithubAdvisories(options = {}) {
  const fetchFn = options.fetchFn || globalThis.fetch;
  const verbose = options.verbose || false;

  const results = [];

  for (let i = 0; i < CRYPTO_CWES.length; i++) {
    const cwe = CRYPTO_CWES[i];

    if (verbose) {
      process.stderr.write(`  github ${i + 1}/${CRYPTO_CWES.length}: ${cwe.id}\n`);
    }

    try {
      const advisories = await fetchAllPages(cwe.id, fetchFn, verbose);
      const { bySeverity, byEcosystem } = countAdvisories(advisories);
      results.push({
        cweId: cwe.id,
        count: advisories.length,
        bySeverity,
        byEcosystem,
      });
    } catch (err) {
      if (verbose) process.stderr.write(`  github ${cwe.id} error: ${err.message}\n`);
      results.push({
        cweId: cwe.id,
        count: 0,
        bySeverity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
        byEcosystem: {},
      });
    }

    // Delay between CWE queries
    if (i < CRYPTO_CWES.length - 1) {
      await sleep(REQUEST_DELAY_MS);
    }
  }

  return {
    advisories: results,
    collectedAt: new Date().toISOString(),
  };
}
