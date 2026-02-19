/**
 * Collect crypto-related security advisories from the GitHub Advisory Database.
 *
 * Endpoint: GET https://api.github.com/advisories?per_page=100
 * - The REST API does NOT support CWE filtering -- we fetch and filter client-side
 * - Free, no authentication required (60 req/hr unauthenticated)
 * - We fetch up to MAX_PAGES pages and filter for crypto-related CWEs
 */

const GITHUB_API = 'https://api.github.com/advisories';
const REQUEST_DELAY_MS = 2000;
const MAX_PAGES = 5; // 500 advisories max to stay under rate limits

const CRYPTO_CWE_IDS = new Set(['CWE-327', 'CWE-326', 'CWE-328']);

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Check if an advisory is crypto-related based on its CWEs.
 */
function isCryptoRelated(advisory) {
  const cwes = advisory.cwes || [];
  return cwes.some(c => CRYPTO_CWE_IDS.has(c.cwe_id));
}

/**
 * Get the crypto CWE IDs from an advisory.
 */
function getCryptoCweIds(advisory) {
  return (advisory.cwes || [])
    .filter(c => CRYPTO_CWE_IDS.has(c.cwe_id))
    .map(c => c.cwe_id);
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

  // Accumulate crypto advisories across all pages
  const byCwe = {};
  for (const cweId of CRYPTO_CWE_IDS) {
    byCwe[cweId] = {
      count: 0,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
      byEcosystem: {},
    };
  }

  let url = `${GITHUB_API}?per_page=100&type=reviewed`;
  let page = 0;
  let totalScanned = 0;

  while (url && page < MAX_PAGES) {
    page++;
    if (verbose) process.stderr.write(`  github page ${page}/${MAX_PAGES}\n`);

    try {
      const res = await fetchFn(url, {
        headers: { 'Accept': 'application/vnd.github+json' },
      });

      if (!res.ok) {
        if (verbose) process.stderr.write(`  github page ${page}: HTTP ${res.status}\n`);
        break;
      }

      const data = await res.json();
      if (!Array.isArray(data) || data.length === 0) break;

      totalScanned += data.length;

      for (const adv of data) {
        if (!isCryptoRelated(adv)) continue;

        const cweIds = getCryptoCweIds(adv);
        const sev = (adv.severity || 'unknown').toLowerCase();

        for (const cweId of cweIds) {
          const entry = byCwe[cweId];
          entry.count++;
          if (sev in entry.bySeverity) {
            entry.bySeverity[sev]++;
          } else {
            entry.bySeverity.unknown++;
          }

          const vulnerabilities = adv.vulnerabilities || [];
          for (const vuln of vulnerabilities) {
            const eco = vuln?.package?.ecosystem || 'other';
            entry.byEcosystem[eco] = (entry.byEcosystem[eco] || 0) + 1;
          }
        }
      }

      // Check for next page
      const linkHeader = res.headers?.get?.('link') || '';
      const nextMatch = linkHeader.match(/<([^>]+)>;\s*rel="next"/);
      url = nextMatch ? nextMatch[1] : null;

      if (url) await sleep(REQUEST_DELAY_MS);
    } catch (err) {
      if (verbose) process.stderr.write(`  github page ${page} error: ${err.message}\n`);
      break;
    }
  }

  if (verbose) {
    process.stderr.write(`  github scanned ${totalScanned} advisories across ${page} pages\n`);
  }

  const results = [...CRYPTO_CWE_IDS].map(cweId => ({
    cweId,
    count: byCwe[cweId].count,
    bySeverity: byCwe[cweId].bySeverity,
    byEcosystem: byCwe[cweId].byEcosystem,
  }));

  return {
    advisories: results,
    collectedAt: new Date().toISOString(),
  };
}
