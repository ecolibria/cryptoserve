/**
 * Collect crypto-related CVE counts from NVD (National Vulnerability Database).
 *
 * Endpoint: GET https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-XXX&resultsPerPage=1
 * - Free, no authentication required (API key optional for higher rate limits)
 * - Rate limit: 5 requests per 30 seconds without API key
 * - We use 7s delay between requests to stay well under limits
 * - resultsPerPage=1 to minimize payload (we only need totalResults)
 */

const NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const REQUEST_DELAY_MS = 7000;

const CRYPTO_CWES = [
  { id: 'CWE-327', name: 'Use of a Broken or Risky Cryptographic Algorithm' },
  { id: 'CWE-326', name: 'Inadequate Encryption Strength' },
  { id: 'CWE-328', name: 'Use of Weak Hash' },
];

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Fetch crypto-related CVE counts from NVD.
 *
 * @param {Object} [options]
 * @param {Function} [options.fetchFn] - Fetch implementation (defaults to globalThis.fetch)
 * @param {boolean} [options.verbose] - Log progress
 * @returns {Promise<{cves: Array<{cweId: string, cweName: string, totalCount: number}>, collectedAt: string}>}
 */
export async function collectNvdCves(options = {}) {
  const fetchFn = options.fetchFn || globalThis.fetch;
  const verbose = options.verbose || false;

  const results = [];

  for (let i = 0; i < CRYPTO_CWES.length; i++) {
    const cwe = CRYPTO_CWES[i];
    const url = `${NVD_API}?cweId=${cwe.id}&resultsPerPage=1`;

    if (verbose) {
      process.stderr.write(`  nvd ${i + 1}/${CRYPTO_CWES.length}: ${cwe.id} (${cwe.name})\n`);
    }

    try {
      const res = await fetchFn(url);
      if (!res.ok) {
        if (verbose) process.stderr.write(`  nvd ${cwe.id}: HTTP ${res.status}\n`);
        results.push({ cweId: cwe.id, cweName: cwe.name, totalCount: 0 });
      } else {
        const data = await res.json();
        const totalCount = data?.totalResults || 0;
        results.push({ cweId: cwe.id, cweName: cwe.name, totalCount });
      }
    } catch (err) {
      if (verbose) process.stderr.write(`  nvd ${cwe.id} error: ${err.message}\n`);
      results.push({ cweId: cwe.id, cweName: cwe.name, totalCount: 0 });
    }

    // Delay between requests (NVD rate limit)
    if (i < CRYPTO_CWES.length - 1) {
      await sleep(REQUEST_DELAY_MS);
    }
  }

  return {
    cves: results,
    collectedAt: new Date().toISOString(),
  };
}
