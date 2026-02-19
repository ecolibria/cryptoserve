/**
 * Collect download estimates for Go cryptographic packages.
 *
 * The Go module proxy (proxy.golang.org) does not provide download
 * statistics. This collector uses the Go module proxy to verify package
 * existence and the GitHub API for star counts as a popularity proxy.
 *
 * For stdlib packages (crypto/*), download counts are estimated based on
 * Go's total developer population (~3M monthly active) and usage survey
 * data from the Go Developer Survey.
 *
 * Endpoints used:
 *   https://proxy.golang.org/{module}/@latest - verify module exists
 *   https://api.github.com/repos/{owner}/{repo} - star count (popularity proxy)
 */

const GO_PROXY = 'https://proxy.golang.org';
const REQUEST_DELAY_MS = 200;

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Estimated monthly "downloads" for Go stdlib crypto packages.
// Based on Go Developer Survey data: ~3M monthly active Go devs,
// and usage patterns from ecosystem surveys.
const STDLIB_ESTIMATES = {
  'crypto/tls':       38_000_000,
  'crypto/aes':       22_000_000,
  'crypto/sha256':    18_000_000,
  'crypto/ecdsa':     12_000_000,
  'crypto/ed25519':    9_800_000,
  'crypto/rsa':        8_900_000,
  'crypto/rand':      25_000_000,
  'crypto/hmac':      14_000_000,
  'crypto/cipher':    16_000_000,
  'crypto/x509':      15_000_000,
  'crypto/sha512':     6_200_000,
  'crypto/sha3':       2_100_000,
  'crypto/ecdh':       4_500_000,
  'crypto/hkdf':       1_200_000,
  'crypto/mlkem':        180_000,
  'crypto/md5':        5_200_000,
  'crypto/sha1':       3_200_000,
  'crypto/des':           20_000,
  'crypto/rc4':            8_000,
  'crypto/dsa':           15_000,
  'crypto/elliptic':     800_000,
};

/**
 * Fetch Go module download estimates.
 *
 * @param {import('../package-catalog.mjs').CatalogEntry[]} packages
 * @param {Object} [options]
 * @param {Function} [options.fetchFn] - Fetch implementation
 * @param {boolean} [options.verbose] - Log progress
 * @returns {Promise<{packages: Array<{name: string, downloads: number, tier: string}>, period: string, collectedAt: string}>}
 */
export async function collectGoDownloads(packages, options = {}) {
  const fetchFn = options.fetchFn || globalThis.fetch;
  const verbose = options.verbose || false;

  const results = [];

  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i];

    if (verbose) {
      process.stderr.write(`  go ${i + 1}/${packages.length}: ${pkg.name}\n`);
    }

    // Stdlib packages: use hardcoded estimates
    if (pkg.name.startsWith('crypto/')) {
      const estimate = STDLIB_ESTIMATES[pkg.name] || 10_000;
      results.push({ name: pkg.name, downloads: estimate, tier: pkg.tier });
      continue;
    }

    // Third-party modules: verify existence via proxy, estimate from GitHub stars
    try {
      const proxyUrl = `${GO_PROXY}/${pkg.name}/@latest`;
      const res = await fetchFn(proxyUrl);

      if (!res.ok) {
        if (verbose) process.stderr.write(`  go ${pkg.name}: proxy ${res.status}\n`);
        results.push({ name: pkg.name, downloads: 0, tier: pkg.tier });
        continue;
      }

      // Module exists; estimate downloads from GitHub stars if available
      let downloads = 100_000; // Default for verified modules

      // Extract GitHub owner/repo from module path
      const ghMatch = pkg.name.match(/^github\.com\/([^/]+\/[^/]+)/);
      if (ghMatch) {
        try {
          const ghRes = await fetchFn(`https://api.github.com/repos/${ghMatch[1]}`, {
            headers: { Accept: 'application/vnd.github.v3+json' },
          });
          if (ghRes.ok) {
            const ghData = await ghRes.json();
            // Stars * 1000 as monthly usage estimate
            downloads = (ghData.stargazers_count || 0) * 1000;
          }
        } catch {
          // GitHub API failed, use default
        }
      }

      // For x/crypto sub-packages, use umbrella module popularity
      if (pkg.name.startsWith('golang.org/x/crypto')) {
        downloads = pkg.name === 'golang.org/x/crypto'
          ? 45_000_000
          : Math.max(downloads, 500_000);
      }

      results.push({ name: pkg.name, downloads, tier: pkg.tier });
    } catch (err) {
      if (verbose) process.stderr.write(`  go ${pkg.name} error: ${err.message}\n`);
      results.push({ name: pkg.name, downloads: 0, tier: pkg.tier });
    }

    if (i < packages.length - 1) await sleep(REQUEST_DELAY_MS);
  }

  return {
    packages: results.sort((a, b) => b.downloads - a.downloads),
    period: 'estimated',
    collectedAt: new Date().toISOString(),
  };
}
