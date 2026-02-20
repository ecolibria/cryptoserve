/**
 * Enrich top packages with GitHub repository metadata.
 *
 * Fetches stars, forks, last push date, and archived status from the GitHub API
 * for the top packages by download count. Uses unauthenticated requests
 * (60 req/hr limit), so we limit to 30 packages with 1s delays.
 */

const REQUEST_DELAY_MS = 1000;
const MAX_ENRICHMENTS = 30;

/**
 * Static mapping of package name to GitHub owner/repo.
 * Many registries don't expose repo URLs in download APIs,
 * so we maintain this mapping for top packages.
 */
const KNOWN_REPOS = {
  // npm
  'crypto-js': 'brix/crypto-js',
  '@noble/hashes': 'paulmillr/noble-hashes',
  '@noble/curves': 'paulmillr/noble-curves',
  '@noble/ciphers': 'paulmillr/noble-ciphers',
  '@noble/post-quantum': 'paulmillr/noble-post-quantum',
  'node-forge': 'digitalbazaar/forge',
  'jose': 'panva/jose',
  'elliptic': 'indutny/elliptic',
  'hash.js': 'indutny/hash.js',
  'tweetnacl': 'nicola/tweetnacl-js',
  'bcryptjs': 'nicola/bcrypt.js',
  'jsonwebtoken': 'auth0/node-jsonwebtoken',
  'sodium-native': 'nicola/sodium-native',
  'md5': 'pvorb/node-md5',
  'scrypt-js': 'nicola/scrypt-js',

  // PyPI
  'cryptography': 'pyca/cryptography',
  'pycryptodome': 'Legrandin/pycryptodome',
  'bcrypt': 'pyca/bcrypt',
  'pynacl': 'pyca/pynacl',
  'argon2-cffi': 'hynek/argon2-cffi',
  'PyJWT': 'jpadilla/pyjwt',
  'liboqs-python': 'open-quantum-safe/liboqs-python',

  // Rust crates
  'ring': 'briansmith/ring',
  'rustls': 'rustls/rustls',
  'ed25519-dalek': 'dalek-cryptography/curve25519-dalek',
  'sha2': 'RustCrypto/hashes',
  'aes-gcm': 'RustCrypto/AEADs',
  'chacha20poly1305': 'RustCrypto/AEADs',
  'argon2': 'RustCrypto/password-hashes',

  // Go
  'github.com/cloudflare/circl': 'cloudflare/circl',
  'golang-jwt/jwt/v5': 'golang-jwt/jwt',

  // Maven
  'org.bouncycastle:bcprov-jdk18on': 'bcgit/bc-java',
  'com.google.crypto.tink:tink': 'google/tink',
  'io.jsonwebtoken:jjwt-api': 'jwtk/jjwt',

  // PHP
  'phpseclib/phpseclib': 'phpseclib/phpseclib',
  'defuse/php-encryption': 'defuse/php-encryption',
  'firebase/php-jwt': 'firebase/php-jwt',

  // Ruby
  'rbnacl': 'crypto-rb/rbnacl',
  'jwt': 'jwt/ruby-jwt',

  // Dart
  'pointycastle': 'nicola/pc-dart',

  // Swift
  'CryptoSwift': 'nicola/CryptoSwift',
};

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Enrich packages with GitHub metadata.
 *
 * @param {Array} allPackages - All package entries (with name + downloads)
 * @param {Object} [options]
 * @param {Function} [options.fetchFn] - Fetch implementation
 * @param {boolean} [options.verbose] - Log progress
 * @returns {Promise<Map<string, {stars: number, forks: number, lastPush: string, archived: boolean}>>}
 */
export async function collectGithubEnrichment(allPackages, options = {}) {
  const fetchFn = options.fetchFn || globalThis.fetch;
  const verbose = options.verbose || false;

  // Sort by downloads descending and pick top packages that have known repos
  const sorted = [...allPackages]
    .sort((a, b) => b.downloads - a.downloads);

  const toEnrich = [];
  const seen = new Set();
  for (const pkg of sorted) {
    const repo = KNOWN_REPOS[pkg.name];
    if (!repo || seen.has(repo)) continue;
    seen.add(repo);
    toEnrich.push({ name: pkg.name, repo });
    if (toEnrich.length >= MAX_ENRICHMENTS) break;
  }

  if (verbose) {
    process.stderr.write(`  github enrichment: ${toEnrich.length} packages to enrich\n`);
  }

  const results = new Map();

  for (const { name, repo } of toEnrich) {
    try {
      const res = await fetchFn(`https://api.github.com/repos/${repo}`, {
        headers: { 'Accept': 'application/vnd.github+json' },
      });

      if (!res.ok) {
        if (verbose) process.stderr.write(`  github ${repo}: HTTP ${res.status}\n`);
        // Check rate limit
        const remaining = res.headers?.get?.('x-ratelimit-remaining');
        if (remaining === '0') {
          if (verbose) process.stderr.write('  github rate limit hit, stopping\n');
          break;
        }
        await sleep(REQUEST_DELAY_MS);
        continue;
      }

      const data = await res.json();
      results.set(name, {
        stars: data.stargazers_count || 0,
        forks: data.forks_count || 0,
        lastPush: data.pushed_at || null,
        archived: data.archived || false,
      });

      if (verbose) {
        process.stderr.write(`  github ${repo}: ${data.stargazers_count} stars\n`);
      }

      await sleep(REQUEST_DELAY_MS);
    } catch (err) {
      if (verbose) process.stderr.write(`  github ${repo} error: ${err.message}\n`);
      await sleep(REQUEST_DELAY_MS);
    }
  }

  if (verbose) {
    process.stderr.write(`  github enrichment: ${results.size} packages enriched\n`);
  }

  return {
    enrichments: Object.fromEntries(results),
    collectedAt: new Date().toISOString(),
  };
}
