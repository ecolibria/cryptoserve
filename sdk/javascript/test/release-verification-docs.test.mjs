/**
 * The release verification instructions are a security claim, so they are held
 * to what the published releases actually contain.
 *
 * The README told Python users to run `gh release download v1.4.3` and then
 * `sha256sum -c SHA256SUMS.txt`. The v1.4.3 GitHub Release has no assets at all,
 * so the first command downloads nothing and the second has nothing to check.
 * Two other documents said SHA-256 checksums covered all release artifacts.
 *
 * What the releases contain, read back from GitHub and the registries:
 *
 *   gh release view <tag> -R ecolibria/cryptoserve --json assets
 *   gh release download <tag> -R ecolibria/cryptoserve -p SHA256SUMS.txt -O -
 *   curl -s -H 'Accept: application/vnd.pypi.simple.v1+json' https://pypi.org/simple/<project>/
 *
 * - Python tags up to v1.4.3: v1.4.3 has no assets. Every earlier one attaches a
 *   SHA256SUMS.txt whose entries are build directory paths (./dist-cryptoserve/...)
 *   and include sdists that were never attached, so the documented commands fail
 *   on every entry. Most of those entries also differ from the file PyPI serves
 *   under the same name.
 * - Python tags v1.5.0 to v1.8.0 are numbered after v1.4.3 but were pushed
 *   before the current workflow: the v1.5.0 and v1.6.0 GitHub Releases have no
 *   assets, v1.7.0 has no GitHub Release, and the v1.8.0 checksum file lists
 *   build directory paths.
 * - CLI tags from js-v0.4.0: SHA256SUMS.txt with bare filenames, and it verifies.
 *   No js-v tag before js-v0.4.0 has a GitHub Release. CLI 0.2.0 and 0.3.4 were
 *   tagged v0.2.0 and v0.3.4, and the GitHub Releases on those tags hold Python
 *   wheels, not the CLI.
 * - PyPI: no file of cryptoserve, cryptoserve-core, cryptoserve-client or
 *   cryptoserve-auto carries provenance.
 *
 * There is no way to read a GitHub Release from a unit test, so these facts are
 * written down here and the documents are checked against them. A Python tag
 * after v1.4.3, other than v1.5.0 to v1.8.0, is accepted: it would be published
 * by the current workflow, which writes bare filenames and checks the file
 * before attaching it.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..', '..');

const read = (rel) => readFileSync(join(REPO_ROOT, rel), 'utf-8');

/** Lines of `text` matching `pattern`, so a failure names the claim, not the file. */
function linesMatching(text, pattern) {
  return text.split('\n').filter((line) => pattern.test(line));
}

/** The `## Verifying releases` section of the README, up to the next `## `. */
function verifyingReleasesSection() {
  const readme = read('README.md');
  const start = readme.indexOf('\n## Verifying releases\n');
  assert.notEqual(start, -1, 'README has no "## Verifying releases" section');
  const end = readme.indexOf('\n## ', start + 1);
  return readme.slice(start, end === -1 ? undefined : end);
}

function parseVersion(text) {
  return text.split('.').map(Number);
}

function compareVersions(a, b) {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

/**
 * Python tags after v1.4.3 that the current workflow did not publish, so the
 * version comparison alone would accept them, with the reason each cannot verify.
 */
const PYTHON_TAGS_BEFORE_CURRENT_WORKFLOW = new Map([
  ['v1.5.0', 'the v1.5.0 GitHub Release has no assets'],
  ['v1.6.0', 'the v1.6.0 GitHub Release has no assets'],
  ['v1.7.0', 'v1.7.0 has no GitHub Release'],
  ['v1.8.0', 'the v1.8.0 checksum file lists build directory paths'],
]);

/**
 * Whether `gh release download <tag>` followed by `sha256sum -c SHA256SUMS.txt`
 * can succeed for this tag. Returns the reason when it cannot.
 */
function checksumProblem(tag) {
  const js = /^js-v(\d+\.\d+\.\d+)$/.exec(tag);
  if (js) {
    return compareVersions(parseVersion(js[1]), [0, 4, 0]) >= 0
      ? null
      : 'no js-v tag before js-v0.4.0 has a GitHub Release';
  }
  const py = /^v(\d+\.\d+\.\d+)$/.exec(tag);
  if (py) {
    const pushedBeforeWorkflow = PYTHON_TAGS_BEFORE_CURRENT_WORKFLOW.get(tag);
    if (pushedBeforeWorkflow) return pushedBeforeWorkflow;
    return compareVersions(parseVersion(py[1]), [1, 4, 3]) > 0
      ? null
      : 'Python releases up to v1.4.3 have no assets or a checksum file of build directory paths';
  }
  return 'not a release tag of this repository';
}

describe('README release verification instructions', () => {
  it('only tells users to verify releases whose checksum file can verify', () => {
    const section = verifyingReleasesSection();
    const tags = [...section.matchAll(/gh release download (\S+)/g)].map((m) => m[1]);
    assert.ok(tags.length > 0, 'the section shows no download command at all');
    const broken = tags
      .map((tag) => [tag, checksumProblem(tag)])
      .filter(([, problem]) => problem !== null);
    assert.deepEqual(broken, [], 'README tells users to verify a release that cannot verify');
  });

  it('does not accept the Python tags after v1.4.3 that were pushed before the current workflow', () => {
    for (const tag of ['v1.5.0', 'v1.6.0', 'v1.7.0', 'v1.8.0']) {
      assert.notEqual(checksumProblem(tag), null, `${tag} is accepted`);
    }
  });

  it('discloses that the published PyPI versions carry no attestations', () => {
    assert.match(
      verifyingReleasesSection(),
      /PyPI versions at or before `1\.4\.3` carry no attestations/,
    );
  });

  it('says which CLI versions have no checksums, rather than pointing at a file that does not exist', () => {
    assert.deepEqual(
      linesMatching(verifyingReleasesSection(), /Verify those with `SHA256SUMS\.txt` only/),
      [],
    );
  });
});

describe('release checksum claims in the trust documents', () => {
  for (const doc of ['README.md', 'docs/trust.md', 'docs/security/transparency-report.md']) {
    it(`${doc} does not claim checksums on every release`, () => {
      const claims = linesMatching(
        read(doc),
        /checksums on all|Every published tag attaches a `SHA256SUMS\.txt`/i,
      );
      assert.deepEqual(claims, []);
    });
  }
});
