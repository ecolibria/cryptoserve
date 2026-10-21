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
 *   gh release list -R ecolibria/cryptoserve --limit 100
 *   gh release view <tag> -R ecolibria/cryptoserve --json assets
 *   gh release download <tag> -R ecolibria/cryptoserve -p SHA256SUMS.txt -O -
 *   curl -s -H 'Accept: application/vnd.pypi.simple.v1+json' https://pypi.org/simple/<project>/
 *
 * - Python tags up to v1.4.3: v0.8.0, v0.8.1 and v1.0.0 to v1.3.6 have no
 *   GitHub Release, and the v1.4.3 GitHub Release has no assets. The releases on
 *   v0.2.0, v0.3.4, v1.4.0, v1.4.1 and v1.4.2 attach a SHA256SUMS.txt whose
 *   entries are build directory paths (./dist-cryptoserve/...) and include
 *   sdists that were never attached, so the documented commands fail on every
 *   entry. Most of those entries also differ from the file PyPI serves under the
 *   same name.
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
 * written down here and the documents are checked against them. Only a tag in
 * TAGS_THAT_VERIFY is accepted, so a mistyped tag in a README edit fails even
 * when it looks like one the current workflow would publish. Add a tag to it
 * after its release has been downloaded and checked with the two documented
 * commands.
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

/**
 * The sentences of a markdown document, with the wrapped lines of a paragraph
 * joined back together. A line that starts with `|` or `#` is a unit of its own,
 * read as a table row or a heading, and so is each line of code; a line that
 * starts with a list marker starts a new unit. Each unit is then split after a
 * `.`, `!` or `?` followed by a space and a capital letter, a backtick, a double
 * quote or an opening parenthesis. So a sentence wrapped onto a line that starts
 * with `|`, `#` or a list marker, or holding such a stop, is checked in parts.
 */
function sentences(text) {
  const units = [];
  let paragraph = [];
  let inFence = false;
  const flush = () => {
    if (paragraph.length > 0) units.push(paragraph.join(' '));
    paragraph = [];
  };
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.startsWith('```')) {
      flush();
      inFence = !inFence;
    } else if (inFence || trimmed === '' || /^[|#]/.test(trimmed)) {
      flush();
      if (trimmed !== '') units.push(trimmed);
    } else {
      if (/^(?:[-*+]|\d+\.)\s/.test(trimmed)) flush();
      paragraph.push(trimmed);
    }
  }
  flush();
  return units.flatMap((unit) => unit.split(/(?<=[.!?])\s+(?=[A-Z`"(])/));
}

/**
 * Sentences that contain `checksum`, `SHA256SUMS`, `SHA-256 digest` or
 * `SHA-256 hash`, in any letter case, and the word all, every or each, unless
 * they also contain from `js-v0.4.0` or `js-v0.4.0` onward: the CLI releases
 * from js-v0.4.0 are the only ones that verify. It matches words, not meaning,
 * so a blanket claim worded without these terms, or beside the exempting
 * words, is not found.
 */
function blanketChecksumClaims(text) {
  return sentences(text).filter(
    (sentence) =>
      /checksum|SHA256SUMS|SHA-256 (?:digest|hash)/i.test(sentence) &&
      /\b(?:all|every|each)\b/i.test(sentence) &&
      !/from `js-v0\.4\.0`|`js-v0\.4\.0` onward/.test(sentence),
  );
}

/** The `## <heading>` section of a markdown document, up to the next `## `. */
function section(doc, heading) {
  const text = read(doc);
  const start = text.indexOf(`\n## ${heading}\n`);
  assert.notEqual(start, -1, `${doc} has no "## ${heading}" section`);
  const end = text.indexOf('\n## ', start + 1);
  return text.slice(start, end === -1 ? undefined : end);
}

const verifyingReleasesSection = () => section('README.md', 'Verifying releases');

/**
 * Tags whose GitHub Release has been downloaded and checked with the documented
 * commands. Add a tag here after its release has been checked, and only then.
 */
const TAGS_THAT_VERIFY = new Set(['js-v0.4.0', 'js-v0.5.0', 'js-v0.6.0']);

/**
 * Tags that look like releases and cannot verify, with the reason. A tag in
 * neither list has no GitHub Release, or is newer than these facts.
 */
const CANNOT_VERIFY = new Map([
  ['v0.2.0', 'the v0.2.0 checksum file lists build directory paths'],
  ['v0.3.4', 'the v0.3.4 checksum file lists build directory paths'],
  ['v1.4.0', 'the v1.4.0 checksum file lists build directory paths'],
  ['v1.4.1', 'the v1.4.1 checksum file lists build directory paths'],
  ['v1.4.2', 'the v1.4.2 checksum file lists build directory paths'],
  ['v1.4.3', 'the v1.4.3 GitHub Release has no assets'],
  ['v1.5.0', 'the v1.5.0 GitHub Release has no assets'],
  ['v1.6.0', 'the v1.6.0 GitHub Release has no assets'],
  ['v1.7.0', 'v1.7.0 has no GitHub Release'],
  ['v1.8.0', 'the v1.8.0 checksum file lists build directory paths'],
]);

/**
 * Whether `gh release download <tag>` followed by `sha256sum -c SHA256SUMS.txt`
 * is known to succeed for this tag. Returns the reason when it is not.
 */
function checksumProblem(tag) {
  if (TAGS_THAT_VERIFY.has(tag)) return null;
  if (CANNOT_VERIFY.has(tag)) return CANNOT_VERIFY.get(tag);
  if (/^(?:js-)?v\d+\.\d+\.\d+$/.test(tag)) {
    return `no GitHub Release on ${tag} is known to verify; add it to TAGS_THAT_VERIFY once its release has been checked`;
  }
  return 'not a release tag of this repository';
}

describe('README release verification instructions', () => {
  it('only tells users to verify releases whose checksum file can verify', () => {
    const tags = [...verifyingReleasesSection().matchAll(/gh release download (\S+)/g)].map(
      (m) => m[1],
    );
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

  it('does not accept a tag that is not known to verify, so a mistyped tag fails', () => {
    for (const tag of ['v1.5.1', 'v1.9.0', 'v2.0.0', 'js-v0.4.1', 'js-v0.7.0', 'js-v0.2.1']) {
      assert.notEqual(checksumProblem(tag), null, `${tag} is accepted`);
    }
    for (const tag of TAGS_THAT_VERIFY) {
      assert.equal(checksumProblem(tag), null, `${tag} is rejected`);
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

  it('says the GitHub Releases on the v0.2.0 and v0.3.4 tags hold Python wheels, not the CLI', () => {
    const said = sentences(verifyingReleasesSection()).filter(
      (s) => s.includes('`v0.2.0`') && s.includes('`v0.3.4`'),
    );
    assert.ok(
      said.some((s) => /Python wheels/.test(s) && /does not cover the CLI tarball/.test(s)),
      'a CLI 0.2.0 or 0.3.4 user who opens that release is not told what it holds',
    );
  });
});

describe('release checksum claims in the trust documents', () => {
  for (const doc of ['README.md', 'docs/trust.md', 'docs/security/transparency-report.md']) {
    it(`${doc} does not claim checksums on every release`, () => {
      assert.deepEqual(blanketChecksumClaims(read(doc)), []);
    });
  }

  it('catches these blanket claims, including a table row and one wrapped across two lines', () => {
    for (const claim of [
      '| Release artifacts | SHA-256 checksums cover every published package |',
      'SHA-256 checksums cover\nevery published package.',
      'Releases ship with checksums on all artifacts.',
      'Every published tag attaches a `SHA256SUMS.txt`.',
      'Each CLI release from `js-v0.4.0` onward is signed. Checksums cover all of them.',
    ]) {
      assert.equal(blanketChecksumClaims(claim).length, 1, claim);
    }
  });

  it('accepts a checksum claim limited to the CLI releases from js-v0.4.0', () => {
    for (const claim of [
      'Each CLI release from `js-v0.4.0` onward attaches a `SHA256SUMS.txt` to its\nGitHub Release.',
      '| Release artifacts | `SHA256SUMS.txt` on each CLI GitHub Release from `js-v0.4.0` |',
    ]) {
      assert.deepEqual(blanketChecksumClaims(claim), [], claim);
    }
  });
});

describe('the release pipeline document', () => {
  const pipeline = () => section('docs/security/ci-security-pipeline.md', '4. Release Pipeline (`publish.yml`)');
  const workflow = read('.github/workflows/publish.yml');

  it('names no secret that the publish workflow does not use', () => {
    const named = [...pipeline().matchAll(/`([A-Z][A-Z0-9_]*_(?:TOKEN|SECRET|KEY))`/g)].map(
      (m) => m[1],
    );
    assert.deepEqual(named.filter((name) => !workflow.includes(name)), []);
  });

  it('lists every kind of file the GitHub Release attaches', () => {
    const bullet = linesMatching(pipeline(), /^- \*\*GitHub Release\*\*/);
    assert.equal(bullet.length, 1, 'no "GitHub Release" bullet in the release pipeline section');
    const kinds = [
      ['release/*.whl', /wheels/],
      ['release/*.tar.gz', /sdists/],
      ['release/SHA256SUMS.txt', /`SHA256SUMS\.txt`/],
    ];
    for (const [attached, described] of kinds) {
      if (workflow.includes(attached)) assert.match(bullet[0], described, attached);
    }
  });
});
