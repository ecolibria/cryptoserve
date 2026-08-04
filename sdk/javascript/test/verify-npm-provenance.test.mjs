/**
 * Regression tests for .github/scripts/verify-npm-provenance.sh.
 *
 * The 0.5.0 release reported FAILURE on this check while having published
 * correctly, with correct provenance. The job waited five attempts at 20s for
 * `npm install` to succeed, npm had not yet made the version installable, and
 * `npm audit signatures` then ran against an empty tree and errored with
 * "found no installed dependencies to audit". Registry propagation was reported
 * as a provenance failure.
 *
 * A release that publishes correctly and reports failure teaches people to
 * ignore the check. These tests hold both halves of the fix: a slow-propagating
 * registry must not fail the job, and a genuinely absent or untrusted
 * attestation must still fail it loudly.
 *
 * There is no way to exercise the real script against the real registry outside
 * a release, so `npm` is stubbed. The stub records every invocation, which lets
 * the tests assert what the script DID rather than only what it printed:
 * "never reached `npm audit signatures`" is the property that matters for the
 * empty-tree cases, and it is not visible in the output.
 *
 * The second half of the file covers a different failure: the job verified that
 * an attestation was TRUSTED and reported it as if that meant it was OURS. A
 * package published from another repository, by another workflow, carries a
 * perfectly valid signature and a SLSA predicate type. Those tests script the
 * registry into serving exactly that, so the origin assertions have something
 * to be wrong about.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdirSync, mkdtempSync, writeFileSync, rmSync, readFileSync, existsSync, chmodSync,
} from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(__dirname, '..', '..', '..', '.github', 'scripts', 'verify-npm-provenance.sh');

// Every literal below is copied from the published cryptoserve@0.6.0, so a
// fixture that drifts from the registry's real shape is a visible edit rather
// than a silent one:
//
//   npm view cryptoserve@0.6.0 dist.attestations --json
//   npm view cryptoserve@0.6.0 dist.integrity
//   curl -s https://registry.npmjs.org/-/npm/v1/attestations/cryptoserve@0.6.0
const ATTESTATION_URL = 'https://registry.npmjs.org/-/npm/v1/attestations/cryptoserve@0.6.0';
const EXPECTED_REPOSITORY = 'https://github.com/ecolibria/cryptoserve';
const EXPECTED_WORKFLOW = '.github/workflows/publish-npm.yml';
const EXPECTED_REF = 'refs/tags/js-v0.6.0';

// One value in two encodings: `dist.integrity` is base64 SRI, the SLSA subject
// records hex. The script converts one to the other, so the fixture keeps both
// rather than deriving the second and testing its own arithmetic.
const TARBALL_INTEGRITY = 'sha512-pH+sT+vikBNGSbqqLR7i6JMPFrHdWSjv9kZiQHgcUhhkskRf+o70PVQCvaND3QMeEjP8VXAthix/AK2B4nJzNQ==';
const TARBALL_SHA512_HEX = 'a47fac4febe290134649baaa2d1ee2e8930f16b1dd5928eff6466240781c5218'
  + '64b2445ffa8ef43d5402bda343dd031e1233fc55702d862c7f00ad81e2727335';

const GOOD_ATTESTATIONS = JSON.stringify({
  url: ATTESTATION_URL,
  provenance: { predicateType: 'https://slsa.dev/provenance/v1' },
});

/** Wrap an in-toto statement the way the registry serves it. */
function sigstoreBundle(statement, { payloadType = 'application/vnd.in-toto+json', payload } = {}) {
  return {
    mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json',
    verificationMaterial: { tlogEntries: [{ logIndex: '0' }] },
    dsseEnvelope: {
      payload: payload ?? Buffer.from(JSON.stringify(statement), 'utf-8').toString('base64'),
      payloadType,
      signatures: [{ sig: 'c3R1Yi1zaWduYXR1cmU=' }],
    },
  };
}

// The registry serves TWO attestations, and this one comes first. It is in every
// fixture on purpose: a script that reads `attestations[0]` reads the publish
// receipt, which carries no build claims at all, and would have to either fail a
// correct release or pass on the absence of the fields it means to check.
const PUBLISH_ATTESTATION = {
  predicateType: 'https://github.com/npm/attestation/tree/main/specs/publish/v0.1',
  bundle: sigstoreBundle({
    _type: 'https://in-toto.io/Statement/v0.1',
    subject: [{ name: 'pkg:npm/cryptoserve@0.6.0', digest: { sha512: TARBALL_SHA512_HEX } }],
    predicateType: 'https://github.com/npm/attestation/tree/main/specs/publish/v0.1',
    predicate: { name: 'cryptoserve', version: '0.6.0', registry: 'https://registry.npmjs.org' },
  }),
};

/**
 * The attestation bundle document, as JSON text, with any part of the SLSA
 * provenance overridable. Defaults reproduce the real 0.6.0 exactly.
 */
function bundleDoc({
  repository = EXPECTED_REPOSITORY,
  path = EXPECTED_WORKFLOW,
  ref = EXPECTED_REF,
  workflow,
  subject,
  subjectName = 'pkg:npm/cryptoserve@0.6.0',
  subjectDigest = TARBALL_SHA512_HEX,
  outerPredicateType = 'https://slsa.dev/provenance/v1',
  innerPredicateType = 'https://slsa.dev/provenance/v1',
  payloadType,
  payload,
  omitProvenance = false,
  attestations,
} = {}) {
  const statement = {
    _type: 'https://in-toto.io/Statement/v1',
    subject: subject ?? [{ name: subjectName, digest: { sha512: subjectDigest } }],
    predicateType: innerPredicateType,
    predicate: {
      buildDefinition: {
        buildType: 'https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1',
        externalParameters: {
          workflow: workflow === undefined ? { ref, repository, path } : workflow,
        },
        internalParameters: { github: { event_name: 'push', repository_id: '1128643599' } },
      },
      runDetails: { builder: { id: 'https://github.com/actions/runner/github-hosted' } },
    },
  };

  if (attestations !== undefined) return JSON.stringify({ attestations });

  const list = [PUBLISH_ATTESTATION];
  if (!omitProvenance) {
    list.push({
      predicateType: outerPredicateType,
      bundle: sigstoreBundle(statement, { payloadType, payload }),
    });
  }
  return JSON.stringify({ attestations: list });
}

const GOOD_BUNDLE = bundleDoc();

// A stub `npm` that scripts the registry's behaviour.
//
// Propagation is modelled as a probe count shared by `npm view <pkg>@<ver>` and
// `npm install <pkg>@<ver>`, because that is how the real registry behaves: an
// unpropagated version is invisible to BOTH. Scripting them independently would
// let a fix that polls the wrong one look correct.
//
// `npm audit signatures` failing on an empty tree is likewise emergent rather
// than scripted -- it is real npm behaviour, and it is what turned a correct
// 0.5.0 release into a reported provenance failure.
const STUB = `#!/usr/bin/env bash
set -uo pipefail
echo "$*" >> "$STUB_LOG"

# Has the published version propagated yet? Counts this probe.
probed_present() {
  local n
  n=\$(( \$(cat "\$STUB_STATE" 2>/dev/null || echo 0) + 1 ))
  echo "\$n" > "\$STUB_STATE"
  local at="\${STUB_VISIBLE_AT:-1}"
  [ "\$at" -gt 0 ] && [ "\$n" -ge "\$at" ]
}

case "\${1:-}" in
  init)
    exit 0
    ;;
  view)
    # Metadata read for the attestation document: not a propagation probe.
    if [[ "$*" == *"dist.attestations"* ]]; then
      if [ -z "\${STUB_ATTESTATIONS:-}" ]; then
        echo "npm error no attestations" >&2
        exit 1
      fi
      printf '%s' "\$STUB_ATTESTATIONS"
      exit 0
    fi
    # Likewise the tarball hash the provenance subject has to agree with.
    if [[ "$*" == *"dist.integrity"* ]]; then
      if [ -z "\${STUB_INTEGRITY:-}" ]; then
        echo "npm error no integrity" >&2
        exit 1
      fi
      printf '%s\\n' "\$STUB_INTEGRITY"
      exit 0
    fi
    if probed_present; then
      echo "0.6.0"
      exit 0
    fi
    echo "npm error code E404" >&2
    echo "npm error 404 Not Found - GET https://registry.npmjs.org/cryptoserve" >&2
    exit 1
    ;;
  install)
    if ! probed_present; then
      echo "npm error code E404" >&2
      echo "npm error 404 No matching version found for cryptoserve@0.6.0" >&2
      exit 1
    fi
    if [ "\${STUB_INSTALL_FAILS:-0}" = "1" ]; then
      echo "npm error network request failed" >&2
      exit 1
    fi
    if [ "\${STUB_INSTALL_EMPTY:-0}" != "1" ]; then
      mkdir -p "node_modules/cryptoserve"
    fi
    exit 0
    ;;
  audit)
    # Real npm: auditing a tree with nothing installed is an error, and its
    # wording is indistinguishable in a log from a signature failure.
    if [ ! -d node_modules ] || [ -z "\$(ls -A node_modules 2>/dev/null)" ]; then
      echo "npm error code EAUDITNOPJSON" >&2
      echo "npm error audit Something went wrong: found no installed dependencies to audit" >&2
      exit 1
    fi
    if [ "\${STUB_AUDIT_FAILS:-0}" = "1" ]; then
      echo "npm error 1 package has an invalid registry signature" >&2
      exit 1
    fi
    echo "1 package has a verified registry signature"
    echo "1 package has a verified attestation"
    exit 0
    ;;
  *)
    echo "stub npm: unhandled: $*" >&2
    exit 1
    ;;
esac
`;

// The attestation bundle lives behind a URL, not behind `npm`. Stubbed the same
// way so the tests can assert WHICH url the script fetched -- "went to the
// registry" is the property that makes reading an unverified document
// defensible, and it is not visible in the script's output.
const CURL_STUB = `#!/usr/bin/env bash
set -uo pipefail
echo "$*" >> "\$STUB_CURL_LOG"

# Redirects are modelled the way curl behaves, not scripted independently:
# whether the hop is taken is decided by the flags the script passed, so a
# script that asks to follow one gets to follow it.
follow=0
for a in "\$@"; do
  case "\$a" in -L|--location|--location-trusted) follow=1 ;; esac
done
if [ -n "\${STUB_REDIRECT_TO:-}" ]; then
  if [ "\$follow" = "1" ]; then
    echo "\$STUB_REDIRECT_TO" >> "\$STUB_CURL_LOG"
    printf '%s' "\${STUB_REDIRECT_BODY:-}"
    exit 0
  fi
  # An unfollowed 3xx is not an error to --fail: curl writes the short redirect
  # body and exits 0.
  printf '<html><head><title>301 Moved Permanently</title></head></html>'
  exit 0
fi

if [ -z "\${STUB_BUNDLE:-}" ]; then
  echo "curl: (22) The requested URL returned error: 404" >&2
  exit 22
fi
printf '%s' "\$STUB_BUNDLE"
`;

let sandbox;
let stubDir;
let stubLog;
let stubCurlLog;
let stubState;

before(() => {
  sandbox = mkdtempSync(join(tmpdir(), 'cryptoserve-provenance-'));
  stubDir = join(sandbox, 'bin');
  stubLog = join(sandbox, 'calls.log');
  stubCurlLog = join(sandbox, 'curl.log');
  stubState = join(sandbox, 'view-count');
  mkdirSync(stubDir, { recursive: true });
  const stubPath = join(stubDir, 'npm');
  writeFileSync(stubPath, STUB);
  chmodSync(stubPath, 0o755);
  const curlPath = join(stubDir, 'curl');
  writeFileSync(curlPath, CURL_STUB);
  chmodSync(curlPath, 0o755);
});

after(() => {
  if (sandbox && existsSync(sandbox)) rmSync(sandbox, { recursive: true, force: true });
});

/**
 * Run the script against a scripted registry. Returns the exit status, the
 * combined output, and the npm subcommands the script actually invoked.
 */
function run(scenario = {}) {
  writeFileSync(stubLog, '');
  writeFileSync(stubCurlLog, '');
  writeFileSync(stubState, '0');

  const env = {
    ...process.env,
    PATH: `${stubDir}:${process.env.PATH}`,
    STUB_LOG: stubLog,
    STUB_CURL_LOG: stubCurlLog,
    STUB_STATE: stubState,
    STUB_ATTESTATIONS: GOOD_ATTESTATIONS,
    STUB_BUNDLE: GOOD_BUNDLE,
    STUB_INTEGRITY: TARBALL_INTEGRITY,
    // Enough attempts to tolerate a slow registry, at no wall-clock cost.
    PROVENANCE_POLL_ATTEMPTS: '30',
    PROVENANCE_POLL_INTERVAL: '0',
    ...scenario,
  };
  // An explicit `undefined` in a scenario means "unset this, use the shipped
  // default" -- deleted rather than passed through, so the script's own default
  // is what runs.
  for (const [k, v] of Object.entries(env)) {
    if (v === undefined) delete env[k];
  }

  const result = spawnSync('bash', [SCRIPT, 'cryptoserve', '0.6.0'], {
    encoding: 'utf-8',
    timeout: 60000,
    env,
  });

  const calls = readFileSync(stubLog, 'utf-8').split('\n').filter(Boolean);
  const fetches = readFileSync(stubCurlLog, 'utf-8').split('\n').filter(Boolean);
  return {
    status: result.status,
    output: `${result.stdout || ''}${result.stderr || ''}`,
    calls,
    subcommands: calls.map((c) => c.split(/\s+/)[0]),
    // Every url the script asked curl for, in order.
    fetched: fetches.map((line) => line.split(/\s+/).filter((a) => !a.startsWith('-')).pop()),
  };
}

describe('verify-npm-provenance.sh', () => {
  it('passes when the version is visible immediately and provenance is good', () => {
    const { status, output } = run({ STUB_VISIBLE_AT: '1' });
    assert.equal(status, 0, output);
    assert.match(output, /Origin verified/);
  });

  it('waits out a registry that is slow to propagate', () => {
    // The 0.5.0 job gave up after 5 attempts. A version that only becomes
    // visible on the 9th must still verify: this is the exact shape that
    // reported FAILURE on a correct release.
    const { status, output, subcommands } = run({ STUB_VISIBLE_AT: '9' });
    assert.equal(status, 0, output);
    assert.match(output, /Origin verified/);

    // Keyed on metadata visibility, then installed ONCE. Retrying `npm install`
    // is what made the wait both slow and misleading.
    assert.equal(subcommands.filter((c) => c === 'install').length, 1, output);
    assert.ok(subcommands.filter((c) => c === 'view').length >= 9, output);
  });

  it('ships a wait budget of ~5 minutes, not the 100s that misreported 0.5.0', () => {
    // Every other test overrides the poll settings to stay fast, which means
    // none of them can see the SHIPPED defaults regress. This one overrides
    // neither and reads the budget the script announces, so lowering either
    // constant back towards 5x20s fails here.
    const { status, output } = run({
      STUB_VISIBLE_AT: '1',
      PROVENANCE_POLL_ATTEMPTS: undefined,
      PROVENANCE_POLL_INTERVAL: undefined,
    });
    assert.equal(status, 0, output);
    assert.match(output, /Waiting up to 290s/);
  });

  it('tolerates 20 propagation probes on the default attempt budget', () => {
    // The loose side of the same threshold: with the default attempt count and
    // no interval, a version that appears on the 20th probe must still verify.
    const { status, output } = run({
      STUB_VISIBLE_AT: '20',
      PROVENANCE_POLL_ATTEMPTS: undefined,
    });
    assert.equal(status, 0, output);
    assert.match(output, /Origin verified/);
  });

  it('refuses a poll budget it cannot act on', () => {
    // Zero attempts is not a shorter wait, it is no wait: the loop never probes
    // and the job reports a propagation failure for a release it never looked
    // at. Exit 2 (cannot run), distinct from exit 1 (verified as bad).
    for (const bad of ['0', 'abc', '-5']) {
      const { status, output, subcommands } = run({ PROVENANCE_POLL_ATTEMPTS: bad });
      assert.equal(status, 2, `PROVENANCE_POLL_ATTEMPTS=${JSON.stringify(bad)}: ${output}`);
      // Rejected before any registry call, so a bad budget cannot half-run.
      assert.equal(subcommands.length, 0, output);
    }

    // An empty value is "unset" to `${VAR:-default}`, so it takes the shipped
    // default rather than being rejected. Asserted so the distinction is
    // deliberate rather than discovered later in CI.
    const { status } = run({ STUB_VISIBLE_AT: '1', PROVENANCE_POLL_ATTEMPTS: '' });
    assert.equal(status, 0);
  });

  it('reports propagation, not provenance, when the version never appears', () => {
    const { status, output, subcommands } = run({
      STUB_VISIBLE_AT: '0',
      PROVENANCE_POLL_ATTEMPTS: '3',
    });
    assert.equal(status, 1);
    assert.match(output, /propagation or reachability/i);
    assert.match(output, /NOT a provenance failure/i);

    // The property, not the wording: a provenance verdict must never be
    // produced from a tree the script could not populate.
    assert.equal(subcommands.includes('audit'), false, output);
    assert.equal(subcommands.includes('install'), false, output);
  });

  it('does not audit an empty tree when install reports success but installs nothing', () => {
    // `npm audit signatures` on an empty tree exits non-zero with "found no
    // installed dependencies to audit", which reads in a log as a signature
    // failure. That is what the 0.5.0 release actually reported.
    const { status, output, subcommands } = run({
      STUB_VISIBLE_AT: '1',
      STUB_INSTALL_EMPTY: '1',
    });
    assert.equal(status, 1);
    assert.equal(subcommands.includes('audit'), false, output);
    assert.match(output, /node_modules\/cryptoserve is not there/);
  });

  it('separates an install failure from a provenance failure', () => {
    const { status, output, subcommands } = run({
      STUB_VISIBLE_AT: '1',
      STUB_INSTALL_FAILS: '1',
    });
    assert.equal(status, 1);
    assert.match(output, /NOT a provenance failure/i);
    assert.equal(subcommands.includes('audit'), false, output);
  });

  it('still fails loudly when the signature does not verify', () => {
    // The case the job exists for. None of the waiting above may soften it.
    const { status, output } = run({
      STUB_VISIBLE_AT: '1',
      STUB_AUDIT_FAILS: '1',
    });
    assert.equal(status, 1);
    assert.match(output, /failed signature\/provenance verification/i);
    assert.doesNotMatch(output, /NOT a provenance failure/i);
  });

  it('fails when the published version carries no attestations', () => {
    const { status, output } = run({
      STUB_VISIBLE_AT: '1',
      STUB_ATTESTATIONS: '',
    });
    assert.equal(status, 1);
    assert.match(output, /no dist\.attestations/i);
  });

  it('fails when the attestation is not a SLSA provenance type', () => {
    // A signed-but-not-provenanced package passes `npm audit signatures`.
    const { status, output } = run({
      STUB_VISIBLE_AT: '1',
      STUB_ATTESTATIONS: JSON.stringify({
        provenance: { predicateType: 'https://example.invalid/attestation/v1' },
      }),
    });
    assert.equal(status, 1);
    assert.match(output, /not a SLSA provenance type/i);
  });
});

/**
 * `npm audit signatures` answers "is this attestation valid and trusted". It
 * does not answer "is it ours", and the job printed a line that read as if it
 * had. Every scenario below is a package with a perfectly good signature and a
 * perfectly good SLSA predicate type, differing from ours only in what the
 * provenance SAYS -- which is exactly the input the old check could not fail on.
 */
describe('verify-npm-provenance.sh origin assertions', () => {
  const ok = { STUB_VISIBLE_AT: '1' };

  /**
   * Refused, and said so. This job's design is that its log never has to be
   * interpreted, so a malformed attestation has to produce a `::error::` line
   * rather than a node stack trace: both exit 1, and only one of them tells a
   * release engineer what happened. Asserting the exit status alone cannot tell
   * a guard from a crash, which is how an untested guard survived here.
   */
  function assertRefused({ status, output }, ctx) {
    assert.equal(status, 1, `${ctx}: ${output}`);
    assert.match(output, /::error::/, `${ctx}: no ::error:: line: ${output}`);
    assert.doesNotMatch(output, /^\s+at /m, `${ctx}: crashed instead of refusing: ${output}`);
    assert.doesNotMatch(output, /Origin verified/, `${ctx}: ${output}`);
  }

  it('accepts provenance naming this repository, workflow and tag', () => {
    const { status, output, fetched } = run(ok);
    assert.equal(status, 0, output);

    // Named, not merely "verified": the success line has to be as narrow as
    // the check behind it.
    assert.match(output, /Origin verified/);
    assert.ok(output.includes(EXPECTED_REPOSITORY), output);
    assert.ok(output.includes(EXPECTED_WORKFLOW), output);
    assert.ok(output.includes(EXPECTED_REF), output);

    // Read from the registry's own attestation endpoint, taken from the
    // metadata rather than assembled here.
    assert.deepEqual(fetched, [ATTESTATION_URL], output);
  });

  it('rejects a valid attestation built in a different repository', () => {
    const { status, output } = run({
      ...ok,
      STUB_BUNDLE: bundleDoc({ repository: 'https://github.com/attacker/cryptoserve' }),
    });
    assert.equal(status, 1, output);
    assert.match(output, /repository/i);
    assert.ok(output.includes('https://github.com/attacker/cryptoserve'), output);
    assert.doesNotMatch(output, /Origin verified/);
  });

  it('rejects a valid attestation built by a different workflow in this repository', () => {
    // Trusted Publishing is keyed to a workflow FILENAME. Any other workflow in
    // the same repo that gains id-token: write can publish, and its attestation
    // is as valid as ours.
    const { status, output } = run({
      ...ok,
      STUB_BUNDLE: bundleDoc({ path: '.github/workflows/ci.yml' }),
    });
    assert.equal(status, 1, output);
    assert.ok(output.includes('.github/workflows/ci.yml'), output);
    assert.doesNotMatch(output, /Origin verified/);
  });

  it('rejects a publish that did not come from this version\'s release tag', () => {
    // A branch publish and a stale tag are the same defect: the artifact on the
    // registry is not the thing the tag says it is.
    for (const ref of ['refs/heads/main', 'refs/tags/js-v0.5.0', 'refs/pull/12/merge']) {
      const { status, output } = run({ ...ok, STUB_BUNDLE: bundleDoc({ ref }) });
      assert.equal(status, 1, `ref=${ref}: ${output}`);
      assert.ok(output.includes(ref), output);
      assert.doesNotMatch(output, /Origin verified/);
    }
  });

  it('rejects provenance that names a different package or version', () => {
    for (const subjectName of ['pkg:npm/cryptoserve-cli@0.6.0', 'pkg:npm/cryptoserve@0.5.0']) {
      const { status, output } = run({ ...ok, STUB_BUNDLE: bundleDoc({ subjectName }) });
      assert.equal(status, 1, `subject=${subjectName}: ${output}`);
      assert.match(output, /pkg:npm\/cryptoserve@0\.6\.0/);
      assert.doesNotMatch(output, /Origin verified/);
    }
  });

  it('rejects provenance whose subject is not the tarball that was published', () => {
    // The name can be right while the digest describes something else. Binding
    // to `dist.integrity` is what ties these claims to the artifact
    // `npm audit signatures` actually verified, rather than to a document that
    // merely mentions our name.
    const { status, output } = run({
      ...ok,
      STUB_BUNDLE: bundleDoc({ subjectDigest: 'b'.repeat(128) }),
    });
    assert.equal(status, 1, output);
    assert.match(output, /different artifact|digest/i);
    assert.doesNotMatch(output, /Origin verified/);
  });

  it('fails when the bundle carries no SLSA provenance attestation', () => {
    const { status, output } = run({ ...ok, STUB_BUNDLE: bundleDoc({ omitProvenance: true }) });
    assert.equal(status, 1, output);
    assert.match(output, /no SLSA provenance/i);

    // Naming what it did find proves the list was searched rather than indexed:
    // the registry puts the publish receipt at [0] and the provenance at [1],
    // so a script reading attestations[0] would report this same absence on a
    // correct release.
    assert.ok(output.includes('https://github.com/npm/attestation/tree/main/specs/publish/v0.1'), output);
  });

  it('fails closed when the bundle cannot be fetched', () => {
    const result = run({ ...ok, STUB_BUNDLE: '' });
    assertRefused(result, 'unfetchable bundle');
    assert.match(result.output, /attestation bundle/i);
  });

  it('fails closed on a bundle it cannot parse', () => {
    for (const body of ['<html>502 Bad Gateway</html>', '', 'null', '{}', '{"attestations":[]}']) {
      // An empty STUB_BUNDLE means "curl failed", covered above; use a blank
      // JSON body for the empty-document case instead.
      const bundle = body === '' ? '   ' : body;
      assertRefused(run({ ...ok, STUB_BUNDLE: bundle }), `body=${JSON.stringify(body)}`);
    }
  });

  it('fails closed when the signed payload is not readable in-toto JSON', () => {
    const cases = [
      { payload: Buffer.from('not json', 'utf-8').toString('base64') },
      { payload: '!!!! not base64 !!!!' },
      { payloadType: 'application/octet-stream' },
    ];
    for (const c of cases) {
      assertRefused(run({ ...ok, STUB_BUNDLE: bundleDoc(c) }), JSON.stringify(c));
    }
  });

  it('trusts the predicate type inside the signature, not the one beside it', () => {
    // The entry's predicateType is registry metadata sitting OUTSIDE the DSSE
    // envelope. Believing it over the signed statement would let an unsigned
    // label decide which document gets read as provenance.
    const { status, output } = run({
      ...ok,
      STUB_BUNDLE: bundleDoc({ innerPredicateType: 'https://example.invalid/attestation/v1' }),
    });
    assert.equal(status, 1, output);
    assert.match(output, /signed statement/i);
  });

  it('fails closed when the workflow claims are absent or not strings', () => {
    const cases = [
      { workflow: null },
      { workflow: {} },
      { workflow: { repository: EXPECTED_REPOSITORY, path: EXPECTED_WORKFLOW } },
      { workflow: { repository: 123, path: EXPECTED_WORKFLOW, ref: EXPECTED_REF } },
      { workflow: 'https://github.com/ecolibria/cryptoserve' },
    ];
    for (const c of cases) {
      assertRefused(run({ ...ok, STUB_BUNDLE: bundleDoc(c) }), JSON.stringify(c));
    }
  });

  it('fails closed when dist.attestations carries no bundle url', () => {
    const { status, output, fetched } = run({
      ...ok,
      STUB_ATTESTATIONS: JSON.stringify({
        provenance: { predicateType: 'https://slsa.dev/provenance/v1' },
      }),
    });
    assert.equal(status, 1, output);
    assert.match(output, /url/i);
    assert.deepEqual(fetched, [], output);
  });

  it('refuses a bundle url that is not on the npm registry', () => {
    // The bundle is parsed, not signature-checked -- `npm audit signatures` did
    // that, against the registry. Reading build claims off an arbitrary host
    // would put the origin verdict in the hands of whoever answers that url.
    const { status, output, fetched } = run({
      ...ok,
      STUB_ATTESTATIONS: JSON.stringify({
        url: 'https://registry.npmjs.org.attacker.example/attestations/cryptoserve@0.6.0',
        provenance: { predicateType: 'https://slsa.dev/provenance/v1' },
      }),
    });
    assert.equal(status, 1, output);
    assert.deepEqual(fetched, [], output);
  });

  it('does not follow a redirect that leaves the registry', () => {
    // The host pin is checked against the url the metadata NAMED. Following a
    // redirect makes the url that was checked and the url that answers two
    // different urls, and the second one was never checked. The body served
    // from off-registry here is a perfectly good bundle naming this repository,
    // so following the hop would produce a PASS from a host we never verified.
    const result = run({
      ...ok,
      STUB_REDIRECT_TO: 'https://cdn.evil.example/attestations/cryptoserve@0.6.0',
      STUB_REDIRECT_BODY: GOOD_BUNDLE,
    });
    assertRefused(result, 'off-registry redirect');
    assert.deepEqual(result.fetched, [ATTESTATION_URL], result.output);
  });

  it('fails closed when the published tarball hash cannot be read', () => {
    const { status, output } = run({ ...ok, STUB_INTEGRITY: '' });
    assert.equal(status, 1, output);
    assert.doesNotMatch(output, /Origin verified/);
  });
});
