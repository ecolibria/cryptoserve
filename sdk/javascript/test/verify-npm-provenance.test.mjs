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

const GOOD_ATTESTATIONS = JSON.stringify({
  provenance: { predicateType: 'https://slsa.dev/provenance/v1' },
});

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

let sandbox;
let stubDir;
let stubLog;
let stubState;

before(() => {
  sandbox = mkdtempSync(join(tmpdir(), 'cryptoserve-provenance-'));
  stubDir = join(sandbox, 'bin');
  stubLog = join(sandbox, 'calls.log');
  stubState = join(sandbox, 'view-count');
  mkdirSync(stubDir, { recursive: true });
  const stubPath = join(stubDir, 'npm');
  writeFileSync(stubPath, STUB);
  chmodSync(stubPath, 0o755);
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
  writeFileSync(stubState, '0');

  const env = {
    ...process.env,
    PATH: `${stubDir}:${process.env.PATH}`,
    STUB_LOG: stubLog,
    STUB_STATE: stubState,
    STUB_ATTESTATIONS: GOOD_ATTESTATIONS,
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
  return {
    status: result.status,
    output: `${result.stdout || ''}${result.stderr || ''}`,
    calls,
    subcommands: calls.map((c) => c.split(/\s+/)[0]),
  };
}

describe('verify-npm-provenance.sh', () => {
  it('passes when the version is visible immediately and provenance is good', () => {
    const { status, output } = run({ STUB_VISIBLE_AT: '1' });
    assert.equal(status, 0, output);
    assert.match(output, /Provenance verified: https:\/\/slsa\.dev\/provenance\/v1/);
  });

  it('waits out a registry that is slow to propagate', () => {
    // The 0.5.0 job gave up after 5 attempts. A version that only becomes
    // visible on the 9th must still verify: this is the exact shape that
    // reported FAILURE on a correct release.
    const { status, output, subcommands } = run({ STUB_VISIBLE_AT: '9' });
    assert.equal(status, 0, output);
    assert.match(output, /Provenance verified/);

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
    assert.match(output, /Provenance verified/);
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
