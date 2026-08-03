#!/usr/bin/env bash
#
# Verify that a published npm version carries a registry signature and a SLSA
# provenance attestation.
#
#     verify-npm-provenance.sh <package> <version>
#
# Exits 0 only when both are present and verified.
#
# Why this is a script rather than an inline `run:` block: the 0.5.0 release
# reported FAILURE here while having published correctly, WITH correct
# provenance (`predicateType https://slsa.dev/provenance/v1`, verified by hand
# afterwards). The job waited five attempts at 20s for `npm install` to succeed,
# npm had not yet finished making the version installable, and
# `npm audit signatures` then ran against an empty tree and errored with
# "found no installed dependencies to audit". Registry propagation was reported
# as absent provenance.
#
# A release that publishes correctly and reports failure trains people to ignore
# the check, which is worse than not having one. Two things follow:
#
#   1. The wait is on registry METADATA, which is the thing that propagates, and
#      the budget is minutes rather than 100 seconds. `publish` is a prerequisite
#      of this job, so the version does exist; only its visibility is in question.
#      The install then happens once.
#   2. `npm audit signatures` is unreachable unless the package is actually in
#      node_modules. An empty tree must not be able to produce a provenance
#      verdict, in either direction.
#
# None of that softens the case the job exists for: a missing, malformed or
# untrusted attestation still fails, loudly, and says so in those words. Every
# other failure path says explicitly that it is NOT a provenance failure, so the
# log never has to be interpreted.

set -euo pipefail

PKG="${1:?usage: verify-npm-provenance.sh <package> <version>}"
VERSION="${2:?usage: verify-npm-provenance.sh <package> <version>}"

# Overridable so the regression test drives the same code path without sleeping.
# CI uses the defaults: 30 attempts at 10s is a ~4.8 minute budget.
POLL_ATTEMPTS="${PROVENANCE_POLL_ATTEMPTS:-30}"
POLL_INTERVAL="${PROVENANCE_POLL_INTERVAL:-10}"

# A budget this job cannot act on is not a shorter wait, it is no wait: at zero
# attempts the loop never probes, `visible` stays false, and the job reports a
# propagation failure for a release it never looked at. Same shape as the
# `--min-score abc` fail-open fixed in 0.5.0, so it is rejected the same way.
case "$POLL_ATTEMPTS" in
  ''|*[!0-9]*) echo "::error::PROVENANCE_POLL_ATTEMPTS must be a positive integer, got '$POLL_ATTEMPTS'." >&2; exit 2 ;;
esac
case "$POLL_INTERVAL" in
  ''|*[!0-9]*) echo "::error::PROVENANCE_POLL_INTERVAL must be a non-negative integer, got '$POLL_INTERVAL'." >&2; exit 2 ;;
esac
if [ "$POLL_ATTEMPTS" -lt 1 ]; then
  echo "::error::PROVENANCE_POLL_ATTEMPTS must be at least 1, got '$POLL_ATTEMPTS'." >&2
  exit 2
fi

WORKDIR="$(mktemp -d)"
cd "$WORKDIR"
npm init -y >/dev/null 2>&1

# Announced before the first probe, and asserted by the regression test: the
# budget is the whole point of this job's fix, so it is stated rather than
# implied by two constants a reader has to multiply.
echo "Waiting up to $(( (POLL_ATTEMPTS - 1) * POLL_INTERVAL ))s for $PKG@$VERSION to become visible on the registry..."
visible=false
attempt=1
while [ "$attempt" -le "$POLL_ATTEMPTS" ]; do
  # --prefer-online: a 404 cached from an earlier attempt must not be replayed
  # from the local cache for the rest of the poll, which would make the wait
  # unable to observe the propagation it is waiting for.
  if npm view --prefer-online "$PKG@$VERSION" version >/dev/null 2>&1; then
    visible=true
    echo "Visible on the registry (attempt $attempt)."
    break
  fi
  if [ "$attempt" -lt "$POLL_ATTEMPTS" ]; then
    echo "Not visible yet (attempt $attempt/$POLL_ATTEMPTS); waiting ${POLL_INTERVAL}s for propagation..."
    sleep "$POLL_INTERVAL"
  fi
  attempt=$((attempt + 1))
done

if [ "$visible" != true ]; then
  echo "::error::$PKG@$VERSION did not become visible on the registry within $(( (POLL_ATTEMPTS - 1) * POLL_INTERVAL ))s."
  echo "::error::This is registry propagation or reachability, NOT a provenance failure."
  echo "::error::The publish job already succeeded. Before assuming the release is bad, check by hand:"
  echo "::error::  npm view $PKG@$VERSION dist.attestations --json"
  exit 1
fi

if ! npm install --no-audit --no-fund "$PKG@$VERSION"; then
  echo "::error::$PKG@$VERSION is on the registry but could not be installed."
  echo "::error::This is an install failure, NOT a provenance failure."
  exit 1
fi

# `npm audit signatures` against a tree with nothing installed exits non-zero
# with "found no installed dependencies to audit". In a log that is
# indistinguishable from a real signature failure, and it is precisely what the
# 0.5.0 release reported. Assert the artifact is present, so the verdict below
# can only be about the artifact this job means to verify.
if [ ! -d "node_modules/$PKG" ]; then
  echo "::error::npm install reported success but node_modules/$PKG is not there."
  echo "::error::Refusing to run 'npm audit signatures' against an empty tree: it would fail"
  echo "::error::with 'no installed dependencies to audit' and read as a provenance failure."
  exit 1
fi

# Cryptographically verifies the registry signature and the provenance
# attestation against npm's public keys. Grepping the metadata blob for the
# string "slsa" would only prove a word appears in some JSON: a descriptor is
# not a signature, and a check that cannot fail on a forged input is not a check.
if ! npm audit signatures; then
  echo "::error::$PKG@$VERSION failed signature/provenance verification."
  echo "::error::Check Trusted Publishing: npm trust list $PKG"
  exit 1
fi

# `audit signatures` also passes for a package that is merely signed, so assert
# the provenance attestation exists and carries a SLSA predicate type in the
# field that defines it, not anywhere in the document.
npm view "$PKG@$VERSION" dist.attestations --json > att.json || true
node -e '
  const fs = require("fs");
  let a = null;
  try { a = JSON.parse(fs.readFileSync("att.json", "utf8") || "null"); } catch {}
  if (!a) {
    console.error("::error::no dist.attestations on the published version");
    process.exit(1);
  }
  const pt = a && a.provenance && a.provenance.predicateType;
  if (typeof pt !== "string" || !pt.startsWith("https://slsa.dev/provenance/")) {
    console.error("::error::provenance.predicateType is not a SLSA provenance type: " + JSON.stringify(pt));
    process.exit(1);
  }
  console.log("Provenance verified: " + pt);
'

echo "$PKG@$VERSION: signature and SLSA provenance verified."
