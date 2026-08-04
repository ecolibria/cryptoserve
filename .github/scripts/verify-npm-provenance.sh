#!/usr/bin/env bash
#
# Verify that a published npm version carries a registry signature and a SLSA
# provenance attestation, and that the provenance names THIS repository's
# release workflow at the tag being released.
#
#     verify-npm-provenance.sh <package> <version>
#
# Exits 0 only when all of that holds.
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

# Constants of THIS repository's release path, deliberately not overridable.
# An expectation that can be relaxed by the environment is an off switch, and
# the only caller is the verify-provenance job in publish-npm.yml.
#
# The tag shape mirrors verify-tag in that workflow, which already refuses to
# publish unless `js-v<version>` agrees with sdk/javascript/package.json. Here
# it does the other half: the artifact ON THE REGISTRY has to have been built
# from that same tag, not from a branch and not from some other version's tag.
EXPECTED_REPOSITORY="https://github.com/ecolibria/cryptoserve"
EXPECTED_WORKFLOW=".github/workflows/publish-npm.yml"
EXPECTED_REF="refs/tags/js-v$VERSION"
EXPECTED_SUBJECT="pkg:npm/$PKG@$VERSION"

if ! command -v curl >/dev/null 2>&1; then
  echo "::error::curl is required to fetch the attestation bundle and is not on PATH." >&2
  echo "::error::This is a runner configuration failure, NOT a provenance failure." >&2
  exit 2
fi

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
  console.log("Attestation predicate type: " + pt);
'

# ---------------------------------------------------------------------------
# Origin.
#
# Everything above establishes that the attestation is VALID and TRUSTED. None
# of it establishes that it is OURS. `npm audit signatures` verifies the
# signature chain against npm's public keys, which a package published from any
# other repository by any other workflow also satisfies, and `predicateType`
# says what KIND of document this is, not what the document says. The old
# success line, "signature and SLSA provenance verified", read as a statement
# about origin and was not one.
#
# The claims that identify the build are inside the attestation bundle, which
# `npm view dist.attestations` only links to. Fetch it and assert the four
# fields that make "ours" checkable: repository, workflow path, ref, subject.
#
# What this deliberately does NOT do is re-verify the bundle's Sigstore
# signature. `npm audit signatures` above already did that, over the tarball
# whose hash is `dist.integrity`. Re-implementing Sigstore verification in bash
# would be a second, worse copy of a check that already ran. Two things keep
# reading this document honest instead:
#
#   1. It is fetched from the registry itself, not from a url an attacker could
#      point elsewhere -- asserted below before the fetch happens.
#   2. Its subject digest must equal `dist.integrity`, so the origin claims
#      describe the exact artifact npm verified, not merely an artifact.
# ---------------------------------------------------------------------------

ATT_URL="$(node -e '
  const fs = require("fs");
  let a = null;
  try { a = JSON.parse(fs.readFileSync("att.json", "utf8") || "null"); } catch {}
  const u = a && a.url;
  if (typeof u !== "string" || u === "") {
    console.error("::error::dist.attestations carries no bundle url; cannot check where this was built.");
    process.exit(1);
  }
  process.stdout.write(u);
')"

case "$ATT_URL" in
  https://registry.npmjs.org/*) ;;
  *)
    echo "::error::attestation bundle url is not on registry.npmjs.org: $ATT_URL" >&2
    echo "::error::The build claims below are read from that document without re-checking its" >&2
    echo "::error::signature, so it has to come from the registry npm just verified against." >&2
    exit 1
    ;;
esac

# No --location on purpose. Following redirects would hand the check straight
# back to whoever the registry redirects to, which is the host pin above
# undone by a 301: the url that was checked and the url that answers stop being
# the same url. The endpoint answers 200 directly, so there is nothing to follow.
if ! curl --silent --show-error --fail --max-time 60 "$ATT_URL" > bundle.json; then
  echo "::error::could not fetch the attestation bundle from $ATT_URL." >&2
  echo "::error::The attestation exists but its contents could not be read, so where this was" >&2
  echo "::error::built is unknown. Refusing to report it as verified." >&2
  exit 1
fi

# The published tarball hash, to bind the provenance subject to it.
if ! npm view "$PKG@$VERSION" dist.integrity > integrity.txt; then
  echo "::error::could not read dist.integrity for $PKG@$VERSION." >&2
  echo "::error::Without it the provenance subject cannot be tied to the published tarball." >&2
  exit 1
fi

EXPECTED_REPOSITORY="$EXPECTED_REPOSITORY" \
EXPECTED_WORKFLOW="$EXPECTED_WORKFLOW" \
EXPECTED_REF="$EXPECTED_REF" \
EXPECTED_SUBJECT="$EXPECTED_SUBJECT" \
node -e '
  const fs = require("fs");
  const fail = (...lines) => {
    for (const l of lines) console.error("::error::" + l);
    process.exit(1);
  };

  let doc;
  try {
    doc = JSON.parse(fs.readFileSync("bundle.json", "utf8") || "null");
  } catch (e) {
    fail("attestation bundle is not readable JSON: " + e.message);
  }
  const list = doc && doc.attestations;
  if (!Array.isArray(list) || list.length === 0) {
    fail("attestation bundle carries no attestations.");
  }

  // The registry serves the npm publish receipt first and the provenance
  // second. Search by type; attestations[0] is the receipt, which carries no
  // build claims at all.
  const entry = list.find((a) => a && typeof a.predicateType === "string"
    && a.predicateType.startsWith("https://slsa.dev/provenance/"));
  if (!entry) {
    fail("attestation bundle carries no SLSA provenance attestation.",
      "types present: " + list.map((a) => (a && a.predicateType) || "(untyped)").join(", "));
  }

  const env = entry.bundle && entry.bundle.dsseEnvelope;
  if (!env || typeof env.payload !== "string" || env.payload === "") {
    fail("SLSA attestation carries no dsseEnvelope payload.");
  }
  if (env.payloadType !== "application/vnd.in-toto+json") {
    fail("SLSA attestation payloadType is not in-toto: " + JSON.stringify(env.payloadType));
  }

  let stmt;
  try {
    // Buffer.from drops invalid base64 rather than throwing, so the parse below
    // is what actually rejects a corrupt payload.
    stmt = JSON.parse(Buffer.from(env.payload, "base64").toString("utf8"));
  } catch (e) {
    fail("SLSA attestation payload is not base64-encoded JSON: " + e.message);
  }
  if (!stmt || typeof stmt !== "object") {
    fail("SLSA attestation payload did not decode to an in-toto statement.");
  }

  // The entry predicateType sits OUTSIDE the envelope and nothing signed it.
  // The one that decides whether this document is provenance is the one inside.
  if (typeof stmt.predicateType !== "string"
    || !stmt.predicateType.startsWith("https://slsa.dev/provenance/")) {
    fail("signed statement is not SLSA provenance: " + JSON.stringify(stmt.predicateType),
      "the entry outside the signature claimed " + JSON.stringify(entry.predicateType) + ".");
  }

  const wantSubject = process.env.EXPECTED_SUBJECT;
  const subjects = Array.isArray(stmt.subject) ? stmt.subject : [];
  const subject = subjects.find((s) => s && s.name === wantSubject);
  if (!subject) {
    fail("provenance does not name " + wantSubject + ".",
      "subjects: " + JSON.stringify(subjects.map((s) => (s && s.name) || null)));
  }

  // Name is not identity: bind to the tarball npm verified the signature over.
  const integrity = fs.readFileSync("integrity.txt", "utf8").trim();
  const sri = /^sha512-(.+)$/.exec(integrity);
  if (!sri) {
    fail("dist.integrity is not a sha512 SRI value: " + JSON.stringify(integrity));
  }
  const published = Buffer.from(sri[1], "base64").toString("hex");
  const attested = subject.digest && subject.digest.sha512;
  if (typeof attested !== "string") {
    fail("provenance subject " + wantSubject + " carries no sha512 digest.");
  }
  if (attested.toLowerCase() !== published) {
    fail("provenance describes a different artifact than the one published.",
      "subject sha512:  " + attested,
      "published tarball: " + published);
  }

  const bd = stmt.predicate && stmt.predicate.buildDefinition;
  const wf = bd && bd.externalParameters && bd.externalParameters.workflow;
  if (!wf || typeof wf !== "object" || Array.isArray(wf)) {
    fail("provenance carries no buildDefinition.externalParameters.workflow; "
      + "there is nothing in it that says where this was built.");
  }

  for (const [field, expected] of [
    ["repository", process.env.EXPECTED_REPOSITORY],
    ["path", process.env.EXPECTED_WORKFLOW],
    ["ref", process.env.EXPECTED_REF],
  ]) {
    // No separate "is it a string" guard: `expected` is always a string and the
    // comparison is strict, so a missing, numeric or object value fails here
    // too, and JSON.stringify makes it visible in the message. A guard no input
    // can reach is not defence in depth, it is a line that cannot be tested --
    // mutation testing reported exactly that one as a survivor.
    const got = wf[field];
    if (got !== expected) {
      fail("provenance workflow." + field + " is " + JSON.stringify(got)
        + ", expected " + JSON.stringify(expected) + ".",
        "The attestation is valid and trusted. It is not from this release.");
    }
  }

  console.log("Origin verified: " + wantSubject + " was built by " + wf.path
    + " in " + wf.repository + " at " + wf.ref + ".");
'

echo "$PKG@$VERSION: npm verified the registry signature and attestation; the SLSA"
echo "provenance names $EXPECTED_REPOSITORY, $EXPECTED_WORKFLOW and $EXPECTED_REF,"
echo "over the tarball that was published."
