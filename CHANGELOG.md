# Changelog

All notable changes to CryptoServe will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

A per-finding waiver, written as a comment next to the code it covers:

```js
// cryptoserve-ignore misuse/tls-verify-disabled -- local test server, self-signed cert
const agent = new https.Agent({ rejectUnauthorized: false });
```

Until now a false `critical` could not be cleared at all. `--max-severity` only
tightens and refuses `high`/`critical` by name, `--allow-secrets` does not reach
misuse, and `.cryptoserve.json` offers only `skipDirs`, which excludes a whole
directory to silence one line. A tool whose false positives are unresolvable
gets excluded entirely, so the absence of this was itself a security defect.

Every misuse rule now carries a stable id (`misuse/create-cipher`,
`misuse/node-tls-reject-unauthorized`, and so on) which is what a pragma names.
The ids are part of the CLI's contract with your source tree and will not be
renamed.

A waiver is a security control's off switch, so it is deliberately narrow:

- **A reason is required.** It is the only part a reviewer can disagree with.
  A pragma without one waives nothing and is reported as malformed.
- **It must be the first thing in the comment**, the same rule
  `eslint-disable` uses. Prose that merely mentions a pragma is not one. Put a
  pragma on its own line ABOVE the finding whenever the finding's line already
  contains a comment opener; see "What a waiver deliberately is not" below.
- **It must be plain text, in a file whose lines have endings.** A pragma
  carrying a control character, or a bidi override or isolate (U+202A-U+202E,
  U+2066-U+2069), is reported as malformed and waives nothing. Both families
  let file content decide how the report RENDERS rather than what it says: an
  escape sequence erases the line the scanner just wrote, and a right-to-left
  override reverses the display order of everything after it, so the reason a
  reviewer reads stops being the reason the file holds. The plain direction
  marks U+200E and U+200F are allowed, and so are ordinary Hebrew and Arabic
  letters, which carry their own direction; refusing a whole language to close a
  spoofing shape would be the wrong trade. The same characters are stripped from
  a finding's `evidence`, which is matched source text and reaches
  `--format json` through a different field. The
  line-ending question is decided once for the whole FILE: a file holding any
  terminator the newline split does not split on (CR, VT, FF, NEL, U+2028,
  U+2029) honours no pragma anywhere in it, and reports the line that carries
  it. Asked per line it could only ever inspect the pragma's OWN line, which
  left a terminator one line below free to collapse the rest of the file into
  the pragma's reach. Measured over 47,486 source files in 258 trees, 7 hold
  such a terminator and all 7 are minified build output or a fixture that
  embeds one deliberately.
- **It waives one rule on one line**, its own or the one below. There is no
  wildcard, and a rule id that no rule uses is reported rather than ignored.
  A finding's line is where its match starts, so a match that runs over
  several lines, such as a `checkServerIdentity` override with a long
  parameter list, is covered whole by a pragma above its first line
  ([#74](https://github.com/ecolibria/cryptoserve/issues/74)).
- **The rule id and reason it reports are capped**, at 80 and 200 characters,
  as a finding's `evidence` and a malformed pragma's quoted text are. Both
  reach the terminal, `--format json` and SARIF, and one pragma could
  otherwise put 200,000 characters in each
  ([#74](https://github.com/ecolibria/cryptoserve/issues/74)).
- **Nothing is silently dropped.** Waived findings are listed by `scan` and by
  `gate` with the reason given, counted in `gate --format json` as
  `summary.waived`, and emitted in SARIF as suppressed results, which code
  scanning renders as dismissed alerts rather than as absent ones.
- **A waiver cannot hide the next finding.** Misuse patterns report only the
  first match per pattern per file, so the scan deliberately keeps reading past
  a waived match. Without that, one pragma at the top of a file would suppress
  every later occurrence of the same rule in it.

`scan` and `gate` also report pragmas that are malformed, name a rule that does
not exist, or covered no finding. A stale waiver is suppression with nothing
under it, and the next real finding on that line would land under it silently.

**Detection is unchanged by this release.** Verified finding-for-finding against
0.6.0 across 22 trees and 10,680 source files, third-party `node_modules` and
minified bundles included: same misuse findings, same lines, same evidence,
nothing added and nothing removed. The only new behaviour is that a finding you
have explicitly waived stops failing the gate.

#### What a waiver deliberately is not

Recognising a comment by its opener is a heuristic, not a parse. The scanner
does not tokenize your source, so a string literal that both begins with a
comment opener and ends the line with pragma text would be honoured.

For the same reason, a pragma that is not the first thing in its comment is
ignored **in silence**. A line that opened a comment earlier gives its first
opener to that comment, so a pragma appended to it is text rather than an
instruction:

```js
const u = "http://x";   // cryptoserve-ignore misuse/create-cipher -- ignored
```

Telling that apart from documentation that quotes a rule id needs to know where
the comment really begins, which is the same parse. A version that guessed it by
re-walking the line shipped in neither release: it was quadratic in the length of
the line, so a 200KB single line took 42 seconds through a `gate` that has no
timeout, and it reported prose as a broken waiver. Put the pragma on its own line
above the finding and the question does not arise. A waiver that IS honoured but
covers nothing is still reported, as `unused`.

That residual is acceptable because of who a waiver is for. It is authored by
whoever can already edit the file, so it is not a privilege boundary: anyone
able to smuggle a pragma through a string could simply write the comment. It is
also bounded by where the scanner looks: `node_modules`, `vendor`, `.venv` and
`venv` are skipped by default, so this is first-party code, not a dependency's.

The property being defended is narrower than "data a project merely CONTAINS
does not switch a check off", which is how earlier drafts of this entry put it.
Two versions of that stronger claim were each disproved during review. First a
Python docstring: the block-comment continuation branch ran without consulting
the language's comment openers, and `*` is not a comment character in Python at
all. Gating that branch produced the second version, "a language with no block
comments cannot have its checks operated by contained data at all", and an
ordinary Python STRING disproved that too, because the first-opener scan reaches
every language whatever its comment style:

```python
SETUP = "https://vendor.example/tls/setup#cryptoserve-ignore misuse/python-cert-none -- documented"
ctx.verify_mode = ssl.CERT_NONE
```

Requiring a comment opener produced a third version, and a Go raw string
disproved that one too: the block-comment continuation branch needs no opener on
the line at all, so ` * cryptoserve-ignore ...` inside any multi-line string
reaches it, in any language whose comment syntax has block comments.

What holds, and all that holds: **data a project merely contains CAN operate this
control, in any of the six languages, and can never do so silently.** A waived
finding is listed by `scan` and `gate`, counted in `gate --format json` as
`summary.waived`, and emitted to SARIF as a suppressed result. Each measured
shape is pinned by a test in `test/waivers.test.mjs`.

The qualifier is gone deliberately. Every bounded version of this claim was
written just after closing the previous example and described that example
rather than the mechanism. What makes the residual acceptable is who a waiver is
for: it is authored by whoever can already edit the file, so it is not a
privilege boundary, and anyone able to smuggle a pragma through a string could
simply write the comment instead.

Doing better needs a real parser per language, which this package cannot have
while it stays dependency-free. A hand-written comment tokenizer was built for
this release and then removed: adversarial review measured it mis-reading
ordinary JSX and minified bundles badly enough to LOSE real findings, including
57% of a 174KB bundle shipped inside a real PyPI package. For a security
scanner, a false negative on a third-party file is worse than the false positive
it was meant to fix.

### Changed

Every compose file sets container log rotation: 50 MB per file, 5 files, for each service.

### Fixed

The request log records the names of query parameters and not their values.

`cryptoserve login` listens on 127.0.0.1 only and stores a token only from the callback that carries the state value it issued.

The Python CLI login accepts a callback only when it carries the per-login state the CLI issued.
The server's CLI login routes (`/auth/login/<provider>`, `/auth/github`,
`/auth/dev-login`) return the `state` a CLI sends alongside `cli_callback` on
the redirect to the callback, so the Python CLI's browser login needs a server
with this change; `login --cookie` works with any server.

The Python CLI's `backup`, `restore`, `backups` and `ceremony` commands send the
session that `login` stored in the `access_token` cookie, which is where the
server reads it. They sent it in a cookie named `session`, which the server does
not read, so it treated their requests as not signed in: right after a
successful `login`, `backups` and `ceremony status` printed `Session expired.
Please login again.` and exited 1.

The `vault delete` command that `vault list` and `vault run` print for an entry
that is not a secret now removes it when the entry's name starts with `-`
([#112](https://github.com/ecolibria/cryptoserve/issues/112)). For the entry
`--verbose`, the printed `cryptoserve vault delete '--verbose'` printed `Usage:
vault delete KEY` and exited `2`, and for `--password` it stopped with `Error:
--password was given more than once.` The vault commands now read an argument
after the first `--` as a name, a value or part of the command `vault run`
starts, not as an option, and the printed command puts `--` before such a
name, as in `cryptoserve vault delete -- '--verbose'`. With the password given
before `--`, that command removes the entries `--verbose`, `--`, `--password`,
`--help` and `-h`. `vault delete` given more than one name after `--`, as in
`vault delete -- '--verbose' --password P`, prints `Error: vault delete takes
one name after --; put options such as --password before --.` and exits `2`
before asking for the password. `vault run --password P -- CMD --help
--password x` now passes `--help --password x` to the command, where it printed
the vault help and exited `0` without running the command for `--help`, and
stopped with `--password was given more than once.` for `--password`.

`cryptoserve census` in the default text format now renders a snapshot that
lacks a figure ([#109](https://github.com/ecolibria/cryptoserve/issues/109));
`--format json` and `--format html` already exited `0` on such a snapshot. A
cached snapshot without `weakPercentage`, `modernPercentage` or
`pqcPercentage` printed no report, only
`Error: Cannot read properties of undefined (reading 'toFixed')`, and exited
`1`. A percentage held as `null` printed the same error with `null` in place of
`undefined`, and a snapshot without `pypi`, `cveBreakdown` or
`advisoryBreakdown`, or with a package without `tier` or an advisory without
`bySeverity`, stopped the same way on another property. The report now prints
such a snapshot and exits `0`. A Headline or PQC Readiness line, or the tier
count of an npm or PyPI section that lists a package, whose figure the
snapshot lacks or holds as `null` prints `not in this snapshot` in its place,
and such a table cell prints `absent`; the field is named on a
`Not in this snapshot:` line in the Data Sources section. A missing or `null`
CVE or advisory count prints no line, as a count of `0` does, and a missing
`npm`, `pypi`, `cveBreakdown` or `advisoryBreakdown` leaves its section out;
each is named on that line too. An npm or PyPI section that lists no package
is left out, as one with an empty `topPackages` was before, and a tier count
it lacks is not named. A `null` `weakToPqcRatio` still prints
`No PQC downloads detected` and is not named. A missing weak, modern or PQC
download count, or
NIST deadline, printed `undefined`; a missing `totalPqcDownloads` printed
`NaN%` as the PQC readiness and a missing `totalDownloads` printed `0%`; a
missing `collectedAt` left the `Snapshot collected` line out. Each now prints
`not in this snapshot`. A snapshot that carries every field prints the same
report as before.

`census --output` with the default text format now writes the report to the
file, without colour codes, and prints `Census report written to <file>`
([#108](https://github.com/ecolibria/cryptoserve/issues/108)). It printed the
report on stdout, wrote no file and exited `0`, also when the file's directory
did not exist. A path that cannot be written now stops as it does with
`--format json` and `--format html`: a file in a directory that does not exist
prints `Error: Path does not exist: <directory>` and exits `2`, and a path that
is a directory prints `Error: Is a directory: <path>` and exits `2`.

`census --output` now stops the way `scan`, `cbom`, `gate`, `encrypt` and
`decrypt` do ([#103](https://github.com/ecolibria/cryptoserve/issues/103)).
With `--format json` or `--format html`, a file in a directory that does not
exist prints `Error: Path does not exist: <directory>` and exits `2`; both
printed Node's raw `ENOENT` text and exited `1`. In every format, an empty value, or
`--output` with nothing after it, prints `Error: --output was given no value.`
and exits `2`; with `--format json` both printed the JSON on stdout, wrote no
file and exited `0`.
`--output` given twice prints `Error: --output was given more than once.` and
exits `2`; with `--format json` or `--format html` the first path was written
and the command exited `0`.

An `--output` path, or a `scan --emit-findings` path, that the system refuses
for a reason #99 did not name is now named with that reason and exit `2`, on
`scan`, `cbom`, `gate`, `encrypt --file`, `decrypt --file`,
`census --format json` and `census --format html`. A name longer than the
system allows prints `Error: File name too long: <path>`, a loop
of symbolic links `Error: Too many levels of symbolic links: <path>`, and a write
to `/dev/full` `Error: No space left on device: /dev/full`. These printed Node's
raw `ENAMETOOLONG`, `ELOOP` and `ENOSPC` text and exited `1`, and `gate` printed
the raw text with exit `2`. A symbolic link into a directory that does not exist
prints `Error: Path does not exist: <directory> (<link> points to <target>)`,
where it printed raw `ENOENT` text with exit `1`, or `2` from `gate`. A name
ending in `/` names a directory: `--output newdir/` prints
`Error: Path does not exist: <path>` when `newdir` does not exist, and
`--output app.js/` prints
`Error: Not a directory: <path>` when `app.js` is a file. On `scan`, `cbom`,
`gate`, `encrypt --file` and `decrypt --file`, macOS printed raw `ENOENT` and
`ENOTDIR` text for these with exit `1`, or `2` from `gate`, and Linux printed
`Error: Is a directory: <path>` for both. `census --format json` and
`census --format html` wrote the file at the name without its trailing `/`:
`--output newdir/` created a file named `newdir`, `--output app.js/` overwrote
`app.js`, and both exited `0`.

`gate --format json` given `--output`, `--min-score`, `--max-risk` or
`--max-severity` twice now puts its JSON error document on stdout, with
`"error": "--output was given more than once."` (or the option given), and
exits `2`, as it does for an unusable value of these options. It printed the
message as plain text on stderr and nothing on stdout.

docs/cli.md used `-o` and `-p` in the `cbom`, `census`, `encrypt` and `decrypt`
examples and listed them in the flag tables. The Node.js CLI has no short form
of `--output` or `--password` and reads them as positional arguments:
`cryptoserve cbom --format cyclonedx -o cbom.json` stopped with
`Error: Path does not exist: <cwd>/-o`, and `census --format json -o out.json`
printed the JSON on stdout and wrote no file. The examples and tables now use
`--output` and `--password`, and the page names the Python CLI commands that
accept `-o` and `-p`.

`cbom --output`, `gate --output`, `encrypt --file --output` and
`decrypt --file --output` given a file in a directory that does not exist now
print `Error: Path does not exist: <directory>` and exit `2`, as `scan` does
since #95 ([#99](https://github.com/ecolibria/cryptoserve/issues/99)). `cbom`
and `encrypt` printed Node's raw `ENOENT` text and exited `1`; `decrypt`
printed `Decryption failed: ENOENT ...` and exited `1`, although the decryption
had succeeded and only the write had failed; `gate` printed the raw text with
exit `2`. `gate --format json` carries the new message in the `error` field of
its JSON document on stdout, where the raw text used to be. On these commands
and on `scan`, an output path that is an existing directory, or one the system
refuses to write, is now named with the reason and exit `2`:
`Error: Is a directory: <path>`, `Error: Permission denied: <path>`,
`Error: Operation not permitted: <path>` or
`Error: Read-only file system: <path>`. `scan --output somedir` printed
`Error: EISDIR: illegal operation on a directory, open 'somedir'` and exited
`1`.

`scan --output` and `scan --emit-findings` with an empty value, or with nothing
after them, now print `Error: --output was given no value.` (or
`--emit-findings`) and exit `2`. They printed the report to stdout, wrote no
file and exited `0`, so a CI step that expected the file saw a clean exit and
no artifact. `cbom`, `gate`, `encrypt` and `decrypt` stop the same way on an
empty or missing `--output` value: `cbom --output ''` printed the CBOM to
stdout and `encrypt --file app.js --output ''` wrote `app.js.enc`, both with
exit `0`. `scan` given `--output` or `--emit-findings` twice now exits `2`
instead of writing to the first path.

`gate --output` writes the text report, the default format, to the file as
`scan --output` does, without colour codes. Only `--format sarif` and
`--format json` wrote the file: the text report went to stdout and no file was
written. `gate --help` lists `--output`.

`scan --output` and `scan --emit-findings` given a file in a directory that does
not exist now print `Error: Path does not exist: <directory>` and exit `2`
([#95](https://github.com/ecolibria/cryptoserve/issues/95)). They printed Node's
raw `ENOENT: no such file or directory, open 'nodir/report.txt'` and exited `1`,
the code for a command that ran and reported a failure. Where the directory is
missing more than one level deep, the highest missing one is named; where a file
stands in the directory's place, `Error: Not a directory: <file>` is printed,
also with exit `2`.

The CBOM `gitRepo` field is written without the userinfo of the origin remote URL.

A dependency version, a file path and the CBOM's git branch, remote and
project name no longer carry characters that steer a terminal
([#75](https://github.com/ecolibria/cryptoserve/issues/75)).

A dependency version and a file name are the scanned tree's own text. DEL, the
C1 block (U+009B is a one-byte CSI) and the bidi overrides and isolates in either
reached `scan`, `gate` and `cbom` raw, in the terminal and in every saved
document: `JSON.stringify` escapes none of them. A hostile file in a tree
somebody scans was enough; no hostile dependency was needed. Each field is now
cleaned once, where it is built, so every output carries the same value:

- Dependency versions from every manifest, and the CBOM's git branch, remote and
  project name, have those characters removed.
- Paths have each one percent-encoded instead (`a%E2%80%AEb.js`), because a
  path with a character removed names a file that does not exist. A literal
  `%` is encoded as well, as `%25`, so that decoding the path gives back the
  file's name, and percent-encoding is the form SARIF's `uri` expects.

A path holding neither `%` nor any of these characters prints exactly as
before. A new test walks every string in the JSON, SARIF and CBOM documents of
`scan`, `gate`, `cbom` and `pqc`, and every line of the `scan`, `gate` and `pqc`
text reports, over a tree built to reach every finding category the scanner
reports.

A file path from the scanned tree that holds a literal `%` now prints it as
`%25` ([#86](https://github.com/ecolibria/cryptoserve/issues/86)).

The encoding above first left a literal `%` as it was, so a file named
`a%E2%80%AEb.js` printed exactly like a file named `a`, U+202E, `b.js`. With an
MD5 call on line 2 of each, `scan --format json` reported both findings under
one path, the two SARIF results carried one `uri`, which decoded to the second
file, and `gate` reported one violation for the two files. The first file now
prints as `a%25E2%2580%25AEb.js`: the two findings carry two paths, each SARIF
`uri` decodes to the file it names, and `gate` reports two violations. A path
such as `src/100% done.js` now prints as `src/100%25 done.js`.
`scan --emit-findings` opens the file a finding names by its decoded path
alone, because the printed path can name another file in the same tree:
`x%.js` prints as `x%25.js`.

The scanned directory's path, and the project name and version that
`scan --emit-findings` records, now have those characters percent-encoded too
([#88](https://github.com/ecolibria/cryptoserve/issues/88)).

The fix above left them out. A newline in a parent directory's name split the
`Directory` line of `scan`, `gate`, `pqc` and `cbom --output` in two. It did the
same to the summary `cbom` writes to stderr, to the error `scan`, `gate`, `pqc`
and `cbom` print for a path that does not exist or is not a directory, and to
the one `gate` prints for a directory it found nothing to read in. ESC, DEL,
U+009B, RLO and RLI in that name reached those lines raw, and DEL, U+009B, RLO
and RLI reached `scannedPath` in `pqc --format json` and the error in
`gate --format json` raw. Each of those places now prints the path the way a
finding's path is printed, and it decodes to the directory when its name holds
no `%`. The commands still open the path as given.

`scan --emit-findings` copied the project's name and version from
`package.json`, or the directory's own name in place of a missing name, into its
records unchanged. They are now percent-encoded in the same way, which is the
form a record's `file` already had. A name or version that is not a string is
recorded as its encoded string form. The source lines a record quotes are the
scanned code and are still kept as written.

The report-fields test now scans a tree under a directory with a hostile name,
and also reads the summary `cbom` prints beside its document, the refusals for a
missing path, a file and an empty directory, and the records, apart from the
source lines they quote.

`gate` now fails a tree that disables TLS certificate verification
([#66](https://github.com/ecolibria/cryptoserve/issues/66)).

`gate --help` promises it fails on "critical API misuse such as a disabled TLS
certificate check". It knew one spelling of that, `rejectUnauthorized: false`,
so a project turning verification off in JavaScript AND in Python scored 100/100
and exited 0. `scan` was equally blind, so the two commands agreed with each
other and were both wrong. Reproduced on released 0.5.0 as well: pre-existing,
not a regression.

Now reported, each in both languages:

- `NODE_TLS_REJECT_UNAUTHORIZED=0` and a no-op `checkServerIdentity`
- `ssl.CERT_NONE` (as `verify_mode=` and `cert_reqs=`), `check_hostname = False`
  and `ssl._create_unverified_context()`
- `ssl.PROTOCOL_TLSv1` and `secureProtocol: 'TLSv1_method'`, which go through
  the same TLS version table `nginx.conf` uses. A deprecated protocol was
  critical in a config file and invisible in source; one defect keeps one
  severity whatever file type it is written in.

Restoring verification passes the same tree, and each spelling on its own fails
the gate at DEFAULT thresholds. A finding `scan` prints that `gate` cannot
reach at its default settings is the defect this release already fixed once for
medium severity.

A library is no longer named as the source of a call it cannot have made
([#67](https://github.com/ecolibria/cryptoserve/issues/67)).

`gate` indexed call sites on the algorithm NAME alone and dropped the language
the scanner had recorded, then paired every inventory library with every site of
any algorithm it declares. `crypto-js` declares MD5, so a Python
`hashlib.md5()` was reported with `source: crypto-js@3.1.9`. Manifest libraries
are inventoried before source ones, so the wrong owner won the first-writer
race every time; SHA-1 stayed correct only because `crypto-js` does not declare
it. A library now claims a site only in a language its ecosystem produces, and
`source` libraries carry the languages the import was actually read in.

The same name-only match was in the CBOM, which dropped an `md5` read from a
`.c` file out of the bill of materials because an npm package elsewhere in the
tree listed MD5. Both now use one shared language predicate.

Ownership is now answered by its own list, separate from the inventory that
feeds scoring. A site no same-language library claims gets a synthetic owner,
without which barring a foreign claim would leave a `#include <openssl/md5.h>`
site with no claimant at all, since a C include produces no library entry in
any ecosystem. Keeping that list separate is what makes this change score-neutral:

**No score changes.** `quantumReadinessScore` is byte-identical to 0.6.0 on
every tree measured, including mixed-language ones. That is deliberate and is
regression-tested. `calculateQuantumScore` counts inventory ROWS
(`deprecatedCount * 10`, uncapped) while `classifyAlgorithms` deduplicates by
algorithm name, so one row per language for the same algorithm moves the score
without the set of algorithms present having changed. It moves it in both
directions, and the upward one is the dangerous one: a tree with `jose`
(declaring `AES-GCM`) and a Python `aes-gcm` site went from 25/100 FAIL to
40/100 PASS at `--min-score 30`, because the second spelling added a SAFE
classification. A security gate must not turn green because attribution got
more precise. The row-counting itself is a pre-existing property of the scoring
model and is unchanged here.

A dependency violation also no longer borrows its remediation from an unrelated
file. `MD5 crypto-js@3.1.9` at `package.json` said "Replace with SHA-256", a fix
written for a call site in another language, which a reader has no line of
`package.json` to apply. It now says what the other dependency-only violations
say.

The release verification instructions now describe the releases that exist.
The README told Python users to run `gh release download v1.4.3` and
`sha256sum -c SHA256SUMS.txt`, against a GitHub Release with no assets, and
two documents said SHA-256 checksums covered every release artifact. Only the
CLI releases from `js-v0.4.0` verify that way. The checksum files on earlier
Python tags record build directory paths, so the documented commands fail on
every entry, and most entries do not match the file PyPI serves. The README now
says so, and states that PyPI versions at or before `1.4.3` carry no
attestations. A test holds the README and both documents to those facts.

A gate that fails on the score alone now names what holds the score down
([#60](https://github.com/ecolibria/cryptoserve/issues/60)).

A project whose only dependency is `jose` failed at default thresholds with
`Score 25 is below minimum 50` and nothing else, while every other failure
names what to change: a file and a line, a committed key file, or the
dependency that declares the algorithm. The gate now lists the libraries that
lower the score, the quantum-vulnerable algorithms each uses, and the points
the score would recover without them
(`jose (RS256, ES256, EdDSA) +75 recoverable`). The points are measured by
scoring the same inventory again without that library's contribution.
`gate --format json` carries the full list as `scoreContributors`, and the
SARIF result for a score failure names the first three.

**No verdict changes.** The score, the default `--min-score 50` and the exit
codes are unchanged. Whether the gate should check post-quantum readiness by
default is still open in #60.

The release documentation now matches the publish workflow and the releases
([#79](https://github.com/ecolibria/cryptoserve/issues/79)).

`docs/security/ci-security-pipeline.md` said PyPI publishes with a
`PYPI_API_TOKEN` repository secret and that the GitHub Release attaches the
wheels. The workflow publishes through PyPI Trusted Publishing with no token,
and attaches the wheels, the sdists and a `SHA256SUMS.txt` of bare filenames.
The README now says what the GitHub Releases on `v0.2.0` and `v0.3.4`, the tags
of CLI `0.2.0` and `0.3.4`, hold: Python wheels and a checksum file that does
not cover the CLI tarball. Every `LICENSE` in the repository, including the
copies in the npm and PyPI packages, is now the published Apache License 2.0
text with its APPENDIX; the license is still Apache-2.0.

The documentation test now rejects a sentence of `README.md`, `docs/trust.md`
or `docs/security/transparency-report.md` that contains `checksum`,
`SHA256SUMS`, `SHA-256 digest` or `SHA-256 hash`, in any letter case, and the
word all, every or each, unless it also contains from `js-v0.4.0` or
`js-v0.4.0` onward. It matches those words, not what the sentence means. It
joins the wrapped lines of a paragraph, but reads a line that starts with `#`
or `|` on its own and does not join a line that starts with a list marker
(`-`, `*`, `+` or a number and a period) to the line above it. It ends a
sentence at a `.`, `!` or `?` followed by a space and a capital letter, a
backtick, a double quote or an opening parenthesis. A sentence wrapped onto
one of those lines, or holding such a stop, is checked in parts. It accepts a
download command only for a tag on a list of releases checked to verify, so a
mistyped tag fails.

The server's ML-KEM encapsulation and decapsulation refuse keys and ciphertexts
of the wrong length before calling liboqs, as FIPS 203 §7.2 and §7.3 require
([#82](https://github.com/ecolibria/cryptoserve/issues/82)). The key exchange
routes answer such an input with 400, and an encapsulation or hybrid ciphertext
shorter than the lengths its header declares is refused instead of read short.

Dependency versions are capped, `gate` documents reach a pipe whole,
`scan --output` writes the text report, and a dependency named after a
property every JavaScript object has is no longer a cryptographic library
([#84](https://github.com/ecolibria/cryptoserve/issues/84)).

- **A dependency version is capped at 256 characters**, where it is built, for
  npm and every other ecosystem, as a finding's `evidence` and a waiver's rule
  and reason already were. A `package.json` pinning `jose` to `1.0.0-` and
  5,000 letters, and a `requirements.txt` pinning `cryptography` to a
  5,000-digit version, put every character into `libraries[].version` and the
  CBOM purl (5,019 and 5,022 characters), and `gate --max-risk low` repeated
  them in each violation's `source`. On that tree the purls are now 269 and 278
  characters, and the longest line `gate --max-risk low` prints is 361
  characters rather than 5,105. A version of 256 characters or fewer is
  carried as before.
- **`gate --format json` and `--format sarif` reach a pipe whole.** `gate`
  printed the document and called `process.exit()` at once, which does not
  wait for stdout to drain. Measured on macOS through `| cat`, a 354,199-byte
  JSON document arrived as 65,536 or 131,072 bytes and a 689,843-byte SARIF
  document as 131,072 bytes, in 4 of 4 runs each, and none of them parsed.
  `gate` now sets the exit code and returns, so it still exits 0 on a pass and
  1 on a failure, and both documents arrived whole in 4 of 4 runs.
- **`scan --output` writes the text report.** It wrote a file only for
  `--format json` and `sarif`; with the default text format the report went to
  stdout, no file was created, and the command exited 0. The text report is
  now written to the file without the colour codes a terminal gets, and
  nothing goes to stdout, as with the other two formats.
- **A dependency named `constructor`, `toString`, `hasOwnProperty` or
  `__proto__` is no longer inventoried.** The package tables are plain
  objects, and looking such a name up in one found the property every object
  inherits. `scan --format json` listed the dependency with no algorithms, and
  `scan`'s text report, `gate` and `cbom` stopped with an error. Only a
  table's own keys match now, in every ecosystem. On a `package.json` listing
  `constructor`, `toString` and `hasOwnProperty` beside `crypto-js`, `gate`
  now reaches the verdict, score and violation count it reaches for
  `crypto-js` alone.
- The `gate` tests run the CLI without a shell, and name their fixture
  directories with a space. Run from a copy of `sdk/javascript` whose path
  holds one, 60 of the file's 63 tests failed; all 65 now pass there.

SARIF `artifactLocation.uri` is now percent-encoded
([#85](https://github.com/ecolibria/cryptoserve/issues/85)).

The uri was the path with backslashes turned into slashes and nothing else, so
a finding in `a#b.js` was written as `a#b.js`, which a URI reader takes as the
file `a` with the fragment `b.js`; `a?b.js` read as `a` with a query, and a
space is not legal in a URI. `scan --format sarif` over files named `a#b.js`,
`c?d.js` and `e f.js` now writes `a%23b.js`, `c%3Fd.js` and `e%20f.js`, and each
resolves against the scanned directory to the file the finding is in. A colon,
a non-ASCII character and a `%` that does not start a `%XX` triplet are encoded
too (`a%3Ab.js`, `caf%C3%A9.js`, `100%25.js`). A `%XX` triplet already in the
path is kept as it is, so the encoded form of a terminal-unsafe character
(`a%E2%80%AEb.js`) is not encoded a second time. The JSON and text reports
print the path as before.

`createHash('constructor')` in a scanned file no longer stops `scan`, `cbom`
and `gate` ([#89](https://github.com/ecolibria/cryptoserve/issues/89)).

The algorithm tables are plain objects and were read with `in`, which is also
true for a name inherited from `Object.prototype`. On a tree whose one file
holds `require('crypto').createHash('constructor')`, the digest name resolved
to the Object function: `scan --format json` and `cbom` exited 1 with nothing
on stdout, and `gate` exited 2, each printing `Error: a.startsWith is not a
function`. `createHash('con-structor')` loses its hyphen on the way to the
database, and was reported as an algorithm called `constructor` with a
`weakPatterns` entry that named no issue and no severity. Only a table's own
keys match now, so both names are unknown algorithms. On each of those trees,
`scan --format json` and `cbom` exit 0 with their document, `gate` exits 0,
and the scan reports no algorithm for the call.

The decrypt engine turns a failure to parse a hybrid ciphertext into a
`DecryptionError`, so `POST /api/v1/crypto/decrypt` answers 400 instead
of 500 and `POST /api/v1/crypto/batch/decrypt` reports the item as "Decryption
failed" instead of "Internal error"
([#91](https://github.com/ecolibria/cryptoserve/issues/91)). Both routes are
tested with a ciphertext cut short inside its ML-KEM ciphertext. The engine is
also tested with a header that has no `mode`, names an unknown mode, carries a
non-string `nonce` or is not a JSON object.

`POST /api/v1/kex/decapsulate` answers 400 instead of 500 when the encapsulation
header is not a JSON object, lacks `mode`, `x25519_len` or `mlkem_len`, or names
a mode other than the key's
([#92](https://github.com/ecolibria/cryptoserve/issues/92)). A `true` or `false`
length in the header is refused as a bad length instead of read as 1 or 0.

The ML-KEM interop test's docstring said the interop CI job sets
`CRYPTOSERVE_INTEROP_REQUIRED=1`. No workflow under `.github/workflows` sets it
or installs liboqs; the docstring now says so and names
`backend/tests/interop/interop.workflow.yml` as the proposed job that does
([#93](https://github.com/ecolibria/cryptoserve/issues/93)). A test reads the
workflows: when no workflow file names the variable, the docstring must not
contain `set by the interop CI job` and must say that no workflow sets it.
Without liboqs, `tests/test_hybrid_crypto.py` and `tests/test_pqc_enhancements.py`
skip 92 tests and `tests/interop` skips 5, so the backend test runs in `ci.yml`
and `publish.yml` do not exercise them.

`vault get constructor` and `vault delete constructor` answer `Not found:
constructor` and exit 1 on a vault that holds no secret of that name, and
`vault set __proto__ VALUE` stores the secret
([#97](https://github.com/ecolibria/cryptoserve/issues/97)).

The vault's secrets table was a plain object, read with `data.secrets[key]` and
`key in data.secrets`, so a name inherited from `Object.prototype` read as an
existing entry. On a vault holding one other secret, `vault get constructor`
printed `undefined` and exited 0, `vault delete constructor` printed `Deleted:
constructor` and exited 0, and `vault set __proto__ VALUE` printed `Stored:
__proto__` while replacing the table's prototype, so `vault list` did not show
the secret and it was not saved. The table now has no prototype. `get` and
`delete` of `constructor`, `toString`, `hasOwnProperty` and `__proto__` report
the name as not found until a secret of that name is stored, and each of those
names can be stored, listed, read, deleted, exported with `vault export` and
imported back with `importVaultBundle` as an ordinary name. `vault run` passes
a secret named `__proto__` to the command as an environment variable.

`importVaultBundle` refuses a bundle holding an entry that is not a string or an
object with a string `value`, names up to five such entries, and stores nothing
from the bundle
([#101](https://github.com/ecolibria/cryptoserve/issues/101)).

The import stored every entry whose `typeof` was `'object'` as it was. After it
imported the bundle `{"A":null}`, `vault list` printed `Cannot read properties
of null (reading 'updatedAt')` and exited 1, and `vault run` printed `Cannot
read properties of null (reading 'value')` and exited 1, until `vault delete A`
removed the entry. An entry that was an array, or an object without a `value`,
was stored as well and read back from `getSecret` as `undefined`, and the
entries `42` and `{"value":7}` were stored as numbers. Each of these now throws
an error naming the entry and what it is, for example `Bundle not imported: "A"
is null. Each entry must be a string or an object with a string "value". The
vault was not changed.`, before the vault is read. A bundle holding a string,
an array or `null` in place of a table of secrets is refused with `Bundle not
imported: it holds a string, not a table of secrets.` and the like; the string
`"str"` was imported as the secrets `0`, `1` and `2`.

An accepted entry is stored as its `value` and an `updatedAt`. The bundle's
`updatedAt` is kept when it is a string `Date.parse` reads and replaced by the
time of the import otherwise, so `vault list` shows an age counted from the
import for an entry whose `updatedAt` was missing or not a date, where it showed
`NaNd ago`.

`vault list` and `vault run` work on a vault that already holds an entry that is
not an object with a string `value`, as `importVaultBundle` could store before
it checked bundle entries, and name each such entry with the command that
removes it ([#105](https://github.com/ecolibria/cryptoserve/issues/105)).

On a vault holding the entry `"A": null`, `vault list` printed `Cannot read
properties of null (reading 'updatedAt')` and `vault run` printed `Cannot read
properties of null (reading 'value')`, each exiting 1 without naming the entry,
whatever other secrets the vault held. `vault list` now lists every name, shows
`not a secret` in place of the update time of such an entry, and prints a
warning for it such as `"A" is not a secret: it is null. Remove it with:
cryptoserve vault delete A`. `vault run` passes each entry whose `value` is a
string to the command and leaves out every other entry, naming it on stderr with
the same command, for example `"A" is not passed to the command: it is null.`
An entry whose `value` is not a string is left out as well: a `value` of
`null`, `["a","b"]`, `7` or `{}` reached the command as the text `null`, `a,b`,
`7` or `[object Object]`, and a `value` of `{"toString":1}` stopped `vault run`
with `Cannot convert object to primitive value` before the command started. The
printed `vault delete` command names the entry in single quotes unless the name
is letters, digits, `_`, `.` and `-` starting with a letter, digit or `_`, as in
`cryptoserve vault delete 'my key'`.

`setSecret` refuses a value that is not a string, and `exportVault` refuses to
export a vault holding an entry that `importVaultBundle` refuses
([#106](https://github.com/ecolibria/cryptoserve/issues/106)).

`setSecret` accepted a value that was not a string, such as `8080`, `true`,
`null`, `undefined` or `{"x":1}`. Since the fix for #101, `importVaultBundle`
refused the bundle `exportVault` then wrote, with an error that begins `Bundle
not imported: "PORT" has no string "value".`, so the library could not import
its own export. `setSecret` now throws a `TypeError` such as `Secret "PORT" not
stored: its value is a number, not a string.` before it reads the vault, and
the vault file is left as it was. A vault that already holds such an entry,
written by an earlier version, is not exported: `vault export` prints `Vault
not exported: "PORT" has no string "value". The bundle would not import. Store
each such secret again as a string, or delete it.`, naming up to five such
entries, and exits 1. After `vault set PORT 8080` or `vault delete PORT`, the
bundle `vault export` writes imports.

`vault list` shows `unknown` in the Updated column for a secret whose update
time is missing or not a date
([#113](https://github.com/ecolibria/cryptoserve/issues/113)).

`listSecrets` returned a secret's `updatedAt` as the vault stored it, and `vault
list` turned it into an age. On a vault an earlier bundle import wrote, it
showed `NaNd ago` for an entry stored without an `updatedAt`, or with one of
`"not a date"`, `""` or `{}`, and an age counted from 1970, such as `20748d
ago`, for `null`, `0` or `true`. `listSecrets` now lists an `updatedAt` that is
not a string `Date.parse` reads as `null`, the rule by which `importVaultBundle`
keeps a bundle's `updatedAt`, and `vault list` shows `unknown` for it. A number
of milliseconds, or an array holding a date string, showed an age and now shows
`unknown` as well.

### Known limitations

The misuse patterns match code, not prose, and they cannot tell either from a
test fixture that CONTAINS code: a fixture string in a test file is textually a
call, and a comment quoting an anti-pattern is textually the anti-pattern. A
pragma clears an isolated one, but it is per line, and a file made of fixtures
needs one per occurrence. This repository's own test files would need 39, which
is what `skipDirs` is for. `createCipher` and `rejectUnauthorized: false` have
always behaved this way; there are now more patterns that can.

A misuse pattern reports only the FIRST match per pattern per file, so a false
positive above a real defect of the same rule hides it until the false one is
waived or fixed. Waiving does not hide it: the scan keeps reading past a waived
match specifically so that a pragma cannot silently widen itself to the rest of
the file. Reporting every match changes finding counts for every existing misuse
pattern, so it wants its own measured change.

These spellings are not yet detected, and each has a test asserting it is not,
so if one starts being detected, this list is what fails:

- `NODE_TLS_REJECT_UNAUTHORIZED` set through anything other than `process.env`
  directly: a destructured `const { env } = process`, an aliased
  `const e = process.env`, `Bun.env`, a spread into a child process's env, or
  `Object.assign(process.env, ...)`. Also `??=` and `Deno.env.set(...)`. The
  rule is scoped to `process.env` on purpose. Widening it to any receiver does
  catch all of these, and also flags `{ rules: { NODE_TLS_REJECT_UNAUTHORIZED: 0 } }`,
  a severity map, an unrelated counter, a class field, and a comment naming the
  variable: 8/8 detected against 6/6 false positives, versus 3/8 against 1/6 as
  shipped.

  The new pragma makes every one of those clearable, which removes the original
  objection. It stays narrow for a second reason, found by adversarial review:
  widened, every remaining critical on this repository's own tree becomes a
  fixture string in its own test suite, so the scanner fails its own gate and
  owes itself 39 pragmas. Reaching those spellings wants the scanner to be able
  to tell code from prose, which needs a real parser rather than a regex.
- `from ssl import CERT_NONE` and `from ssl import PROTOCOL_TLSv1`: unqualified
  after a `from` import; both rules require the `ssl.` qualifier.
- The method-shorthand, `async`, quoted-key and commented-body forms of a no-op
  `checkServerIdentity`.

## [CLI 0.6.0] - 2026-08-03

A minor rather than a patch because the shape of a `gate` violation changed. A
CI job that filters the JSON on `.risk` will read different values after this
release, and that is the point: `.risk` meant two different things depending on
which flags were passed.

### Changed

`gate` had one threshold, `--max-risk`, and it carried two meanings.

`--max-risk` bounds QUANTUM risk: how far a cryptographically relevant quantum
computer would weaken an algorithm. Nothing in the flag name, the help text or
the output said so, while the same output printed `[CRITICAL] md5` using
`critical` to mean security severity. Two meanings, one vocabulary. The
consequences were all reachable from the command line:

- `--max-risk none` FAILED a correct AES-256-GCM + SHA-256 + bcrypt project,
  because SHA-256 carries quantum risk `low`.
- `--max-risk none` PASSED unauthenticated CBC, which `scan` reports at
  severity `medium`. The strictest available setting failed good code and
  passed a real weakness.
- No value of `--max-risk` tightened the gate on security severity at all.
- Medium-severity findings -- unauthenticated CBC, a static IV -- were
  unreachable by any combination of `--max-risk`, `--fail-on-weak` and
  `--min-score`. `gate` counted them as `safe`.

There are now two thresholds, because a finding has two independent properties:

- `--max-risk` keeps its meaning and says so, in the help and in the report,
  which now reads `Max quantum risk`. A quantum-risk violation is labelled
  `[QUANTUM LOW]` rather than `[LOW]`, so no two labels share a vocabulary
  without sharing a meaning.
- `--max-severity` is new and bounds security severity as `scan` reports it.
  It takes `none`, `low` or `medium` and defaults to `medium`, which is exactly
  the previous behaviour: high and critical fail. Lower it to reach medium
  findings.

`--max-severity high` and `--max-severity critical` are refused with exit `2`.
High and critical findings always fail the gate, so a higher value could only
loosen it. Accepting and ignoring it would be a flag that appears to act and
does not; honouring it would make the flag a kill switch for a disabled TLS
certificate check. Refusing by name is the third option.

The default verdict is deliberately unchanged. The defect was that medium
findings were unreachable, not that the gate was lax, and tightening the default
would flip verdicts for every existing CI job on upgrade with no code change --
the same "teaches people to ignore the check" failure this release fixes in the
publish workflow.

### Fixed

- **`--fail-on-weak` rewrote the findings it took over.** AES-ECB reported
  `risk: "high"` normally and `risk: "none"` under the flag; 3DES and Blowfish
  went `high` to `low` the same way; `type` was dropped; and the actionable fix
  (`Replace with AES-256-GCM (any authenticated mode)`) was replaced by a bare
  description (`ECB mode leaks patterns`). The exit code was unaffected, so it
  was not a fail-open, but a CI policy filtering `.risk == "high"` saw nothing
  under the flag whose name sounds strictest. The cause was deduplication
  order: the algorithm-level record silently replaced the scanner's record
  instead of merging with it. Every violation now carries both `risk` (quantum)
  and `severity` (security), neither of which depends on the flags, plus
  `riskBreach` / `severityBreach` / `weak` recording which threshold fired.
- **`gate` counted an algorithm it had just failed on as `safe`.** AES-ECB is
  quantum-`none` and structurally broken, so it appeared in the `safe` count of
  the same summary whose violation list failed the build.
- **`gate` ignored TLS findings entirely.** This is the fifth appearance of one
  fail-open, after secrets, committed private keys, misuse findings and AES-ECB.
  `scan` reported SSLv3 at `critical`, `gate` passed the same tree 100/100, and
  `gate --format sarif` emitted three `level: "error"` results while exiting
  `0` -- one command contradicting itself about one tree, so a CI job uploading
  that report got three code-scanning alerts from a gate that had just told the
  build it passed. Deprecated protocol versions now fail the gate, bounded by
  `--max-severity` and deduplicated by location and protocol.
- The severity of a weak algorithm is now defined once, in the scanner, and
  imported by the gate. It was about to be restated in a second place, which is
  how two commands drift into rating the same algorithm differently.
- **A severity the ladder does not recognise now fails closed.** Comparing
  ladder indices directly meant `indexOf` returned `-1` for an unrecognised
  value and `-1 > anything` is false, so a typo in a single pattern definition
  (`severity: 'moderate'`) would have made that finding unable to breach any
  threshold, silently, while the gate reported the tree clean. A gate must not
  be disarmed by a misspelling.
- **Violation labels now read on one scale.** `[TLS]` and `[MEDIUM]` in the same
  list gave no way to see that the TLS finding was the more severe of the two.
  Severity leads every label that has one and the category follows it
  (`[CRITICAL TLS]`, `[CRITICAL SECRET]`, `[MEDIUM]`), and a quantum-risk
  breach is labelled `[QUANTUM LOW]` so the other axis names itself.
- **A quantum-risk violation is no longer a dead end.** It had no remediation
  line at all, because the answer is a migration rather than a per-line edit.
  It now says so and names `cryptoserve pqc`.
- **`gate --format sarif` did not describe the decision `gate` had made.** It
  re-read the tree with `scan`'s collector, so the document was byte-identical
  to `scan --format sarif` however the gate had been configured, and every
  threshold reached the exit code, the text report and the JSON report but not
  the one artifact a CI job uploads. A build that failed on three manifest
  violations uploaded a SARIF naming none of them; a build that passed uploaded
  alerts for findings it had just accepted; a build that failed on `--min-score`
  alone uploaded an empty document. This is the sixth appearance of one
  fail-open, and the first in the reporting layer rather than the decision. The
  SARIF is now built from the same `violations` array the other two formats
  read, so there is one decision and three renderings of it. Each result also
  names the threshold it breached, which is the answer to "why is this build
  red" and was in no format before.
- **`gate` collapsed one algorithm across files.** MD5 in `a.js`, `b.js` and
  `c.js` was one violation naming `a.js`, so a CI user fixed one file per run
  and learned about the next only after the first was green, while `scan`
  reported all three from the start. The cause is one level down: `scanProject`
  deduplicates `sourceAlgorithms` on `algorithm:language` across the whole tree,
  which is right for an inventory (a CBOM must not list one component three
  times) and wrong for a gate (a violation is a place to change code). Scan
  results now carry `algorithmSites`, every place an algorithm was seen, and the
  gate reports one violation per place. The 0.4.0 deduplication stays: that bug
  was one call site emitting a risk row and a weakness row for the SAME line,
  and the violation key is now `algorithm:file:line`, which still merges those.
- **A violation from a manifest had nowhere to point.** A dependency the scanner
  never saw used carried no location, which is a dead end in the text report and
  a result that GitHub code scanning drops in the SARIF one. It now points at
  the manifest that declares it.
- **A violation from a manifest had no step the reader could take.** It carried
  the algorithm database's description (`56-bit key is trivially brutable`)
  rather than an action, and the scanner's action is the wrong one here:
  crypto-js lists DES in its catalogue whether or not anything calls it, so
  "Replace with AES-256-GCM" points at a call site that does not exist. A user
  who had fixed every line of their own code still failed the gate with nothing
  left to edit. A dependency-declared algorithm now says so and gives the action
  that applies to a dependency: use the replacement where you call it, or drop
  the dependency.
- **`scan` and `gate` filed one finding under two SARIF rule ids.** Code
  scanning groups and tracks alerts by `ruleId`. The scanner canonicalizes
  source tokens to lowercase (`md5`) and the package database spells the same
  algorithm as a datasheet does (`MD5`), so an alert could close and reopen
  depending on which command last ran. Rule ids are lowercase. A committed
  private key also had no rule of its own and shared the catch-all
  `cryptoserve/finding`; it is now `cryptoserve/private-key`.

### Added

- `violations` in `--format json` carry `manifest` (the file that declares a
  dependency), `protocol` on a TLS violation and `secretType` on a credential
  violation. All three were already implied by other fields; naming them lets a
  CI policy group without parsing a sentence.
- `scan --format json` carries `algorithmSites`: every algorithm occurrence with
  its file and line, alongside the deduplicated `sourceAlgorithms` inventory.

### Notes

`gate --format sarif` and `scan --format sarif` are now different documents on
purpose. The gate reports what failed THIS run at THESE thresholds, so a passing
gate emits no results. `scan --format sarif` still reports every finding in the
tree. A pipeline that uploads the gate's document to code scanning will see
fewer alerts after this release, and the ones it loses are the findings the gate
was configured to accept.

One algorithm used in N files now reports N violations where it reported one, so
a CI policy comparing `summary` counts or `violations.length` across the upgrade
will see them rise. The verdict does not change: a tree that failed still fails.

`--max-severity` does not reach credential findings. Secrets and committed
private keys fail under their own rule and are waivable only by name, with
`--allow-secrets`; a threshold that could waive them would be a second,
unnamed waiver.

## [CLI 0.5.0] - 2026-07-30

A minor rather than a patch because `census --live` is gone. Under 0.x semver a
breaking change bumps the minor, and a user pinned to `^0.4.0` should not
silently receive a CLI whose flag was deleted -- even one that was reporting
rate-limited requests as zero downloads.

### Fixed

Five defects that shared one shape: an argument the command could not act on was
carried into the work instead of stopping it, so the command reported a confident
result about something it had not measured. All five predate 0.5.0.

- `gate --min-score abc` failed OPEN. `parseInt('abc')` is `NaN` and every
  comparison against `NaN` is false, so the threshold was not lax -- it was
  absent. A gate that was failing on score printed `min: NaN` and exited `0`,
  which means a typo in a CI threshold turned a red build green. `--min-score`
  now requires a number from 0 to 100; `--max-risk` requires one of the five
  levels (an unknown value scored `-1` in the risk order, making every algorithm
  a breach); an unknown `--format` no longer falls back to text. Each exits `2`.
  `Number` rather than `parseInt`, so `--min-score 40abc` is rejected instead of
  silently becoming 40.
- `cbom <path that does not exist>` emitted a valid CBOM asserting
  `quantumReadiness.score: 100, riskLevel: none` and exited `0`, while `scan` and
  `gate` rejected the same path. A mistyped path produced a compliance artifact
  certifying a tree nobody had read. It now exits `2`, and both `cbom` and `gate`
  report how many files they read -- neither showed a count, which is why an
  empty result and a clean result looked identical.
- `cryptoserve init --insecure-storage` died with
  `Cannot access 'configPath' before initialization`. A local `const configPath`
  shadowed the imported `configPath` for the whole function body, so the
  plaintext-storage branch read it from its temporal dead zone. That branch is
  the exact recovery the preceding no-keychain error recommends, so `init`
  dead-ended for every user without a keychain.
- Any password prompt with stdin redirected -- `</dev/null`, a pipe, any CI
  runner -- printed a Node "Detected unsettled top-level await" diagnostic
  carrying installed file paths, and exited `13`. The prompt registered a `data`
  listener that could never fire. It now says what to pass and exits `2`; the
  hint is per-command, because the answer differs (`--password` for most,
  `--insecure-storage` for `init`, a positional value for `vault set`).
  `--password ""` and a bare `--password` were both read as "not supplied" and
  answered with a prompt, so a CI job whose password variable resolved empty
  blocked on a question it could not answer; both are now rejected by name.
- `pqc <path>` accepted the path and then discarded it, analysing the current
  directory instead -- exit `0`, no warning, a confident readiness score for the
  wrong tree. It now analyses the directory it was given and names it, with
  `scannedPath` and `filesScanned` added to the JSON report and a `Directory`
  line in the text report.

An adversarial review of the five fixes above found the same fail-open shape in
five more places, all pre-existing:

- `scan` and `gate` checked only that a path EXISTED. A file exists, walks to
  zero source files and reports a clean tree, so `gate ./package.json
  --min-score 99` certified 100/100 and exited `0` -- the same fail-open as a
  missing path, in the command whose whole job is to fail closed. All four
  path-taking commands now require a directory.
- `pqc --profile helthcare` fell back to `general`, and the warning was
  SUPPRESSED in JSON mode. A CI job asserting HIPAA posture with one transposed
  letter got "not vulnerable / medium", exit `0`, and no signal on any stream.
  `--profile` and `--algorithm` are now validated against the lists their
  implementations actually switch on, rather than a second copy that can drift.
- An option given twice was resolved by `indexOf`, silently taking the first.
  `gate . --min-score 10 $EXTRA_ARGS` therefore discarded a stricter threshold
  the caller appended and never reported the one it ignored. A repeated option
  is now refused.
- `vault set KEY --password PW` read the positional arguments raw and stored the
  literal string `--password` as the secret, exit `0`. That is the exact
  non-interactive form the docs recommend for CI.
- `--min-score 0x10` became 16 and `0b101` became 5, because `Number` accepts
  more shapes than the usage line promises. Only a plain decimal is accepted.

A fresh-user release test then found three more, also pre-existing:

- **`scan` reported no hardcoded secrets in `.env` or any other config file.**
  An AWS key committed in `.env` produced `Secrets found: 0` while the SAME
  literal in `config.js` was found. The walker collected `.env` and then used it
  only for TLS settings; secret detection ran inside the source-file loop,
  behind a language check `.env` can never satisfy. So the highest-value target
  the scanner has returned a deliberate-looking all-clear, on a capability both
  help surfaces advertise. Detection is now one function applied to source and
  config files alike, and `.env.local` / `.env.production` and the other
  value-bearing dotenv variants are collected too (templates are not). The
  report counts source and config files separately, because `Secrets found: 0`
  means something different when no `.env` was read.
- **`cryptoserve login` hung with no terminal**, printing a URL and waiting 120
  seconds on a browser callback that could never arrive, where every other
  interactive command exits `2` at once. It now refuses immediately. A callback
  port that is already held is reported by name rather than killing the process
  with a raw Node `EADDRINUSE` stack trace.
- **`login --server` is now required.** The built-in default was
  `https://localhost:8003`, where nothing runs on a user's machine, so the
  out-of-the-box flow could only ever time out. The CLI cannot know the
  operator's server, and a guess that is wrong for everyone is worse than an
  error naming what to pass.

A re-test after those fixes found one more, and it made the `.env` fix
unreachable from the enforcement path:

- **`gate` ignored hardcoded secrets entirely.** `scan` printed
  `[CRIT] AWS Access Key .env:1` and `gate` on the identical tree returned
  `PASS 100/100`, exit `0`, `violations: []`. The gate evaluated algorithm risk
  only, so the highest-severity finding the scanner produces had no path into
  CI. Two commands reading one tree must not disagree on direction. Secrets are
  now violations, with `file:line`, and `--allow-secrets` waives them by name
  for a documented false positive.

A final re-test found two more, one of them the unswept sibling of the fix
immediately above:

- **A committed private key passed the gate.** `scan` listed
  `Certificate/Key Files: server.key` and `gate` on the same tree returned
  `PASS 100/100`, exit `0`, with no flag that caught it. `-----BEGIN RSA PRIVATE
  KEY-----` was treated identically to a public `-----BEGIN CERTIFICATE-----`.
  Publishing a certificate is routine; publishing the key that signs it is the
  incident. `scan` now reports `privateKeyFiles` separately from `certFiles`,
  and `gate` fails on them (waivable with the same `--allow-secrets`).
- **`vault reset` destroyed the vault with a wrong password, or none at all.**
  It printed `Vault deleted.` and exited `0` either way, while
  `vault delete KEY` with a wrong password correctly refused. Deleting one
  secret was authenticated and deleting all of them was not. `reset` now proves
  it can open the vault first.

A systematic sweep of every finding class `scan` can produce against `gate`
then found the third instance of the same defect, before another review had to:

- **`gate` ignored API-misuse findings.** `scan` reported
  `TLS certificate verification disabled` at severity CRITICAL and `gate`
  exited `0`, because violations were derived from the algorithm inventory and
  a misuse finding carries no algorithm. Disabling certificate verification is
  precisely what a CI gate exists to stop. Misuse findings at `critical` or
  `high` are violations now; a weak ALGORITHM still produces exactly one
  violation rather than two.

A final pre-publish check then caught two defects in that very fix:

- **`--allow-secrets` waived the TLS-verification-bypass finding too**, silently,
  turning a credential waiver into an enforcement kill switch. It waives
  credentials only: a committed secret and a committed private key. Weak
  algorithms, AES-ECB, 3DES and a disabled certificate check are unaffected by
  it, and any waiver is now stated in the human output.
- **AES-ECB and 3DES passed the gate at every `--max-risk` level, including
  `none`.** Deduplication skipped any weak-pattern finding that carried an
  algorithm name, on the assumption it had already produced a violation. Those
  are different sets: ECB is structurally broken rather than quantum-broken, so
  its `quantumRisk` is correctly `none`, it breaches no risk level, and it had
  raised no violation to be deduplicated against. `scan` rated the same line
  `severity: high`. Deduplication is now against the violations actually
  raised, so a HIGH finding is always reachable and a weak algorithm is still
  counted exactly once.

A final check found three more, two of them about surfaces disagreeing:

- **Private-key detection was gated on the file EXTENSION**, so `server.key`
  was found and a byte-identical `id_rsa` was not. `id_rsa` is the most common
  name a committed private key actually has; `id_ed25519`, `deploy_key` and
  `key.txt` were missed the same way. A key's evidence is its first line, so
  small unclassified files are now sniffed for a PEM private-key header. A
  public `-----BEGIN CERTIFICATE-----` is deliberately not a match.
- **`--allow-secrets` did not filter SARIF.** Text said "waived", JSON dropped
  the violation, and SARIF still emitted it at `level: "error"`, so a gate that
  exited `0` uploaded alerts to code scanning for findings it had just declared
  waived. And private keys never reached SARIF at all, so a CI job saw no alert
  for the finding that failed its build. All three surfaces agree now.
- `--allow-secrets` was undocumented on every help surface. A switch that turns
  exit `1` into exit `0` has to be visible in a CI config review.

`gate --help` now also states plainly that `--max-risk` bounds QUANTUM risk
rather than security severity, which is why a weak algorithm fails the gate
regardless of it.

The full sweep now agrees in both directions. Fails by default: a committed
secret, a committed private key (whatever it is named), MD5, SHA-1, RC4,
AES-ECB, 3DES, RSA-1024, and a disabled certificate check. Passes: a public
certificate and a clean SHA-256 tree. `--allow-secrets` moves only the
credential findings, on every output format.

Two detection gaps closed while there:

- `AWS_SECRET_ACCESS_KEY` was not detected. Detection was prefix-driven (`AKIA`,
  `ghp_`, `sk-`), which catches an access key ID and misses its more sensitive
  other half, because a 40-character secret has no prefix to key on. The
  variable it is assigned to is the signal, so the value's length and alphabet
  now qualify it. Verified against three real trees for false positives: the
  only hits were this repository's own deliberate fixtures.
- Placeholder suppression was by FILENAME, so any value in `.env.example` was
  ignored. That is backwards: a template is the file that actually gets
  committed while `.env` is usually gitignored, so a real key pasted into a
  template is the higher-risk case. Templates are scanned, and placeholders are
  filtered by their value (`your-key-here`, `<your-key>`, `changeme`).

### Added
- `--password-stdin` on every command that takes a password. `--password <value>`
  puts the secret in `argv`, where it is readable from `ps`,
  `/proc/<pid>/cmdline` and shell history; this is the `docker login
  --password-stdin` shape and it is now the form the CLI recommends. The two are
  mutually exclusive.
- `CRYPTOSERVE_NO_KEYCHAIN=1` to never touch the OS keychain. Containers and CI
  runners have no keychain service, and probing for one costs a subprocess and
  can hang. It also makes `--insecure-storage` reachable on demand: that branch
  runs only when no master key is found, so on any machine where `cryptoserve
  init` has ever succeeded, a regression test for it silently exercises nothing
  -- which is how the ReferenceError above shipped in the first place.
- `gate --format json` reports `summary.manifestsFound` alongside
  `summary.filesScanned`. The text output could already distinguish a
  manifest-only project from an empty directory; the JSON that CI actually
  parses could not, because both reported `filesScanned: 0`.

### Fixed (census)
- `cryptoserve census` reported collection failures as measurements of zero.
  Every one of the eleven download collectors recorded a failed request as
  `downloads: 0`: 24 sites, plus 6 more in the inline copy behind `--live`.
  pypistats.org rate-limits at the rate the collector asked, so `cryptography`,
  which really has over a billion downloads a month, was printed as none. Three
  runs of identical code hours apart differed by hundreds of millions of
  downloads depending on which packages were throttled that minute.
- The command carried its own package catalog, which had drifted to 357 entries
  against the census's 355, so the CLI and census.cryptoserve.dev disagreed on
  the denominator of every published share.
- The report never showed the collection date, presenting a snapshot as a
  current reading, and never separated measured from modelled downloads. NuGet
  and RubyGems divide a lifetime total by an assumed number of months and
  CocoaPods publishes nothing, so 10.5% of the headline is a proxy times a
  constant. Both are now shown: the collection date leads the report and the
  measured figure is named alongside the combined one.
- `cryptoserve help <command>` printed the full command list instead of that
  command's help. The per-command help existed but only `<command> --help`
  reached it.

### Changed
- **An unknown flag now stops the command (exit `2`) rather than warning and
  continuing.** That was a fail-open in flag-name form: `gate . --min-scoree 95`
  warned, silently fell back to the default threshold, printed `(min: 50)` and
  exited `0`. A typo must not loosen a gate, and an unparseable option *value*
  already exited `2`.
- **`gate` fails on hardcoded secrets and committed private keys by default**,
  and refuses a tree it read no files from rather than certifying it `100/100`. A repository with a
  committed credential that previously passed will now fail; that is the point.
  `--allow-secrets` opts out explicitly.
- Exit `2` now means "the command could not run as invoked" across the whole
  CLI, not just `gate`; one condition should not have two codes. `1` keeps its
  meaning: the command ran and reported a failure. Moved from `1` to `2`: `scan`
  on a bad path, an unknown command, an unknown subcommand, an unknown context
  name, an invalid `--algorithm`, and a missing required argument.
  The Python CLI is unchanged and its `scan` still exits `1` on a missing path,
  so the two SDKs disagree on that one case until Python is brought in line.
- `cryptoserve census` renders the published snapshot from
  census.cryptoserve.dev rather than collecting its own. The census publishes
  dated snapshots, so there is now one definition of the measurement and the
  CLI's figures match the site by construction. Cached for a day;
  `--no-cache` re-fetches.
- `cryptoserve census --live` has been removed. It collected three of the eleven
  ecosystems from a third copy of the fetch logic, with the same silent zeros,
  while the help text advertised all eleven. Running it now prints why and exits
  non-zero.

### Removed
- `lib/census/collectors/`, `lib/census/package-catalog.mjs` and
  `lib/census/aggregator.mjs`. Only `formatNumber` survives, in
  `lib/census/format.mjs`.

## [CLI 0.4.0] - 2026-07-27

### Fixed
- SHA-1 was reported as SHA-256. The JS literal matcher mapped every
  `sha256|sha384|sha512|sha1` hit to the single label `SHA-256`, so
  `createHash('sha1')` appeared in the inventory as a strong hash. HS/ES/PS
  token algorithms collapsed onto `RS256` the same way.
- 3DES, Blowfish and RC2 were undetectable in JavaScript. The weak-cipher
  patterns required a closing quote immediately after the family name, so
  `createCipheriv('des-ede3-cbc', ...)`, `'bf-cbc'` and `'rc2-40-cbc'` matched
  nothing at all.
- JavaScript and TypeScript source algorithms never reached `sourceAlgorithms`,
  so `cbom`, `gate` and `pqc` saw no crypto from JS source at all.
- `require('node:crypto')` was never recognized as an import. The pattern used a
  character class that could match the opening paren or the quote but not both.
- pyca/cryptography idioms were unmatched: `rsa.generate_private_key`,
  `ec.generate_private_key`, `padding.*`, `hashes.*`, and the legacy ciphers
  exposed through `algorithms.TripleDES`, `algorithms.Blowfish`,
  `algorithms.ARC4`.
- CBOM documents named the wrong producer. `cbom.mjs` hardcoded version `0.2.0`,
  so every CycloneDX `metadata.tools[].version` and SPDX `Tool: CryptoServe-`
  string emitted across the 0.3.x line was wrong.
- `gate --format sarif` and `scan --format sarif` were documented but not
  implemented; both fell through to the terminal renderer, so a CI job piping
  the output into `upload-sarif` was handing it a text report.
- `gate` emitted each algorithm twice when `--fail-on-weak` was set, inflating
  the violation count.
- Truncated table cells gave no indication they had been cut, so
  `chacha20-poly1305, argon2, bcr` read as a package named `bcr`.
- A wrong vault password surfaced the raw OpenSSL string "Unsupported state or
  unable to authenticate data".
- `vault init` reported the path `~/.cryptoserve/vault.enc` regardless of where
  it had actually written.

### Added
- Every finding carries `file:line`, and every weak algorithm carries a CWE and
  a named replacement.
- SARIF 2.1.0 output for `scan` and `gate`, with a physical location on every
  result. `--output <file>` writes the document to disk.
- Weak asymmetric key-size detection across languages: `modulusLength`,
  `key_size=`, `rsa.GenerateKey`, `RSA_generate_key`, `RsaPrivateKey::new` and
  `openssl genrsa`, restricted to forms where algorithm and bit length are
  unambiguous in a single expression.
- Weak-algorithm findings are derived from the algorithm database rather than
  per-language regexes, so Go, Python, Java, Rust and C now get the coverage
  that previously existed only for JavaScript.
- API misuse detection distinct from weak algorithms: `createCipher` without an
  IV, non-CSPRNG randomness used for secrets, and disabled TLS verification.
- `CRYPTOSERVE_HOME` and `XDG_CONFIG_HOME` relocate the state directory. Five
  modules previously hardcoded `~/.cryptoserve`, so no test, CI job or container
  could avoid writing into the invoking user's home.
- WebCrypto algorithm names, crypto-js, node-forge, tweetnacl and JOSE
  algorithm identifiers are recognized in JS/TS.
- `aria` and `sm4` added to the algorithm database (133 entries, 22 weak).

### Changed
- JavaScript and TypeScript are scanned by the same table-driven engine as every
  other language instead of a separate code path.
- Algorithm names that appear as call arguments are read from the source and
  canonicalized rather than matched to a fixed label.
- A source-detected library is given an algorithm list only when its file
  imports exactly one crypto library. With two or more, attribution is not
  decidable without dataflow analysis.
- `scan` reports "Source files" (analyzed) and "Files examined" (walked)
  separately. The single "Files scanned" number counted only the former.
- Census collectors have a 15 second per-request deadline and report progress
  without `--verbose`.
- An unrecognized `--format` is an error instead of a silent fall back to text.

---

## [SDK 1.4.3] - 2026-03-18

### Fixed
- CryptoClient and AsyncCryptoClient now accept `base_url` as keyword alias for `server_url` for backwards compatibility
- Clarified easy.py encrypt/decrypt docstrings to state these are offline password-based functions, not server-connected operations with crypto contexts

---

## [CLI 0.3.4] - 2026-03-17

### Added
- `--help` flag support for all subcommands (scan --help, pqc --help, etc.)
- Built-in help text for scan, pqc, cbom, gate, context, vault, encrypt, decrypt, census commands
- Nonexistent path detection with exit code 1 for scan command

### Fixed
- LICENSE file now included in npm package

### Documentation
- README: Added Built-in Help, Use Cases, and Exit Codes sections
- README: Split SDK section into Node.js (offline) and Python (server-connected)
- cli.md: Reconciled gate flags with actual CLI source, added output examples
- cli.md: Added missing census command documentation
- New CLI quickstart guide (docs/getting-started/cli-quickstart.md)

---

## [SDK 1.4.2] - 2026-03-17

### Added
- `encrypt()` now accepts both `str` and `bytes` input (auto-encodes strings to UTF-8)
- `create_token()` and `verify_token()` now accept both `str` and `bytes` keys
- argon2 password hashing support (optional: `pip install cryptoserve-core[password]`)
- `--password` flag for vault and hash-password CLI commands (non-interactive/CI mode)

### Fixed
- Python 3.14 compatibility: updated sqlalchemy (>=2.0.40) and asyncpg (>=0.30.0) pins
- Dockerfile.allinone: application processes now run as non-root user
- SDK hash_verify format normalization (hex/base64 auto-detection)
- Server key exchange now case-insensitive (X25519, x25519, ECDH-P256 all accepted)
- argon2-cffi added to backend production requirements
- Docker liboqs LD_LIBRARY_PATH fixed (PQC operations now work in containers)
- pyhpke added to backend requirements (HPKE endpoints functional)

---

## [SDK 1.0.1] - 2026-02-06

### Fixed
- CLI commands (`verify`, `info`, `configure`, `status`) crashed due to removed `crypto` singleton (removed in v0.7.0)
- Added missing `pyyaml>=6.0` dependency for `cryptoserve gate` command
- Fixed `AESGCMCipher.encrypt()` docstring showing incorrect 3-tuple return (actual: 2-tuple)

---

## [SDK 1.0.0] - 2026-02-06

### Added

#### PyPI Publication
- Published 4 packages to PyPI: `cryptoserve`, `cryptoserve-core`, `cryptoserve-client`, `cryptoserve-auto`
- Install with `pip install cryptoserve` (no more local editable installs required)
- Modular architecture: use individual packages for specific needs

#### Python SDK Features
- `CryptoServe` class with auto-registration and local key caching (~250x speedup)
- `encrypt()` / `decrypt()` with context-based key management
- `encrypt_string()` / `decrypt_string()` for string convenience
- `encrypt_json()` / `decrypt_json()` for JSON objects
- Usage hints (`at_rest`, `in_transit`, `in_use`, `streaming`, `disk`) for automatic algorithm selection
- FastAPI integration with `EncryptedStr` type annotation
- SQLAlchemy integration with `EncryptedString` column type
- CLI with 18 commands: `login`, `logout`, `verify`, `info`, `wizard`, `scan`, `cbom`, `pqc`, `gate`, `certs`, `backup`, `restore`, `ceremony`, and more

#### SDK Packages
- `cryptoserve-core` (0.1.0): Pure crypto primitives (AES-GCM, ChaCha20-Poly1305, RSA, hashing)
- `cryptoserve-client` (0.1.0): HTTP client for CryptoServe API
- `cryptoserve-auto` (0.1.0): Auto-protect third-party libraries

---

## [1.1.0] - 2026-01-03

### Added

#### Certificate Revocation Checking
- OCSP (Online Certificate Status Protocol) support for real-time revocation checking
- CRL (Certificate Revocation List) support with automatic URL extraction
- Combined revocation check with OCSP-to-CRL fallback
- New methods: `get_ocsp_url()`, `get_crl_urls()`, `check_ocsp()`, `check_crl()`, `check_revocation()`

#### Batch Encryption API
- `POST /v1/crypto/batch/encrypt` - Encrypt up to 100 items per request
- `POST /v1/crypto/batch/decrypt` - Decrypt up to 100 items per request
- Client-provided IDs for tracking individual items
- `fail_fast` mode (stop on first error) or continue mode
- AAD (Additional Authenticated Data) support per item

#### SDK Key Bundle Caching
- `GET /v1/crypto/key-bundle` endpoint for SDK local caching
- Enables offline encryption/decryption operations
- Measured 95%+ cache hit rate in production workloads

#### Documentation
- Comprehensive migration guide for AWS KMS, HashiCorp Vault, and crypto libraries
- Cryptographic assessment report documenting NIST compliance

### Fixed
- Dynamic version retrieval in backup metadata (was hardcoded)

### Security
- Certificate revocation checking prevents use of compromised certificates
- Batch API enforces same authorization as single-item operations

---

## [1.0.0] - 2025-01-03

### Added

#### 5-Layer Context Model
- Data Identity layer: sensitivity classification (low/medium/high/critical), PII/PHI/PCI flags
- Regulatory layer: compliance framework support (HIPAA, GDPR, PCI-DSS, SOC2)
- Threat Model layer: quantum resistance requirements, protection lifetime
- Access Patterns layer: frequency-based optimization, latency requirements
- Technical layer: hardware acceleration, key size requirements
- Automatic algorithm selection based on all 5 layers

#### Policy Engine
- Customizable cryptographic policy rules
- Three severity levels: block, warn, info
- Default policies for common security requirements
- Policy evaluation API for testing before deployment
- Context-specific policy scoping
- CI/CD integration support via `/api/policies/check` endpoint

#### Admin Dashboard
- Overview with KPI cards (users, identities, operations, success rate)
- User management with search and pagination
- Global identity management with filtering
- Audit log viewer with export (CSV/JSON)
- Context management with key rotation
- Usage analytics with charts
- System health monitoring

#### Frontend Improvements
- Policies page with interactive policy evaluator
- Dashboard navigation with policies link
- Mobile-responsive layout improvements

#### Backend Features
- PostgreSQL-based context configuration storage
- Context-derived cryptographic requirements
- Algorithm recommendation engine
- Admin API endpoints with role-based access

### Security
- AES-256-GCM encryption by default
- HKDF-SHA256 key derivation
- JWT-based identity tokens
- Full audit logging
- Policy enforcement at runtime

### Infrastructure
- Docker Compose deployment
- GitHub OAuth integration
- CI/CD integration documentation

## [0.1.0] - 2024-12-01

### Added
- Initial release
- Basic encrypt/decrypt operations
- Context-based key management
- Identity management
- Personalized SDK generation
- GitHub OAuth authentication
- Audit logging

---

[CLI 0.3.4]: https://github.com/ecolibria/cryptoserve/compare/cli-v0.3.3...cli-v0.3.4
[SDK 1.4.2]: https://github.com/ecolibria/cryptoserve/compare/sdk-v1.4.1...sdk-v1.4.2
[SDK 1.0.1]: https://github.com/ecolibria/cryptoserve/compare/sdk-v1.0.0...sdk-v1.0.1
[SDK 1.0.0]: https://github.com/ecolibria/cryptoserve/compare/v1.1.0...sdk-v1.0.0
[1.1.0]: https://github.com/ecolibria/cryptoserve/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/ecolibria/cryptoserve/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/ecolibria/cryptoserve/releases/tag/v0.1.0
