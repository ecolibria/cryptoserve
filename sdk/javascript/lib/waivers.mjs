/**
 * Per-finding waivers, written as a comment pragma next to the code they cover.
 *
 *     // cryptoserve-ignore <rule-id> -- why this one is not a defect
 *     const agent = new https.Agent({ rejectUnauthorized: false });
 *
 * Until this existed, a false `critical` could not be cleared at all:
 * `--max-severity` only tightens and refuses `high`/`critical` by name,
 * `--allow-secrets` does not reach misuse, and `.cryptoserve.json` offers only
 * `skipDirs`, which excludes a whole directory to silence one line. A tool
 * whose false positives are unresolvable gets excluded entirely, so the absence
 * of this was itself a security defect.
 *
 * Five decisions worth stating, because a waiver is a security control's off
 * switch and the failure modes are not symmetric:
 *
 *   1. **A reason is required.** A waiver with no stated reason is not
 *      auditable, and the reason is the only part a reviewer can disagree with.
 *      A pragma without one waives nothing and is reported as malformed.
 *   2. **The marker must directly follow a comment opener**, at the start of a
 *      line or after whitespace, and the pragma must run to the end of the
 *      line. Prose that merely mentions `cryptoserve-ignore` in a sentence is
 *      not a pragma, which is the rule `eslint-disable` uses. Without it,
 *      documentation about the mechanism operates the mechanism: every comment
 *      in this scanner that DESCRIBES a pragma was parsed as one.
 *   3. **It waives one rule, never all of them.** There is no wildcard. A rule
 *      id that no rule uses is reported rather than ignored, so a typo surfaces
 *      as a warning instead of as silence.
 *   4. **Its reach is one line.** A pragma covers findings on its own line and
 *      on the line immediately after it, and nothing else. Anything wider
 *      drifts away from what it was written for as the file changes around it.
 *   5. **It is plain text, in a file with line endings.** A control character
 *      in a pragma, or a bidi override or isolate, is reported as malformed and
 *      waives nothing: the reason and the rule id are file content on their way
 *      to a terminal, and both families decide how that terminal RENDERS the
 *      report rather than what the report says. Line
 *      terminators are decided once for the FILE, before any line is chosen --
 *      a file holding any terminator `split('\n')` does not split on honours no
 *      pragma anywhere in it. Asked instead of the pragma's own line, which is
 *      the only line a guard inside the loop can see, a terminator one line
 *      further down collapsed the file and waived a finding an unbounded
 *      distance away, in silence.
 *
 * Waived findings are never silently dropped: they leave `weakPatterns` and
 * arrive in `waivedFindings`, where `scan`, `gate` and the JSON output all
 * report them.
 *
 * ## What this is NOT
 *
 * Recognising a comment by its opener is a heuristic, not a parse. This module
 * does not tokenize the file, so in a language that HAS block comments there
 * are three shapes it cannot tell from a real pragma. All three are measured
 * and pinned by tests rather than left to be rediscovered:
 *
 *   - a string that begins with an opener: `"// <marker> <rule> -- why"`
 *   - an opener that is not directly after the quote: `" // <marker> ..."`,
 *     because the adjacency guard reads exactly one character
 *   - a block-comment continuation inside a template literal: a line of
 *     backtick-delimited text starting ` * <marker>`
 *
 * So the property defended here is NARROWER than "data a project merely
 * contains cannot switch a check off". That is what an earlier version of this
 * comment claimed, and a Python docstring disproved it. What actually holds:
 *
 *   In a language with no block comments, contained data cannot operate the
 *   control at all -- the continuation branch is gated on the language having
 *   the opener it is a continuation of. In the C family it can, but only from a
 *   string shaped like a comment, and never SILENTLY: a waived finding is still
 *   listed by `scan` and `gate`, counted in `summary.waived`, and emitted to
 *   SARIF as a suppressed result.
 *
 * The residual is bounded by who a waiver is for and by where the scanner
 * looks. It is authored by whoever can already edit the file, so it is not a
 * privilege boundary: anyone able to smuggle a pragma through a string could
 * simply write the comment instead. And `walker.mjs` skips `node_modules`,
 * `vendor`, `.venv` and `venv` by default, so the code this applies to is
 * first-party, not a dependency's.
 *
 * Closing it needs a real parser per language -- six of them for the languages
 * here, not one -- which this package cannot have while it stays
 * dependency-free. A hand-written tokenizer was built for this and removed:
 * adversarial review measured it mis-reading ordinary JSX and minified bundles
 * badly enough to LOSE real findings.
 *
 * ## Known limitation: a pragma this module ignores in silence
 *
 * A pragma that is not the first thing in its comment does nothing, and says
 * nothing about it. A line that already opened a comment earlier -- a URL, a
 * doc block quoting the anti-pattern -- gives its FIRST opener to that earlier
 * comment, so a pragma written at the end of it is text inside a comment rather
 * than a comment carrying a pragma:
 *
 *     const u = "http://x";      // cryptoserve-ignore <rule-id> -- ignored
 *
 * Telling that apart from prose that merely quotes a rule id needs to know
 * where the comment really begins, which is the parse this module does not do.
 * The version that guessed it by re-walking the line was quadratic in the
 * length of the line -- a 200KB line took 42 seconds through a `gate` that has
 * no timeout -- and reported documentation as a broken waiver. It was removed
 * rather than tuned.
 *
 * So a pragma goes on its OWN LINE ABOVE the finding whenever the finding's
 * line already contains a comment opener. These spellings always work:
 *
 *     // cryptoserve-ignore <rule-id> -- why      (own line, above the finding)
 *     # cryptoserve-ignore <rule-id> -- why       (the same, in Python)
 *     code();  // cryptoserve-ignore <rule-id> -- why   (trailing, only when
 *                                                       nothing else on the
 *                                                       line opens a comment)
 *
 * A waiver that is honoured and covers nothing IS reported, as `unused`, so a
 * pragma placed on the wrong line still surfaces from the other direction.
 *
 * Zero dependencies.
 */

const MARKER = 'cryptoserve-ignore';

/**
 * How far after its own line a pragma reaches. One line: the pragma sits either
 * at the end of the offending line or directly above it.
 */
const PRAGMA_REACH = 1;

/** Comment openers per language family. */
const BLOCK_OPENER = '/*';
const C_FAMILY = ['//', BLOCK_OPENER];
const HASH = ['#'];

const OPENERS_BY_LANGUAGE = {
  javascript: C_FAMILY,
  go: C_FAMILY,
  java: C_FAMILY,
  c: C_FAMILY,
  rust: C_FAMILY,
  python: HASH,
};

const SEPARATOR = '--';

/**
 * Everything a pragma must not CONTAIN, because each of these lets file content
 * decide how a terminal renders the report rather than what the report says.
 *
 * Two families, and the second is why this is no longer called CONTROL:
 *
 *   - Every control character except tab. Tab renders as whitespace and forges
 *     nothing, so refusing it would turn an ordinary reason into a malformed
 *     pragma. DEL and the C1 block matter more than they look: JSON.stringify
 *     escapes C0 and NEITHER of those, so both survive raw into a saved
 *     `--format json` report, and U+009B is a one-byte CSI.
 *   - The bidi overrides and isolates. These are not control characters at all,
 *     so the family above does not reach them, and they steer rendering just as
 *     effectively: RLO reverses the display order of everything after it, so
 *     the reason a reviewer READS stops being the reason the file HOLDS. A
 *     reason is the only part of a waiver a reviewer can disagree with, which
 *     makes an audit trail that renders differently from its source the whole
 *     failure. Found by the pre-push gate and measured as new on this branch:
 *     the base revision has no reason field to carry one.
 *
 * The plain marks U+200E and U+200F are deliberately NOT here. They set
 * direction without overriding it, and ordinary Hebrew and Arabic letters carry
 * their own, so a reason written in either stays writable. Refusing a whole
 * language to close a spoofing shape would be the wrong trade.
 *
 * This class answers a different question from `UNSPLIT_TERMINATOR`: what a
 * pragma may CONTAIN, rather than whether the string it sits on is one line.
 * The two overlap, deliberately.
 */
const TERMINAL_UNSAFE = /[\u0000-\u0008\u000a-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/;

/**
 * The same class, applied. Derived from `TERMINAL_UNSAFE` so the two cannot
 * drift.
 *
 * Exported because `evidence` is the other half of a finding built from file
 * content and printed, and it reaches a report through a pattern that matches
 * these bytes rather than through a pragma.
 */
export const stripTerminalUnsafe = (s) => s.replace(new RegExp(TERMINAL_UNSAFE.source, 'g'), '');

/**
 * Every Unicode line terminator except the newline, which is the only one
 * `split('\n')` splits on.
 *
 * VT, FF and CR end a line for Unicode; NEL does for an EBCDIC-derived file;
 * U+2028 and U+2029 do for a JavaScript engine. Any of them leaves the split
 * holding one enormous "line", and that is not cosmetic: `lineNumberAt` counts
 * newlines too, so every finding in such a file reports as line 1, one pragma
 * at the top reaches all of them, and the gate goes green over a tree that
 * disables TLS verification 400 lines further down.
 *
 * Written as the whole family, not as the bytes that were reported. CR was the
 * measured shape and U+2028 reproduced it exactly; a guard covering only those
 * two then still let VT, FF and NEL through, because the control-character rule
 * that would otherwise have caught them reads the pragma TEXT, so a separator
 * appearing only BEFORE the pragma was seen by neither. Asked of the whole raw
 * line, over the whole family, there is no such gap to find.
 */
const UNSPLIT_TERMINATOR = /[\u000b-\u000d\u0085\u2028\u2029]/;

/**
 * Split `<rule-id> -- <reason>` without a regex.
 *
 * Written as code because the regex this replaced backtracked cubically. Its
 * tail, `(.*?)[ \t]*(?:\*\/)?[ \t]*$`, put three ambiguous quantifiers over the
 * same run of spaces, so one comment line carrying `-- r` and 4KB of trailing
 * whitespace took 7.8 SECONDS to reject, against 2ms before this feature
 * existed, growing about eightfold per doubling. No finding had to exist in the
 * tree to trigger it. A scanner that a single crafted comment can hang is a
 * denial of service on every CI job that runs it, and `gate` has no timeout.
 *
 * Returns null when the text does not begin with a rule id at all.
 */
function splitPragma(text) {
  const stripTerminator = (s) => (s.endsWith('*/') ? s.slice(0, -2).trimEnd() : s);

  const space = text.search(/[ \t]/);
  const rule = stripTerminator(space === -1 ? text : text.slice(0, space));
  if (!rule) return null;

  const rest = stripTerminator(space === -1 ? '' : text.slice(space).trim());
  if (!rest.startsWith(SEPARATOR)) {
    // Includes `<rule> <reason>` with the separator missing or spelled with a
    // single hyphen, a colon, or a dash character that is not `--`. Reported,
    // never silently honoured and never silently dropped: the docs promise a
    // malformed pragma says so, and a waiver that vanishes without a word is
    // the failure this whole module is trying not to be.
    return { rule, reason: '' };
  }
  return { rule, reason: rest.slice(SEPARATOR.length).trim() };
}

/**
 * The text a line carries AFTER its first comment opener, or null if the marker
 * is not the first thing in that comment.
 *
 * "First thing in the comment" is the rule, not "somewhere in a comment", and
 * it has to be decided by finding the FIRST opener rather than by matching any
 * opener that happens to precede the marker. A doc block that shows an example
 * is the case that separates the two:
 *
 *      *     // cryptoserve-ignore <rule-id> -- an example
 *
 * The `//` there is preceded by whitespace, so a pattern that merely requires
 * "an opener before the marker" reads a documented example as a live waiver.
 * This module's own header contains exactly that line. Taking the first opener
 * on the line instead leaves `// cryptoserve-ignore ...` as the comment's text,
 * which does not begin with the marker, and the example stays an example.
 */
function pragmaText(rawLine, openers) {
  const afterMarker = (s) =>
    s.startsWith(MARKER) ? s.slice(MARKER.length).replace(/^[ \t]+/, '') : null;

  // A block-comment continuation is decoration, not an opener: the comment
  // began on an earlier line, so this line's text starts right after the `*`.
  // The marker must follow it DIRECTLY. Anything else there, including a
  // further `//`, is an example being shown rather than a pragma being written,
  // which is what this module's own header contains.
  //
  // Gated on the language actually HAVING the opener this is a continuation
  // OF. Ungated it ran before the opener scan and before the quote guard, so
  // ` * <marker>` was read as a pragma in Python, where `*` is not a comment
  // character at all and the line is far likelier to be a docstring quoting
  // the JavaScript spelling. That let a documentation sample switch off a
  // Python check, which is exactly the property this module claims to hold.
  if (openers.includes(BLOCK_OPENER)) {
    const continuation = /^[ \t]*\*(?!\/)[ \t]*/.exec(rawLine);
    if (continuation) return afterMarker(rawLine.slice(continuation[0].length));
  }

  let at = -1;
  let opener = '';
  for (const tok of openers) {
    const i = rawLine.indexOf(tok);
    if (i !== -1 && (at === -1 || i < at)) { at = i; opener = tok; }
  }
  if (at === -1) return null;

  // An opener sitting DIRECTLY after a quote is a comment opener inside a
  // string literal, which is how a test fixture or a documentation sample
  // spells one: `'// cryptoserve-ignore rule -- why'`. Without this, scanning
  // this scanner's own test suite reported 28 waiver problems against fixture
  // data. It errs safe in the one ambiguous direction: a real trailing pragma
  // written with no space after a string (`const s = "a"// cryptoserve-ignore`)
  // is refused, which leaves the finding reported rather than suppressed.
  if (at > 0 && '\'"`'.includes(rawLine[at - 1])) return null;

  // Repeated opener characters (`///`, `/**`, `##`) are still one opener.
  let after = at + opener.length;
  while (rawLine[after] === opener[opener.length - 1]) after++;

  return afterMarker(rawLine.slice(after).replace(/^[ \t]+/, ''));
}

/**
 * Parse waiver pragmas out of a source file.
 *
 * One pass over the lines, so the cost is linear in the file. Resolving each
 * pragma's line by counting newlines from the start of the file instead made
 * this quadratic: a file of 8,000 pragma lines took 258ms, and 1MB of them took
 * a second and a half.
 *
 * @param {string} content - the file text
 * @param {string} language - a `LANGUAGE_PATTERNS` key
 * @returns {{waivers: Array<object>, malformed: Array<object>}}
 */
export function parseWaiverPragmas(content, language) {
  const openers = OPENERS_BY_LANGUAGE[language];
  const waivers = [];
  const malformed = [];
  if (!openers || !content.includes(MARKER)) return { waivers, malformed };

  // CRLF is a line ending this parser understands, so it is normalised away
  // first. That leaves the test below to be about the terminators that are
  // genuinely left, and it removes the trailing-CR strip this loop used to do
  // per line: after this replace, the only CR that can still be in `source` is
  // a lone one, and the refusal below returns before any line is read.
  const source = content.replace(/\r\n/g, '\n');

  // Decided ONCE for the FILE, before a single line has been selected.
  //
  // The guard this replaced ran inside the loop, which had already skipped
  // every line that does not contain the marker, so it could only ever inspect
  // the pragma's OWN line. A terminator one line further down collapsed the
  // body into the pragma's reach and waived it in silence -- no warning at all.
  // Three rounds widened the character class and each was defeated the same
  // way, because the axis that stayed pinned was never the byte: it was WHICH
  // LINE gets asked. Asking the file leaves no other line to move it to.
  //
  // Refusing the whole file is the safe direction and a cheap one: measured
  // over 47,486 source files in 258 trees, 7 carry a stray terminator (0.015%)
  // and every one of them is minified build output or a security fixture that
  // embeds U+2028 deliberately. None carried a pragma.
  const stray = source.search(UNSPLIT_TERMINATOR);
  if (stray !== -1) {
    const lineEnd = source.indexOf('\n', stray);
    malformed.push({
      line: source.slice(0, stray).split('\n').length,
      // On a file with no line endings at all, "the line" is the whole file, so
      // this is capped the way `evidence` is, and stripped of the characters
      // that made it a problem rather than carried out of this module for
      // whoever reads the report to print.
      text: stripTerminalUnsafe(
        source.slice(source.lastIndexOf('\n', stray) + 1, lineEnd === -1 ? undefined : lineEnd).trim(),
      ).slice(0, 120),
      issue: 'this file does not end its lines the way the scanner reads line endings,'
        + ' so no pragma in it has an end; save it with LF or CRLF line endings',
    });
    return { waivers, malformed };
  }

  const lines = source.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (!raw.includes(MARKER)) continue;

    const text = pragmaText(raw, openers);
    if (text === null) continue;   // a mention, not a pragma

    const line = i + 1;
    const shape = splitPragma(text);
    // A bare marker with no rule at all is not a pragma anybody wrote by
    // mistake; it is prose, and reporting it would fire on this module's own
    // documentation.
    if (!shape) continue;

    // Two ways a pragma this module can see is still not one it will honour.
    // Both REPORT: every refusal above this point is prose that never claimed
    // to be a pragma, and every refusal below it is somebody's waiver, which
    // must never disappear without a word.
    //
    // The control-character check runs on the pragma text, so it covers the
    // rule id and the reason together. Both are file content and both are
    // printed to a terminal by `scan` and `gate`, so a reason of
    // `ok<ESC>[2K<CR>FORGED` erases the line the scanner just wrote and prints
    // its own. Nothing before this feature put file text on that surface at all.
    //
    // The line-terminator question is NOT asked here. It is decided once for
    // the file above, because asking it of a line the loop already selected can
    // only ever see the pragma's own line.
    const issue = TERMINAL_UNSAFE.test(text)
      ? 'a waiver must be plain text; remove the control or direction-override character from this one'
      : !shape.reason
        ? 'a waiver needs a reason: cryptoserve-ignore <rule> -- <why>'
        : null;

    if (issue) {
      // The offending line is quoted back, so it is stripped of the characters
      // that made it a problem rather than carried out of this module for
      // whoever reads the report to print. Capped for the same reason `evidence`
      // is: on a file with no line endings, "the line" is the whole file.
      malformed.push({ line, text: stripTerminalUnsafe(raw.trim()).slice(0, 120), issue });
      continue;
    }

    waivers.push({ rule: shape.rule, reason: shape.reason, line, used: false });
  }

  return { waivers, malformed };
}

/**
 * Waivers bucketed by the line they were written on, keyed by the array they
 * came from.
 *
 * A linear scan here was the second half of a quadratic: `findWaiver` runs once
 * per misuse match, and the scan is over every pragma in the file, so a file
 * that waives everything costs matches x pragmas. Resolving the line faster was
 * not enough on its own -- with that alone, doubling the file still took 4.5x
 * the time. Both halves are attacker-authorable in a pull request and `gate`
 * has no timeout.
 *
 * Keyed on the array because that is what a caller already holds per file, and
 * weakly so a scan of many files does not retain them. `parseWaiverPragmas`
 * never mutates the array after returning it, and the buckets hold the same
 * objects, so `used` set through a bucket is visible to `waiverWarnings`.
 */
const BY_LINE = new WeakMap();

function bucketsFor(waivers) {
  let byLine = BY_LINE.get(waivers);
  if (byLine) return byLine;

  byLine = new Map();
  for (const w of waivers) {
    const bucket = byLine.get(w.line);
    if (bucket) bucket.push(w);
    else byLine.set(w.line, [w]);
  }
  BY_LINE.set(waivers, byLine);
  return byLine;
}

/**
 * Does a waiver cover a finding of `rule` at `line`?
 *
 * Marks the waiver used, so the ones that cover nothing can be reported. A
 * pragma left behind after the code it covered was fixed is suppression with
 * nothing under it, and the next real finding on that line would land under it
 * silently.
 */
export function findWaiver(waivers, rule, line) {
  const byLine = bucketsFor(waivers);

  // A pragma covers its own line and the next one, so the only lines that can
  // hold a covering pragma are `line - PRAGMA_REACH` through `line`. Walked
  // oldest-first so the earliest pragma still wins, which is what the linear
  // scan did and what `does not reach two lines down` pins.
  for (let at = line - PRAGMA_REACH; at <= line; at++) {
    for (const w of byLine.get(at) || []) {
      if (w.rule !== rule) continue;
      w.used = true;
      return w;
    }
  }
  return null;
}

/**
 * Warnings for the pragmas in one file: malformed ones, ones naming a rule that
 * does not exist, and ones that waived nothing.
 *
 * @param {Array<object>} waivers - after `findWaiver` has run over every finding
 * @param {Array<object>} malformed
 * @param {Set<string>} knownRules - every rule id the scanner can emit
 * @param {string} file - the path these came from
 */
export function waiverWarnings(waivers, malformed, knownRules, file) {
  const warnings = [];

  for (const m of malformed) {
    warnings.push({ file, line: m.line, kind: 'malformed', detail: m.issue, text: m.text });
  }

  for (const w of waivers) {
    if (!knownRules.has(w.rule)) {
      warnings.push({
        file,
        line: w.line,
        kind: 'unknown-rule',
        detail: `no rule is called ${w.rule}`,
        rule: w.rule,
      });
      continue;
    }
    if (!w.used) {
      warnings.push({
        file,
        line: w.line,
        kind: 'unused',
        detail: 'this waiver covered no finding; delete it or move it onto the line it was written for',
        rule: w.rule,
      });
    }
  }

  return warnings;
}
