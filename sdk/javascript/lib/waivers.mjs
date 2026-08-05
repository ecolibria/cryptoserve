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
 *   5. **It is plain text on a line with an end.** A control character in a
 *      pragma, or a line the newline split did not actually split, is reported
 *      as malformed and waives nothing. The reason and the rule id are file
 *      content on their way to a terminal, and "one line" is not a bound at all
 *      on a file that has no line endings.
 *
 * Waived findings are never silently dropped: they leave `weakPatterns` and
 * arrive in `waivedFindings`, where `scan`, `gate` and the JSON output all
 * report them.
 *
 * ## What this is NOT
 *
 * Recognising a comment by its opener is a heuristic, not a parse. This module
 * does not tokenize the file, so a string literal that both begins with a
 * comment opener and ends the line with pragma text would be honoured. Doing
 * better needs a real parser per language, which this package cannot have while
 * it stays dependency-free, and a hand-written tokenizer was measured to
 * mis-read ordinary JSX and minified bundles badly enough to lose real
 * findings.
 *
 * That residual is acceptable because of who a waiver is for. It is authored by
 * whoever can already edit the file, so it is not a privilege boundary: anyone
 * able to smuggle a pragma through a string could simply write the comment. The
 * property being defended is that data a project merely CONTAINS -- a fixture,
 * a JSON blob, a documentation sample -- does not silently switch a check off.
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
const C_FAMILY = ['//', '/*'];
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
 * Every control character except tab.
 *
 * Tab renders as whitespace and forges nothing, so refusing it would turn an
 * ordinary reason into a malformed pragma. This class answers a different
 * question from `UNSPLIT_TERMINATOR`: what a pragma may CONTAIN, rather than
 * whether the string it sits on is one line. The two overlap, deliberately.
 */
const CONTROL = /[\u0000-\u0008\u000a-\u001f\u007f-\u009f]/;

/** The same class, applied. Derived from `CONTROL` so the two cannot drift. */
const stripControl = (s) => s.replace(new RegExp(CONTROL.source, 'g'), '');

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

  // A JSDoc continuation is decoration, not an opener: the comment began on an
  // earlier line, so this line's text starts right after the `*`. The marker
  // must follow it DIRECTLY. Anything else there, including a further `//`, is
  // an example being shown rather than a pragma being written, which is what
  // this module's own header contains.
  const continuation = /^[ \t]*\*(?!\/)[ \t]*/.exec(rawLine);
  if (continuation) return afterMarker(rawLine.slice(continuation[0].length));

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

  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    // A trailing CR from a CRLF file is line terminator, not pragma text.
    const raw = lines[i].replace(/\r$/, '');
    if (!raw.includes(MARKER)) continue;

    const text = pragmaText(raw, openers);
    if (text === null) continue;   // a mention, not a pragma

    const line = i + 1;
    const shape = splitPragma(text);
    // A bare marker with no rule at all is not a pragma anybody wrote by
    // mistake; it is prose, and reporting it would fire on this module's own
    // documentation.
    if (!shape) continue;

    // Three ways a pragma this module can see is still not one it will honour.
    // All of them REPORT: every refusal above this point is prose that never
    // claimed to be a pragma, and every refusal below it is somebody's waiver,
    // which must never disappear without a word.
    //
    // A terminator this split does not split on means the string is not one
    // line, and every finding in the file then reports as line 1 with one
    // pragma reaching all of them: measured for CR and again for U+2028, a tree
    // disabling TLS verification 400 lines below an unrelated waiver PASSED the
    // gate. Refusing leaves the finding reported, which is the only safe
    // direction for an off switch. Asked of the RAW line, because a separator
    // that appears only before the pragma never reaches the pragma text.
    //
    // The control-character check runs on the pragma text, so it covers the
    // rule id and the reason together. Both are file content and both are
    // printed to a terminal by `scan` and `gate`, so a reason of
    // `ok<ESC>[2K<CR>FORGED` erases the line the scanner just wrote and prints
    // its own. Nothing before this feature put file text on that surface at all.
    const issue = UNSPLIT_TERMINATOR.test(raw)
      ? 'this line does not end the way the scanner reads line endings, so the pragma on it has no end;'
        + ' save the file with LF or CRLF line endings'
      : CONTROL.test(text)
        ? 'a waiver must be plain text; remove the control character from this one'
        : !shape.reason
          ? 'a waiver needs a reason: cryptoserve-ignore <rule> -- <why>'
          : null;

    if (issue) {
      // The offending line is quoted back, so it is stripped of the characters
      // that made it a problem rather than carried out of this module for
      // whoever reads the report to print. Capped for the same reason `evidence`
      // is: on a file with no line endings, "the line" is the whole file.
      malformed.push({ line, text: stripControl(raw.trim()).slice(0, 120), issue });
      continue;
    }

    waivers.push({ rule: shape.rule, reason: shape.reason, line, used: false });
  }

  return { waivers, malformed };
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
  for (const w of waivers) {
    if (w.rule !== rule) continue;
    if (line < w.line || line > w.line + PRAGMA_REACH) continue;
    w.used = true;
    return w;
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
