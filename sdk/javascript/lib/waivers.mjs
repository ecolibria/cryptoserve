/**
 * Per-finding waivers, written as a comment pragma next to the code they cover.
 *
 *     // cryptoserve-ignore misuse/node-tls-reject-unauthorized -- documents the anti-pattern
 *     const forbidden = "process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0";
 *
 * Until this existed, a false `critical` could not be cleared at all:
 * `--max-severity` only tightens and refuses `high`/`critical` by name,
 * `--allow-secrets` does not reach misuse, and `.cryptoserve.json` offers only
 * `skipDirs`, which excludes a whole directory to silence one line. A tool
 * whose false positives are unresolvable gets excluded entirely, so the absence
 * of this was itself a security defect.
 *
 * Four decisions worth stating, because a waiver is a security control's off
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

/** `<rule-id> -- <reason>`, applied to a line already reduced to its pragma. */
const PRAGMA = /^(\S+)(?:[ \t]*--[ \t]*(.*?))?[ \t]*(?:\*\/)?[ \t]*$/;

/**
 * The text a line carries AFTER its first comment opener, or null if the marker
 * is not the first thing in that comment.
 *
 * "First thing in the comment" is the rule, not "somewhere in a comment", and
 * it has to be decided by finding the FIRST opener rather than by matching any
 * opener that happens to precede the marker. A doc block that shows an example
 * is the case that separates the two:
 *
 *      *     // cryptoserve-ignore misuse/create-cipher -- an example
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
    // A trailing CR from a CRLF file is line terminator, not pragma text. Left
    // in place it lands in the reason and breaks the end-of-line anchor.
    const raw = lines[i].replace(/\r$/, '');
    if (!raw.includes(MARKER)) continue;

    const text = pragmaText(raw, openers);
    if (text === null) continue;   // a mention, not a pragma

    const line = i + 1;
    const m = PRAGMA.exec(text);
    const reason = m && m[2] ? m[2].trim() : '';
    if (m && reason) {
      waivers.push({ rule: m[1], reason, line, used: false });
    } else if (m) {
      malformed.push({
        line,
        text: raw.trim(),
        issue: 'a waiver needs a reason: cryptoserve-ignore <rule> -- <why>',
      });
    }
    // A bare marker with no rule at all is not a pragma anybody wrote by
    // mistake; it is prose. Reporting it as malformed would fire on this
    // module's own documentation.
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
