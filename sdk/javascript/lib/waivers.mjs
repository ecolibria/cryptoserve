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

const SEPARATOR = '--';

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
  return readPragma(rawLine, openers).honoured;
}

/**
 * What a line says about a pragma: the text of one this module will honour, and
 * separately the text of one it will REFUSE because the marker is not the first
 * thing in its comment.
 *
 * The refusal is returned rather than discarded because refusing in silence is
 * its own defect. A trailing pragma on a line that already contains a `//` -- a
 * URL, or an anti-pattern quoted inside a doc block -- is not the first thing in
 * its comment, so it does nothing, and a user watching a `critical` they just
 * waived stay red has nothing to go on. Measured on real trees, that shape is
 * most of the trailing pragmas anyone would actually write.
 */
function readPragma(rawLine, openers) {
  const afterMarker = (s) =>
    s.startsWith(MARKER) ? s.slice(MARKER.length).replace(/^[ \t]+/, '') : null;

  // Every place the marker directly follows an opener, so a refusal can be
  // told apart from prose that merely contains the word.
  const laterPragma = (from) => {
    for (let i = from; i < rawLine.length; i++) {
      for (const tok of openers) {
        if (!rawLine.startsWith(tok, i)) continue;
        let after = i + tok.length;
        while (rawLine[after] === tok[tok.length - 1]) after++;
        const text = afterMarker(rawLine.slice(after).replace(/^[ \t]+/, ''));
        if (text !== null) return text;
      }
    }
    return null;
  };

  // A JSDoc continuation is decoration, not an opener: the comment began on an
  // earlier line, so this line's text starts right after the `*`. The marker
  // must follow it DIRECTLY. Anything else there, including a further `//`, is
  // an example being shown rather than a pragma being written, which is what
  // this module's own header contains.
  const continuation = /^[ \t]*\*(?!\/)[ \t]*/.exec(rawLine);
  if (continuation) {
    const honoured = afterMarker(rawLine.slice(continuation[0].length));
    return honoured !== null
      ? { honoured, refused: null }
      : { honoured: null, refused: laterPragma(continuation[0].length) };
  }

  let at = -1;
  let opener = '';
  for (const tok of openers) {
    const i = rawLine.indexOf(tok);
    if (i !== -1 && (at === -1 || i < at)) { at = i; opener = tok; }
  }
  if (at === -1) return { honoured: null, refused: null };

  // An opener sitting DIRECTLY after a quote is a comment opener inside a
  // string literal, which is how a test fixture or a documentation sample
  // spells one: `'// cryptoserve-ignore rule -- why'`. Without this, scanning
  // this scanner's own test suite reported 28 waiver problems against fixture
  // data. It errs safe in the one ambiguous direction: a real trailing pragma
  // written with no space after a string (`const s = "a"// cryptoserve-ignore`)
  // is refused, which leaves the finding reported rather than suppressed.
  if (at > 0 && '\'"`'.includes(rawLine[at - 1])) return { honoured: null, refused: null };

  // Repeated opener characters (`///`, `/**`, `##`) are still one opener.
  let after = at + opener.length;
  while (rawLine[after] === opener[opener.length - 1]) after++;

  const honoured = afterMarker(rawLine.slice(after).replace(/^[ \t]+/, ''));
  return honoured !== null
    ? { honoured, refused: null }
    : { honoured: null, refused: laterPragma(after) };
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
  const refused = [];
  if (!openers || !content.includes(MARKER)) return { waivers, malformed, refused };

  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    // A CRLF file leaves a trailing CR on every line. It needs no stripping
    // here: `splitPragma` trims the reason and a lone CR cannot end up inside a
    // rule id, so an explicit strip made no input behave differently. Mutation
    // testing proved that by removing one and killing nothing, and a defence no
    // test can tell from its absence is not a defence. CRLF stays covered by
    // tests either way.
    const raw = lines[i];
    if (!raw.includes(MARKER)) continue;

    const line = i + 1;
    const read = readPragma(raw, openers);

    if (read.honoured === null) {
      // Not the first thing in its comment. Recorded so it can be reported IF
      // it names a real rule; a placeholder like `<rule-id>` in prose is
      // documentation and stays silent.
      const shape = read.refused === null ? null : splitPragma(read.refused);
      if (shape) refused.push({ line, rule: shape.rule, text: raw.trim() });
      continue;
    }

    const shape = splitPragma(read.honoured);
    // A bare marker with no rule at all is not a pragma anybody wrote by
    // mistake; it is prose, and reporting it would fire on this module's own
    // documentation.
    if (!shape) continue;

    if (shape.reason) {
      waivers.push({ rule: shape.rule, reason: shape.reason, line, used: false });
    } else {
      malformed.push({
        line,
        text: raw.trim(),
        issue: 'a waiver needs a reason: cryptoserve-ignore <rule> -- <why>',
      });
    }
  }

  return { waivers, malformed, refused };
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
export function waiverWarnings(waivers, malformed, refused, knownRules, file) {
  const warnings = [];

  for (const m of malformed) {
    warnings.push({ file, line: m.line, kind: 'malformed', detail: m.issue, text: m.text });
  }

  // Only when it names a REAL rule. A doc example writing `<rule-id>` is
  // documentation and must stay silent, or this module's own header becomes a
  // warning on every scan.
  for (const r of refused) {
    if (!knownRules.has(r.rule)) continue;
    warnings.push({
      file,
      line: r.line,
      kind: 'not-honoured',
      detail: 'a pragma must be the first thing in its comment, and this line opens a comment earlier'
        + ' (a URL, or a doc block); move it to its own line above the finding',
      rule: r.rule,
      text: r.text,
    });
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
