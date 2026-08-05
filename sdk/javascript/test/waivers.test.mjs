import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseWaiverPragmas, findWaiver, waiverWarnings } from '../lib/waivers.mjs';

/**
 * A waiver is a security control's off switch, so these test what it refuses to
 * do at least as much as what it does.
 */

const KNOWN = new Set(['misuse/create-cipher', 'misuse/node-tls-reject-unauthorized']);

const parse = (src, language = 'javascript') => parseWaiverPragmas(src, language);

/**
 * The marker, assembled rather than written out.
 *
 * A few fixtures below put a comment opener after whitespace INSIDE a string
 * (`'a; // cryptoserve-ignore ...'`), which is the shape the parser knowingly
 * cannot tell from a real comment. Spelled literally, those lines make this
 * file's own source look like it carries live pragmas, and scanning this
 * repository reports them as unused waivers. Building the marker at runtime
 * gives the tests the exact same input without lying to a scanner about what
 * this file contains.
 */
const IGNORE = 'cryptoserve' + '-ignore';

describe('parseWaiverPragmas', () => {
  it('reads rule and reason from a line comment', () => {
    const { waivers, malformed } = parse('// cryptoserve-ignore misuse/create-cipher -- legacy fixture\ncode;\n');
    assert.deepEqual(malformed, []);
    assert.equal(waivers.length, 1);
    assert.equal(waivers[0].rule, 'misuse/create-cipher');
    assert.equal(waivers[0].reason, 'legacy fixture');
    assert.equal(waivers[0].line, 1);
  });

  it('reads a pragma from a trailing comment and keeps the code line number', () => {
    const { waivers } = parse(`a;\nb; // ${IGNORE} misuse/create-cipher -- why\n`);
    assert.equal(waivers.length, 1);
    assert.equal(waivers[0].line, 2);
  });

  it('attributes a pragma inside a block comment to its own line', () => {
    // Not to the line the comment opened on. The pragma covers the code below
    // ITS line.
    const { waivers } = parse('/*\n * cryptoserve-ignore misuse/create-cipher -- why\n */\ncode;\n');
    assert.equal(waivers.length, 1);
    assert.equal(waivers[0].line, 2);
  });

  it('strips a block comment terminator off the reason', () => {
    const { waivers } = parse('/* cryptoserve-ignore misuse/create-cipher -- the reason */\n');
    assert.equal(waivers[0].reason, 'the reason');
  });

  it('rejects a pragma with no reason', () => {
    const { waivers, malformed } = parse('// cryptoserve-ignore misuse/create-cipher\n');
    assert.deepEqual(waivers, []);
    assert.equal(malformed.length, 1);
    assert.match(malformed[0].issue, /needs a reason/);
  });

  it('rejects a pragma with an empty reason after the separator', () => {
    // `--` followed by nothing is a reason field that was typed and left blank,
    // which is the same amount of audit trail as omitting it.
    const { waivers, malformed } = parse('// cryptoserve-ignore misuse/create-cipher --\n');
    assert.deepEqual(waivers, []);
    assert.equal(malformed.length, 1);
  });

  it('ignores a bare marker with no rule at all', () => {
    const { waivers, malformed } = parse('// cryptoserve-ignore\n');
    assert.deepEqual(waivers, []);
    assert.deepEqual(malformed, []);
  });

  it('ignores a pragma that is not behind a comment opener', () => {
    // A pragma written in a string literal, a JSON blob or a fixture's expected
    // output is text, not an instruction. Without this, data a project merely
    // CONTAINS could switch a check off.
    for (const src of [
      'const s = "cryptoserve-ignore misuse/create-cipher -- from a string";\n',
      'const t = `cryptoserve-ignore misuse/create-cipher -- from a template`;\n',
      '{ "note": "cryptoserve-ignore misuse/create-cipher -- from JSON" }\n',
      'cryptoserve-ignore misuse/create-cipher -- bare, no comment at all\n',
    ]) {
      const { waivers, malformed } = parse(src);
      assert.deepEqual(waivers, [], src);
      assert.deepEqual(malformed, [], src);
    }
  });

  it('ignores an opener that sits directly inside a string', () => {
    // How a test fixture or a documentation sample spells a comment. Without
    // this, scanning this scanner's own test suite reported 28 waiver problems
    // against fixture data. Found by mutation testing: removing the guard left
    // nothing failing.
    for (const src of [
      'const s = "// cryptoserve-ignore misuse/create-cipher -- fixture text";\n',
      "const s = '// cryptoserve-ignore misuse/create-cipher -- fixture text';\n",
      'const s = `// cryptoserve-ignore misuse/create-cipher -- fixture text`;\n',
      "const s = '# cryptoserve-ignore misuse/create-cipher -- fixture text';\n",
    ]) {
      const language = src.includes('#') ? 'python' : 'javascript';
      const { waivers, malformed } = parse(src, language);
      assert.deepEqual(waivers, [], src);
      assert.deepEqual(malformed, [], src);
    }
  });

  it('reads the FIRST comment opener on the line, not the last', () => {
    // Otherwise a comment that shows a pragma later in the same line becomes
    // one. The first opener wins, so everything after it is that comment's
    // text, and text that does not begin with the marker is prose. Found by
    // mutation testing.
    for (const src of [
      '// see /* cryptoserve-ignore misuse/create-cipher -- why\n',
      '// example: // cryptoserve-ignore misuse/create-cipher -- why\n',
    ]) {
      const { waivers, malformed } = parse(src);
      assert.deepEqual(waivers, [], src);
      assert.deepEqual(malformed, [], src);
    }
  });

  it('reports a separator that is missing or misspelled', () => {
    // `<rule> <reason>` with no `--`, or with a single hyphen or a colon, used
    // to produce no waiver AND no report: the pragma vanished and the finding
    // stayed red with nothing to explain it. The docs promise malformed says so.
    for (const src of [
      '// cryptoserve-ignore misuse/create-cipher a reason with no separator\n',
      '// cryptoserve-ignore misuse/create-cipher - single hyphen\n',
      '// cryptoserve-ignore misuse/create-cipher : colon\n',
    ]) {
      const { waivers, malformed } = parse(src);
      assert.deepEqual(waivers, [], src);
      assert.equal(malformed.length, 1, `${src} -> ${JSON.stringify(malformed)}`);
    }
  });

  it('ignores a pragma that is not the first thing in its comment, in silence', () => {
    // The documented limitation, pinned in both of its halves. A line that
    // opened a comment earlier gives its FIRST opener to that comment, so a
    // pragma at the end of it is text rather than an instruction.
    //
    // Silence is the deliberate part. Diagnosing this shape needs to know where
    // the comment really begins, which is a parse this module does not do: the
    // version that guessed it by re-walking the line was quadratic in the line
    // length and reported documentation that quoted a rule id as a broken
    // waiver. If that ever becomes diagnosable, it will be from a real parse,
    // and this test is the record of what was traded for removing it.
    const { waivers, malformed } = parse(`const u = "http://x"; // ${IGNORE} misuse/create-cipher -- why\n`);
    assert.deepEqual(waivers, [], 'the limitation changed; update the module docs with it');
    assert.deepEqual(malformed, []);
  });

  it('parses a long reason in linear time', () => {
    // The regex this replaced backtracked cubically on its tail: one comment
    // line carrying `-- r` and 4KB of trailing whitespace took 7.8 SECONDS to
    // reject, against 2ms before the feature existed, and no finding had to
    // exist in the tree to trigger it. A scanner one crafted comment can hang
    // is a denial of service on every CI job that runs it.
    const time = (n) => {
      const src = '// cryptoserve-ignore misuse/create-cipher -- r' + ' '.repeat(n) + 'x';
      const t = process.hrtime.bigint();
      parseWaiverPragmas(src, 'javascript');
      return Number(process.hrtime.bigint() - t) / 1e6;
    };
    time(4000);
    assert.ok(time(4000) < 200, `4KB of trailing whitespace took ${time(4000).toFixed(0)}ms`);
    assert.ok(time(16000) < 200, `16KB of trailing whitespace took ${time(16000).toFixed(0)}ms`);
  });

  it('ignores prose that merely mentions the marker', () => {
    // Found by running the scanner over its own source: every comment in this
    // repository that DESCRIBES the pragma was being parsed as one, and each
    // reported itself as malformed, unused, or naming a rule that does not
    // exist. Prose about a security control must not be able to operate it.
    for (const src of [
      '// with a cryptoserve-ignore misuse/create-cipher pragma -- see the docs\n',
      '// The format is `cryptoserve-ignore misuse/create-cipher -- why`.\n',
      '// Docs: cryptoserve-ignore <rule-id> -- <reason>, one per line\n',
      '/**\n *     // cryptoserve-ignore misuse/create-cipher -- an EXAMPLE in a doc block\n */\n',
    ]) {
      const { waivers, malformed } = parse(src);
      assert.deepEqual(waivers, [], src);
      assert.deepEqual(malformed, [], src);
    }
  });

  it('reads every documented spelling', () => {
    // The other direction of the same rule. Refusing prose must not stop the
    // documented forms from working.
    for (const src of [
      '// cryptoserve-ignore misuse/create-cipher -- why\n',
      '//cryptoserve-ignore misuse/create-cipher -- why\n',
      '// cryptoserve-ignore misuse/create-cipher   --   why\n',
      '/* cryptoserve-ignore misuse/create-cipher -- why */\n',
      '/** cryptoserve-ignore misuse/create-cipher -- why */\n',
      '/*\n * cryptoserve-ignore misuse/create-cipher -- why\n */\n',
      `code(); // ${IGNORE} misuse/create-cipher -- why\n`,
      `    // ${IGNORE} misuse/create-cipher -- why\n`,
    ]) {
      const { waivers, malformed } = parse(src);
      assert.equal(waivers.length, 1, `${src} -> ${JSON.stringify({ waivers, malformed })}`);
      assert.equal(waivers[0].rule, 'misuse/create-cipher');
      assert.equal(waivers[0].reason, 'why');
    }
  });

  it('records the shape this heuristic knowingly cannot refuse', () => {
    // Recognising a comment by its opener is a heuristic, not a parse. A string
    // that both begins with a comment opener AND ends the line with pragma text
    // is honoured. Reaching this needs a real per-language parser, which this
    // package cannot have while it stays dependency-free.
    //
    // Pinned rather than hidden: if it ever starts being refused, this test
    // fails and the documented limitation is stale. It is acceptable because a
    // waiver is authored by whoever can already edit the file, so anyone able
    // to smuggle one could simply write the comment instead.
    const { waivers } = parse(`const s = " // ${IGNORE} misuse/create-cipher -- smuggled";\n`);
    assert.equal(waivers.length, 1, 'the documented limitation changed; update the docs with it');
  });

  it('reads a Python pragma from a # comment', () => {
    const { waivers } = parse('# cryptoserve-ignore misuse/create-cipher -- why\n', 'python');
    assert.equal(waivers.length, 1);
    assert.equal(waivers[0].reason, 'why');
  });

  it('does not read a JavaScript comment opener in a Python file', () => {
    assert.deepEqual(parse('// cryptoserve-ignore misuse/create-cipher -- why\n', 'python').waivers, []);
    assert.deepEqual(parse('# cryptoserve-ignore misuse/create-cipher -- why\n', 'javascript').waivers, []);
  });

  it('keeps a reason that itself contains a double hyphen', () => {
    const { waivers } = parse('// cryptoserve-ignore misuse/create-cipher -- see RFC 5280 -- section 6\n');
    assert.equal(waivers[0].reason, 'see RFC 5280 -- section 6');
  });

  it('does not leave a CR in the rule id of a CRLF pragma', () => {
    // A reason-less pragma on a CRLF line must still report as needing a reason
    // rather than as naming a rule that does not exist, which is what a stray
    // CR inside the rule id would produce.
    const { malformed, waivers } = parse('// cryptoserve-ignore misuse/create-cipher\r\n');
    assert.deepEqual(waivers, []);
    assert.equal(malformed.length, 1, JSON.stringify(malformed));
    assert.match(malformed[0].issue, /needs a reason/);
  });

  it('handles CRLF line endings', () => {
    const { waivers } = parse('// cryptoserve-ignore misuse/create-cipher -- why\r\ncode;\r\n');
    assert.equal(waivers.length, 1);
    assert.equal(waivers[0].reason, 'why');
  });

  it('honours nothing on a string the newline split did not actually split', () => {
    // A file separated by something other than a newline arrives here whole, so
    // `split('\n')` hands back one line. Every finding in it is then line 1,
    // inside the reach of any pragma at the top, and one waiver covers the
    // entire file: a tree disabling TLS verification 400 lines down PASSED the
    // gate behind an unrelated waiver. A red gate turning green is the one
    // direction that must never happen.
    //
    // Swept rather than fixed one byte at a time. CR was the reported shape and
    // U+2028 reproduced it exactly, so a guard written for CR alone would have
    // left that live; a guard written for those two still let VT, FF and NEL
    // through. The whole Unicode line-terminator family, minus the newline the
    // split already handles.
    //
    // The pragma goes LAST as well as first, because the control-character rule
    // reads the pragma text: a separator that appears only before the pragma
    // never reaches it, and that is exactly how the second gap was found.
    const seps = ['\r', '\u000b', '\u000c', '\u0085', '\u2028', '\u2029'];
    for (const sep of seps) {
      const pragma = '// cryptoserve-ignore misuse/create-cipher -- why';
      const code = Array.from({ length: 40 }, (_, i) => `const f${i} = ${i};`);
      for (const src of [[pragma].concat(code).join(sep), code.concat([pragma]).join(sep)]) {
        const { waivers, malformed } = parse(src);
        assert.deepEqual(waivers, [], `${JSON.stringify(sep)} -> ${JSON.stringify(waivers)}`);
        // Refused, not dropped. Past the point where a line looks like a
        // pragma, silence is the failure this module is trying not to be.
        assert.equal(malformed.length, 1, `${JSON.stringify(sep)} -> ${JSON.stringify(malformed)}`);
        // The RIGHT refusal, not just any refusal. Without this, the message
        // could drift to "needs a reason" and the test would stay green while
        // telling a user with a CR-only file to go and look at the wrong thing.
        assert.match(malformed[0].issue, /line ending/,
          `${JSON.stringify(sep)} -> ${malformed[0].issue}`);
        // "The line" here is the whole file, so the quote-back is capped the
        // same way `evidence` is rather than carrying a megabyte into a report.
        assert.ok(src.length > 200, 'the fixture stopped being long enough to test the cap');
        assert.ok(malformed[0].text.length <= 120, `quoted ${malformed[0].text.length} characters back`);
      }
    }
  });

  it('honours nothing on a mixed CR and LF line', () => {
    // The same refusal has to hold for one bad line in an otherwise normal
    // file, not just for a file that is CR-only throughout.
    const { waivers, malformed } = parse(`a;\nb;\rc; // ${IGNORE} misuse/create-cipher -- why\nd;\n`);
    assert.deepEqual(waivers, [], JSON.stringify(waivers));
    assert.equal(malformed.length, 1, JSON.stringify(malformed));
    assert.equal(malformed[0].line, 2);
  });

  it('honours nothing when the terminator is on a line the pragma merely COVERS', () => {
    // The guard this replaced was asked only of lines that CONTAINED the
    // marker, because the loop skipped every other line first. So it only ever
    // inspected the pragma's OWN line. Put the pragma on a clean LF-terminated
    // line 1 and separate the BODY with any non-LF terminator, and the whole
    // body collapses into LF-line 2, inside `PRAGMA_REACH`: `gate` went from
    // exit 1 to exit 0, `waived 1`, and `waiverWarnings` EMPTY. No warning of
    // any kind, which is the half that made it critical rather than wrong.
    //
    // Three rounds each widened the character class and each was defeated,
    // because the axis that was pinned was never the byte: it was WHICH LINE
    // gets asked. This is now decided once per FILE, so there is no other line
    // left to move the terminator to.
    const pragma = `// ${IGNORE} misuse/create-cipher -- unrelated`;
    for (const cp of [0x0b, 0x0c, 0x0d, 0x85, 0x2028, 0x2029]) {
      const sep = String.fromCodePoint(cp);
      const body = Array.from({ length: 40 }, (_, i) => `const f${i} = ${i};`).join(sep);
      const what = 'U+' + cp.toString(16).toUpperCase().padStart(4, '0');
      const { waivers, malformed } = parse(`${pragma}\n${body}\n`);
      assert.deepEqual(waivers, [], `${what} -> ${JSON.stringify(waivers)}`);
      assert.equal(malformed.length, 1, `${what} -> ${JSON.stringify(malformed)}`);
      assert.match(malformed[0].issue, /line ending/, `${what} -> ${malformed[0].issue}`);
      // The line REPORTED is the one carrying the terminator, not the pragma's.
      // A refusal that pointed at the pragma would send a user to edit the one
      // line in the file that is fine.
      assert.equal(malformed[0].line, 2, `${what} -> line ${malformed[0].line}`);
    }
  });

  it('does not take a block-comment continuation in a language with no block comments', () => {
    // `pragmaText` took its continuation branch on any line matching
    // /^[ \t]*\*(?!\/)[ \t]*/, BEFORE the opener scan and WITHOUT consulting
    // the language's openers. `*` is not a comment character in Python at all,
    // so a docstring quoting the JavaScript spelling switched off a Python
    // check -- the module's stated property, falsified by a documentation
    // sample. The branch is now gated on the language actually having the
    // opener it is a continuation OF.
    const src = [
      'import ssl',
      'DOC = """',
      ` * ${IGNORE} misuse/create-cipher -- an example copied from the JS docs`,
      '"""',
      'ctx = ssl.SSLContext()',
    ].join('\n') + '\n';
    const { waivers, malformed } = parse(src, 'python');
    assert.deepEqual(waivers, [], JSON.stringify(waivers));
    assert.deepEqual(malformed, [], JSON.stringify(malformed));
  });

  it('records the C-family shapes this heuristic still cannot refuse', () => {
    // Gating the continuation branch on the opener set fixes the languages that
    // have no block comment. It cannot fix the C family, where ` * pragma` in a
    // template literal and a comment continuation are the same characters, and
    // telling them apart needs a real parse.
    //
    // Pinned so the documented limitation cannot drift silently, and so nobody
    // reads the Python fix above as closing the whole class. Both of these
    // still produce a waiver:
    const templateLiteral = `const doc = \`\n * ${IGNORE} misuse/create-cipher -- smuggled\n\`;\n`;
    assert.equal(parse(templateLiteral).waivers.length, 1,
      'the template-literal limitation changed; update the docs with it');

    // And one space between the quote and the opener defeats the adjacency
    // guard, which reads only the character immediately before the opener.
    const spacedInString = `const s = " // ${IGNORE} misuse/create-cipher -- smuggled";\n`;
    assert.equal(parse(spacedInString).waivers.length, 1,
      'the quote-adjacency limitation changed; update the docs with it');
  });

  it('records that a language with no block comments is not exempt either', () => {
    // The module claimed the opposite, and this is the third distinct shape to
    // falsify a version of that claim. Gating the continuation branch fixed the
    // `*` spelling in Python and was written up as "in a language with no block
    // comments, contained data cannot operate the control AT ALL". It cannot:
    // the FIRST-OPENER scan reaches Python too, and `#` is an opener there, so
    // any string containing one followed by the marker is read as a pragma.
    //
    // The quote-adjacency guard does not help. It reads exactly one character
    // before the opener, and in the shape below that character is `p`, not a
    // quote. Found by adversarial review of the fix for the `*` spelling.
    //
    // Pinned, not fixed. Refusing this needs to know where a Python string
    // really ends, which is the parse this module does not do, and three
    // rounds of widening the heuristic each ended in another shape like this
    // one. What is defended instead is that it is never SILENT, which the
    // assertions below hold to.
    const urlFragment =
      `SETUP = "https://vendor.example/tls/setup#${IGNORE} misuse/python-cert-none -- documented"\n`;
    const { waivers, malformed } = parse(urlFragment, 'python');
    assert.equal(waivers.length, 1,
      'the Python string limitation changed; update the docs and this test together');
    assert.deepEqual(malformed, []);

    // `parseWaiverPragmas` returns waivers unused by construction; whether the
    // finding is REPORTED is a property of the scan, and `scanner.test.mjs`
    // measures it there rather than here. Asserting `used === false` at this
    // point would only restate how this function initialises the field.
    assert.equal(waivers[0].rule, 'misuse/python-cert-none');
  });

  it('records that a continuation line needs no comment opener at all', () => {
    // The third shape to falsify a bounded version of the module's claim, and
    // the reason the claim now carries no bound. Requiring "a comment opener
    // followed by the marker" excluded this one: the continuation branch runs
    // BEFORE the opener scan, so a line inside a multi-line string operates
    // the control with no opener anywhere on it.
    //
    // Not JavaScript-specific, which is what the earlier wording implied by
    // naming template literals. The branch is gated on the LANGUAGE having
    // block comments, so a Go or Rust raw string and a Java text block all
    // reach it. Pinned in Go, because the previous wording said "backtick-
    // delimited" as though that were a JavaScript-only spelling.
    const go = [
      'package main',
      'var doc = `',
      ` * ${IGNORE} misuse/tls-verify-disabled -- smuggled through a raw string\``,
      'var c = &tls.Config{InsecureSkipVerify: true}',
    ].join('\n') + '\n';
    const { waivers } = parse(go, 'go');
    assert.equal(waivers.length, 1,
      'the raw-string continuation limitation changed; update the docs and this test together');
    assert.equal(waivers[0].rule, 'misuse/tls-verify-disabled');

    // And the language gate still holds in the other direction: Python has no
    // block comment, so the same line is not a continuation there.
    const py = `DOC = """\n * ${IGNORE} misuse/python-cert-none -- example\n"""\n`;
    assert.deepEqual(parse(py, 'python').waivers, []);
  });

  it('stays linear in the length of one line', () => {
    // Walking every start index of an opener run to find a later pragma was
    // quadratic in the line: `// x cryptoserve-ignore ` followed by N slashes
    // ran 119 / 405 / 1589 ms at N = 10k / 20k / 40k, a clean 4x per doubling,
    // and a 200KB single line took 42 SECONDS through `gate`, which has no
    // timeout. The same input took 0.2ms before that walk existed. One crafted
    // comment must not be able to hang every CI job that runs this scanner.
    const time = (n) => {
      const src = '// x cryptoserve-ignore ' + '/'.repeat(n) + '\n';
      const t = process.hrtime.bigint();
      parseWaiverPragmas(src, 'javascript');
      return Number(process.hrtime.bigint() - t) / 1e6;
    };
    time(10000);                      // warm up, so JIT does not skew the ratio
    const small = Math.max(time(10000), 1);
    const large = time(40000);
    assert.ok(large < small * 12,
      `4x the line took ${(large / small).toFixed(1)}x the time (${small.toFixed(1)}ms -> ${large.toFixed(1)}ms)`);
  });

  it('refuses a reason carrying a control character', () => {
    // The reason is file content, and both `scan` and `gate` print it to a
    // terminal. Left raw, a file in the scanned tree can erase and rewrite the
    // scanner's own output: `-- ok\x1b[2K\rFORGED` prints as `FORGED`. Nothing
    // before this feature put file text on that surface. Reported rather than
    // stripped, so the pragma waives nothing and the finding stays red.
    for (const ctrl of ['\x1b[2K', '\x07', '\x7f', '\u009b2K', '\b']) {
      const { waivers, malformed } = parse(`// cryptoserve-ignore misuse/create-cipher -- ok${ctrl}FORGED\n`);
      assert.deepEqual(waivers, [], JSON.stringify(ctrl));
      assert.equal(malformed.length, 1, `${JSON.stringify(ctrl)} -> ${JSON.stringify(malformed)}`);
      // The report quotes the offending line back, so it must not carry the
      // character that made the line a problem out to whoever prints it.
      assert.ok(!/[\u0000-\u0008\u000a-\u001f\u007f-\u009f]/.test(malformed[0].text),
        `the report carried ${JSON.stringify(ctrl)} back out: ${JSON.stringify(malformed[0].text)}`);
    }
  });

  it('refuses a reason carrying a bidi or isolate override', () => {
    // The same question as the control-character rule above, asked of the
    // characters that answer it differently. An override is not a control
    // character, so a class covering C0, DEL and C1 does not reach it, and it
    // controls terminal rendering just as effectively: RLO reverses the display
    // order of everything after it, so the reason a reviewer READS is not the
    // reason the file HOLDS. The reason is the only part of a waiver a reviewer
    // can disagree with, which makes an audit trail that renders differently
    // from its source the whole failure.
    //
    // Built with fromCodePoint rather than written as literals: an override is
    // invisible in a diff, so a literal here would be a fixture nobody can
    // review.
    const OVERRIDES = [0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069];
    for (const cp of OVERRIDES) {
      const ch = String.fromCodePoint(cp);
      const src = `// cryptoserve-ignore misuse/create-cipher -- ok${ch}degrof\n`;
      const { waivers, malformed } = parse(src);
      const name = `U+${cp.toString(16).toUpperCase()}`;
      assert.deepEqual(waivers, [], `${name} was honoured`);
      assert.equal(malformed.length, 1, `${name} -> ${JSON.stringify(malformed)}`);
      // The report quotes the line back, so it must not carry the character
      // that made the line a problem out to whoever prints it.
      assert.ok(!malformed[0].text.includes(ch),
        `the report carried ${name} back out: ${JSON.stringify(malformed[0].text)}`);
    }
  });

  it('keeps a reason carrying ordinary right-to-left text', () => {
    // The other direction, and the reason the rule names the OVERRIDES rather
    // than everything bidirectional. Hebrew and Arabic letters carry their own
    // direction and forge nothing; refusing them would make a whole class of
    // legitimate reason unwritable.
    const { waivers, malformed } = parse(
      '// cryptoserve-ignore misuse/create-cipher -- מפתח בדיקה בלבד\n',
    );
    assert.deepEqual(malformed, []);
    assert.equal(waivers.length, 1);
  });

  it('keeps a reason carrying a tab', () => {
    // The other direction. A tab is a control character that renders as
    // whitespace and forges nothing, and refusing it would turn an ordinary
    // reason into a malformed pragma.
    const { waivers, malformed } = parse('// cryptoserve-ignore misuse/create-cipher -- see\tthe RFC\n');
    assert.deepEqual(malformed, []);
    assert.equal(waivers.length, 1);
    assert.equal(waivers[0].reason, 'see\tthe RFC');
  });

  it('stays linear in the number of pragma lines', () => {
    // Resolving each pragma's line by counting newlines from the start of the
    // file made this quadratic: 8,000 pragma lines took 258ms and 1MB of them
    // took 1.5 seconds inside a single scanProject call. Found by adversarial
    // review. The bound is loose on purpose, because a tight one turns a slow
    // CI machine into a red build; quadratic growth blows through it either way.
    const time = (n) => {
      const src = '// cryptoserve-ignore misuse/create-cipher -- r\n'.repeat(n);
      const t = process.hrtime.bigint();
      parseWaiverPragmas(src, 'javascript');
      return Number(process.hrtime.bigint() - t) / 1e6;
    };
    time(2000);                       // warm up, so JIT does not skew the ratio
    const small = Math.max(time(2000), 1);
    const large = time(16000);
    assert.ok(large < small * 24,
      `8x the input took ${(large / small).toFixed(1)}x the time (${small.toFixed(1)}ms -> ${large.toFixed(1)}ms)`);
  });
});

describe('findWaiver', () => {
  const waiversAt = (line) => [{ rule: 'r', reason: 'why', line, used: false }];

  it('covers its own line and the next one', () => {
    assert.ok(findWaiver(waiversAt(10), 'r', 10));
    assert.ok(findWaiver(waiversAt(10), 'r', 11));
  });

  it('does not reach two lines down, or the line above', () => {
    assert.equal(findWaiver(waiversAt(10), 'r', 12), null);
    assert.equal(findWaiver(waiversAt(10), 'r', 9), null);
  });

  it('does not cover a different rule on the right line', () => {
    assert.equal(findWaiver(waiversAt(10), 'other', 10), null);
  });

  it('has no wildcard', () => {
    assert.equal(findWaiver([{ rule: '*', reason: 'w', line: 10, used: false }], 'r', 10), null);
  });

  it('marks the waiver used only when it covered something', () => {
    const hit = waiversAt(10);
    findWaiver(hit, 'r', 10);
    assert.equal(hit[0].used, true);

    const miss = waiversAt(10);
    findWaiver(miss, 'r', 99);
    assert.equal(miss[0].used, false);
  });
});

describe('waiverWarnings', () => {
  it('reports a rule id no rule uses', () => {
    const waivers = [{ rule: 'misuse/typo', reason: 'why', line: 3, used: false }];
    const warnings = waiverWarnings(waivers, [], KNOWN, 'app.js');
    assert.equal(warnings.length, 1);
    assert.equal(warnings[0].kind, 'unknown-rule');
    assert.equal(warnings[0].file, 'app.js');
    assert.equal(warnings[0].line, 3);
  });

  it('reports an unknown rule ONLY as unknown, not also as unused', () => {
    // Two warnings for one typo reads as two problems. The rule not existing is
    // the reason it covered nothing, so it is one finding.
    const waivers = [{ rule: 'misuse/typo', reason: 'why', line: 3, used: false }];
    const warnings = waiverWarnings(waivers, [], KNOWN, 'app.js');
    assert.equal(warnings.filter(w => w.kind === 'unused').length, 0);
  });

  it('reports a known rule that covered nothing', () => {
    const waivers = [{ rule: 'misuse/create-cipher', reason: 'why', line: 3, used: false }];
    const warnings = waiverWarnings(waivers, [], KNOWN, 'app.js');
    assert.equal(warnings.length, 1);
    assert.equal(warnings[0].kind, 'unused');
  });

  it('says nothing about a waiver that did its job', () => {
    const waivers = [{ rule: 'misuse/create-cipher', reason: 'why', line: 3, used: true }];
    assert.deepEqual(waiverWarnings(waivers, [], KNOWN, 'app.js'), []);
  });

  it('passes malformed pragmas through with the file they came from', () => {
    const warnings = waiverWarnings([], [{ line: 2, text: '// cryptoserve-ignore x', issue: 'needs a reason' }], KNOWN, 'app.js');
    assert.equal(warnings.length, 1);
    assert.equal(warnings[0].kind, 'malformed');
    assert.equal(warnings[0].file, 'app.js');
  });
});
