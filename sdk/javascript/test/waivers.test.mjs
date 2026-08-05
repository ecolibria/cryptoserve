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

  it('records a pragma it refuses, so the refusal is not silent', () => {
    // A trailing pragma on a line that already opened a comment earlier (a URL,
    // or a doc block quoting the anti-pattern) is not the first thing in its
    // comment, so it does nothing. Refusing in silence leaves a user watching a
    // critical they just waived stay red with nothing to go on.
    const { waivers, refused } = parse(`const u = "http://x"; // ${IGNORE} misuse/create-cipher -- why\n`);
    assert.deepEqual(waivers, []);
    assert.equal(refused.length, 1, JSON.stringify(refused));
    assert.equal(refused[0].rule, 'misuse/create-cipher');
    assert.equal(refused[0].line, 1);
  });

  it('does not record a refusal for prose', () => {
    // The refusal report must not fire on documentation, or every comment in
    // this repository that describes the feature becomes a warning.
    for (const src of [
      '// The format is `cryptoserve-ignore misuse/create-cipher -- why`.\n',
      '// with a cryptoserve-ignore misuse/create-cipher pragma -- see the docs\n',
    ]) {
      assert.deepEqual(parse(src).refused, [], src);
    }
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
    const warnings = waiverWarnings(waivers, [], [], KNOWN, 'app.js');
    assert.equal(warnings.length, 1);
    assert.equal(warnings[0].kind, 'unknown-rule');
    assert.equal(warnings[0].file, 'app.js');
    assert.equal(warnings[0].line, 3);
  });

  it('reports an unknown rule ONLY as unknown, not also as unused', () => {
    // Two warnings for one typo reads as two problems. The rule not existing is
    // the reason it covered nothing, so it is one finding.
    const waivers = [{ rule: 'misuse/typo', reason: 'why', line: 3, used: false }];
    const warnings = waiverWarnings(waivers, [], [], KNOWN, 'app.js');
    assert.equal(warnings.filter(w => w.kind === 'unused').length, 0);
  });

  it('reports a known rule that covered nothing', () => {
    const waivers = [{ rule: 'misuse/create-cipher', reason: 'why', line: 3, used: false }];
    const warnings = waiverWarnings(waivers, [], [], KNOWN, 'app.js');
    assert.equal(warnings.length, 1);
    assert.equal(warnings[0].kind, 'unused');
  });

  it('reports a refused pragma only when it names a real rule', () => {
    // A doc example writing `<rule-id>` is documentation and must stay silent,
    // or every comment in this repository that describes the feature becomes a
    // warning on every scan. A refusal naming a REAL rule is somebody's waiver
    // quietly doing nothing, which they need told. Found by mutation testing.
    const refused = (rule) => [{ line: 3, rule, text: '// ...' }];
    assert.deepEqual(waiverWarnings([], [], refused('<rule-id>'), KNOWN, 'app.js'), []);

    const warnings = waiverWarnings([], [], refused('misuse/create-cipher'), KNOWN, 'app.js');
    assert.equal(warnings.length, 1);
    assert.equal(warnings[0].kind, 'not-honoured');
    assert.match(warnings[0].detail, /first thing in its comment/);
  });

  it('says nothing about a waiver that did its job', () => {
    const waivers = [{ rule: 'misuse/create-cipher', reason: 'why', line: 3, used: true }];
    assert.deepEqual(waiverWarnings(waivers, [], [], KNOWN, 'app.js'), []);
  });

  it('passes malformed pragmas through with the file they came from', () => {
    const warnings = waiverWarnings([], [{ line: 2, text: '// cryptoserve-ignore x', issue: 'needs a reason' }], [], KNOWN, 'app.js');
    assert.equal(warnings.length, 1);
    assert.equal(warnings[0].kind, 'malformed');
    assert.equal(warnings[0].file, 'app.js');
  });
});
