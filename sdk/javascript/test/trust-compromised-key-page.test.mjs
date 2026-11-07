/**
 * The compromised-key finding page (docs/findings/trust-compromised-key.md)
 * gives 2026-10-17 to the report alone and says the report included proof of
 * control of all eight private keys. It does not say the keys were recovered
 * after the report.
 *
 * The page is read with each run of whitespace as one space, so re-wrapping
 * the paragraph does not change what is checked. The paragraph is also read
 * line by line: a wrapped line that opens with a list marker, such as "- G3C)",
 * would end the paragraph and turn the rest of it into a list when the page is
 * rendered. Nothing here reaches the network.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = join(__dirname, '..', '..', '..');
const PAGE = join(REPO, 'docs', 'findings', 'trust-compromised-key.md');

// The two sentences that date the report and the revocations, as the page
// reads with each run of whitespace as one space.
const INCIDENT_SENTENCES = 'A report to the root programs and to eMudhra on 2026-10-17 included proof of control of all eight private keys, and several parties, Mozilla among them, have recovered the keys independently (Mozilla Bug 2083449, comments 0 and 18). eMudhra revoked its eight certificates on 2026-10-18, the cross-signed copies were revoked on 2026-10-19, and Chrome and Firefox block the six TLS keys.';
// The start of the paragraph that names the eight keys and holds those
// sentences.
const KEY_PARAGRAPH_START = "The certificate's public key, or the key that signed it";
// A list marker at the start of a line: up to three spaces, then -, * or +, or
// a number and a dot, then a space, a tab or the end of the line.
const LIST_MARKER = /^ {0,3}(?:[-*+]|[0-9]+\.)(?:[ \t]|$)/;

function normalise(text) {
  return text.replace(/\s+/g, ' ');
}

function count(text, needle) {
  return text.split(needle).length - 1;
}

// The raw lines from the one that starts the key paragraph to the next blank
// line.
function keyParagraphLines(raw) {
  const lines = raw.split('\n');
  const start = lines.findIndex((line) => line.startsWith(KEY_PARAGRAPH_START));
  assert.notEqual(start, -1, `no line of the page starts with "${KEY_PARAGRAPH_START}"`);
  const end = lines.findIndex((line, i) => i > start && line.trim() === '');
  return lines.slice(start, end === -1 ? lines.length : end);
}

const raw = readFileSync(PAGE, 'utf8');
const page = normalise(raw);

describe('compromised-key finding page: the report and the key recoveries', () => {
  it('gives 2026-10-17 to the report alone and says it included proof of control of all eight private keys', () => {
    assert.equal(count(page, INCIDENT_SENTENCES), 1,
      'the page holds the sentences that date the report and the revocations exactly once');
    assert.ok(normalise(keyParagraphLines(raw).join('\n')).includes(INCIDENT_SENTENCES),
      'those sentences sit in the paragraph that names the eight keys');
  });

  it('does not say the keys were recovered after the report', () => {
    assert.equal(count(page, 'after a report'), 0,
      'the page does not place the key recoveries after the report');
    assert.equal(count(page, 'proof of control'), 1,
      'the page says once that the report included proof of control');
  });

  it('keeps the key paragraph one paragraph: no wrapped line starts with a list marker', () => {
    const lines = keyParagraphLines(raw);
    assert.ok(lines.length > 1, 'the key paragraph spans more than one line');
    assert.deepEqual(lines.filter((line) => LIST_MARKER.test(line)), []);
  });
});
