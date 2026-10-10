/**
 * Every LICENSE in the repository, including the copies shipped in the npm and
 * PyPI packages, is the Apache License 2.0 text exactly as published, APPENDIX
 * included. The copies had read "submitted to the Licensor" where the published
 * text reads "submitted to Licensor", and left out the APPENDIX.
 *
 * The digest is that of the published text:
 *
 *   curl -sL https://www.apache.org/licenses/LICENSE-2.0.txt | sha256sum
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..', '..');

const APACHE_2_0_SHA256 = 'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30';

const COPIES = [
  'LICENSE',
  'sdk/javascript/LICENSE',
  'sdk/python/LICENSE',
  'sdk/python/packages/cryptoserve-core/LICENSE',
  'sdk/python/packages/cryptoserve-client/LICENSE',
  'sdk/python/packages/cryptoserve-auto/LICENSE',
];

describe('LICENSE files', () => {
  for (const copy of COPIES) {
    it(`${copy} is the published Apache License 2.0 text`, () => {
      const digest = createHash('sha256').update(readFileSync(join(REPO_ROOT, copy))).digest('hex');
      assert.equal(digest, APACHE_2_0_SHA256);
    });
  }
});
