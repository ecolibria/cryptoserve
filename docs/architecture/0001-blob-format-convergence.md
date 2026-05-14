# ADR-0001: Cross-SDK Blob Format Convergence

- **Status:** Proposed — open for review.
- **Date:** 2026-05-14
- **Last verified against:** `main` at commit 729d2e7.

## Context

The JavaScript and Python SDKs encrypt to structurally incompatible
on-the-wire blob formats. Same-SDK roundtrip works on both sides
(covered by the release-smoke harnesses described in
[`docs/testing/release-smoke.md`](../testing/release-smoke.md)).
Cross-SDK encrypt-then-decrypt fails by design today.

| | JS SDK | Python SDK |
|---|---|---|
| Source | `sdk/javascript/lib/local-crypto.mjs:21` | `sdk/python/packages/cryptoserve-core/cryptoserve_core/encoding.py:34` |
| Declared version | `FORMAT_VERSION = 4` (inside JSON header) | `version = 1` (struct byte 0) |
| Header shape | `[uint16-BE len][JSON {v, ctx, kid, alg, nonce(b64), local, aad_len?}][ct][tag]` | `[u8 version][u8 alg-id][u8 nonce-len][nonce][ct+tag]` |
| Metadata in blob | context, key-id, algorithm name, optional AAD length | algorithm-id only |
| Algorithm encoding | string name (`"AES-256-GCM"`) | byte (`0x01`); `0x10` reserved for future KYBER hybrid |
| Auth-tag layout | appended after ciphertext | appended after ciphertext |

Python errors on a JS blob look like `Unsupported format version: 0`
because Python reads byte 0 of the JS `uint16-BE` header-length prefix
as its own version field. JS headers typically run 80–120 bytes, so the
high byte is `0`.

### Why this matters

- Customers running both SDKs in the same system (a JS frontend with a
  Python backend, for example) cannot exchange ciphertext directly.
- The `0x10` algorithm slot Python reserves for KYBER hybrid is
  unreachable from JS today.
- Both formats are shipped in real customer data. Neither side can be
  dropped without a migration story.

## Decision drivers

1. Both formats are in production; a forklift replacement is not
   acceptable without a decrypt-only compatibility path.
2. Self-describing blobs (carrying context, key-id, optional AAD length
   inline) are a useful UX property — the JS managed-mode experience
   depends on them.
3. Compact binary encoding is also useful — Python's three-byte header
   costs almost nothing compared to JS's JSON overhead.
4. The post-quantum roadmap reserves `0x10` for hybrid algorithms and
   must remain reachable from every SDK.

## Considered options

### A. JS adopts Python's struct format

- **Pro:** compact; binary-canonical; matches conventions used by
  libsodium and similar AEAD libraries.
- **Con:** JS loses inline `ctx` / `kid` / `aad_len`. Consumers of
  `getKeyIdFromCiphertext(blob)` and `getContextFromCiphertext(blob)`
  break. The managed-mode property of JS blobs being self-describing
  goes away.
- **Migration:** JS keeps `parseCiphertext` as legacy-decrypt only;
  encrypt switches to the new format; document the change for one
  minor.

### B. Python adopts JS's JSON-header format

- **Pro:** blobs are self-describing; inline metadata enables
  managed-mode features symmetrically on both sides.
- **Con:** roughly 80–120 bytes of overhead per blob (JSON plus
  base64-encoded nonce); refactors every `encode_ciphertext` /
  `decode_ciphertext` caller; legacy Python `version = 1` blobs in
  production need a decrypt-only compat path.
- **Migration:** Python `decode_ciphertext` sniffs the leading bytes
  (`if encoded[0] == 1 and encoded[1] in ALGORITHM_IDS:` → legacy
  struct; else → uint16-BE JSON header) for one major.

### C. New shared spec, both SDKs bump

Both SDKs ship dual-decode for one major, then switch encrypt to the
new spec in lockstep.

- **Pro:** design once; deliberately resolve the `version = 1` vs.
  `version = 4` collision; pick an algorithm-naming scheme on purpose;
  add a magic prefix so a future format change is unambiguous.
- **Con:** highest engineering cost (two SDK changes in lockstep + two
  legacy decode paths).

Proposed shape (subject to review):

```
[magic: 2 bytes "CS"]
[version: 1 byte = 5]
[alg-id: 1 byte]
[flags: 1 byte; bit0=has-ctx, bit1=has-kid, bit2=has-aad-len]
[nonce-len: 1 byte][nonce]
[optional ctx-len: 2 bytes BE][ctx UTF-8]
[optional kid-len: 1 byte][kid UTF-8]
[optional aad-len: 4 bytes BE]
[ciphertext + tag]
```

The leading `"CS"` magic eliminates the version-byte ambiguity
permanently. Any future format must change the magic or bump the
version.

### D. Magic-byte sniff plus dual-decode, no format change

Both SDKs detect which format a blob is in and decode accordingly. No
format change on the encrypt side.

- **Pro:** zero migration; existing blobs work both directions
  immediately; can ship in two patches.
- **Con:** formats stay forked forever; JS metadata-in-blob features
  stay JS-only because Python blobs do not carry them; cross-SDK
  parity becomes asymmetric. A JS-encrypted blob carrying `ctx` and
  `kid` will not round-trip those fields through Python.

### E. Status quo plus explicit non-support

- **Pro:** zero work, no risk.
- **Con:** the release-smoke documentation continues to state
  "expected blob-format mismatch" indefinitely. A real cross-runtime
  use case stays locked out.

## Decision outcome

**Proposed: Option C (new shared spec, both SDKs bump).**

Rationale: it is the only option that does not strand one side's
design intent. Inline metadata is kept (the JS managed-mode UX is
real, and customers want it). The encoding stays compact (close to
Python's current design, but extensible). Byte algorithm-ids keep the
KYBER `0x10` slot reachable from both runtimes. A `"CS"` magic prefix
prevents the version-byte ambiguity from recurring.

This is a recommendation, not a final decision. Open questions for
reviewers below.

## Open questions for reviewers

1. **Pick A / B / C / D / E.** If C, approve or revise the wire-format
   sketch.
2. **Compatibility window.** How many minor releases should both sides
   accept legacy-format decrypt? Suggested floor: one full major.
3. **Release sequencing.** Both SDKs ship simultaneously, or
   staggered? Suggested: ship dual-decode in both first patches, then
   switch encrypt in lockstep in a later release.
4. **Test gate.** Once formats converge, §8 of both release-smoke
   runner scripts should grow a positive cross-SDK assertion. The
   harnesses already exist; convergence work needs to commit cross-SDK
   fixtures (proposed home: `test/fixtures/cross-sdk/`) for the
   runners to consume.

## Consequences

- **If C is accepted:** plan a two-release rollout (dual-decode
  patches, then a coordinated encrypt switch). Treat the wire-format
  sketch above as a starting point, not a contract — review must
  confirm field order, sizes, and the magic.
- **If A or B is accepted:** the chosen side keeps its current
  shipped behavior; the other side gets a decrypt-only compat path
  scoped to one major.
- **If D is accepted:** document the asymmetry explicitly — managed-
  mode metadata stays JS-only round-trip until a future format-bump
  ADR supersedes this one.
- **If E is accepted:** close this ADR with "rejected" status and
  carry the §8 caveat forward.

No code changes will be made against blob format until reviewers pick
an option.

## Pointers

- JS encrypt: `sdk/javascript/lib/local-crypto.mjs:36-67`
- JS decrypt / parse: `sdk/javascript/lib/local-crypto.mjs:69-104`
- Python encode: `sdk/python/packages/cryptoserve-core/cryptoserve_core/encoding.py:30-61`
- Python decode: `sdk/python/packages/cryptoserve-core/cryptoserve_core/encoding.py:64-101`
- Release-smoke §8 (both runtimes):
  [`docs/testing/release-smoke.md`](../testing/release-smoke.md)
