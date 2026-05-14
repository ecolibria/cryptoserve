# Release-smoke fixtures

Reproducible inputs for `npm run release-smoke`. Three small projects, each
shaped to hit a specific path in `scan` / `pqc` / `cbom` / `gate`:

| Fixture   | Purpose                                                     |
| --------- | ----------------------------------------------------------- |
| `benign/` | Clean Node project. No weak algorithms, no secrets.         |
| `weak/`   | MD5, DES, `jsonwebtoken@^9`, AWS example access key.        |
| `pqc/`    | Source references `ml-kem-768` / `ml-dsa-65` (PQC).         |

These are inputs to the smoke runner — do not import them at runtime, do not
publish them. The `files` field in `package.json` excludes `test/`.
