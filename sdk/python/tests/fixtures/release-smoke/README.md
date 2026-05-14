# Release-smoke fixtures (Python)

Reproducible inputs for `python scripts/release_smoke.py`. Three small
projects, each shaped to hit a specific path in `scan` / `pqc` / `cbom` /
`gate`:

| Fixture   | Purpose                                                         |
| --------- | --------------------------------------------------------------- |
| `benign/` | Clean Python project. No weak algorithms, no secrets.           |
| `weak/`   | MD5, DES, RSA-1024, AWS example access key.                     |
| `pqc/`    | Source references `ml-kem-768` / `ml-dsa-65` (PQC).             |

These are inputs to the smoke runner. They are not collected by `pytest`
and are not packaged on `python -m build` (the `tool.setuptools.packages`
configuration excludes `tests*`). Do not import them at runtime.

The credential string `AKIAIOSFODNN7EXAMPLE` is AWS' own documented example
access key. GitHub's push protection treats it as a placeholder, so the
fixture stays committable.
