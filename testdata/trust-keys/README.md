# Certificates behind the trust check

Public certificates only. No file here holds a private key, and nothing here is fetched at test time.

| Directory | What it holds | Where it came from |
|---|---|---|
| `listed/<sha256>/cert.crt` | The 16 certificates of the eight compromised eMudhra intermediate keys: for each key, the certificate eMudhra issued and a cross-signed copy. | Downloaded on 2026-10-24 from crt.sh by the SHA-256 values in Mozilla Bug 2083449, comments 0 and 2 (`https://crt.sh/?d=<sha256>`). |
| `root/emsign-ecc-root-ca-g3.crt` | emSign ECC Root CA - G3, the root browsers removed. | Copied from a system CA bundle (`/etc/ssl/cert.pem`). |
| `control/emsign-root-ca-g1.crt` | emSign Root CA - G1, another eMudhra root, which must not be flagged. | Copied from the same system CA bundle. |
| `leaves/crtsh-<id>/cert.crt` | Two certificates issued under listed keys (one under EM OV TLS CA - G3C, one under EM EV TLS CA - G3B), for rule 2. | Downloaded on 2026-10-24 from crt.sh by id (`https://crt.sh/?d=<id>`). |
| `anchored/crtsh-<id>/cert.crt` | A CA certificate whose signature verifies under the removed root's key, for rule 4. | Downloaded on 2026-10-24 from crt.sh by id. |
| `scan/` | The layouts a repository commits: a certificate alone (`cert.crt`), a chain file (`chain.crt`) and a CA bundle whose second certificate is the removed root (`ca-bundle.crt`). | Built from the files above by `scripts/trust-keys/generate.mjs`. |

`scripts/trust-keys/generate.mjs` reads `listed/` and `root/` and writes the key table
(`backend/app/core/trust_keys.json` and the byte-equal `sdk/javascript/lib/trust-keys.json`), the `scan/`
files, and the table on the two finding pages under `docs/findings/`. `--check` exits 1 when any of them
differs from what the certificates give.

Each value can be recomputed with openssl:

```sh
# certificate SHA-256 (the directory name under listed/)
openssl x509 -in listed/<sha256>/cert.crt -outform DER | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \n'
# SPKI SHA-256 (the table's spkiSha256)
openssl x509 -in listed/<sha256>/cert.crt -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \n'
# a rule 2 certificate verifies under its listed intermediate
openssl verify -no_check_time -partial_chain -trusted listed/<sha256>/cert.crt leaves/crtsh-<id>/cert.crt
```
