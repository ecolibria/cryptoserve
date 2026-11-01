<img src="docs/assets/logo.svg" alt="" width="64" height="64" align="left">

# cryptoserve

[![Build](https://img.shields.io/github/actions/workflow/status/ecolibria/cryptoserve/ci.yml?branch=main&label=build)](https://github.com/ecolibria/cryptoserve/actions/workflows/ci.yml)
[![Security](https://github.com/ecolibria/cryptoserve/actions/workflows/security.yml/badge.svg)](https://github.com/ecolibria/cryptoserve/actions/workflows/security.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

[Website](https://cryptoserve.dev) · [Docs](https://cryptoserve.dev/docs/) · [Crypto Census](https://census.cryptoserve.dev)

A self-hosted cryptography server, run by a platform or security team, that encrypts and decrypts data for application teams over a REST API: each request names a context such as `user-pii`, and the server chooses the algorithm, derives the key and writes an audit record.

## Quick start

With Docker, git, curl and jq installed, start the API and its PostgreSQL database from the development compose file and check that it is ready:

```bash
git clone https://github.com/ecolibria/cryptoserve.git && cd cryptoserve
docker compose up -d --wait backend
curl -s localhost:8003/health/ready | jq
```

What `curl -s localhost:8003/health/ready | jq` prints, trimmed ([full output](docs/captures/health-ready.txt)):

```json
{
  "status": "healthy",
  ...
  "checks": {
    "database": {
      "status": "healthy",
      ...
    "kms": {
      "status": "healthy",
      "latency_ms": 0.27,
      "message": "KMS backend: local",
      ...
```

The first run builds the backend image from source. This stack is for evaluation: it listens on localhost only, uses a fixed development master key, and turns on a sign-in that skips OAuth. [Deploy](#deploy) covers production.

Sign in with the development sign-in and register an application allowed one context. Its token authorizes the encrypt call; plaintext travels base64-encoded (`aGVsbG8gd29ybGQ=` is `hello world`):

```bash
curl -s -c cookies.txt localhost:8003/auth/dev-login -o /dev/null
TOKEN=$(curl -s -b cookies.txt localhost:8003/api/v1/applications -H 'Content-Type: application/json' \
  -d '{"name": "my-app", "team": "platform", "allowed_contexts": ["user-pii"]}' | jq -r .access_token)
curl -s localhost:8003/api/v1/crypto/encrypt -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"plaintext": "aGVsbG8gd29ybGQ=", "context": "user-pii"}' > enc.json
jq '{algorithm, usage}' enc.json
```

What `jq '{algorithm, usage}' enc.json` prints ([full output](docs/captures/encrypt.txt)):

```json
{
  "algorithm": {
    "name": "AES-256-GCM+ML-KEM-768",
    "mode": "hybrid",
    "key_bits": 256,
    "description": "Hybrid classical + post-quantum, NIST PQC Level 3 (FIPS 203)"
  },
  "usage": "at_rest"
}
```

The application never named an algorithm: the `user-pii` context chose a hybrid of AES-256-GCM and ML-KEM-768. The ciphertext in `enc.json` decrypts under the same context:

```bash
jq '{ciphertext, context: "user-pii"}' enc.json | curl -s localhost:8003/api/v1/crypto/decrypt \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d @-
```

What the request prints ([full output](docs/captures/decrypt.txt)):

```json
{"plaintext":"aGVsbG8gd29ybGQ="}
```

Now ask for a context the application was not granted. The server answers HTTP 403 and encrypts nothing:

```bash
curl -s localhost:8003/api/v1/crypto/encrypt -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"plaintext": "aGVsbG8gd29ybGQ=", "context": "payment-data"}'
```

What the request prints ([full output](docs/captures/encrypt-refused.txt)):

```json
{"detail":"Identity not authorized for context: payment-data"}
```

Every encrypt and decrypt request is an audit row, a refusal included. Read the newest with the administrator session:

```bash
curl -s -b cookies.txt localhost:8003/api/admin/audit/global | jq '.[0] | {operation, context, success, error_message}'
```

What `curl -s -b cookies.txt localhost:8003/api/admin/audit/global | jq '.[0] | {operation, context, success, error_message}'` prints ([full output](docs/captures/audit.txt)):

```json
{
  "operation": "encrypt",
  "context": "payment-data",
  "success": false,
  "error_message": "Identity not authorized for context: payment-data"
}
```

To allow `payment-data`, add it to the application's `allowed_contexts` with `PATCH /api/v1/applications/{app_id}`.

### What you can do

- Run it on your own infrastructure with PostgreSQL, TLS and generated secrets: [Deploy](#deploy).
- Call it from an application over HTTP or from Python: [API](#api), [Python SDK](docs/sdk/python.md).
- Decide which algorithm each kind of data gets: [context model](docs/concepts/context-model.md), [policy engine](docs/concepts/policy-engine.md).
- Rotate a context's keys: [key rotation](docs/guides/key-rotation.md).
- Know what the server records about each request, and for how long: [Data and retention](#data-and-retention).
- Harden a deployment and report a vulnerability: [Security](#security).

## Deploy

| Mode | When | Start | Includes |
|---|---|---|---|
| Evaluation | One machine | `docker compose up -d --wait backend` | API on `localhost:8003`, PostgreSQL on `localhost:5433`, development secrets and sign-in |
| Production | Your infrastructure | `docker compose -f docker-compose.production.yml up -d` | API on port 8003 and dashboard on port 3003 on every interface, PostgreSQL, strict startup checks, secure cookies |
| Several API instances | More load than one process serves | `docker compose -f docker-compose.scale.yml up -d --scale backend=3` | nginx on port 8003 in front of the instances, Redis for shared rate limits, PostgreSQL, dashboard; development secrets unless you set them |

The production file runs the `crypto-serve-backend` and `crypto-serve-frontend` images from GHCR at `latest`, which were built from an earlier release than this branch. Build both from this checkout before the first start:

```bash
docker build -t ghcr.io/ecolibria/crypto-serve-backend:latest ./backend
docker build -t ghcr.io/ecolibria/crypto-serve-frontend:latest ./frontend
```

It reads `POSTGRES_PASSWORD`, `CRYPTOSERVE_MASTER_KEY`, `JWT_SECRET_KEY`, `OAUTH_STATE_SECRET`, `HKDF_SALT`, `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` from the environment or a `.env` file beside it. Started that way, it reports the same healthy readiness as the Quick start, with the dashboard on port 3003. TLS, secret generation, backups and monitoring: [production deployment checklist](docs/guides/production-deployment.md). Several instances: [horizontal scaling](docs/horizontal-scaling.md).

### Configuration

The server reads these environment variables; [configuration](docs/getting-started/configuration.md) describes more.

| Variable | Sets |
|---|---|
| `DATABASE_URL` | The PostgreSQL connection, as `postgresql+asyncpg://`. The images ship no SQLite driver. |
| `CRYPTOSERVE_MASTER_KEY` | The secret every data key is derived from or encrypted under. |
| `CRYPTOSERVE_HKDF_SALT` | The salt the `local` key backend derives with; unset, it uses a built-in constant. |
| `JWT_SECRET_KEY`, `OAUTH_STATE_SECRET`, `HKDF_SALT` | Session signing, OAuth state, and the salt the startup checks require. |
| `ENVIRONMENT`, `DEV_MODE`, `STARTUP_VALIDATION_LEVEL` | `production` trims health responses; `DEV_MODE`: see [Security](#security); checks: `strict`, `warn` or `skip`. |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `OAUTH_GOOGLE_*`, `OAUTH_AZURE_AD_*`, `OAUTH_OKTA_*`, `OAUTH_OIDC_*` | Dashboard sign-in. A provider is offered once its client ID and secret are set; Okta also needs its domain, OIDC its discovery URL. |
| `FRONTEND_URL`, `BACKEND_URL`, `COOKIE_SECURE`, `COOKIE_DOMAIN` | Where the dashboard and API live. CORS admits `FRONTEND_URL` only. |
| `KMS_BACKEND` | `local`, the default and the only backend the images can load; `aws_kms` also needs boto3. |
| `KEY_CEREMONY_ENABLED`, `KEY_CEREMONY_THRESHOLD`, `KEY_CEREMONY_SHARES` | Take the master key from a Shamir key ceremony (`/api/admin/ceremony`) instead of the environment. |
| `FIPS_MODE` | `disabled`, `enabled` or `preferred`. |
| `REDIS_URL`, `RATE_LIMIT_REQUESTS`, `RATE_LIMIT_CRYPTO_OPS`, `RATE_LIMIT_BURST` | Rate limits, shared between instances through Redis. |
| `CRYPTOSERVE_BACKUP_DIR` | Where `POST /api/admin/backups` writes archives. |

## API

The server lists every route on its OpenAPI page, `localhost:8003/docs`. Application routes take the token `POST /api/v1/applications` returns, as `Authorization: Bearer`; management routes take the dashboard session.

| Job | Routes |
|---|---|
| Check health and readiness | `GET /health`, `/health/live`, `/health/ready`, `/health/deep`, `/health/fips` |
| Sign in to the dashboard | `/auth/login/{provider}`, `/auth/callback/{provider}`; `/auth/dev-login` in development mode |
| Register applications, rotate and revoke their tokens | `/api/v1/applications`, `/api/v1/auth` |
| Encrypt and decrypt by context | `/api/v1/crypto/encrypt`, `/decrypt`, `/batch/encrypt`, `/batch/decrypt` |
| Manage contexts and rotate their keys | `/api/contexts`, `/api/v1/contexts/{name}/keys` |
| Hash, MAC and hash passwords | `/api/v1/crypto/hash`, `/mac`, `/password/hash` |
| Sign and verify; JOSE, HPKE and RSA | `/api/v1/signatures`, `/api/v1/jose`, `/api/v1/crypto/hpke`, `/api/v1/crypto/rsa` |
| Post-quantum signatures and key exchange | `/api/v1/pqc`, `/api/v1/kex`, `/api/v1/crypto/hybrid` |
| Split secrets and lease them | `/api/v1/secrets` |
| Parse, issue and verify certificates; query CT logs | `/api/v1/certificates`, `/api/v1/ct` |
| Set algorithm policy and migrate contexts | `/api/policies`, `/api/v1/admin/algorithm-policies`, `/api/migration` |
| Read the audit log and compliance reports | `/api/admin/audit/global`, `/api/audit`, `/api/compliance` |
| Administer users, tenants, roles, backups and the key ceremony | `/api/admin`, `/api/tenants`, `/api/rbac`, `/api/v1/teams` |

Python applications can use the [Python SDK](docs/sdk/python.md). Request and response fields for each route: [REST API reference](docs/api-reference/index.md).

## Data and retention

The server keeps its state in PostgreSQL, except where the table says otherwise. An encrypt or decrypt request stores neither the plaintext nor the ciphertext.

| Data | Where | Kept until |
|---|---|---|
| Tenants, users, teams, applications, contexts, policies, policy violations and key versions | PostgreSQL tables | the server deletes only a policy, on request |
| Keys of classical contexts | Not stored: derived on each use from `CRYPTOSERVE_MASTER_KEY` and the context | nothing to delete |
| ML-KEM key pairs of hybrid contexts such as `user-pii` | `pqc_keys`, the private key encrypted under a key derived from `CRYPTOSERVE_MASTER_KEY` | the server never deletes them |
| Keys made with `/api/v1/signatures`, `/api/v1/pqc` and `/api/v1/kex` | The API process's memory | the process stops; instances do not share them |
| One row per operation: operation, context, algorithm, identity, outcome and reason, sizes, latency, caller IP address and user agent | `audit_log` | you delete it: no server code removes audit rows |
| Revoked session tokens | `revoked_tokens` | the first start after they expire |
| Request log: method, path, query parameter names (never values), client IP | container output | Docker log rotation, `max-size` and `max-file` in each compose file |
| Backup archives, password-encrypted | `CRYPTOSERVE_BACKUP_DIR` | `DELETE /api/admin/backups/{backup_id}` |

The audit log holds an IP address and a user agent for each request, which are personal data, so set its retention in the database. A context's `retention` fields record a requirement; the server does not delete data on that schedule.

A backup holds no symmetric keys and leaves out audit rows unless asked: restoring needs the archive, its password and the original `CRYPTOSERVE_MASTER_KEY`.

The [Crypto Census](https://census.cryptoserve.dev) is the public data this project publishes: a dated measurement of the cryptography that open-source package ecosystems use. Its snapshot is JSON at `https://census.cryptoserve.dev/api/census`, with one object per ecosystem and measured download counts kept apart from modelled ones.

## Security

- `DEV_MODE=true` turns on `/auth/dev-login`, which signs any caller in as an administrator without OAuth, and fills each missing secret with a random value at every start. Keep it off on any host others can reach.
- Outside development mode the server refuses to start without `CRYPTOSERVE_MASTER_KEY`, `JWT_SECRET_KEY`, `HKDF_SALT` and `OAUTH_STATE_SECRET`. `STARTUP_VALIDATION_LEVEL=skip` turns the other startup checks off, in production too.
- Whoever holds `CRYPTOSERVE_MASTER_KEY` and a copy of the database can decrypt everything, and losing the key loses every ciphertext. Store it, and `CRYPTOSERVE_HKDF_SALT` if set, apart from the database and its backups.
- With `ENVIRONMENT=production`, `/health/deep` and `/health/fips` leave error messages, configuration issues and library versions out of their responses.
- API responses carry `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and a `default-src 'none'` Content Security Policy.

Threat model and controls: [docs/security](docs/security/index.md). Report a vulnerability as [SECURITY.md](SECURITY.md) describes.

## Scanning repositories

The repository scanner lives in [cryptoscan](https://github.com/csnp/cryptoscan).

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) covers the backend and dashboard development setup, tests and pull requests. [CHANGELOG.md](CHANGELOG.md) lists changes by release.

## License

Apache 2.0. See [LICENSE](LICENSE).
