# Run the server

How to run cryptoserve for a team: the three compose files, the production images and secrets, configuration, the routes by job, and what the server stores. The [README](../README.md) starts the evaluation stack and shows the SDK against it.

## Deploy

| Mode | When | Start | Includes |
|---|---|---|---|
| Evaluation | One machine | `docker compose up -d --wait backend` | API on `localhost:8003`, PostgreSQL on `localhost:5433`, development secrets and sign-in |
| Production | Your infrastructure | `docker compose -f docker-compose.production.yml up -d` | API on port 8003 and dashboard on port 3003 on every interface, PostgreSQL, strict startup checks, secure cookies |
| Several API instances | More load than one process serves | `docker compose -f docker-compose.scale.yml up -d --scale backend=3` | nginx on port 8003 in front of the instances, Redis for shared rate limits, PostgreSQL, dashboard; development secrets unless you set them |

The production file runs the `crypto-serve-backend` and `crypto-serve-frontend` images from GHCR at `latest`. Build both from your checkout before the first start, so they run the code you cloned:

```bash
docker build -t ghcr.io/ecolibria/crypto-serve-backend:latest ./backend
docker build -t ghcr.io/ecolibria/crypto-serve-frontend:latest ./frontend
```

It reads `POSTGRES_PASSWORD`, `CRYPTOSERVE_MASTER_KEY`, `JWT_SECRET_KEY`, `OAUTH_STATE_SECRET`, `HKDF_SALT`, `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` from the environment or a `.env` file beside it. Started that way, it reports the same healthy readiness as the evaluation stack ([README](../README.md#run-the-server)), with the dashboard on port 3003. TLS, secret generation, backups and monitoring: [production deployment checklist](guides/production-deployment.md). Several instances: [horizontal scaling](horizontal-scaling.md).

### Configuration

The server reads these environment variables; [configuration](getting-started/configuration.md) describes more.

| Variable | Sets |
|---|---|
| `DATABASE_URL` | The PostgreSQL connection, as `postgresql+asyncpg://`. The images ship no SQLite driver. |
| `CRYPTOSERVE_MASTER_KEY` | The secret every data key is derived from or encrypted under. |
| `CRYPTOSERVE_HKDF_SALT` | The salt the `local` key backend derives with; unset, it uses a built-in constant. |
| `JWT_SECRET_KEY`, `OAUTH_STATE_SECRET`, `HKDF_SALT` | Session signing, OAuth state, and the salt the startup checks require. |
| `ENVIRONMENT`, `DEV_MODE`, `STARTUP_VALIDATION_LEVEL` | `production` trims health responses; `DEV_MODE`: see [Security](../README.md#security); checks: `strict`, `warn` or `skip`. |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `OAUTH_GOOGLE_*`, `OAUTH_AZURE_AD_*`, `OAUTH_OKTA_*`, `OAUTH_OIDC_*` | Dashboard sign-in. A provider is offered once its client ID and secret are set; Okta also needs its domain, OIDC its discovery URL. |
| `FRONTEND_URL`, `BACKEND_URL`, `COOKIE_SECURE`, `COOKIE_DOMAIN` | Where the dashboard and API live. CORS admits `FRONTEND_URL` only. |
| `KMS_BACKEND` | `local`, the default and the only backend the images can load; `aws_kms` also needs boto3. |
| `KEY_CEREMONY_ENABLED`, `KEY_CEREMONY_THRESHOLD`, `KEY_CEREMONY_SHARES` | Take the master key from a Shamir key ceremony (`/api/admin/ceremony`) instead of the environment. |
| `FIPS_MODE` | `disabled`, `enabled` or `preferred`. |
| `REDIS_URL`, `RATE_LIMIT_REQUESTS`, `RATE_LIMIT_CRYPTO_OPS`, `RATE_LIMIT_BURST` | Rate limits, shared between instances through Redis. |
| `CRYPTOSERVE_BACKUP_DIR` | Where `POST /api/admin/backups` writes archives. |

## API routes

The server lists every route in its OpenAPI document, `localhost:8003/openapi.json`. Application routes take the token `POST /api/v1/applications` returns, as `Authorization: Bearer`; management routes take the dashboard session.

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

Python applications can use the [Python SDK](sdk/python.md). Request and response fields for each route: [REST API reference](api-reference/index.md).

## Data and retention

The server keeps its state in PostgreSQL, except where the table says otherwise. An encrypt or decrypt request stores neither the plaintext nor the ciphertext.

| Data | Where | Kept until |
|---|---|---|
| Tenants, users, teams, applications, contexts, policies, policy violations and key versions | PostgreSQL tables | the server deletes only a policy, on request |
| Keys of classical contexts | Not stored: derived on each use from `CRYPTOSERVE_MASTER_KEY` and the context | nothing to delete |
| ML-KEM key pairs of hybrid contexts such as `user-pii` | `pqc_keys`, the private key encrypted under a key derived from `CRYPTOSERVE_MASTER_KEY` | the server never deletes them |
| Keys made with `/api/v1/signatures`, `/api/v1/pqc` and `/api/v1/kex`; algorithm policy overrides | The API process's memory | their `DELETE` route, or the process stops; instances do not share them |
| One row per encrypt, decrypt, key rotation and rotation schedule change: operation, context, algorithm, identity, outcome and reason, sizes, latency, caller IP address and user agent | `audit_log` | you delete it: no server code removes audit rows |
| Revoked session tokens | `revoked_tokens` | the first start after they expire |
| Request log: method, path, query parameter names and value lengths (never values), client IP | container output | Docker log rotation, `max-size` and `max-file` in each compose file |
| Backup archives, password-encrypted | `CRYPTOSERVE_BACKUP_DIR` | `DELETE /api/admin/backups/{backup_id}` |

The audit log holds an IP address and a user agent for each request, which are personal data, so set its retention in the database. A context's `retention` fields record a requirement; the server does not delete data on that schedule.

A backup holds no symmetric keys and leaves out audit rows unless asked: restoring needs the archive, its password and the original `CRYPTOSERVE_MASTER_KEY`.

The [Crypto Census](https://census.cryptoserve.dev) is the public data this project publishes: a dated measurement of the cryptography that open-source package ecosystems use. Its snapshot is JSON at `https://census.cryptoserve.dev/api/census`, with one object per ecosystem and measured download counts kept apart from modelled ones.
