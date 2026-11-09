<img src="docs/assets/logo.svg" alt="" width="64" height="64" align="left">

# cryptoserve

[![Build](https://img.shields.io/github/actions/workflow/status/ecolibria/cryptoserve/ci.yml?branch=main&label=build)](https://github.com/ecolibria/cryptoserve/actions/workflows/ci.yml)
[![Security](https://github.com/ecolibria/cryptoserve/actions/workflows/security.yml/badge.svg)](https://github.com/ecolibria/cryptoserve/actions/workflows/security.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

[Website](https://cryptoserve.dev) · [Docs](https://cryptoserve.dev/docs/) · [Examples](https://cryptoserve.dev/docs/examples/) · [Crypto Census](https://census.cryptoserve.dev)

Encrypt and decrypt your application's data through a cryptography server your platform team runs: your code names a context such as `user-pii`, and the server picks the algorithm, holds the keys and writes an audit record.

## Quick start

```bash
git clone https://github.com/ecolibria/cryptoserve.git && cd cryptoserve
docker compose up -d --wait backend               # evaluation server on localhost:8003
python3 -m venv .venv && source .venv/bin/activate && pip install cryptoserve
cryptoserve login --server http://localhost:8003  # or your platform team's server
python examples/sdk/quickstart.py
```

What `python examples/sdk/quickstart.py` prints ([full output](docs/captures/sdk-quickstart.txt)):

```
[CryptoServe] Registered new app: my-app (development)
AH17InYiOjEsIm1vZGUiOiJBRVMtMjU2LUdDTStNTC1LRU0t...
alex.chen@example.com
```

The script names a context, never an algorithm:

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", contexts=["user-pii", "payment-data"])

token = crypto.encrypt_string("alex.chen@example.com", context="user-pii")
print(token[:48] + "...")
print(crypto.decrypt_string(token, context="user-pii"))
```

On its first run, `CryptoServe(...)` registers `my-app` with the contexts it lists and stores the application's token in `~/.cryptoserve/apps/`. The server chose AES-256-GCM with ML-KEM-768 for `user-pii`, and the token begins with a header that names it.

The evaluation server listens on localhost only, uses a fixed development master key, and `cryptoserve login` signs you in to it without OAuth; on your team's server, `login` opens its sign-in page in your browser. The SDK is the `cryptoserve` package on PyPI and needs Python 3.9 or later.

## Using the service

Each example is a script in [examples/sdk/](examples/sdk/), run after the Quick start; [cryptoserve.dev/docs/examples](https://cryptoserve.dev/docs/examples/) shows the same examples.

### Handle a context you were not granted

`my-app` holds `user-pii` and `payment-data`, so the server refuses a `health-data` request and encrypts nothing:

```python
from cryptoserve import CryptoServe
from cryptoserve.client import AuthorizationError

crypto = CryptoServe(app_name="my-app", contexts=["user-pii", "payment-data"])

try:
    crypto.encrypt_string("blood type: A+", context="health-data")
except AuthorizationError as e:
    print(e)
```

What `python examples/sdk/refused.py` prints ([full output](docs/captures/sdk-refused.txt)):

```
Not authorized for context 'health-data': Identity not authorized for context: health-data
```

Listing another context in `contexts=` later does not grant it, because the SDK reuses the registration it stored; your platform team adds it with `PATCH /api/v1/applications/{app_id}` (`allowed_contexts`). Import error classes from `cryptoserve.client`: the same names imported from `cryptoserve` are other classes and do not catch these errors.

### Encrypt the fields of a record

Encrypt each sensitive field under the context that fits it, and store the base64 text the SDK returns:

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", contexts=["user-pii", "payment-data"])

user = {"id": 42, "email": "alex.chen@example.com", "card": "4242 4242 4242 4242"}
row = {
    "id": user["id"],
    "email": crypto.encrypt_string(user["email"], context="user-pii"),
    "card": crypto.encrypt_string(user["card"], context="payment-data"),
}
print({column: len(value) if isinstance(value, str) else value for column, value in row.items()})
print(crypto.decrypt_string(row["card"], context="payment-data"))
```

What `python examples/sdk/record.py` prints ([full output](docs/captures/sdk-record.txt)):

```
{'id': 42, 'email': 1672, 'card': 284}
4242 4242 4242 4242
```

Size columns for the context: `user-pii` adds an ML-KEM ciphertext to every value, so a 21-character address is stored as 1672 characters, against 284 for the card number under `payment-data` (AES-256-GCM).

### Bind a value to its row

Pass the row's identity as associated data. The value then decrypts only with the same associated data, so a ciphertext copied into another row fails:

```python
from cryptoserve import CryptoServe
from cryptoserve.client import CryptoServeError

crypto = CryptoServe(app_name="my-app", contexts=["user-pii", "payment-data"])

email = crypto.encrypt_string("alex.chen@example.com", context="user-pii", associated_data=b"users:42:email")
print(crypto.decrypt_string(email, context="user-pii", associated_data=b"users:42:email"))

try:
    crypto.decrypt_string(email, context="user-pii", associated_data=b"users:43:email")
except CryptoServeError as e:
    print("refused:", e)
```

What `python examples/sdk/bind.py` prints ([full output](docs/captures/sdk-bind.txt)):

```
alex.chen@example.com
refused: Hybrid decryption failed: Decryption failed: 
```

### Encrypt a JSON document

`encrypt_json` serializes the object and returns base64 text; `decrypt_json` returns the object:

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", contexts=["user-pii", "payment-data"])

token = crypto.encrypt_json({"email": "alex.chen@example.com", "plan": "team"}, context="user-pii")
print(crypto.decrypt_json(token, context="user-pii"))
```

What `python examples/sdk/document.py` prints ([full output](docs/captures/sdk-document.txt)):

```
{'email': 'alex.chen@example.com', 'plan': 'team'}
```

### Say how the data is used

The context says what the data is; `usage` says how it is used, and the server can choose another algorithm for it. A value encrypted with a usage decrypts with the context alone:

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", contexts=["user-pii", "payment-data"])

for usage in ["at_rest", "in_use", "streaming"]:
    token = crypto.encrypt(b"4242 4242 4242 4242", context="payment-data", usage=usage)
    print(usage, crypto.decrypt(token, context="payment-data"))
```

What `python examples/sdk/usage.py` prints ([full output](docs/captures/sdk-usage.txt)):

```
at_rest b'4242 4242 4242 4242'
in_use b'4242 4242 4242 4242'
streaming b'4242 4242 4242 4242'
```

What the evaluation server chose for each usage, read from each ciphertext's header ([capture](docs/captures/sdk-usage-algorithms.txt)):

| `usage` | `user-pii` | `payment-data` |
|---|---|---|
| none, `at_rest`, `in_transit` | AES-256-GCM+ML-KEM-768 | AES-256-GCM |
| `in_use` | AES-256-GCM+ML-KEM-768 | AES-256-GCM-SIV |
| `streaming` | ChaCha20-Poly1305+ML-KEM-768 | ChaCha20-Poly1305 |
| `disk` | AES-256-GCM+ML-KEM-768 | fails: `XTS requires 64-byte key (two 256-bit keys)` |

### Encrypt in a web handler

Encrypt in the handler that stores a value and decrypt in the one that returns it. With FastAPI (`pip install fastapi uvicorn`):

```python
from fastapi import FastAPI
from pydantic import BaseModel
from cryptoserve import CryptoServe

app = FastAPI()
crypto = CryptoServe(app_name="my-app", contexts=["user-pii", "payment-data"])
rows = {}

class User(BaseModel):
    email: str

@app.put("/users/{user_id}")
def save_user(user_id: int, user: User):
    rows[user_id] = crypto.encrypt_string(user.email, context="user-pii")
    return {"stored_characters": len(rows[user_id])}

@app.get("/users/{user_id}")
def read_user(user_id: int):
    return {"email": crypto.decrypt_string(rows[user_id], context="user-pii")}
```

Start it with `uvicorn --app-dir examples/sdk api:app`, then store and read a user:

```bash
curl -s -X PUT localhost:8000/users/42 -H 'Content-Type: application/json' -d '{"email": "alex.chen@example.com"}'; echo
curl -s localhost:8000/users/42
```

What the two requests print ([full output](docs/captures/sdk-api.txt)):

```
{"stored_characters":1672}
{"email":"alex.chen@example.com"}
```

### Run tests without a server

`CryptoServe.local()` derives keys from a password on your machine. It sends no request and writes no audit record, and a server cannot decrypt what it produces, so keep it to tests and offline tools:

```python
from cryptoserve import CryptoServe

crypto = CryptoServe.local(password="test-only-password")

token = crypto.encrypt_string("alex.chen@example.com", context="user-pii")
print(crypto.decrypt_string(token, context="user-pii"))
```

What `python examples/sdk/local.py` prints ([full output](docs/captures/sdk-local.txt)):

```
alex.chen@example.com
```

### Call the server from another language

Python is the only SDK; the `cryptoserve` package on npm is a command-line tool that does not call these routes. Any language can call the REST API with the application's token. Plaintext travels base64-encoded (`YWxleC5jaGVuQGV4YW1wbGUuY29t` is `alex.chen@example.com`):

```bash
TOKEN=$(jq -r .access_token ~/.cryptoserve/apps/my-app_development.json)
curl -s localhost:8003/api/v1/crypto/encrypt -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"plaintext": "YWxleC5jaGVuQGV4YW1wbGUuY29t", "context": "user-pii"}' > enc.json
jq '{algorithm: .algorithm.name, usage}' enc.json
```

What `jq '{algorithm: .algorithm.name, usage}' enc.json` prints ([full output](docs/captures/sdk-rest-encrypt.txt)):

```json
{
  "algorithm": "AES-256-GCM+ML-KEM-768",
  "usage": "at_rest"
}
```

```bash
jq '{ciphertext, context: "user-pii"}' enc.json | curl -s localhost:8003/api/v1/crypto/decrypt \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d @-
```

What the request prints ([full output](docs/captures/sdk-rest-decrypt.txt)):

```json
{"plaintext":"YWxleC5jaGVuQGV4YW1wbGUuY29t"}
```

The token is the one the SDK stored for `my-app`; for a new application, an administrator gets one from `POST /api/v1/applications`.

The server allows each application bursts of 20 requests and 100 a minute, and answers HTTP 429 above that. On a hybrid context such as `user-pii`, every SDK call reaches the server, so a loop is refused after 10 encrypts; on `payment-data` the SDK caches the key after the first call and encrypts locally.

## Run the server

The Quick start's evaluation stack is one of three compose files:

| Mode | Start | Includes |
|---|---|---|
| Evaluation | `docker compose up -d --wait backend` | API on `localhost:8003`, PostgreSQL on `localhost:5433`, development secrets and sign-in |
| Production | `docker compose -f docker-compose.production.yml up -d` | API on port 8003 and dashboard on port 3003 on every interface, PostgreSQL, strict startup checks, secure cookies |
| Several API instances | `docker compose -f docker-compose.scale.yml up -d --scale backend=3` | nginx on port 8003 in front of the instances, Redis for shared rate limits, PostgreSQL, dashboard; development secrets unless you set them |

The first `up` builds the backend image from source. Check that the server is ready:

```bash
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
      ...
      "message": "KMS backend: local",
      ...
```

Production images and secrets, configuration, and what the server stores and for how long: [docs/server.md](docs/server.md). Contexts and their algorithms: [context model](docs/concepts/context-model.md); rotating a context's keys: [key rotation](docs/guides/key-rotation.md).

## API

The server lists every route in its OpenAPI document, `localhost:8003/openapi.json`. Application routes take the application's token as `Authorization: Bearer`; management routes take the dashboard session. Routes by job: [docs/server.md](docs/server.md#api-routes). Request and response fields: [REST API reference](docs/api-reference/index.md).

## Security

- `DEV_MODE=true` turns on `/auth/dev-login`, which signs any caller in as an administrator without OAuth, and fills each missing secret with a random value at every start. Keep it off on any host others can reach.
- Outside development mode the server refuses to start without `CRYPTOSERVE_MASTER_KEY`, `JWT_SECRET_KEY`, `HKDF_SALT` and `OAUTH_STATE_SECRET`. `STARTUP_VALIDATION_LEVEL=skip` turns the other startup checks off, in production too.
- Whoever holds `CRYPTOSERVE_MASTER_KEY` and a copy of the database can decrypt everything, and losing the key loses every ciphertext. Store it, and `CRYPTOSERVE_HKDF_SALT` if set, apart from the database and its backups.
- With `ENVIRONMENT=production`, `/health/deep` and `/health/fips` leave error messages, configuration issues and library versions out of their responses.
- API responses carry `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and a `default-src 'none'` Content Security Policy.

Threat model and controls: [docs/security](docs/security/index.md). Report a vulnerability as [SECURITY.md](SECURITY.md) describes.

## Scanning repositories

Repository scanning lives in [cryptoscan](https://github.com/csnp/cryptoscan).

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) covers the backend and dashboard development setup, tests and pull requests. [CHANGELOG.md](CHANGELOG.md) lists changes by release.

## License

Apache 2.0. See [LICENSE](LICENSE).
