# Configuration

CryptoServe is configured through environment variables. This guide covers all available options.

## Quick Setup

Copy the example file and customize:

```bash
cp .env.example .env
```

## Required Variables

These must be set for CryptoServe to function:

### GitHub OAuth

```bash
# Create at: https://github.com/settings/developers
GITHUB_CLIENT_ID=Iv1.abc123def456
GITHUB_CLIENT_SECRET=secret123...
```

!!! info "Setting up GitHub OAuth"
    1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
    2. Click **New OAuth App**
    3. Set **Homepage URL**: `http://localhost:3003`
    4. Set **Callback URL**: `http://localhost:8003/auth/github/callback`
    5. Copy the Client ID and generate a Client Secret

### Security Keys

```bash
# Master key for key derivation (32+ characters)
CRYPTOSERVE_MASTER_KEY=your-secure-random-key-here-min-32-chars

# JWT signing key
JWT_SECRET_KEY=another-secure-random-key-for-jwt
```

!!! danger "Production Keys"
    In production, generate cryptographically secure keys:
    ```bash
    python -c "import secrets; print(secrets.token_hex(32))"
    ```

---

## Optional Variables

### URLs

```bash
# Frontend URL (for OAuth redirects)
FRONTEND_URL=http://localhost:3003

# Backend URL (for SDK downloads)
BACKEND_URL=http://localhost:8003
```

### Database

```bash
# SQLite (default, good for development)
DATABASE_URL=sqlite:///./cryptoserve.db

# PostgreSQL (recommended for production)
DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/cryptoserve
```

### FIPS Mode

```bash
# FIPS 140-2/140-3 compliance mode
# disabled - No restrictions (default)
# preferred - Use FIPS algorithms when available, warn otherwise
# enabled - Strictly enforce FIPS algorithms
FIPS_MODE=disabled
```

| Mode | ChaCha20 | AES-GCM | ML-KEM | Argon2 |
|------|----------|---------|--------|--------|
| disabled | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| preferred | :warning: warn | :white_check_mark: | :white_check_mark: | :warning: warn |
| enabled | :x: blocked | :white_check_mark: | :white_check_mark: | :x: blocked |

### Logging

```bash
# Log level
LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR, CRITICAL

# JSON structured logs (recommended for production)
LOG_FORMAT=json
```

### KMS Integration

```bash
# AWS KMS
KMS_PROVIDER=aws
AWS_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789:key/abc123
AWS_REGION=us-east-1

# Google Cloud KMS
KMS_PROVIDER=gcp
GCP_KMS_KEY_ID=projects/myproject/locations/global/keyRings/myring/cryptoKeys/mykey
```

### Rate Limiting

```bash
# Requests per minute per identity
RATE_LIMIT_PER_MINUTE=1000

# Enable/disable rate limiting
RATE_LIMIT_ENABLED=true
```

### CORS

```bash
# Allowed origins (comma-separated)
CORS_ORIGINS=http://localhost:3003,https://myapp.example.com

# Allow credentials
CORS_ALLOW_CREDENTIALS=true
```

---

## Environment-Specific Configs

### Development

```bash title=".env.development"
LOG_LEVEL=DEBUG
DATABASE_URL=sqlite:///./cryptoserve.db
FIPS_MODE=disabled
RATE_LIMIT_ENABLED=false
```

### Staging

```bash title=".env.staging"
LOG_LEVEL=INFO
DATABASE_URL=postgresql+asyncpg://user:pass@db:5432/cryptoserve
FIPS_MODE=preferred
RATE_LIMIT_ENABLED=true
RATE_LIMIT_PER_MINUTE=500
```

### Production

```bash title=".env.production"
LOG_LEVEL=WARNING
LOG_FORMAT=json
DATABASE_URL=postgresql+asyncpg://user:pass@db:5432/cryptoserve
FIPS_MODE=enabled
RATE_LIMIT_ENABLED=true
RATE_LIMIT_PER_MINUTE=1000
KMS_PROVIDER=aws
AWS_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789:key/abc123
```

---

## Docker Compose Configuration

The `docker-compose.yml` can reference environment variables:

```yaml title="docker-compose.yml"
services:
  backend:
    image: cryptoserve/backend
    environment:
      - GITHUB_CLIENT_ID=${GITHUB_CLIENT_ID}
      - GITHUB_CLIENT_SECRET=${GITHUB_CLIENT_SECRET}
      - CRYPTOSERVE_MASTER_KEY=${CRYPTOSERVE_MASTER_KEY}
      - DATABASE_URL=postgresql+asyncpg://postgres:postgres@db:5432/cryptoserve
    depends_on:
      - db

  frontend:
    image: cryptoserve/frontend
    environment:
      - NEXT_PUBLIC_API_URL=http://backend:8001

  db:
    image: postgres:15
    environment:
      - POSTGRES_PASSWORD=postgres
      - POSTGRES_DB=cryptoserve
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

---

## Default Contexts

CryptoServe creates these contexts on startup:

| Context | Algorithm | Sensitivity | Compliance |
|---------|-----------|-------------|------------|
| `user-pii` | AES-256-GCM | High | GDPR, CCPA |
| `payment-data` | AES-256-GCM | Critical | PCI-DSS |
| `session-tokens` | AES-256-GCM | Medium | - |
| `health-data` | AES-256-GCM | Critical | HIPAA |
| `general` | AES-256-GCM | Medium | - |

Custom contexts can be created via the dashboard or API.

---

## Validation

CryptoServe validates configuration on startup:

```bash
# Check configuration
python -c "from app.config import settings; print(settings)"
```

Missing required variables will cause startup failure with clear error messages:

```
ERROR: GITHUB_CLIENT_ID is required
ERROR: CRYPTOSERVE_MASTER_KEY must be at least 32 characters
```

---

## Security Best Practices

!!! warning "Production Checklist"

    - [ ] Generate unique `CRYPTOSERVE_MASTER_KEY` (32+ chars)
    - [ ] Generate unique `JWT_SECRET_KEY`
    - [ ] Use PostgreSQL instead of SQLite
    - [ ] Enable FIPS mode if required
    - [ ] Configure KMS for key management
    - [ ] Set appropriate CORS origins
    - [ ] Enable rate limiting
    - [ ] Use TLS termination (nginx/load balancer)
    - [ ] Rotate secrets regularly

---

## Next Steps

- [Quick Start Guide](quickstart.md)
- [Architecture Overview](../concepts/architecture.md)
- [Production Deployment](../guides/production.md)
