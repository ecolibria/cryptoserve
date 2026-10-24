# Production Deployment Checklist

Step-by-step guide for deploying CryptoServe to production using `docker-compose.production.yml`.

## Prerequisites

- Docker Engine 24+ and Docker Compose v2
- A domain name with DNS configured
- TLS certificate (or use Let's Encrypt)
- PostgreSQL 16+ (included in compose, or use managed)

## 1. Generate Secrets

Generate all required secrets before deployment. Never reuse values across environments.

```bash
# Generate each secret independently
export POSTGRES_PASSWORD=$(openssl rand -base64 32)
export CRYPTOSERVE_MASTER_KEY=$(openssl rand -base64 32)
export JWT_SECRET_KEY=$(openssl rand -base64 32)
export OAUTH_STATE_SECRET=$(openssl rand -base64 32)
export HKDF_SALT=$(openssl rand -base64 32)
```

Store these in a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.) -- not in files on disk.

## 2. Environment Variables

Create a `.env` file (mode 0600) or export variables directly. Reference `docker-compose.production.yml` for the full list.

| Variable | Description | Required |
|----------|-------------|----------|
| `POSTGRES_PASSWORD` | PostgreSQL password | Yes |
| `CRYPTOSERVE_MASTER_KEY` | Master encryption key (32+ chars) | Yes |
| `JWT_SECRET_KEY` | JWT signing secret (32+ chars) | Yes |
| `OAUTH_STATE_SECRET` | OAuth CSRF protection secret | Yes |
| `HKDF_SALT` | HKDF key derivation salt | Yes |
| `GITHUB_CLIENT_ID` | GitHub OAuth app client ID | Yes |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth app client secret | Yes |
| `FRONTEND_URL` | Public frontend URL (e.g., `https://app.example.com`) | Yes |
| `BACKEND_URL` | Public backend URL (e.g., `https://api.example.com`) | Yes |

## 3. GitHub OAuth Setup

1. Go to GitHub Settings > Developer Settings > OAuth Apps > New OAuth App
2. Set **Homepage URL** to your `FRONTEND_URL`
3. Set **Authorization callback URL** to `{BACKEND_URL}/api/auth/github/callback`
4. Copy the Client ID and Client Secret into your environment

## 4. TLS / Reverse Proxy

Place nginx (or another reverse proxy) in front of the services. The compose file exposes backend on port 8003 and frontend on port 3003.

Example nginx configuration:

```nginx
server {
    listen 443 ssl http2;
    server_name api.example.com;

    ssl_certificate /etc/ssl/certs/api.example.com.crt;
    ssl_certificate_key /etc/ssl/private/api.example.com.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;

    location / {
        proxy_pass http://127.0.0.1:8003;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 443 ssl http2;
    server_name app.example.com;

    ssl_certificate /etc/ssl/certs/app.example.com.crt;
    ssl_certificate_key /etc/ssl/private/app.example.com.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;

    location / {
        proxy_pass http://127.0.0.1:3003;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

For Let's Encrypt automation, use certbot with the nginx plugin.

## 5. Deploy

```bash
docker compose -f docker-compose.production.yml up -d
```

Verify services are healthy:

```bash
docker compose -f docker-compose.production.yml ps
curl -f https://api.example.com/health
curl -f https://api.example.com/health/deep | jq .
```

The `/health/deep` endpoint validates that no default/insecure secrets are in use. If it reports `degraded`, update your secrets immediately.

## 6. Database Backup Strategy

Set up automated daily backups of PostgreSQL:

```bash
# Daily backup via cron
0 2 * * * docker compose -f docker-compose.production.yml exec -T postgres \
  pg_dump -U cryptoserve cryptoserve | gzip > /backups/cryptoserve-$(date +\%Y\%m\%d).sql.gz

# Retain last 30 days
find /backups -name "cryptoserve-*.sql.gz" -mtime +30 -delete
```

For managed PostgreSQL (AWS RDS, Cloud SQL), enable automated snapshots with at least 7-day retention.

Test restore procedures quarterly.

## 7. Monitoring and Health Checks

The compose file includes built-in health checks:
- **PostgreSQL**: `pg_isready` every 5s
- **Backend**: `curl http://localhost:8003/health` every 10s (30s start period)

Additional monitoring to configure:
- Prometheus metrics at `/api/admin/metrics`
- Alert on error rate > 1%, p99 latency > 100ms, connection pool > 80%
- Set up log aggregation (ELK, Loki, CloudWatch) for audit trail
- Container logs rotate at 50 MB per file and keep the newest 5 files (250 MB per container); to keep more, raise `max-size` or `max-file` in each service's `logging` block of the compose file

## 8. Security Checklist

- [ ] All secrets are randomly generated (not default values)
- [ ] `ENVIRONMENT=production` and `DEV_MODE=false` are set
- [ ] `STARTUP_VALIDATION_LEVEL=strict` is set (validates config on boot)
- [ ] `COOKIE_SECURE=true` is set
- [ ] TLS 1.2+ only (no SSLv3, TLS 1.0, TLS 1.1)
- [ ] Backend runs as non-root user inside the container
- [ ] Rate limiting is enabled
- [ ] `.env` file permissions are 0600 (owner-only read/write)
- [ ] Database is not exposed to public network
- [ ] Backup encryption is enabled for database dumps
- [ ] `/health/deep` returns `healthy` (not `degraded`)
