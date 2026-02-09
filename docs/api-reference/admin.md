# Admin API

Administrative operations for platform management.

> **Note:** All endpoints in this section require admin privileges.

---

## Dashboard

Get dashboard statistics.

```
GET /api/admin/dashboard
```

### Response

```json
{
  "users": {
    "total": 150,
    "active_today": 42,
    "new_this_week": 8
  },
  "identities": {
    "total": 324,
    "active": 298,
    "revoked": 26
  },
  "operations": {
    "total": 1523400,
    "today": 15234,
    "success_rate": 0.998
  },
  "contexts": {
    "total": 12,
    "most_used": "user-pii"
  }
}
```

---

## Users

### List All Users

```
GET /api/admin/users
```

### Response

```json
{
  "users": [
    {
      "id": "user_abc123",
      "github_username": "developer1",
      "email": "dev@example.com",
      "is_admin": false,
      "created_at": "2024-01-01T00:00:00Z",
      "last_login": "2024-01-15T10:00:00Z",
      "identity_count": 3
    }
  ],
  "pagination": {
    "total": 150,
    "limit": 100,
    "offset": 0
  }
}
```

### Get User

```
GET /api/admin/users/{id}
```

### Update User

```
PUT /api/admin/users/{id}
```

```json
{
  "is_admin": true
}
```

---

## All Identities

### List All Identities

```
GET /api/admin/identities
```

### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `user_id` | string | Filter by user |
| `status` | string | `active`, `revoked` |
| `team` | string | Filter by team |
| `environment` | string | Filter by environment |

### Response

```json
{
  "identities": [
    {
      "id": "id_abc123",
      "name": "backend-api",
      "user_id": "user_xyz789",
      "user_name": "developer1",
      "team": "platform",
      "environment": "production",
      "contexts": ["user-pii"],
      "status": "active",
      "operations_total": 15234,
      "last_used": "2024-01-15T15:00:00Z"
    }
  ]
}
```

### Revoke Identity

```
DELETE /api/admin/identities/{id}
```

---

## Global Audit

### Get Global Audit Logs

```
GET /api/admin/audit/global
```

### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `user_id` | string | Filter by user |
| `identity_id` | string | Filter by identity |
| `context` | string | Filter by context |
| `operation` | string | `encrypt`, `decrypt`, `sign`, `verify` |
| `success` | bool | Filter by success/failure |
| `start` | datetime | Start time |
| `end` | datetime | End time |
| `limit` | int | Max results (default 100) |

### Response

```json
{
  "logs": [
    {
      "id": "log_abc123",
      "timestamp": "2024-01-15T15:30:00Z",
      "operation": "encrypt",
      "context": "user-pii",
      "identity_id": "id_xyz789",
      "identity_name": "backend-api",
      "team": "platform",
      "algorithm": "AES-256-GCM",
      "success": true,
      "latency_ms": 12,
      "input_size_bytes": 1024,
      "output_size_bytes": 1052
    }
  ],
  "pagination": {
    "total": 1523400,
    "limit": 100,
    "offset": 0
  }
}
```

### Export Audit Logs

```
GET /api/admin/audit/export
```

### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `format` | string | `json`, `csv` |
| `start` | datetime | Start time |
| `end` | datetime | End time |

Returns a downloadable file.

---

## Contexts Administration

### List Contexts with Stats

```
GET /api/admin/contexts
```

### Response

```json
{
  "contexts": [
    {
      "name": "user-pii",
      "display_name": "User PII",
      "algorithm": "AES-256-GCM",
      "key_version": 3,
      "operations_total": 152340,
      "operations_today": 1234,
      "unique_identities": 45,
      "last_key_rotation": "2024-01-10T00:00:00Z"
    }
  ]
}
```

### Rotate Context Key

```
POST /api/admin/contexts/{name}/rotate-key
```

### Response

```json
{
  "context": "user-pii",
  "previous_version": 3,
  "new_version": 4,
  "new_key_id": "key_user-pii_v4_abc123",
  "rotated_at": "2024-01-15T16:00:00Z"
}
```

### Rotate All Keys

```
POST /api/admin/contexts/rotate-all
```

---

## Analytics

### Usage Trends

```
GET /api/admin/analytics/trends
```

### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `period` | string | `hour`, `day`, `week`, `month` |
| `start` | datetime | Start time |
| `end` | datetime | End time |

### Response

```json
{
  "period": "day",
  "data": [
    {
      "timestamp": "2024-01-15T00:00:00Z",
      "encryptions": 15234,
      "decryptions": 12456,
      "errors": 23,
      "avg_latency_ms": 11
    },
    {
      "timestamp": "2024-01-14T00:00:00Z",
      "encryptions": 14876,
      "decryptions": 11234,
      "errors": 18,
      "avg_latency_ms": 12
    }
  ]
}
```

### Team Usage

```
GET /api/admin/analytics/teams
```

### Response

```json
{
  "teams": [
    {
      "team": "platform",
      "identities": 12,
      "operations_total": 523400,
      "operations_this_month": 45600,
      "top_contexts": ["user-pii", "session-tokens"],
      "error_rate": 0.001
    }
  ]
}
```

### Algorithm Distribution

```
GET /api/admin/analytics/algorithms
```

### Response

```json
{
  "algorithms": [
    {
      "algorithm": "AES-256-GCM",
      "operations": 1234567,
      "percentage": 0.89
    },
    {
      "algorithm": "AES-256-GCM+ML-KEM-768",
      "operations": 123456,
      "percentage": 0.09
    },
    {
      "algorithm": "ChaCha20-Poly1305",
      "operations": 23456,
      "percentage": 0.02
    }
  ]
}
```

---

## System Health

```
GET /api/admin/health
```

### Response

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime_seconds": 864000,
  "components": {
    "database": {
      "status": "healthy",
      "latency_ms": 2,
      "connections": 10
    },
    "crypto": {
      "status": "healthy",
      "fips_mode": "disabled",
      "pqc_available": true
    },
    "kms": {
      "status": "healthy",
      "provider": "aws"
    }
  },
  "metrics": {
    "requests_per_minute": 1523,
    "avg_latency_ms": 12,
    "error_rate": 0.001,
    "active_connections": 42
  }
}
```

---

## Metrics Endpoint

Prometheus-compatible metrics.

```
GET /api/admin/metrics
```

### Response

```
# HELP cryptoserve_operations_total Total cryptographic operations
# TYPE cryptoserve_operations_total counter
cryptoserve_operations_total{operation="encrypt",context="user-pii"} 152340
cryptoserve_operations_total{operation="decrypt",context="user-pii"} 98234

# HELP cryptoserve_operation_latency_seconds Operation latency
# TYPE cryptoserve_operation_latency_seconds histogram
cryptoserve_operation_latency_seconds_bucket{le="0.01"} 145000
cryptoserve_operation_latency_seconds_bucket{le="0.05"} 152000
cryptoserve_operation_latency_seconds_bucket{le="0.1"} 152300

# HELP cryptoserve_active_identities Active identity count
# TYPE cryptoserve_active_identities gauge
cryptoserve_active_identities 298
```
