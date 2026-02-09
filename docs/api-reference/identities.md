# Identities API

Manage API identities for applications and services.

## Overview

Identities represent applications or services that use CryptoServe. Each identity:

- Has a unique JWT signing keypair
- Is authorized for specific contexts
- Generates audit logs tied to its ID

---

## List Identities

Get all identities for the authenticated user.

```
GET /api/identities
```

### Response

```json
{
  "identities": [
    {
      "id": "id_abc123",
      "name": "backend-api",
      "team": "platform",
      "environment": "production",
      "contexts": ["user-pii", "session-tokens"],
      "created_at": "2024-01-15T10:00:00Z",
      "last_used": "2024-01-15T15:30:00Z",
      "status": "active"
    }
  ]
}
```

---

## Get Identity

Get details for a specific identity.

```
GET /api/identities/{id}
```

### Response

```json
{
  "id": "id_abc123",
  "name": "backend-api",
  "team": "platform",
  "environment": "production",
  "contexts": ["user-pii", "session-tokens"],
  "created_at": "2024-01-15T10:00:00Z",
  "last_used": "2024-01-15T15:30:00Z",
  "status": "active",
  "stats": {
    "total_operations": 15234,
    "operations_today": 423,
    "errors_today": 2
  }
}
```

---

## Create Identity

Create a new identity.

```
POST /api/identities
```

### Request

```json
{
  "name": "backend-api",
  "team": "platform",
  "environment": "production",
  "contexts": ["user-pii", "session-tokens"]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique name for the identity |
| `team` | string | No | Team or department |
| `environment` | string | No | Environment (dev, staging, production) |
| `contexts` | array | Yes | List of authorized context names |

### Response

```json
{
  "id": "id_abc123",
  "name": "backend-api",
  "team": "platform",
  "environment": "production",
  "contexts": ["user-pii", "session-tokens"],
  "created_at": "2024-01-15T10:00:00Z",
  "status": "active",
  "sdk_download": {
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "url": "http://localhost:8003/sdk/download/eyJhbG.../python",
    "expires_at": "2024-01-15T11:00:00Z"
  }
}
```

### Errors

| Code | Error | Description |
|------|-------|-------------|
| 400 | `invalid_name` | Name contains invalid characters |
| 409 | `identity_exists` | Identity with this name already exists |
| 404 | `context_not_found` | One or more contexts don't exist |

---

## Update Identity

Update an existing identity.

```
PUT /api/identities/{id}
```

### Request

```json
{
  "name": "backend-api",
  "team": "engineering",
  "environment": "production",
  "contexts": ["user-pii", "session-tokens", "payment-data"]
}
```

### Response

```json
{
  "id": "id_abc123",
  "name": "backend-api",
  "team": "engineering",
  "environment": "production",
  "contexts": ["user-pii", "session-tokens", "payment-data"],
  "updated_at": "2024-01-15T16:00:00Z"
}
```

---

## Delete Identity

Delete (revoke) an identity.

```
DELETE /api/identities/{id}
```

### Response

```json
{
  "id": "id_abc123",
  "status": "revoked",
  "revoked_at": "2024-01-15T16:30:00Z"
}
```

> **Warning:** Deleting an identity immediately invalidates all its tokens. The SDK will stop working.

---

## Regenerate Tokens

Generate new tokens for an identity (rotates keypair).

```
POST /api/identities/{id}/regenerate
```

### Response

```json
{
  "id": "id_abc123",
  "sdk_download": {
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "url": "http://localhost:8003/sdk/download/eyJhbG.../python",
    "expires_at": "2024-01-15T17:30:00Z"
  },
  "previous_tokens_revoked": true
}
```

> **Warning:** This invalidates all existing tokens. Applications using the old SDK will need to reinstall.

---

## Get SDK Download URL

Get a new SDK download URL for an existing identity.

```
POST /api/identities/{id}/sdk-download
```

### Request

```json
{
  "platform": "python"  // or "typescript"
}
```

### Response

```json
{
  "url": "http://localhost:8003/sdk/download/eyJhbG.../python",
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "expires_at": "2024-01-15T11:00:00Z",
  "install_command": "pip install http://localhost:8003/sdk/download/eyJhbG.../python"
}
```

---

## Identity Tokens

### Get Access Token

Exchange identity credentials for an access token.

```
POST /api/identities/{id}/token
```

> **Note:** This is typically called by the SDK automatically. You don't need to call it directly.

### Request

```json
{
  "grant_type": "client_credentials"
}
```

### Response

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIs...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Refresh Token

Refresh an access token using a refresh token.

```
POST /api/identities/{id}/token/refresh
```

### Request

```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

### Response

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

---

## Identity Audit

Get audit logs for a specific identity.

```
GET /api/identities/{id}/audit
```

### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | int | Max results (default 100, max 1000) |
| `offset` | int | Pagination offset |
| `operation` | string | Filter by operation (encrypt, decrypt) |
| `context` | string | Filter by context |
| `success` | bool | Filter by success/failure |

### Response

```json
{
  "logs": [
    {
      "id": "log_xyz789",
      "timestamp": "2024-01-15T15:30:00Z",
      "operation": "encrypt",
      "context": "user-pii",
      "algorithm": "AES-256-GCM",
      "success": true,
      "latency_ms": 12
    }
  ],
  "pagination": {
    "total": 15234,
    "limit": 100,
    "offset": 0
  }
}
```

---

## Bulk Operations

### Bulk Create

Create multiple identities at once.

```
POST /api/identities/bulk
```

### Request

```json
{
  "identities": [
    {"name": "service-a", "team": "team-1", "contexts": ["user-pii"]},
    {"name": "service-b", "team": "team-1", "contexts": ["session-tokens"]}
  ]
}
```

### Response

```json
{
  "created": 2,
  "identities": [
    {"id": "id_abc123", "name": "service-a", "sdk_download": {...}},
    {"id": "id_def456", "name": "service-b", "sdk_download": {...}}
  ]
}
```
