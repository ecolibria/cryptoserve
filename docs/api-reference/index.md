# API Reference

Complete reference documentation for the CryptoServe REST API.

## Interactive API Documentation

> **Tip:** CryptoServe provides **interactive API documentation** powered by OpenAPI 3.1, available when the server is running:
>
> - **Swagger UI** (`/docs`) — Interactive API explorer with live request testing
> - **ReDoc** (`/redoc`) — Three-panel API documentation
> - **OpenAPI Spec** (`/openapi.json`) — Import into Postman, Insomnia, or any OpenAPI-compatible tool

---

## Base URL

```
https://your-server/v1    # Production
http://localhost:8003      # Development
```

## Authentication

All API requests require a valid JWT token in the Authorization header:

```bash
curl -H "Authorization: Bearer <access_token>" \
  https://your-server/v1/crypto/encrypt
```

See [Authentication](../concepts/architecture.md#authentication-layer) for token details.

## API Sections

| Section | Description | Link |
|---------|-------------|------|
| **Crypto Operations** | Encrypt, decrypt, sign, verify, hash, and MAC | [Crypto API](crypto.md) |
| **Identities** | Create and manage API identities | [Identities API](identities.md) |
| **Contexts** | Configure encryption contexts | [Contexts API](contexts.md) |
| **Policies** | Define and evaluate cryptographic policies | [Policies API](policies.md) |
| **Admin** | Administrative operations and analytics | [Admin API](admin.md) |
| **Keys** | Key management, rotation, and status | [Keys API](keys.md) |
| **Usage** | Usage statistics and analytics | [Usage API](usage.md) |
| **Algorithm Policy** | Configure allowed algorithms and FIPS mode | [Algorithm Policy API](algorithm-policy.md) |

## Response Format

All responses use JSON with consistent structure:

### Success Response

```json
{
  "data": { ... },
  "warnings": []
}
```

### Error Response

```json
{
  "error": "error_code",
  "message": "Human-readable description",
  "details": { ... }
}
```

## HTTP Status Codes

| Code | Description |
|------|-------------|
| `200` | Success |
| `201` | Created |
| `400` | Bad Request — Invalid input |
| `401` | Unauthorized — Invalid/missing token |
| `403` | Forbidden — Insufficient permissions |
| `404` | Not Found |
| `409` | Conflict — Resource already exists |
| `429` | Too Many Requests — Rate limited |
| `500` | Internal Server Error |

## Rate Limiting

Default limits:

| Endpoint Type | Rate Limit |
|---------------|------------|
| Crypto operations | 1000/min |
| Management APIs | 100/min |
| SDK downloads | 10/min |

Rate limit headers:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1642089600
```

## Pagination

List endpoints support pagination:

```bash
GET /api/audit?limit=100&offset=0
```

Response includes pagination info:

```json
{
  "data": [...],
  "pagination": {
    "total": 1523,
    "limit": 100,
    "offset": 0,
    "has_more": true
  }
}
```

## Client SDKs

For type-safe API access, use the official SDKs:

- [Python SDK](../sdk/python.md) — Full async support, Django/FastAPI integrations
- [TypeScript SDK](../sdk/typescript.md) — Browser and Node.js compatible
