# API Reference

Complete reference documentation for the CryptoServe REST API.

## Interactive API Documentation

!!! tip "Try it live with Swagger UI"
    CryptoServe provides **interactive API documentation** powered by OpenAPI 3.1:

    <div class="grid cards" markdown>

    -   :material-api:{ .lg .middle } **Swagger UI**

        ---

        Interactive API explorer with live request testing

        [:octicons-arrow-right-24: Open Swagger UI](http://localhost:8001/docs){ .md-button }

    -   :material-file-document-outline:{ .lg .middle } **ReDoc**

        ---

        Beautiful, three-panel API documentation

        [:octicons-arrow-right-24: Open ReDoc](http://localhost:8001/redoc){ .md-button }

    </div>

    **OpenAPI Specification**: [`/openapi.json`](http://localhost:8001/openapi.json) - Import into Postman, Insomnia, or any OpenAPI-compatible tool.

---

## Base URL

```
https://api.cryptoserve.io/v1    # Production
http://localhost:8001            # Development
```

## Authentication

All API requests require a valid JWT token in the Authorization header:

```bash
curl -H "Authorization: Bearer <access_token>" \
  https://api.cryptoserve.io/v1/crypto/encrypt
```

See [Authentication](../concepts/architecture.md#authentication-layer) for token details.

## API Sections

<div class="grid cards" markdown>

-   :material-lock:{ .lg .middle } **Crypto Operations**

    ---

    Encrypt, decrypt, sign, verify, hash, and MAC

    [:octicons-arrow-right-24: Crypto API](crypto.md)

-   :material-account-key:{ .lg .middle } **Identities**

    ---

    Create and manage API identities

    [:octicons-arrow-right-24: Identities API](identities.md)

-   :material-folder-cog:{ .lg .middle } **Contexts**

    ---

    Configure encryption contexts

    [:octicons-arrow-right-24: Contexts API](contexts.md)

-   :material-shield-check:{ .lg .middle } **Policies**

    ---

    Define and evaluate cryptographic policies

    [:octicons-arrow-right-24: Policies API](policies.md)

-   :material-shield-account:{ .lg .middle } **Admin**

    ---

    Administrative operations and analytics

    [:octicons-arrow-right-24: Admin API](admin.md)

-   :material-key:{ .lg .middle } **Keys**

    ---

    Key management, rotation, and status

    [:octicons-arrow-right-24: Keys API](keys.md)

-   :material-chart-line:{ .lg .middle } **Usage**

    ---

    Usage statistics and analytics

    [:octicons-arrow-right-24: Usage API](usage.md)

-   :material-shield-lock:{ .lg .middle } **Algorithm Policy**

    ---

    Configure allowed algorithms and FIPS mode

    [:octicons-arrow-right-24: Algorithm Policy API](algorithm-policy.md)

</div>

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
| `400` | Bad Request - Invalid input |
| `401` | Unauthorized - Invalid/missing token |
| `403` | Forbidden - Insufficient permissions |
| `404` | Not Found |
| `409` | Conflict - Resource already exists |
| `429` | Too Many Requests - Rate limited |
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

For type-safe API access, use our official SDKs:

- [Python SDK](../sdk/python.md) - Full async support, Django/FastAPI integrations
- [TypeScript SDK](../sdk/typescript.md) - Browser and Node.js compatible
