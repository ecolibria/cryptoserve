# Usage API

Monitor cryptographic operations, view usage statistics, and analyze trends.

## Endpoints

### Get Usage Summary

```http
GET /api/v1/usage/summary
```

Get overall usage summary for the current tenant.

**Query Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `period` | string | No | Time period: `day`, `week`, `month` (default: `day`) |

**Response:**

```json
{
  "period": "day",
  "startDate": "2026-01-02T00:00:00Z",
  "endDate": "2026-01-02T23:59:59Z",
  "operations": {
    "encrypt": 15420,
    "decrypt": 12890,
    "sign": 2340,
    "verify": 2280,
    "hash": 5670,
    "mac": 1230
  },
  "totalOperations": 39830,
  "uniqueContexts": 4,
  "uniqueApplications": 8
}
```

---

### Get Usage by Context

```http
GET /api/v1/usage/by-context
```

Get usage breakdown by encryption context.

**Response:**

```json
{
  "contexts": [
    {
      "context": "user-pii",
      "operations": {
        "encrypt": 8500,
        "decrypt": 7200
      },
      "totalOperations": 15700,
      "percentOfTotal": 39.4
    },
    {
      "context": "payment-data",
      "operations": {
        "encrypt": 4200,
        "decrypt": 3800
      },
      "totalOperations": 8000,
      "percentOfTotal": 20.1
    }
  ]
}
```

---

### Get Usage by Application

```http
GET /api/v1/usage/by-application
```

Get usage breakdown by application.

**Response:**

```json
{
  "applications": [
    {
      "applicationId": "app_backend_abc123",
      "applicationName": "Backend API",
      "team": "platform",
      "environment": "production",
      "operations": {
        "encrypt": 12000,
        "decrypt": 10500
      },
      "totalOperations": 22500
    }
  ]
}
```

---

### Get Usage Trends

```http
GET /api/v1/usage/trends
```

Get usage trends over time.

**Query Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `period` | string | No | `hour`, `day`, `week` (default: `day`) |
| `points` | int | No | Number of data points (default: 24) |

**Response:**

```json
{
  "period": "hour",
  "dataPoints": [
    {
      "timestamp": "2026-01-02T00:00:00Z",
      "operations": 1250
    },
    {
      "timestamp": "2026-01-02T01:00:00Z",
      "operations": 980
    }
  ]
}
```

---

### Get Top Operations

```http
GET /api/v1/usage/top
```

Get most frequently used contexts and operations.

**Response:**

```json
{
  "topContexts": [
    {"context": "user-pii", "count": 15700},
    {"context": "payment-data", "count": 8000},
    {"context": "session-tokens", "count": 5200}
  ],
  "topOperations": [
    {"operation": "encrypt", "count": 15420},
    {"operation": "decrypt", "count": 12890},
    {"operation": "hash", "count": 5670}
  ],
  "topApplications": [
    {"name": "Backend API", "count": 22500},
    {"name": "Payment Service", "count": 8500}
  ]
}
```

---

## Dashboard Integration

The Usage API powers the Community Dashboard's analytics views:

- **Usage Overview** - Real-time operation counts
- **Context Usage** - Breakdown by encryption context
- **Trends Chart** - Historical usage visualization
- **Top Operations** - Most frequent operations ranking

## Rate Limiting

Usage API endpoints have separate rate limits:

| Endpoint | Rate Limit |
|----------|------------|
| `/usage/summary` | 60/min |
| `/usage/by-*` | 30/min |
| `/usage/trends` | 20/min |
