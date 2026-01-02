# Keys API

Manage encryption keys, view rotation history, and monitor key health.

## Endpoints

### List Keys

```http
GET /api/v1/keys
```

List all keys for a context.

**Query Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `context` | string | Yes | Context name |
| `status` | string | No | Filter by status (active, rotated, retired) |

**Response:**

```json
{
  "keys": [
    {
      "keyId": "key_user-pii_v3_abc123",
      "context": "user-pii",
      "version": 3,
      "status": "active",
      "algorithm": "AES-256-GCM",
      "createdAt": "2026-01-02T10:30:00Z",
      "lastUsedAt": "2026-01-02T15:45:00Z"
    }
  ],
  "total": 3
}
```

---

### Get Key Details

```http
GET /api/v1/keys/{key_id}
```

Get detailed information about a specific key.

**Response:**

```json
{
  "keyId": "key_user-pii_v3_abc123",
  "context": "user-pii",
  "version": 3,
  "status": "active",
  "algorithm": "AES-256-GCM",
  "keyBits": 256,
  "createdAt": "2026-01-02T10:30:00Z",
  "lastUsedAt": "2026-01-02T15:45:00Z",
  "encryptionCount": 15420,
  "decryptionCount": 12890
}
```

---

### Rotate Key

```http
POST /api/v1/keys/{context}/rotate
```

Rotate the active key for a context. The current key is marked as `rotated` and remains available for decryption.

**Response:**

```json
{
  "newKeyId": "key_user-pii_v4_def456",
  "previousKeyId": "key_user-pii_v3_abc123",
  "version": 4,
  "status": "active",
  "createdAt": "2026-01-02T16:00:00Z"
}
```

---

### Get Key History

```http
GET /api/v1/keys/{context}/history
```

Get rotation history for a context.

**Response:**

```json
{
  "context": "user-pii",
  "history": [
    {
      "keyId": "key_user-pii_v4_def456",
      "version": 4,
      "status": "active",
      "createdAt": "2026-01-02T16:00:00Z",
      "rotatedBy": "admin@example.com"
    },
    {
      "keyId": "key_user-pii_v3_abc123",
      "version": 3,
      "status": "rotated",
      "createdAt": "2026-01-01T10:00:00Z",
      "rotatedAt": "2026-01-02T16:00:00Z"
    }
  ]
}
```

---

### Get Key Statistics

```http
GET /api/v1/keys/stats
```

Get aggregate key statistics.

**Response:**

```json
{
  "totalKeys": 12,
  "activeKeys": 4,
  "rotatedKeys": 6,
  "retiredKeys": 2,
  "byAlgorithm": {
    "AES-256-GCM": 10,
    "ML-KEM-768": 2
  },
  "byContext": {
    "user-pii": 3,
    "payment-data": 3,
    "session-tokens": 3,
    "default": 3
  }
}
```

---

## Key Status

| Status | Description |
|--------|-------------|
| `active` | Current key used for encryption |
| `rotated` | Previous key, available for decryption only |
| `retired` | Key no longer available for any operations |

## Best Practices

1. **Regular Rotation** - Rotate keys periodically (e.g., every 90 days)
2. **Keep Rotated Keys** - Don't retire keys until all data is re-encrypted
3. **Monitor Usage** - Track encryption/decryption counts to detect anomalies
4. **Audit Rotations** - Review rotation history for compliance
