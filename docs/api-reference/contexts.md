# Contexts API

Manage encryption contexts and their configurations.

## Overview

Contexts define encryption policies including:

- Algorithm selection via the 5-layer model
- Compliance requirements
- Access controls
- Key rotation settings

---

## List Contexts

Get all contexts for the current tenant.

```
GET /api/contexts
```

### Response

```json
{
  "contexts": [
    {
      "name": "user-pii",
      "display_name": "User PII",
      "description": "Personal identifiable information",
      "algorithm": "AES-256-GCM",
      "sensitivity": "critical",
      "quantum_resistant": false,
      "compliance_tags": ["gdpr", "ccpa"]
    }
  ]
}
```

---

## Get Context

Get detailed information about a specific context.

```
GET /api/contexts/{name}
```

### Response

```json
{
  "name": "user-pii",
  "display_name": "User PII",
  "description": "Personal identifiable information",
  "config": {
    "data_identity": {
      "sensitivity": "critical",
      "classification": "pii",
      "examples": ["SSN", "email", "phone"]
    },
    "regulatory": {
      "frameworks": ["gdpr", "ccpa"],
      "audit_requirements": "detailed"
    },
    "threat_model": {
      "adversary_capability": "criminal",
      "protection_duration_years": 7
    },
    "access_patterns": {
      "read_frequency": "high",
      "latency_sensitive": true
    },
    "technical": {
      "fips_required": false
    }
  },
  "derived": {
    "resolved_algorithm": "AES-256-GCM",
    "key_bits": 256,
    "quantum_resistant": false,
    "rationale": [
      "Critical sensitivity requires 256-bit keys",
      "GDPR compliance requires strong encryption"
    ]
  },
  "algorithm_policy": null,
  "policy_enforcement": "none",
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-15T10:00:00Z"
}
```

---

## Create Context

Create a new encryption context.

```
POST /api/contexts
```

### Request (5-Layer Config)

```json
{
  "name": "financial-records",
  "display_name": "Financial Records",
  "description": "Financial documents and records",
  "config": {
    "data_identity": {
      "sensitivity": "critical",
      "classification": "pci",
      "examples": ["bank statements", "tax returns"]
    },
    "regulatory": {
      "frameworks": ["pci-dss", "sox"],
      "audit_requirements": "detailed"
    },
    "threat_model": {
      "adversary_capability": "criminal",
      "protection_duration_years": 7
    },
    "access_patterns": {
      "read_frequency": "low",
      "write_frequency": "low"
    },
    "technical": {
      "fips_required": true
    }
  }
}
```

### Response

```json
{
  "name": "financial-records",
  "display_name": "Financial Records",
  "algorithm": "AES-256-GCM",
  "derived": {
    "resolved_algorithm": "AES-256-GCM",
    "key_bits": 256,
    "quantum_resistant": false,
    "rationale": [
      "Critical sensitivity requires 256-bit keys",
      "PCI-DSS compliance requires AES-256",
      "FIPS mode enabled"
    ]
  },
  "created_at": "2024-01-15T10:00:00Z"
}
```

### Errors

| Code | Error | Description |
|------|-------|-------------|
| 400 | `invalid_config` | Configuration is invalid |
| 409 | `context_exists` | Context with this name already exists |

---

## Create Context (Legacy)

Create a context with simple configuration.

```
POST /api/contexts/legacy
```

### Request

```json
{
  "name": "simple-context",
  "display_name": "Simple Context",
  "description": "Basic encryption context",
  "algorithm": "AES-256-GCM",
  "data_examples": ["general data"],
  "compliance_tags": []
}
```

---

## Update Context

Update an existing context.

```
PUT /api/contexts/{name}
```

### Request

```json
{
  "name": "user-pii",
  "display_name": "User PII (Updated)",
  "description": "Personal identifiable information",
  "config": {
    "data_identity": {
      "sensitivity": "critical",
      "classification": "pii"
    },
    "threat_model": {
      "quantum_threat": true,
      "protection_duration_years": 15
    }
  },
  "algorithm_policy": {
    "allowed_algorithms": ["AES-256-GCM", "AES-256-GCM+ML-KEM-768"]
  },
  "policy_enforcement": "enforce"
}
```

### Response

```json
{
  "name": "user-pii",
  "algorithm": "AES-256-GCM+ML-KEM-768",
  "derived": {
    "resolved_algorithm": "AES-256-GCM+ML-KEM-768",
    "quantum_resistant": true,
    "rationale": [
      "Quantum threat requires hybrid PQC",
      "15-year protection exceeds quantum timeline"
    ]
  },
  "updated_at": "2024-01-15T12:00:00Z"
}
```

---

## Delete Context

Delete a context.

```
DELETE /api/contexts/{name}
```

> **Warning:** Deleting a context does not delete encrypted data. Existing ciphertext can still be decrypted as long as the key exists.

### Response

```json
{
  "name": "user-pii",
  "deleted_at": "2024-01-15T12:00:00Z"
}
```

---

## Resolve Algorithm

Get the resolved algorithm for a context configuration.

```
GET /api/contexts/{name}/resolve
```

### Response

```json
{
  "resolved_algorithm": "AES-256-GCM+ML-KEM-768",
  "key_bits": 256,
  "quantum_resistant": true,
  "rationale": [
    "Critical sensitivity requires 256-bit keys",
    "Quantum threat model requires hybrid PQC",
    "15-year protection duration exceeds quantum timeline"
  ],
  "alternatives": [
    {
      "algorithm": "AES-256-GCM",
      "reason": "If quantum resistance not required"
    }
  ]
}
```

---

## Context Statistics

Get usage statistics for a context.

```
GET /api/contexts/{name}/stats
```

### Response

```json
{
  "name": "user-pii",
  "stats": {
    "total_encryptions": 152340,
    "total_decryptions": 98234,
    "encryptions_today": 1234,
    "decryptions_today": 876,
    "avg_latency_ms": 12,
    "error_rate": 0.001,
    "unique_identities": 15
  },
  "key_info": {
    "current_version": 3,
    "created_at": "2024-01-01T00:00:00Z",
    "last_rotation": "2024-01-10T00:00:00Z"
  }
}
```

---

## Algorithm Policy

### Set Algorithm Policy

Attach an algorithm policy to a context.

```
PUT /api/contexts/{name}/policy
```

### Request

```json
{
  "algorithm_policy": {
    "allowed_algorithms": ["AES-256-GCM", "AES-256-GCM+ML-KEM-768"],
    "blocked_algorithms": ["AES-128-*", "ChaCha20-*"],
    "min_key_bits": 256,
    "require_quantum_resistant": false
  },
  "policy_enforcement": "enforce"
}
```

### Response

```json
{
  "name": "user-pii",
  "algorithm_policy": {
    "allowed_algorithms": ["AES-256-GCM", "AES-256-GCM+ML-KEM-768"],
    "blocked_algorithms": ["AES-128-*", "ChaCha20-*"],
    "min_key_bits": 256
  },
  "policy_enforcement": "enforce",
  "updated_at": "2024-01-15T12:00:00Z"
}
```

### Remove Algorithm Policy

```
DELETE /api/contexts/{name}/policy
```
