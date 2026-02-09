# SDK Examples

Common patterns and use cases for CryptoServe SDKs.

> **Note:** TypeScript examples show the planned API. For production use today, use the Python SDK.

## Basic Encryption

### Encrypt and Decrypt a String

**Python**

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", team="platform")

# Encrypt
secret = "My secret message"
encrypted = crypto.encrypt_string(secret, context="user-pii")

# Decrypt
decrypted = crypto.decrypt_string(encrypted, context="user-pii")
assert decrypted == secret
```

**TypeScript**

```typescript
import { crypto } from '@cryptoserve/sdk';

// Encrypt
const secret = "My secret message";
const encrypted = await crypto.encrypt(secret, { context: "user-pii" });

// Decrypt
const decrypted = await crypto.decrypt(encrypted);
console.assert(decrypted === secret);
```

### Encrypt Binary Data

**Python**

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", team="platform")

# Read a file
with open("document.pdf", "rb") as f:
    data = f.read()

# Encrypt
encrypted = crypto.encrypt(data, context="documents")

# Save encrypted file
with open("document.pdf.enc", "wb") as f:
    f.write(encrypted)

# Later, decrypt
with open("document.pdf.enc", "rb") as f:
    encrypted = f.read()

decrypted = crypto.decrypt(encrypted, context="documents")
```

**TypeScript**

```typescript
import { crypto } from '@cryptoserve/sdk';
import { readFile, writeFile } from 'fs/promises';

// Read a file
const data = await readFile('document.pdf');

// Encrypt
const encrypted = await crypto.encrypt(data, { context: 'documents' });

// Save encrypted file
await writeFile('document.pdf.enc', encrypted);
```

---

## JSON Encryption

### Encrypt User Data

**Python**

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", team="platform")

user = {
    "name": "John Doe",
    "ssn": "123-45-6789",
    "email": "john@example.com",
    "address": {
        "street": "123 Main St",
        "city": "New York"
    }
}

# Encrypt entire object
encrypted = crypto.encrypt_json(user, context="user-pii")

# Decrypt
decrypted_user = crypto.decrypt_json(encrypted, context="user-pii")
print(decrypted_user["name"])  # "John Doe"
```

**TypeScript**

```typescript
import { crypto } from '@cryptoserve/sdk';

interface User {
  name: string;
  ssn: string;
  email: string;
}

const user: User = {
  name: "John Doe",
  ssn: "123-45-6789",
  email: "john@example.com"
};

// Encrypt
const encrypted = await crypto.encryptObject(user, { context: "user-pii" });

// Decrypt with type safety
const decrypted = await crypto.decryptObject<User>(encrypted);
console.log(decrypted.name); // TypeScript knows this is string
```

---

## Associated Data (AAD)

Use associated data to bind ciphertext to a specific context:

**Python**

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", team="platform")

user_id = "user_12345"
secret_data = "sensitive information"

# Encrypt with AAD
encrypted = crypto.encrypt_string(
    secret_data,
    context="user-pii",
    associated_data=f"user:{user_id}".encode()
)

# Decrypt - AAD must match
decrypted = crypto.decrypt_string(
    encrypted,
    context="user-pii",
    associated_data=f"user:{user_id}".encode()
)

# Wrong AAD fails
try:
    crypto.decrypt_string(
        encrypted,
        context="user-pii",
        associated_data=b"user:wrong_id"
    )
except Exception:
    print("AAD mismatch - decryption failed")
```

**TypeScript**

```typescript
import { crypto } from '@cryptoserve/sdk';

const userId = "user_12345";
const secretData = "sensitive information";

// Encrypt with AAD
const encrypted = await crypto.encrypt(secretData, {
  context: "user-pii",
  associatedData: `user:${userId}`
});

// Decrypt - AAD must match
const decrypted = await crypto.decrypt(encrypted, {
  associatedData: `user:${userId}`
});
```

---

## Database Integration

### SQLAlchemy Model

```python
from sqlalchemy import Column, String, create_engine
from sqlalchemy.orm import declarative_base, Session
from sqlalchemy.ext.hybrid import hybrid_property
from cryptoserve import CryptoServe

Base = declarative_base()
crypto = CryptoServe(app_name="my-app", team="platform")

class User(Base):
__tablename__ = 'users'

id = Column(String, primary_key=True)
email = Column(String, unique=True)
_ssn = Column("ssn_encrypted", String)
_credit_card = Column("credit_card_encrypted", String)

@hybrid_property
def ssn(self):
    if self._ssn:
        return crypto.decrypt_string(self._ssn, context="user-pii")
    return None

@ssn.setter
def ssn(self, value):
    if value:
        self._ssn = crypto.encrypt_string(value, context="user-pii")
    else:
        self._ssn = None

@hybrid_property
def credit_card(self):
    if self._credit_card:
        return crypto.decrypt_string(self._credit_card, context="payment-data")
    return None

@credit_card.setter
def credit_card(self, value):
    if value:
        self._credit_card = crypto.encrypt_string(
            value, context="payment-data"
        )
    else:
        self._credit_card = None


# Usage
user = User(
id="user_123",
email="john@example.com",
ssn="123-45-6789",  # Automatically encrypted
credit_card="4111111111111111"  # Automatically encrypted
)
session.add(user)
session.commit()

# Reading decrypts automatically
print(user.ssn)  # "123-45-6789"
```

### Django Model

```python
from django.db import models
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-django-app", team="platform")


class EncryptedCharField(models.TextField):
"""Custom field that encrypts/decrypts automatically."""

def __init__(self, context, *args, **kwargs):
    self.context = context
    super().__init__(*args, **kwargs)

def from_db_value(self, value, expression, connection):
    if value is None:
        return None
    return crypto.decrypt_string(value, context=self.context)

def get_prep_value(self, value):
    if value is None:
        return None
    return crypto.encrypt_string(value, context=self.context)


class Patient(models.Model):
name = models.CharField(max_length=100)
ssn = EncryptedCharField(context="user-pii")
diagnosis = EncryptedCharField(context="health-data")

class Meta:
    db_table = 'patients'


# Usage
patient = Patient.objects.create(
name="John Doe",
ssn="123-45-6789",  # Encrypted before storage
diagnosis="Confidential medical information"
)

# Reading decrypts automatically
patient = Patient.objects.get(id=1)
print(patient.ssn)  # "123-45-6789"
```

---

## API Integration

### FastAPI Service

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptoserve import CryptoServe, CryptoServeError
from cryptoserve.fastapi import configure

app = FastAPI()
crypto = CryptoServe(app_name="my-fastapi-app", team="platform")
configure(crypto)


class CreateUserRequest(BaseModel):
email: str
ssn: str


class UserResponse(BaseModel):
id: str
email: str
ssn_encrypted: str


@app.post("/users", response_model=UserResponse)
async def create_user(request: CreateUserRequest):
try:
    encrypted_ssn = crypto.encrypt_string(
        request.ssn,
        context="user-pii"
    )
    return UserResponse(
        id="user_123",
        email=request.email,
        ssn_encrypted=encrypted_ssn
    )
except CryptoServeError as e:
    raise HTTPException(status_code=500, detail=str(e))


@app.get("/users/{user_id}/ssn")
async def get_user_ssn(user_id: str, encrypted_ssn: str):
try:
    ssn = crypto.decrypt_string(encrypted_ssn, context="user-pii")
    return {"ssn": ssn}
except CryptoServeError as e:
    raise HTTPException(status_code=400, detail=str(e))
```

### Express.js Service

```typescript
import express from 'express';
import { crypto } from '@cryptoserve/sdk';
import { CryptoServeError } from '@cryptoserve/sdk/errors';

const app = express();
app.use(express.json());

app.post('/users', async (req, res) => {
  try {
const { email, ssn } = req.body;
const encryptedSsn = await crypto.encrypt(ssn, { context: 'user-pii' });

res.json({
  id: 'user_123',
  email,
  ssn_encrypted: encryptedSsn
});
  } catch (error) {
if (error instanceof CryptoServeError) {
  res.status(500).json({ error: error.message });
}
throw error;
  }
});

app.listen(3000);
```

---

## Batch Processing

### Process Multiple Records

```python
from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", team="platform")

# Prepare batch
records = [
{"id": "1", "ssn": "111-11-1111"},
{"id": "2", "ssn": "222-22-2222"},
{"id": "3", "ssn": "333-33-3333"},
]

# Encrypt each record
for record in records:
record["ssn_encrypted"] = crypto.encrypt_string(
    record["ssn"], context="user-pii"
)

# Decrypt each record
for record in records:
decrypted = crypto.decrypt_string(
    record["ssn_encrypted"], context="user-pii"
)
print(f"Record {record['id']}: {decrypted}")
```

---

## Error Handling

### Comprehensive Error Handling

```python
from cryptoserve import CryptoServe
from cryptoserve import (
CryptoServeError,
AuthenticationError,
AuthorizationError,
ContextNotFoundError,
TokenRefreshError
)

crypto = CryptoServe(app_name="my-app", team="platform")


def safe_encrypt(data: str, context: str) -> str | None:
"""Encrypt with comprehensive error handling."""
try:
    return crypto.encrypt_string(data, context=context)

except AuthorizationError as e:
    # Identity not authorized for this context
    print(f"Authorization failed: {e}")
    raise PermissionError(f"Not authorized for context: {context}")

except ContextNotFoundError as e:
    # Context doesn't exist
    print(f"Context not found: {e}")
    raise ValueError(f"Invalid context: {context}")

except CryptoServeError as e:
    # Catch-all for other errors
    print(f"Encryption failed: {e}")
    raise


def safe_decrypt(ciphertext: str, context: str) -> str | None:
"""Decrypt with comprehensive error handling."""
try:
    return crypto.decrypt_string(ciphertext, context=context)

except AuthenticationError as e:
    # Authentication failed
    print(f"Authentication failed: {e}")
    return None

except TokenRefreshError:
    # Token refresh failed
    print("Token expired and refresh failed")
    return None

except CryptoServeError as e:
    print(f"Decryption error: {e}")
    raise
```

---

## Testing

### Mock Mode for Tests

```python
import pytest
from unittest.mock import Mock, patch


@pytest.fixture
def mock_crypto():
"""Create a mock CryptoServe instance for tests."""
with patch('mymodule.CryptoServe') as mock_class:
    instance = Mock()
    mock_class.return_value = instance

    # Configure mock encrypt/decrypt behavior
    encrypted_data = {}
    def mock_encrypt(data, context):
        key = f"{context}:{data}"
        encrypted_data[key] = data
        return f"ENC:{key}"

    def mock_decrypt(ciphertext, context):
        key = ciphertext.replace("ENC:", "")
        return encrypted_data.get(key, "")

    instance.encrypt_string.side_effect = mock_encrypt
    instance.decrypt_string.side_effect = mock_decrypt
    yield instance


def test_encrypt_decrypt(mock_crypto):
"""Test basic encryption/decryption."""
original = "test data"
encrypted = mock_crypto.encrypt_string(original, context="test")
decrypted = mock_crypto.decrypt_string(encrypted, context="test")
assert decrypted == original
```
