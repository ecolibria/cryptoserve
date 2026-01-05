# TypeScript SDK

!!! warning "Coming Soon"
    The TypeScript SDK is currently in development. This documentation describes the **planned API** and is subject to change. For production use, please use the [Python SDK](python.md).

The official TypeScript SDK for CryptoServe will provide type-safe cryptographic operations for Node.js and browser environments.

## Installation

```bash
npm install @cryptoserve/sdk
# or
yarn add @cryptoserve/sdk
```

## Requirements

- Node.js 16+ or modern browser
- TypeScript 4.5+ (optional, works with JavaScript)

---

## Quick Start

```typescript
import { crypto } from '@cryptoserve/sdk';

// Encrypt a string
const encrypted = await crypto.encrypt('Hello World!', {
  context: 'user-pii'
});

// Decrypt it back
const decrypted = await crypto.decrypt(encrypted);

console.log(decrypted); // "Hello World!"
```

---

## API Reference

### Encryption

#### `encrypt(data, options)`

Encrypt data.

```typescript
import { crypto } from '@cryptoserve/sdk';

// Encrypt string
const encrypted = await crypto.encrypt('sensitive data', {
  context: 'user-pii'
});

// Encrypt with associated data
const encrypted = await crypto.encrypt('sensitive data', {
  context: 'user-pii',
  associatedData: 'user_id:123'
});

// Encrypt binary data
const buffer = new Uint8Array([1, 2, 3, 4]);
const encryptedBuffer = await crypto.encrypt(buffer, {
  context: 'user-pii'
});
```

**Options:**

```typescript
interface EncryptOptions {
  context: string;           // Required
  associatedData?: string;   // Optional AAD
  algorithm?: string;        // Override default
}
```

**Returns:** `Promise<string>` - Base64-encoded ciphertext

#### `encryptObject(obj, options)`

Encrypt a JSON object.

```typescript
const user = { name: 'John', ssn: '123-45-6789' };
const encrypted = await crypto.encryptObject(user, {
  context: 'user-pii'
});
```

---

### Decryption

#### `decrypt(ciphertext, options?)`

Decrypt data.

```typescript
const plaintext = await crypto.decrypt(encrypted);

// With associated data
const plaintext = await crypto.decrypt(encrypted, {
  associatedData: 'user_id:123'
});
```

#### `decryptObject<T>(ciphertext, options?)`

Decrypt to a typed object.

```typescript
interface User {
  name: string;
  ssn: string;
}

const user = await crypto.decryptObject<User>(encrypted);
console.log(user.name); // TypeScript knows this is a string
```

---

### Configuration

#### `configure(options)`

Configure SDK behavior.

```typescript
import { configure } from '@cryptoserve/sdk';

configure({
  serverUrl: 'https://api.cryptoserve.io',
  timeout: 30000,
  retries: 3
});
```

#### `getIdentityInfo()`

Get current identity information.

```typescript
import { getIdentityInfo } from '@cryptoserve/sdk';

const info = await getIdentityInfo();
console.log(info);
// {
//   identityId: 'id_abc123',
//   name: 'frontend-app',
//   contexts: ['user-pii', 'session-tokens']
// }
```

---

## Error Handling

```typescript
import { crypto } from '@cryptoserve/sdk';
import {
  CryptoServeError,
  DecryptionError,
  AuthorizationError,
  PolicyViolationError
} from '@cryptoserve/sdk/errors';

try {
  const decrypted = await crypto.decrypt(ciphertext);
} catch (error) {
  if (error instanceof DecryptionError) {
    console.error('Decryption failed:', error.message);
  } else if (error instanceof AuthorizationError) {
    console.error('Not authorized:', error.message);
  } else if (error instanceof PolicyViolationError) {
    console.error('Policy violation:', error.violations);
  } else if (error instanceof CryptoServeError) {
    console.error('CryptoServe error:', error.message);
  }
}
```

---

## TypeScript Types

```typescript
// Encryption result
interface EncryptResult {
  ciphertext: string;
  algorithm: string;
  keyId: string;
  warnings: string[];
}

// Decryption result
interface DecryptResult {
  plaintext: string;
  context: string;
  algorithm: string;
}

// Context information
interface ContextInfo {
  name: string;
  displayName: string;
  algorithm: string;
  sensitivity: 'low' | 'medium' | 'high' | 'critical';
}

// Identity information
interface IdentityInfo {
  identityId: string;
  name: string;
  team?: string;
  environment?: string;
  contexts: string[];
}
```

---

## Framework Integration

### React

```tsx
import { useState, useEffect } from 'react';
import { crypto } from '@cryptoserve/sdk';

function SecureInput({ value, onChange, context }) {
  const [encrypted, setEncrypted] = useState('');

  useEffect(() => {
    if (value) {
      crypto.encrypt(value, { context }).then(setEncrypted);
    }
  }, [value, context]);

  return (
    <input
      type="text"
      value={value}
      onChange={(e) => onChange(e.target.value)}
    />
  );
}
```

### Next.js

```typescript
// pages/api/encrypt.ts
import type { NextApiRequest, NextApiResponse } from 'next';
import { crypto } from '@cryptoserve/sdk';

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  const { data, context } = req.body;
  const encrypted = await crypto.encrypt(data, { context });
  res.json({ encrypted });
}
```

### Express

```typescript
import express from 'express';
import { crypto } from '@cryptoserve/sdk';

const app = express();

app.post('/encrypt', async (req, res) => {
  const { data, context } = req.body;
  const encrypted = await crypto.encrypt(data, { context });
  res.json({ encrypted });
});

app.post('/decrypt', async (req, res) => {
  const { ciphertext } = req.body;
  const plaintext = await crypto.decrypt(ciphertext);
  res.json({ plaintext });
});
```

---

## Browser Usage

The SDK works in browsers with some limitations:

```html
<script type="module">
  import { crypto } from 'https://cdn.cryptoserve.io/sdk/latest.js';

  const encrypted = await crypto.encrypt('secret', {
    context: 'user-pii'
  });
</script>
```

!!! warning "CORS"
    Ensure your CryptoServe server has appropriate CORS headers configured.

---

## Testing

### Jest

```typescript
import { crypto } from '@cryptoserve/sdk';
import { mockCrypto } from '@cryptoserve/sdk/testing';

jest.mock('@cryptoserve/sdk', () => mockCrypto());

test('encrypts and decrypts', async () => {
  const encrypted = await crypto.encrypt('test', { context: 'test' });
  const decrypted = await crypto.decrypt(encrypted);
  expect(decrypted).toBe('test');
});
```

### Vitest

```typescript
import { describe, it, expect, vi } from 'vitest';
import { crypto } from '@cryptoserve/sdk';
import { mockCrypto } from '@cryptoserve/sdk/testing';

vi.mock('@cryptoserve/sdk', () => mockCrypto());

describe('encryption', () => {
  it('encrypts and decrypts', async () => {
    const encrypted = await crypto.encrypt('test', { context: 'test' });
    const decrypted = await crypto.decrypt(encrypted);
    expect(decrypted).toBe('test');
  });
});
```
