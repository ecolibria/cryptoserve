#!/usr/bin/env python3
"""
Error Handling Example

Demonstrates comprehensive error handling patterns with CryptoServe.
"""

from cryptoserve import CryptoServe
from cryptoserve.exceptions import (
    CryptoServeError,
    AuthenticationError,
    AuthorizationError,
    ContextNotFoundError,
    DecryptionError,
    ConnectionError,
    RateLimitError,
    ValidationError,
)


def main():
    crypto = CryptoServe(
        app_name="error-handling-example",
        team="examples",
    )

    print("CryptoServe Error Handling Example")
    print("=" * 50)

    # Example 1: Basic try/except pattern
    print("\n1. Basic error handling...")

    def safe_encrypt(data: bytes, context: str) -> bytes | None:
        """Safely encrypt data with error handling."""
        try:
            return crypto.encrypt(data, context=context)
        except CryptoServeError as e:
            print(f"   Encryption failed: {e}")
            return None

    result = safe_encrypt(b"test data", "default")
    print(f"   Result: {'Success' if result else 'Failed'}")

    # Example 2: Specific exception handling
    print("\n2. Handling specific exceptions...")

    def robust_decrypt(ciphertext: bytes, context: str) -> bytes | None:
        """Decrypt with specific error handling for each case."""
        try:
            return crypto.decrypt(ciphertext, context=context)

        except AuthenticationError as e:
            # Token expired or invalid
            print(f"   Authentication error: {e}")
            print("   Action: Re-authenticate user")
            return None

        except AuthorizationError as e:
            # Not allowed to access this context
            print(f"   Authorization error: {e}")
            print("   Action: Request access or use different context")
            return None

        except ContextNotFoundError as e:
            # Context doesn't exist
            print(f"   Context not found: {e}")
            print("   Action: Create context or use existing one")
            return None

        except DecryptionError as e:
            # Decryption failed (wrong key, corrupted data, etc.)
            print(f"   Decryption error: {e}")
            print("   Action: Verify ciphertext integrity")
            return None

        except ConnectionError as e:
            # Network or server error
            print(f"   Connection error: {e}")
            print("   Action: Retry with backoff")
            return None

        except RateLimitError as e:
            # Too many requests
            print(f"   Rate limit error: {e}")
            print("   Action: Wait and retry")
            return None

        except CryptoServeError as e:
            # Catch-all for other CryptoServe errors
            print(f"   CryptoServe error: {e}")
            return None

    # Test with valid ciphertext
    valid_ciphertext = crypto.encrypt(b"test data", context="default")
    result = robust_decrypt(valid_ciphertext, context="default")
    print(f"   Valid ciphertext result: {result}")

    # Example 3: Retry pattern with exponential backoff
    print("\n3. Retry pattern with exponential backoff...")

    import time
    import random

    def encrypt_with_retry(
        data: bytes,
        context: str,
        max_retries: int = 3,
        base_delay: float = 0.5
    ) -> bytes | None:
        """Encrypt with automatic retry on transient failures."""
        last_error = None

        for attempt in range(max_retries):
            try:
                return crypto.encrypt(data, context=context)

            except (ConnectionError, RateLimitError) as e:
                # Transient errors - retry
                last_error = e
                delay = base_delay * (2 ** attempt) + random.uniform(0, 0.1)
                print(f"   Attempt {attempt + 1} failed: {e}")
                print(f"   Retrying in {delay:.2f}s...")
                time.sleep(delay)

            except CryptoServeError as e:
                # Non-transient error - don't retry
                print(f"   Non-retryable error: {e}")
                raise

        print(f"   All {max_retries} attempts failed")
        raise last_error or CryptoServeError("Max retries exceeded")

    result = encrypt_with_retry(b"important data", "default")
    print(f"   Result: {len(result)} bytes encrypted")

    # Example 4: Graceful degradation
    print("\n4. Graceful degradation pattern...")

    class SecureStorage:
        """Storage with encryption fallback."""

        def __init__(self):
            self.crypto = crypto
            self.fallback_mode = False

        def store(self, key: str, value: str) -> dict:
            """Store value, falling back to plaintext if encryption fails."""
            try:
                encrypted = self.crypto.encrypt_string(value, context="default")
                return {
                    "key": key,
                    "value": encrypted,
                    "encrypted": True,
                }
            except CryptoServeError as e:
                print(f"   Warning: Encryption unavailable ({e})")
                print("   Falling back to plaintext storage")
                self.fallback_mode = True
                return {
                    "key": key,
                    "value": value,
                    "encrypted": False,
                }

        def retrieve(self, record: dict) -> str:
            """Retrieve value, handling both encrypted and plaintext."""
            if record.get("encrypted"):
                try:
                    return self.crypto.decrypt_string(
                        record["value"], context="default"
                    )
                except CryptoServeError as e:
                    print(f"   Warning: Decryption failed ({e})")
                    raise
            return record["value"]

    storage = SecureStorage()
    record = storage.store("user_secret", "my-secret-value")
    print(f"   Stored: encrypted={record['encrypted']}")
    retrieved = storage.retrieve(record)
    print(f"   Retrieved: {retrieved}")

    # Example 5: Validation error handling
    print("\n5. Input validation...")

    def validate_and_encrypt(data: str | bytes, context: str) -> bytes:
        """Validate input before encryption."""
        # Validate data
        if data is None:
            raise ValidationError("Data cannot be None")

        if isinstance(data, str):
            data = data.encode("utf-8")

        if len(data) == 0:
            raise ValidationError("Data cannot be empty")

        if len(data) > 10 * 1024 * 1024:  # 10 MB limit
            raise ValidationError("Data exceeds maximum size (10 MB)")

        # Validate context
        if not context or not context.strip():
            raise ValidationError("Context cannot be empty")

        if not context.replace("-", "").replace("_", "").isalnum():
            raise ValidationError("Context contains invalid characters")

        return crypto.encrypt(data, context=context)

    try:
        result = validate_and_encrypt("valid data", "valid-context")
        print(f"   Valid input: {len(result)} bytes")
    except ValidationError as e:
        print(f"   Validation error: {e}")

    try:
        result = validate_and_encrypt("", "valid-context")
    except ValidationError as e:
        print(f"   Empty data: {e}")

    # Example 6: Logging errors for monitoring
    print("\n6. Error logging pattern...")

    import logging
    import traceback

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("cryptoserve")

    def monitored_operation(data: bytes, context: str) -> bytes | None:
        """Perform operation with detailed logging."""
        operation_id = f"op_{hash(data)}"

        logger.info(f"Starting encryption: {operation_id}")

        try:
            result = crypto.encrypt(data, context=context)
            logger.info(f"Encryption successful: {operation_id}, size={len(result)}")
            return result

        except AuthenticationError as e:
            logger.error(f"Auth error in {operation_id}: {e}")
            # Alert on-call if auth is failing
            return None

        except RateLimitError as e:
            logger.warning(f"Rate limited in {operation_id}: {e}")
            # Consider backing off
            return None

        except CryptoServeError as e:
            logger.error(
                f"Crypto error in {operation_id}: {e}\n"
                f"Traceback: {traceback.format_exc()}"
            )
            return None

        except Exception as e:
            logger.critical(
                f"Unexpected error in {operation_id}: {e}\n"
                f"Traceback: {traceback.format_exc()}"
            )
            raise

    result = monitored_operation(b"monitored data", "default")

    # Example 7: Context manager for error handling
    print("\n7. Context manager pattern...")

    from contextlib import contextmanager

    @contextmanager
    def crypto_operation(operation_name: str):
        """Context manager for crypto operations with logging and timing."""
        start = time.time()
        try:
            yield
            elapsed = time.time() - start
            print(f"   {operation_name}: SUCCESS ({elapsed:.3f}s)")
        except CryptoServeError as e:
            elapsed = time.time() - start
            print(f"   {operation_name}: FAILED ({elapsed:.3f}s) - {e}")
            raise

    with crypto_operation("Encrypt user data"):
        encrypted = crypto.encrypt(b"user data", context="user-pii")

    with crypto_operation("Decrypt user data"):
        decrypted = crypto.decrypt(encrypted, context="user-pii")

    print("\n" + "=" * 50)
    print("Error handling examples completed!")


if __name__ == "__main__":
    main()
