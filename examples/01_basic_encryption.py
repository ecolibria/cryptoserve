#!/usr/bin/env python3
"""
Basic Encryption Example

Demonstrates fundamental encrypt/decrypt operations with CryptoServe.
"""

from cryptoserve import CryptoServe


def main():
    # Initialize CryptoServe - app auto-registers on first use
    crypto = CryptoServe(
        app_name="encryption-example",
        team="examples",
        environment="development",
    )

    print("CryptoServe Basic Encryption Example")
    print("=" * 50)

    # Example 1: Encrypt bytes
    print("\n1. Encrypting binary data...")
    plaintext = b"This is sensitive binary data"
    ciphertext = crypto.encrypt(plaintext, context="default")
    print(f"   Plaintext:  {plaintext}")
    print(f"   Ciphertext: {ciphertext[:50]}... ({len(ciphertext)} bytes)")

    # Example 2: Decrypt bytes
    print("\n2. Decrypting binary data...")
    decrypted = crypto.decrypt(ciphertext, context="default")
    print(f"   Decrypted:  {decrypted}")
    assert decrypted == plaintext, "Decryption failed!"
    print("   Verification: PASSED")

    # Example 3: Different contexts
    print("\n3. Using different contexts...")
    contexts = ["user-pii", "session-tokens", "default"]
    for ctx in contexts:
        try:
            enc = crypto.encrypt(b"test data", context=ctx)
            dec = crypto.decrypt(enc, context=ctx)
            print(f"   Context '{ctx}': OK")
        except Exception as e:
            print(f"   Context '{ctx}': {e}")

    # Example 4: Large data
    print("\n4. Encrypting larger data...")
    large_data = b"X" * 1_000_000  # 1 MB
    encrypted_large = crypto.encrypt(large_data, context="default")
    decrypted_large = crypto.decrypt(encrypted_large, context="default")
    print(f"   Original size:  {len(large_data):,} bytes")
    print(f"   Encrypted size: {len(encrypted_large):,} bytes")
    print(f"   Decrypted size: {len(decrypted_large):,} bytes")
    assert decrypted_large == large_data, "Large data decryption failed!"
    print("   Verification: PASSED")

    # Example 5: Health check
    print("\n5. Health check...")
    if crypto.health_check():
        print("   CryptoServe connection: HEALTHY")
    else:
        print("   CryptoServe connection: UNHEALTHY")

    print("\n" + "=" * 50)
    print("All examples completed successfully!")


if __name__ == "__main__":
    main()
