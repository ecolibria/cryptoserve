#!/usr/bin/env python3
"""
Cryptographic Hashing Example

Demonstrates various hashing operations with CryptoServe.
"""

from cryptoserve import CryptoServe


def main():
    crypto = CryptoServe(
        app_name="hashing-example",
        team="examples",
    )

    print("CryptoServe Cryptographic Hashing Example")
    print("=" * 50)

    data = b"The quick brown fox jumps over the lazy dog"

    # Example 1: SHA-256 (default)
    print("\n1. SHA-256 hashing (default)...")
    sha256_hash = crypto.hash(data)
    print(f"   Input:  {data.decode()}")
    print(f"   SHA256: {sha256_hash}")

    # Example 2: Different hash algorithms
    print("\n2. Different hash algorithms...")
    algorithms = ["sha256", "sha384", "sha512", "sha3-256", "blake2b"]

    for algo in algorithms:
        try:
            hash_result = crypto.hash(data, algorithm=algo)
            print(f"   {algo.upper():12} {hash_result[:48]}...")
        except Exception as e:
            print(f"   {algo.upper():12} Error: {e}")

    # Example 3: Hash consistency
    print("\n3. Hash consistency (same input = same output)...")
    hash1 = crypto.hash(data, algorithm="sha256")
    hash2 = crypto.hash(data, algorithm="sha256")
    assert hash1 == hash2, "Hashes should be identical!"
    print(f"   Hash 1: {hash1[:32]}...")
    print(f"   Hash 2: {hash2[:32]}...")
    print("   Verification: IDENTICAL")

    # Example 4: Hash sensitivity (small change = completely different hash)
    print("\n4. Hash sensitivity (avalanche effect)...")
    data1 = b"Hello World"
    data2 = b"Hello World!"  # Just added an exclamation mark
    data3 = b"hello World"   # Changed H to h

    hash_1 = crypto.hash(data1)
    hash_2 = crypto.hash(data2)
    hash_3 = crypto.hash(data3)

    print(f"   'Hello World'  -> {hash_1[:32]}...")
    print(f"   'Hello World!' -> {hash_2[:32]}...")
    print(f"   'hello World'  -> {hash_3[:32]}...")

    # Count differing characters
    diff_2 = sum(a != b for a, b in zip(hash_1, hash_2))
    diff_3 = sum(a != b for a, b in zip(hash_1, hash_3))
    print(f"   Difference from original: {diff_2} chars, {diff_3} chars")

    # Example 5: MAC (Message Authentication Code)
    print("\n5. HMAC (keyed hashing)...")
    secret_key = b"my-secret-key-32-bytes-long!!!!!"

    mac_result = crypto.mac(data, key=secret_key)
    print(f"   Data: {data.decode()[:30]}...")
    print(f"   Key:  {secret_key.decode()[:20]}...")
    print(f"   HMAC: {mac_result}")

    # Verify MAC consistency
    mac_result2 = crypto.mac(data, key=secret_key)
    assert mac_result == mac_result2
    print("   Verification: CONSISTENT")

    # Different key = different MAC
    different_key = b"different-key-32-bytes-long!!!!"
    mac_different = crypto.mac(data, key=different_key)
    assert mac_result != mac_different
    print("   Different key: DIFFERENT MAC")

    # Example 6: Hashing for integrity verification
    print("\n6. File integrity verification pattern...")

    # Simulate a file and its hash
    file_content = b"Important document content\n" * 100
    original_hash = crypto.hash(file_content, algorithm="sha256")
    print(f"   File size:     {len(file_content)} bytes")
    print(f"   Original hash: {original_hash[:32]}...")

    # Simulate file transfer/storage
    received_content = file_content  # In real scenario, this comes from storage

    # Verify integrity
    received_hash = crypto.hash(received_content, algorithm="sha256")
    is_intact = original_hash == received_hash
    print(f"   Received hash: {received_hash[:32]}...")
    print(f"   Integrity:     {'VERIFIED' if is_intact else 'CORRUPTED'}")

    # Example 7: Hash chaining
    print("\n7. Hash chaining (blockchain-like)...")

    blocks = [
        b"Genesis block",
        b"Transaction: Alice -> Bob: $100",
        b"Transaction: Bob -> Charlie: $50",
    ]

    previous_hash = "0" * 64  # Genesis previous hash
    chain = []

    for i, block_data in enumerate(blocks):
        # Create block with previous hash
        block_content = previous_hash.encode() + block_data
        block_hash = crypto.hash(block_content, algorithm="sha256")
        chain.append({
            "index": i,
            "data": block_data.decode(),
            "prev_hash": previous_hash[:16] + "...",
            "hash": block_hash[:16] + "..."
        })
        previous_hash = block_hash

    for block in chain:
        print(f"   Block {block['index']}: {block['hash']} <- {block['prev_hash']}")

    print("\n" + "=" * 50)
    print("All examples completed successfully!")


if __name__ == "__main__":
    main()
