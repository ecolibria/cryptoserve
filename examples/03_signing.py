#!/usr/bin/env python3
"""
Digital Signatures Example

Demonstrates signing and verifying data with CryptoServe.
"""

import hashlib
from cryptoserve import CryptoServe


def main():
    crypto = CryptoServe(
        app_name="signing-example",
        team="examples",
    )

    print("CryptoServe Digital Signatures Example")
    print("=" * 50)

    # Example 1: Sign a message
    print("\n1. Signing a message...")
    message = b"This document represents a legally binding agreement."
    signature = crypto.sign(message, key_id="default-signing-key")
    print(f"   Message:   {message.decode()[:50]}...")
    print(f"   Signature: {signature.hex()[:50]}... ({len(signature)} bytes)")

    # Example 2: Verify the signature
    print("\n2. Verifying the signature...")
    is_valid = crypto.verify_signature(message, signature, key_id="default-signing-key")
    print(f"   Valid: {is_valid}")
    assert is_valid, "Signature verification failed!"

    # Example 3: Verify with wrong message
    print("\n3. Verifying with tampered message...")
    tampered_message = b"This document represents a legally binding agreement!"  # Note the !
    is_valid_tampered = crypto.verify_signature(
        tampered_message, signature, key_id="default-signing-key"
    )
    print(f"   Valid: {is_valid_tampered}")
    assert not is_valid_tampered, "Tampered message should not verify!"
    print("   Correctly rejected tampered message!")

    # Example 4: Sign structured data
    print("\n4. Signing structured data (JSON)...")
    import json

    contract = {
        "contract_id": "CONTRACT-2024-001",
        "parties": ["Alice Corp", "Bob Inc"],
        "amount": 1_000_000,
        "currency": "USD",
        "terms": "Standard 30-day payment terms",
        "signed_date": "2024-01-15",
    }

    # Canonicalize JSON for consistent signing
    contract_bytes = json.dumps(contract, sort_keys=True, separators=(",", ":")).encode()
    contract_signature = crypto.sign(contract_bytes, key_id="contract-signing")

    print(f"   Contract ID: {contract['contract_id']}")
    print(f"   Signature:   {contract_signature.hex()[:40]}...")

    # Verify
    is_contract_valid = crypto.verify_signature(
        contract_bytes, contract_signature, key_id="contract-signing"
    )
    print(f"   Verification: {'VALID' if is_contract_valid else 'INVALID'}")

    # Example 5: Sign a file hash (common pattern)
    print("\n5. Signing a file hash...")

    # Simulate file content
    file_content = b"This is the content of an important document.\n" * 100

    # Hash the file first (more efficient for large files)
    file_hash = hashlib.sha256(file_content).digest()
    print(f"   File size:   {len(file_content)} bytes")
    print(f"   SHA-256:     {file_hash.hex()[:32]}...")

    # Sign the hash
    hash_signature = crypto.sign(file_hash, key_id="document-signing")
    print(f"   Signature:   {hash_signature.hex()[:32]}...")

    # Verify
    is_file_valid = crypto.verify_signature(
        file_hash, hash_signature, key_id="document-signing"
    )
    print(f"   Verification: {'VALID' if is_file_valid else 'INVALID'}")

    # Example 6: Multiple signatures (multi-party)
    print("\n6. Multi-party signing scenario...")

    document = b"Agreement between Party A and Party B"

    # Party A signs
    sig_a = crypto.sign(document, key_id="party-a-signing")
    print(f"   Party A signature: {sig_a.hex()[:24]}...")

    # Party B signs
    sig_b = crypto.sign(document, key_id="party-b-signing")
    print(f"   Party B signature: {sig_b.hex()[:24]}...")

    # Both signatures can be verified independently
    valid_a = crypto.verify_signature(document, sig_a, key_id="party-a-signing")
    valid_b = crypto.verify_signature(document, sig_b, key_id="party-b-signing")
    print(f"   Party A valid: {valid_a}")
    print(f"   Party B valid: {valid_b}")

    print("\n" + "=" * 50)
    print("All examples completed successfully!")


if __name__ == "__main__":
    main()
