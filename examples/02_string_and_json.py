#!/usr/bin/env python3
"""
String and JSON Encryption Example

Demonstrates encrypting strings and JSON objects with CryptoServe.
"""

import json
from cryptoserve import CryptoServe


def main():
    crypto = CryptoServe(
        app_name="string-json-example",
        team="examples",
    )

    print("CryptoServe String and JSON Encryption Example")
    print("=" * 50)

    # Example 1: Encrypt a string
    print("\n1. Encrypting a string...")
    secret_message = "This is a secret message with special chars: éàü"
    encrypted_string = crypto.encrypt_string(secret_message, context="default")
    print(f"   Original:  {secret_message}")
    print(f"   Encrypted: {encrypted_string[:50]}...")

    decrypted_string = crypto.decrypt_string(encrypted_string, context="default")
    print(f"   Decrypted: {decrypted_string}")
    assert decrypted_string == secret_message
    print("   Verification: PASSED")

    # Example 2: Encrypt JSON object
    print("\n2. Encrypting a JSON object...")
    user_data = {
        "id": "user_12345",
        "name": "John Doe",
        "email": "john.doe@example.com",
        "ssn": "123-45-6789",
        "address": {
            "street": "123 Main St",
            "city": "San Francisco",
            "state": "CA",
            "zip": "94102"
        },
        "payment_methods": [
            {"type": "credit_card", "last4": "1234"},
            {"type": "bank_account", "last4": "5678"}
        ]
    }

    encrypted_json = crypto.encrypt_json(user_data, context="user-pii")
    print(f"   Original:  {json.dumps(user_data, indent=2)[:100]}...")
    print(f"   Encrypted: {encrypted_json[:50]}...")

    decrypted_json = crypto.decrypt_json(encrypted_json, context="user-pii")
    print(f"   Decrypted: {json.dumps(decrypted_json, indent=2)[:100]}...")
    assert decrypted_json == user_data
    print("   Verification: PASSED")

    # Example 3: Encrypt sensitive fields only
    print("\n3. Encrypting only sensitive fields...")
    record = {
        "id": "record_001",
        "public_data": "This is visible",
        "ssn": "987-65-4321",
        "credit_score": 750
    }

    # Encrypt only the sensitive fields
    record["ssn_encrypted"] = crypto.encrypt_string(record["ssn"], context="user-pii")
    del record["ssn"]
    record["credit_score_encrypted"] = crypto.encrypt_string(
        str(record["credit_score"]), context="user-pii"
    )
    del record["credit_score"]

    print(f"   Partially encrypted record:")
    print(f"   {json.dumps(record, indent=2)}")

    # Decrypt back
    record["ssn"] = crypto.decrypt_string(record["ssn_encrypted"], context="user-pii")
    record["credit_score"] = int(crypto.decrypt_string(
        record["credit_score_encrypted"], context="user-pii"
    ))
    del record["ssn_encrypted"]
    del record["credit_score_encrypted"]

    print(f"\n   After decryption:")
    print(f"   {json.dumps(record, indent=2)}")

    # Example 4: Empty and edge cases
    print("\n4. Edge cases...")

    # Empty string
    empty_enc = crypto.encrypt_string("", context="default")
    empty_dec = crypto.decrypt_string(empty_enc, context="default")
    assert empty_dec == ""
    print("   Empty string: PASSED")

    # Unicode characters
    unicode_text = "Hello in Japanese: \u3053\u3093\u306b\u3061\u306f"
    unicode_enc = crypto.encrypt_string(unicode_text, context="default")
    unicode_dec = crypto.decrypt_string(unicode_enc, context="default")
    assert unicode_dec == unicode_text
    print("   Unicode text: PASSED")

    # Null values in JSON
    json_with_null = {"name": "Test", "optional_field": None, "count": 0}
    null_enc = crypto.encrypt_json(json_with_null, context="default")
    null_dec = crypto.decrypt_json(null_enc, context="default")
    assert null_dec == json_with_null
    print("   JSON with null: PASSED")

    print("\n" + "=" * 50)
    print("All examples completed successfully!")


if __name__ == "__main__":
    main()
