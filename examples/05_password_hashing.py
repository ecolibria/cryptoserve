#!/usr/bin/env python3
"""
Password Hashing Example

Demonstrates secure password hashing with CryptoServe using Argon2id.
"""

import time
from cryptoserve import CryptoServe


def main():
    crypto = CryptoServe(
        app_name="password-example",
        team="examples",
    )

    print("CryptoServe Password Hashing Example")
    print("=" * 50)

    # Example 1: Hash a password
    print("\n1. Hashing a password...")
    password = "MySecurePassword123!"

    start = time.time()
    password_hash = crypto.hash_password(password)
    elapsed = time.time() - start

    print(f"   Password: {password}")
    print(f"   Hash:     {password_hash[:60]}...")
    print(f"   Time:     {elapsed:.3f}s")
    print(f"   Length:   {len(password_hash)} characters")

    # Example 2: Verify correct password
    print("\n2. Verifying correct password...")
    start = time.time()
    is_valid = crypto.verify_password(password, password_hash)
    elapsed = time.time() - start

    print(f"   Valid: {is_valid}")
    print(f"   Time:  {elapsed:.3f}s")
    assert is_valid, "Password verification failed!"

    # Example 3: Verify wrong password
    print("\n3. Verifying wrong password...")
    wrong_password = "WrongPassword456!"

    start = time.time()
    is_valid_wrong = crypto.verify_password(wrong_password, password_hash)
    elapsed = time.time() - start

    print(f"   Valid: {is_valid_wrong}")
    print(f"   Time:  {elapsed:.3f}s")
    assert not is_valid_wrong, "Wrong password should not verify!"
    print("   Correctly rejected wrong password!")

    # Example 4: Same password = different hash (salting)
    print("\n4. Demonstrating salting (same password, different hashes)...")
    hash1 = crypto.hash_password(password)
    hash2 = crypto.hash_password(password)

    print(f"   Hash 1: {hash1[:40]}...")
    print(f"   Hash 2: {hash2[:40]}...")
    print(f"   Same:   {hash1 == hash2}")
    assert hash1 != hash2, "Hashes should be different due to salting!"

    # Both should still verify
    assert crypto.verify_password(password, hash1)
    assert crypto.verify_password(password, hash2)
    print("   Both verify: YES")

    # Example 5: Timing attack resistance
    print("\n5. Timing attack resistance...")
    # Hash verification should take similar time regardless of how wrong the password is

    times_correct = []
    times_wrong_first_char = []
    times_wrong_completely = []

    for _ in range(3):
        start = time.time()
        crypto.verify_password(password, password_hash)
        times_correct.append(time.time() - start)

        start = time.time()
        crypto.verify_password("X" + password[1:], password_hash)
        times_wrong_first_char.append(time.time() - start)

        start = time.time()
        crypto.verify_password("CompletelyDifferent", password_hash)
        times_wrong_completely.append(time.time() - start)

    print(f"   Correct password:     {sum(times_correct)/len(times_correct):.4f}s avg")
    print(f"   Wrong first char:     {sum(times_wrong_first_char)/len(times_wrong_first_char):.4f}s avg")
    print(f"   Completely different: {sum(times_wrong_completely)/len(times_wrong_completely):.4f}s avg")
    print("   (Times should be similar to prevent timing attacks)")

    # Example 6: Password strength demonstration
    print("\n6. Password hashing for different password strengths...")
    passwords = [
        ("weak", "password"),
        ("medium", "Password123"),
        ("strong", "MyStr0ng!P@ssw0rd#2024"),
        ("very_strong", "xK9#mP2$vL5@nQ8*wR3&bT6^"),
    ]

    for strength, pwd in passwords:
        hash_result = crypto.hash_password(pwd)
        # All passwords get the same treatment - strong hashing
        print(f"   {strength:12} '{pwd[:15]:15}' -> {hash_result[:30]}...")

    # Example 7: User registration/login flow
    print("\n7. Complete user registration and login flow...")

    # Simulated user database
    users_db = {}

    def register_user(username: str, password: str) -> bool:
        """Register a new user."""
        if username in users_db:
            return False
        users_db[username] = {
            "password_hash": crypto.hash_password(password),
            "created_at": "2024-01-15T10:30:00Z"
        }
        return True

    def login_user(username: str, password: str) -> bool:
        """Authenticate a user."""
        if username not in users_db:
            # Still do a hash operation to prevent timing attacks
            crypto.hash_password("dummy")
            return False
        return crypto.verify_password(password, users_db[username]["password_hash"])

    # Register users
    print("\n   Registering users...")
    register_user("alice", "AliceSecure123!")
    register_user("bob", "BobPassword456!")
    print(f"   Registered: {list(users_db.keys())}")

    # Login attempts
    print("\n   Login attempts...")
    attempts = [
        ("alice", "AliceSecure123!", True),   # Correct
        ("alice", "WrongPassword", False),     # Wrong password
        ("bob", "BobPassword456!", True),      # Correct
        ("charlie", "AnyPassword", False),     # Non-existent user
    ]

    for username, pwd, expected in attempts:
        result = login_user(username, pwd)
        status = "SUCCESS" if result else "FAILED"
        expected_str = "expected" if result == expected else "UNEXPECTED!"
        print(f"   {username:10} -> {status:8} ({expected_str})")

    print("\n" + "=" * 50)
    print("All examples completed successfully!")


if __name__ == "__main__":
    main()
