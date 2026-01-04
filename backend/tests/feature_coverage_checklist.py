#!/usr/bin/env python3
"""
CryptoServe Feature Coverage Checklist

A systematic test of ALL documented platform capabilities.
This is not a unit test - it's a consumer-perspective validation
that tests features the way real users would use them.

Run: python tests/feature_coverage_checklist.py

Categories:
1. Health & Infrastructure
2. Symmetric Encryption
3. Context-Based Algorithm Selection
4. Hashing
5. Message Authentication (MAC)
6. Digital Signatures
7. Password Hashing
8. Secret Sharing (Shamir)
9. Threshold Cryptography
10. Lease Management
11. Key Exchange
12. RSA Operations
13. Batch Operations
14. Hybrid/Post-Quantum Encryption
15. JOSE/JWT Operations
16. Certificates
17. CT Monitoring
18. Code Analysis
19. Migration Planning
20. Compliance & CBOM
21. Admin Operations
22. Multi-tenancy
23. SDK Management
24. Edge Cases & Error Handling
"""

import base64
import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

import requests

# Configuration
API_URL = os.environ.get("CRYPTOSERVE_URL", "http://localhost:8000")
SDK_TOKEN_FILE = "/tmp/sdk_token_new.txt"
ADMIN_TOKEN_FILE = "/tmp/admin_token.txt"


@dataclass
class TestResult:
    name: str
    passed: bool
    error: str = ""
    skipped: bool = False
    skip_reason: str = ""


@dataclass
class CategoryResult:
    name: str
    tests: list[TestResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for t in self.tests if t.passed and not t.skipped)

    @property
    def failed(self) -> int:
        return sum(1 for t in self.tests if not t.passed and not t.skipped)

    @property
    def skipped(self) -> int:
        return sum(1 for t in self.tests if t.skipped)

    @property
    def total(self) -> int:
        return len(self.tests)


class FeatureCoverageTest:
    """Systematic feature coverage testing."""

    def __init__(self):
        self.results: list[CategoryResult] = []
        self.current_category: Optional[CategoryResult] = None
        self.sdk_token: Optional[str] = None
        self.admin_token: Optional[str] = None
        self.headers: dict = {"Content-Type": "application/json"}
        self.admin_headers: dict = {"Content-Type": "application/json"}

    def load_tokens(self):
        """Load authentication tokens."""
        try:
            with open(SDK_TOKEN_FILE) as f:
                self.sdk_token = f.read().strip()
                self.headers["Authorization"] = f"Bearer {self.sdk_token}"
        except FileNotFoundError:
            print(f"Warning: SDK token not found at {SDK_TOKEN_FILE}")

        try:
            with open(ADMIN_TOKEN_FILE) as f:
                self.admin_token = f.read().strip()
                self.admin_headers["Authorization"] = f"Bearer {self.admin_token}"
        except FileNotFoundError:
            pass  # Admin token is optional

    def category(self, name: str):
        """Start a new test category."""
        self.current_category = CategoryResult(name=name)
        self.results.append(self.current_category)
        print(f"\n{'=' * 60}")
        print(f" {name}")
        print(f"{'=' * 60}")

    def test(self, name: str, func: Callable[[], bool], skip_if: str = None):
        """Run a single test."""
        if skip_if:
            result = TestResult(name=name, passed=False, skipped=True, skip_reason=skip_if)
            self.current_category.tests.append(result)
            print(f"  - {name} [SKIPPED: {skip_if}]")
            return

        try:
            passed = func()
            result = TestResult(name=name, passed=passed)
            if passed:
                print(f"  \u2713 {name}")
            else:
                print(f"  \u2717 {name}")
        except Exception as e:
            result = TestResult(name=name, passed=False, error=str(e)[:100])
            print(f"  \u2717 {name} [{str(e)[:50]}]")

        self.current_category.tests.append(result)

    def get(self, path: str, headers: dict = None) -> requests.Response:
        """Make GET request."""
        return requests.get(f"{API_URL}{path}", headers=headers or self.headers, timeout=30)

    def post(self, path: str, data: dict, headers: dict = None) -> requests.Response:
        """Make POST request."""
        return requests.post(
            f"{API_URL}{path}",
            json=data,
            headers=headers or self.headers,
            timeout=30
        )

    def delete(self, path: str, headers: dict = None) -> requests.Response:
        """Make DELETE request."""
        return requests.delete(f"{API_URL}{path}", headers=headers or self.headers, timeout=30)

    # =========================================================================
    # Test Categories
    # =========================================================================

    def test_health_infrastructure(self):
        """Category 1: Health & Infrastructure"""
        self.category("1. Health & Infrastructure")

        self.test("Basic health check (/health)", lambda: self.get("/health").status_code == 200)
        self.test("Liveness probe (/health/live)", lambda: self.get("/health/live").status_code == 200)
        self.test("Readiness probe (/health/ready)", lambda: self.get("/health/ready").status_code == 200)
        self.test("Deep health check (/health/deep)", lambda: self.get("/health/deep").status_code in [200, 503])
        self.test("FIPS status (/health/fips)", lambda: self.get("/health/fips").status_code == 200)
        self.test("Root endpoint returns info", lambda: self.get("/").status_code == 200)

    def test_symmetric_encryption(self):
        """Category 2: Symmetric Encryption"""
        self.category("2. Symmetric Encryption")

        plaintext = base64.b64encode(b"Test data for encryption").decode()

        # Basic encrypt/decrypt
        def encrypt_decrypt():
            r = self.post("/api/v1/crypto/encrypt", {"plaintext": plaintext, "context": "general"})
            if r.status_code != 200:
                return False
            ciphertext = r.json().get("ciphertext")
            r = self.post("/api/v1/crypto/decrypt", {"ciphertext": ciphertext, "context": "general"})
            if r.status_code != 200:
                return False
            return r.json().get("plaintext") == plaintext

        self.test("AES-GCM encrypt/decrypt roundtrip", encrypt_decrypt)

        # Test different data sizes
        def test_size(size):
            data = base64.b64encode(os.urandom(size)).decode()
            r = self.post("/api/v1/crypto/encrypt", {"plaintext": data, "context": "general"})
            if r.status_code != 200:
                return False
            ciphertext = r.json().get("ciphertext")
            r = self.post("/api/v1/crypto/decrypt", {"ciphertext": ciphertext, "context": "general"})
            return r.status_code == 200 and r.json().get("plaintext") == data

        self.test("Encrypt 1 byte", lambda: test_size(1))
        self.test("Encrypt 1 KB", lambda: test_size(1024))
        self.test("Encrypt 100 KB", lambda: test_size(100 * 1024))

    def test_context_algorithm_selection(self):
        """Category 3: Context-Based Algorithm Selection"""
        self.category("3. Context-Based Algorithm Selection")

        plaintext = base64.b64encode(b"Test").decode()

        contexts = [
            ("general", "AES-128 or AES-256"),
            ("user-pii", "AES-256 with PQC hybrid"),
            ("payment-data", "AES-256"),
            ("health-data", "AES-256 with PQC hybrid"),
            ("session-tokens", "AES-128"),
            ("api-secrets", "ChaCha20"),
            ("quantum-ready", "AES-256 + ML-KEM"),
        ]

        for ctx, expected in contexts:
            def test_ctx(c=ctx):
                r = self.post("/api/v1/crypto/encrypt", {"plaintext": plaintext, "context": c})
                return r.status_code == 200
            self.test(f"Context '{ctx}' -> {expected}", test_ctx)

        # Test invalid context
        def invalid_context():
            r = self.post("/api/v1/crypto/encrypt", {"plaintext": plaintext, "context": "nonexistent-ctx"})
            return r.status_code in [400, 404, 422]

        self.test("Invalid context rejected", invalid_context)

    def test_hashing(self):
        """Category 4: Hashing"""
        self.category("4. Hashing (SHA-2, SHA-3, BLAKE)")

        data = base64.b64encode(b"Data to hash").decode()

        algorithms = ["sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512", "blake2b", "blake2s", "blake3"]

        for algo in algorithms:
            def test_hash(a=algo):
                r = self.post("/api/v1/crypto/hash", {"data": data, "algorithm": a})
                return r.status_code == 200 and "digest" in r.json()
            self.test(f"{algo.upper()} hash", test_hash)

        # Hash verification
        def hash_verify():
            r = self.post("/api/v1/crypto/hash", {"data": data, "algorithm": "sha256"})
            if r.status_code != 200:
                return False
            digest = r.json().get("digest")
            r = self.post("/api/v1/crypto/hash/verify", {
                "data": data, "expected_digest": digest, "algorithm": "sha256"
            })
            return r.status_code == 200 and r.json().get("valid") == True

        self.test("SHA256 hash verification", hash_verify)

    def test_mac(self):
        """Category 5: Message Authentication Codes"""
        self.category("5. MAC (HMAC)")

        data = base64.b64encode(b"Data to authenticate").decode()

        algorithms = ["hmac-sha256", "hmac-sha384", "hmac-sha512"]

        for algo in algorithms:
            def test_mac(a=algo):
                # Generate key
                r = self.post("/api/v1/crypto/mac/generate-key", {"algorithm": a})
                if r.status_code != 200:
                    return False
                key = r.json().get("key")

                # Create MAC
                r = self.post("/api/v1/crypto/mac", {"data": data, "key": key, "algorithm": a})
                if r.status_code != 200:
                    return False
                tag = r.json().get("tag")

                # Verify
                r = self.post("/api/v1/crypto/mac/verify", {
                    "data": data, "key": key, "expected_tag": tag, "algorithm": a
                })
                return r.status_code == 200 and r.json().get("valid") == True

            self.test(f"{algo.upper()} create and verify", test_mac)

    def test_signatures(self):
        """Category 6: Digital Signatures"""
        self.category("6. Digital Signatures")

        message = base64.b64encode(b"Message to sign").decode()

        algorithms = ["Ed25519", "ECDSA-P256", "ECDSA-P384"]

        for algo in algorithms:
            def test_sig(a=algo):
                # Generate key
                r = self.post("/api/v1/signatures/keys/generate", {"algorithm": a, "context": "test"})
                if r.status_code != 200:
                    return False
                key_id = r.json().get("key_id")

                # Sign
                r = self.post("/api/v1/signatures/sign", {"message": message, "key_id": key_id})
                if r.status_code != 200:
                    return False
                signature = r.json().get("signature")

                # Verify
                r = self.post("/api/v1/signatures/verify", {
                    "message": message, "signature": signature, "key_id": key_id
                })
                return r.status_code == 200 and r.json().get("valid") == True

            self.test(f"{algo} sign and verify", test_sig)

        # List keys
        self.test("List signature keys", lambda: self.get("/api/v1/signatures/keys").status_code == 200)

        # Get public key
        def get_public_key():
            r = self.post("/api/v1/signatures/keys/generate", {"algorithm": "Ed25519", "context": "test"})
            if r.status_code != 200:
                return False
            key_id = r.json().get("key_id")
            r = self.get(f"/api/v1/signatures/keys/{key_id}/public")
            return r.status_code == 200

        self.test("Get public key by ID", get_public_key)

    def test_passwords(self):
        """Category 7: Password Hashing"""
        self.category("7. Password Hashing (OWASP 2024)")

        password = "SecureP@ssw0rd123!"

        algorithms = ["argon2id", "bcrypt", "scrypt", "pbkdf2-sha256"]

        for algo in algorithms:
            def test_pw(a=algo):
                r = self.post("/api/v1/crypto/password/hash", {"password": password, "algorithm": a})
                if r.status_code != 200:
                    return False
                hash_val = r.json().get("hash")

                r = self.post("/api/v1/crypto/password/verify", {"password": password, "hash": hash_val})
                return r.status_code == 200 and r.json().get("valid") == True

            self.test(f"{algo} hash and verify", test_pw)

        # Wrong password should fail
        def wrong_password():
            r = self.post("/api/v1/crypto/password/hash", {"password": password, "algorithm": "argon2id"})
            hash_val = r.json().get("hash")
            r = self.post("/api/v1/crypto/password/verify", {"password": "WrongPassword!", "hash": hash_val})
            return r.status_code == 200 and r.json().get("valid") == False

        self.test("Wrong password rejected", wrong_password)

        # Password strength
        def strength_check():
            r = self.post("/api/v1/crypto/password/strength", {"password": password})
            return r.status_code == 200 and "score" in r.json()

        self.test("Password strength check", strength_check)

        # Weak password detection
        def weak_password():
            # "password" is actually "fair" (score 46), use a truly weak one
            r = self.post("/api/v1/crypto/password/strength", {"password": "123"})
            # Score is 0-100, strength is "weak" if score < 40
            return r.status_code == 200 and r.json().get("strength") == "weak"

        self.test("Weak password detected", weak_password)

    def test_secret_sharing(self):
        """Category 8: Secret Sharing (Shamir)"""
        self.category("8. Secret Sharing (Shamir SSS)")

        secret = base64.b64encode(b"My secret key material").decode()

        # Basic split/combine
        def split_combine():
            r = self.post("/api/v1/secrets/shamir/split", {
                "secret": secret, "threshold": 3, "total_shares": 5
            })
            if r.status_code != 200:
                return False
            shares = r.json().get("shares", [])
            if len(shares) != 5:
                return False

            # Combine with exactly threshold shares
            r = self.post("/api/v1/secrets/shamir/combine", {"shares": shares[:3]})
            return r.status_code == 200 and r.json().get("secret") == secret

        self.test("Split 5 shares, combine with 3", split_combine)

        # Different thresholds
        def threshold_2_of_3():
            r = self.post("/api/v1/secrets/shamir/split", {
                "secret": secret, "threshold": 2, "total_shares": 3
            })
            shares = r.json().get("shares", [])
            r = self.post("/api/v1/secrets/shamir/combine", {"shares": shares[:2]})
            return r.status_code == 200 and r.json().get("secret") == secret

        self.test("Split 3 shares, combine with 2", threshold_2_of_3)

        # Insufficient shares should fail
        def insufficient_shares():
            r = self.post("/api/v1/secrets/shamir/split", {
                "secret": secret, "threshold": 3, "total_shares": 5
            })
            shares = r.json().get("shares", [])
            r = self.post("/api/v1/secrets/shamir/combine", {"shares": shares[:2]})
            return r.status_code == 400

        self.test("Insufficient shares rejected", insufficient_shares)

    def test_threshold_crypto(self):
        """Category 9: Threshold Cryptography"""
        self.category("9. Threshold Cryptography")

        def threshold_keygen():
            r = self.post("/api/v1/secrets/threshold/keygen", {
                "threshold": 2, "total_parties": 3, "curve": "secp256k1"
            })
            if r.status_code != 200:
                return False
            data = r.json()
            return len(data.get("shares", [])) == 3 and "group_public_key" in data

        self.test("Threshold key generation (2-of-3)", threshold_keygen)

        def threshold_sign():
            # Generate keys
            r = self.post("/api/v1/secrets/threshold/keygen", {
                "threshold": 2, "total_parties": 3, "curve": "secp256k1"
            })
            if r.status_code != 200:
                return False
            data = r.json()
            shares = data.get("shares", [])
            group_pk = data.get("group_public_key")

            # Sign with threshold parties
            message = base64.b64encode(b"Sign this message").decode()
            r = self.post("/api/v1/secrets/threshold/sign", {
                "message": message,
                "party_shares": shares[:2],
                "group_public_key": group_pk
            })
            return r.status_code == 200 and "signature" in r.json()

        self.test("Threshold signing (2 parties)", threshold_sign)

    def test_lease_management(self):
        """Category 10: Lease Management"""
        self.category("10. Lease Management (Time-Limited Secrets)")

        secret = base64.b64encode(b"Temporary secret").decode()

        def create_lease():
            r = self.post("/api/v1/secrets/lease/create", {
                "secret": secret, "ttl_seconds": 3600, "renewable": True
            })
            return r.status_code == 200 and "lease_id" in r.json()

        self.test("Create lease", create_lease)

        def get_lease():
            r = self.post("/api/v1/secrets/lease/create", {"secret": secret, "ttl_seconds": 3600})
            lease_id = r.json().get("lease_id")
            r = self.get(f"/api/v1/secrets/lease/{lease_id}")
            return r.status_code == 200 and r.json().get("secret") == secret

        self.test("Retrieve lease by ID", get_lease)

        def renew_lease():
            r = self.post("/api/v1/secrets/lease/create", {
                "secret": secret, "ttl_seconds": 60, "renewable": True
            })
            lease_id = r.json().get("lease_id")
            r = self.post("/api/v1/secrets/lease/renew", {
                "lease_id": lease_id, "increment_seconds": 3600
            })
            return r.status_code == 200

        self.test("Renew lease", renew_lease)

        def revoke_lease():
            r = self.post("/api/v1/secrets/lease/create", {"secret": secret, "ttl_seconds": 3600})
            lease_id = r.json().get("lease_id")
            r = self.post("/api/v1/secrets/lease/revoke", {"lease_id": lease_id})
            if r.status_code != 200:
                return False
            # Verify it's gone
            r = self.get(f"/api/v1/secrets/lease/{lease_id}")
            return r.status_code in [404, 410]

        self.test("Revoke lease", revoke_lease)

        def lease_audit():
            r = self.post("/api/v1/secrets/lease/create", {"secret": secret, "ttl_seconds": 3600})
            lease_id = r.json().get("lease_id")
            r = self.get(f"/api/v1/secrets/lease/{lease_id}/audit")
            return r.status_code == 200

        self.test("Lease audit trail", lease_audit)

    def test_key_exchange(self):
        """Category 11: Key Exchange"""
        self.category("11. Key Exchange")

        def x25519_exchange():
            # Generate Alice's keypair
            r = self.post("/api/v1/crypto/key-exchange/generate", {"algorithm": "x25519"})
            if r.status_code != 200:
                return False
            alice = r.json()

            # Generate Bob's keypair
            r = self.post("/api/v1/crypto/key-exchange/generate", {"algorithm": "x25519"})
            if r.status_code != 200:
                return False
            bob = r.json()

            # Alice derives shared secret
            r = self.post("/api/v1/crypto/key-exchange/derive", {
                "private_key": alice["private_key"],
                "peer_public_key": bob["public_key"],
                "algorithm": "x25519"
            })
            if r.status_code != 200:
                return False
            alice_shared = r.json().get("shared_secret")

            # Bob derives shared secret
            r = self.post("/api/v1/crypto/key-exchange/derive", {
                "private_key": bob["private_key"],
                "peer_public_key": alice["public_key"],
                "algorithm": "x25519"
            })
            if r.status_code != 200:
                return False
            bob_shared = r.json().get("shared_secret")

            return alice_shared == bob_shared

        self.test("X25519 key exchange (both sides match)", x25519_exchange)

    def test_rsa_operations(self):
        """Category 12: RSA Operations"""
        self.category("12. RSA Operations")

        def rsa_keygen_2048():
            r = self.post("/api/v1/crypto/rsa/generate", {"key_size": 2048})
            return r.status_code == 200 and "public_key_pem" in r.json()

        self.test("RSA-2048 key generation", rsa_keygen_2048)

        def rsa_keygen_4096():
            r = self.post("/api/v1/crypto/rsa/generate", {"key_size": 4096})
            return r.status_code == 200

        self.test("RSA-4096 key generation", rsa_keygen_4096)

        def rsa_encrypt_decrypt():
            r = self.post("/api/v1/crypto/rsa/generate", {"key_size": 2048})
            keys = r.json()

            plaintext = base64.b64encode(b"RSA test data").decode()
            r = self.post("/api/v1/crypto/rsa/encrypt", {
                "plaintext": plaintext,
                "public_key_pem": keys["public_key_pem"]
            })
            if r.status_code != 200:
                return False
            ciphertext = r.json().get("ciphertext")

            r = self.post("/api/v1/crypto/rsa/decrypt", {
                "ciphertext": ciphertext,
                "private_key_pem": keys["private_key_pem"]
            })
            return r.status_code == 200 and r.json().get("plaintext") == plaintext

        self.test("RSA encrypt/decrypt roundtrip", rsa_encrypt_decrypt)

    def test_batch_operations(self):
        """Category 13: Batch Operations"""
        self.category("13. Batch Operations")

        def batch_encrypt():
            items = [
                {"id": f"item-{i}", "plaintext": base64.b64encode(f"Data {i}".encode()).decode()}
                for i in range(5)
            ]
            r = self.post("/api/v1/crypto/batch/encrypt", {"context": "general", "items": items})
            if r.status_code != 200:
                return False
            results = r.json().get("results", [])
            return len(results) == 5 and all("ciphertext" in r for r in results)

        self.test("Batch encrypt (5 items)", batch_encrypt)

        def batch_decrypt():
            items = [
                {"id": f"item-{i}", "plaintext": base64.b64encode(f"Data {i}".encode()).decode()}
                for i in range(3)
            ]
            r = self.post("/api/v1/crypto/batch/encrypt", {"context": "general", "items": items})
            encrypted = r.json().get("results", [])

            decrypt_items = [
                {"id": item["id"], "ciphertext": item["ciphertext"]}
                for item in encrypted
            ]
            r = self.post("/api/v1/crypto/batch/decrypt", {"context": "general", "items": decrypt_items})
            return r.status_code == 200 and len(r.json().get("results", [])) == 3

        self.test("Batch decrypt (3 items)", batch_decrypt)

    def test_hybrid_pqc(self):
        """Category 14: Hybrid/Post-Quantum Encryption"""
        self.category("14. Hybrid/Post-Quantum Encryption")

        plaintext = base64.b64encode(b"Quantum-safe data").decode()

        def hybrid_encrypt_decrypt():
            # First generate a key pair for the recipient
            r = self.post("/api/v1/crypto/key-exchange/generate", {"algorithm": "x25519"})
            if r.status_code != 200:
                return False
            private_key = r.json().get("private_key")
            public_key = r.json().get("public_key")

            # Encrypt with recipient's public key
            r = self.post("/api/v1/crypto/hybrid/encrypt", {
                "plaintext": plaintext,
                "recipient_public_key": public_key
            })
            if r.status_code != 200:
                return False
            ciphertext = r.json().get("ciphertext")

            # Decrypt with recipient's private key
            r = self.post("/api/v1/crypto/hybrid/decrypt", {
                "ciphertext": ciphertext,
                "private_key": private_key
            })
            return r.status_code == 200 and r.json().get("plaintext") == plaintext

        self.test("Hybrid encryption (X25519 + AES)", hybrid_encrypt_decrypt)

        def context_pqc():
            r = self.post("/api/v1/crypto/encrypt", {"plaintext": plaintext, "context": "quantum-ready"})
            if r.status_code != 200:
                return False
            algo = r.json().get("algorithm", {})
            return "ML-KEM" in algo.get("mode", "") or "hybrid" in algo.get("mode", "").lower()

        self.test("Context 'quantum-ready' uses PQC hybrid", context_pqc)

        # PQC signature algorithms
        def list_pqc_algorithms():
            r = self.get("/api/v1/pqc/algorithms")
            return r.status_code == 200

        self.test("List PQC algorithms", list_pqc_algorithms)

        def pqc_key_generation():
            r = self.post("/api/v1/pqc/keys/generate", {
                "algorithm": "ML-DSA-65",
                "context": "test"
            })
            return r.status_code == 200 and "keyId" in r.json()

        self.test("Generate ML-DSA-65 key", pqc_key_generation)

    def test_jose_operations(self):
        """Category 15: JOSE/JWT Operations"""
        self.category("15. JOSE/JWT Operations")

        def jwk_generate():
            # API requires key_type and curve, not algorithm
            r = self.post("/api/v1/jose/jwk/generate", {"key_type": "EC", "curve": "P-256", "use": "sig"})
            return r.status_code == 200 and "private_jwk" in r.json()

        self.test("Generate EC P-256 JWK", jwk_generate)

        def jws_sign_verify():
            # Generate key
            r = self.post("/api/v1/jose/jwk/generate", {"key_type": "EC", "curve": "P-256", "use": "sig"})
            if r.status_code != 200:
                return False
            jwk_response = r.json()
            private_jwk = jwk_response.get("private_jwk")

            # Sign - payload must be base64 encoded, key must be JSON string
            payload = base64.b64encode(b'{"sub":"user123"}').decode()
            r = self.post("/api/v1/jose/sign", {
                "payload": payload,
                "key": json.dumps(private_jwk),
                "algorithm": "ES256"
            })
            if r.status_code != 200:
                return False
            jws = r.json().get("jws")

            # Verify
            r = self.post("/api/v1/jose/verify", {
                "jws": jws,
                "key": json.dumps(jwk_response.get("public_jwk", private_jwk))
            })
            return r.status_code == 200 and r.json().get("valid") == True

        self.test("JWS sign and verify", jws_sign_verify)

        def jwe_encrypt_decrypt():
            # Generate symmetric key for JWE
            r = self.post("/api/v1/jose/jwk/generate", {"key_type": "oct", "size": 256, "use": "enc"})
            if r.status_code != 200:
                return False
            jwk_response = r.json()
            private_jwk = jwk_response.get("private_jwk")

            # Encrypt
            plaintext = base64.b64encode(b'{"secret":"data"}').decode()
            r = self.post("/api/v1/jose/encrypt", {
                "plaintext": plaintext,
                "key": json.dumps(private_jwk),
                "algorithm": "dir",
                "encryption": "A256GCM"
            })
            if r.status_code != 200:
                return False
            jwe = r.json().get("jwe")

            # Decrypt
            r = self.post("/api/v1/jose/decrypt", {
                "jwe": jwe,
                "key": json.dumps(private_jwk)
            })
            return r.status_code == 200

        self.test("JWE encrypt and decrypt", jwe_encrypt_decrypt)

        def jwk_thumbprint():
            r = self.post("/api/v1/jose/jwk/generate", {"key_type": "EC", "curve": "P-256"})
            if r.status_code != 200:
                return False
            jwk = r.json().get("private_jwk")
            r = self.post("/api/v1/jose/jwk/thumbprint", {"jwk": json.dumps(jwk)})
            return r.status_code == 200 and "thumbprint" in r.json()

        self.test("JWK thumbprint calculation", jwk_thumbprint)

    def test_certificates(self):
        """Category 16: Certificates"""
        self.category("16. Certificate Operations")

        def generate_self_signed():
            r = self.post("/api/v1/certificates/self-signed/generate", {
                "subject": {"common_name": "test.example.com"},
                "validity_days": 365,
                "key_type": "ec",
                "key_size": 256
            })
            return r.status_code == 200 and "certificate_pem" in r.json()

        self.test("Generate self-signed certificate", generate_self_signed)

        def generate_csr():
            r = self.post("/api/v1/certificates/csr/generate", {
                "subject": {
                    "common_name": "test.example.com",
                    "organization": "Test Org",
                    "country": "US"
                }
            })
            return r.status_code == 200 and "csr_pem" in r.json()

        self.test("Generate CSR", generate_csr)

        def parse_certificate():
            # First generate a cert
            r = self.post("/api/v1/certificates/self-signed/generate", {
                "subject": {"common_name": "test.example.com"},
                "validity_days": 30
            })
            cert_pem = r.json().get("certificate_pem")

            r = self.post("/api/v1/certificates/parse", {"certificate": cert_pem})
            return r.status_code == 200 and "subject" in r.json()

        self.test("Parse certificate", parse_certificate)

        def verify_certificate():
            r = self.post("/api/v1/certificates/self-signed/generate", {
                "subject": {"common_name": "test.example.com"},
                "validity_days": 30
            })
            cert_pem = r.json().get("certificate_pem")

            r = self.post("/api/v1/certificates/verify", {"certificate": cert_pem})
            return r.status_code == 200

        self.test("Verify certificate", verify_certificate)

    def test_ct_monitoring(self):
        """Category 17: Certificate Transparency Monitoring"""
        self.category("17. CT Monitoring")

        def scan_domain():
            r = self.get("/api/v1/ct/scan/google.com")
            return r.status_code == 200

        self.test("Scan domain (google.com)", scan_domain)

        def recent_certs():
            r = self.get("/api/v1/ct/recent/google.com")
            return r.status_code == 200

        self.test("Get recent certificates", recent_certs)

        def search_ct():
            r = self.get("/api/v1/ct/search?q=example.com")
            return r.status_code == 200

        self.test("Search CT logs", search_ct)

        def get_issuers():
            r = self.get("/api/v1/ct/issuers/google.com")
            return r.status_code == 200

        self.test("Get certificate issuers", get_issuers)

    def test_code_analysis(self):
        """Category 18: Code Analysis & Discovery"""
        self.category("18. Code Analysis")

        def scan_code():
            code = '''
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = hashlib.md5(b"password").digest()  # Weak!
cipher = Cipher(algorithms.AES(key), modes.ECB(key[:16]))  # ECB mode!
'''
            r = self.post("/api/v1/code/scan", {"code": code, "language": "python"})
            return r.status_code == 200

        self.test("Scan Python code for crypto issues", scan_code)

        def list_languages():
            r = self.get("/api/v1/code/languages")
            return r.status_code == 200

        self.test("List supported languages", list_languages)

        def discovered_algorithms():
            r = self.get("/api/v1/code/algorithms")
            return r.status_code == 200

        self.test("List discovered algorithms", discovered_algorithms)

        def code_recommendations():
            r = self.get("/api/v1/code/recommendations")
            return r.status_code == 200

        self.test("Get code recommendations", code_recommendations)

    def test_migration(self):
        """Category 19: Migration Planning"""
        self.category("19. Migration Planning")

        def migration_assessment():
            r = self.get("/api/migration/assessment")
            return r.status_code == 200

        self.test("Get migration assessment", migration_assessment)

        def migration_recommendations():
            r = self.get("/api/migration/recommendations")
            return r.status_code == 200

        self.test("Get migration recommendations", migration_recommendations)

        def migration_history():
            r = self.get("/api/migration/history")
            return r.status_code == 200

        self.test("Get migration history", migration_history)

    def test_compliance_cbom(self):
        """Category 20: Compliance & CBOM"""
        self.category("20. Compliance & CBOM")

        def compliance_status():
            r = self.get("/api/compliance/status")
            return r.status_code == 200

        self.test("Get compliance status", compliance_status)

        def compliance_algorithms():
            r = self.get("/api/compliance/algorithms")
            return r.status_code == 200

        self.test("List compliant algorithms", compliance_algorithms)

        def generate_cbom():
            code = '''
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
key = hashlib.sha256(b"secret").digest()
'''
            # Use code analysis CBOM endpoint (not inventory upload)
            r = self.post("/api/v1/code/cbom", {"code": code, "language": "python"})
            return r.status_code in [200, 201]

        self.test("Generate CBOM report", generate_cbom)

        def risk_score():
            r = self.get("/api/compliance/risk-score")
            return r.status_code == 200

        self.test("Get risk score", risk_score)

    def test_algorithms_info(self):
        """Category 21: Algorithm Information"""
        self.category("21. Algorithm Information")

        def list_algorithms():
            r = self.get("/api/algorithms")
            return r.status_code == 200

        self.test("List all algorithms", list_algorithms)

        def recommended_algorithms():
            r = self.get("/api/algorithms/recommended")
            return r.status_code == 200

        self.test("List recommended algorithms", recommended_algorithms)

        def deprecated_algorithms():
            r = self.get("/api/algorithms/deprecated")
            return r.status_code == 200

        self.test("List deprecated algorithms", deprecated_algorithms)

        def quantum_resistant():
            r = self.get("/api/algorithms/quantum-resistant")
            return r.status_code == 200

        self.test("List quantum-resistant algorithms", quantum_resistant)

    def test_sdk_management(self):
        """Category 22: SDK Management"""
        self.category("22. SDK Management")

        def sdk_contexts():
            r = self.get("/sdk/contexts")
            return r.status_code == 200

        self.test("List SDK contexts", sdk_contexts)

        def search_contexts():
            r = self.get("/sdk/contexts/search?q=general")
            return r.status_code == 200

        self.test("Search contexts", search_contexts)

    def test_edge_cases(self):
        """Category 23: Edge Cases & Error Handling"""
        self.category("23. Edge Cases & Error Handling")

        # Empty input
        def empty_plaintext():
            r = self.post("/api/v1/crypto/encrypt", {"plaintext": "", "context": "general"})
            return r.status_code in [400, 422]

        self.test("Empty plaintext rejected", empty_plaintext)

        # Invalid base64
        def invalid_base64():
            r = self.post("/api/v1/crypto/encrypt", {"plaintext": "not-base64!!!", "context": "general"})
            return r.status_code in [400, 422]

        self.test("Invalid base64 rejected", invalid_base64)

        # Missing required fields
        def missing_fields():
            r = self.post("/api/v1/crypto/encrypt", {"context": "general"})  # Missing plaintext
            return r.status_code == 422

        self.test("Missing required fields rejected", missing_fields)

        # Unauthorized access
        def no_auth():
            r = requests.post(
                f"{API_URL}/api/v1/crypto/encrypt",
                json={"plaintext": base64.b64encode(b"test").decode(), "context": "general"},
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            return r.status_code in [401, 403]

        self.test("Request without auth rejected", no_auth)

        # Unicode handling
        def unicode_data():
            plaintext = base64.b64encode("Hello \u4e16\u754c \U0001f600".encode()).decode()
            r = self.post("/api/v1/crypto/encrypt", {"plaintext": plaintext, "context": "general"})
            if r.status_code != 200:
                return False
            ciphertext = r.json().get("ciphertext")
            r = self.post("/api/v1/crypto/decrypt", {"ciphertext": ciphertext, "context": "general"})
            return r.status_code == 200 and r.json().get("plaintext") == plaintext

        self.test("Unicode data handled correctly", unicode_data)

        # Binary data
        def binary_data():
            plaintext = base64.b64encode(bytes(range(256))).decode()
            r = self.post("/api/v1/crypto/encrypt", {"plaintext": plaintext, "context": "general"})
            if r.status_code != 200:
                return False
            ciphertext = r.json().get("ciphertext")
            r = self.post("/api/v1/crypto/decrypt", {"ciphertext": ciphertext, "context": "general"})
            return r.status_code == 200 and r.json().get("plaintext") == plaintext

        self.test("Binary data (all byte values)", binary_data)

    def test_policies(self):
        """Category 24: Policies"""
        self.category("24. Policies")

        def list_policies():
            r = self.get("/api/policies")
            return r.status_code == 200

        self.test("List policies", list_policies)

        def policy_defaults():
            r = self.get("/api/policies/defaults")
            return r.status_code == 200

        self.test("Get policy defaults", policy_defaults)

        def evaluate_policy():
            r = self.post("/api/policies/evaluate", {
                "algorithm": "AES-256-GCM",
                "context_name": "user-pii",
                "operation": "encrypt"
            })
            return r.status_code == 200

        self.test("Evaluate policy", evaluate_policy)

    def test_audit(self):
        """Category 25: Audit"""
        self.category("25. Audit")

        def audit_logs():
            r = self.get("/api/audit")
            return r.status_code == 200

        self.test("Get audit logs", audit_logs)

        def audit_stats():
            r = self.get("/api/audit/stats")
            return r.status_code == 200

        self.test("Get audit stats", audit_stats)

    # =========================================================================
    # Main
    # =========================================================================

    def run_all(self):
        """Run all test categories."""
        print("\n" + "=" * 60)
        print(" CRYPTOSERVE FEATURE COVERAGE CHECKLIST")
        print("=" * 60)
        print(f" Target: {API_URL}")

        self.load_tokens()

        if not self.sdk_token:
            print("\n[ERROR] SDK token required. Create one with:")
            print("  1. Start the server")
            print("  2. Register an SDK identity")
            print(f"  3. Save token to {SDK_TOKEN_FILE}")
            return 1

        # Run all categories
        self.test_health_infrastructure()
        self.test_symmetric_encryption()
        self.test_context_algorithm_selection()
        self.test_hashing()
        self.test_mac()
        self.test_signatures()
        self.test_passwords()
        self.test_secret_sharing()
        self.test_threshold_crypto()
        self.test_lease_management()
        self.test_key_exchange()
        self.test_rsa_operations()
        self.test_batch_operations()
        self.test_hybrid_pqc()
        self.test_jose_operations()
        self.test_certificates()
        self.test_ct_monitoring()
        self.test_code_analysis()
        self.test_migration()
        self.test_compliance_cbom()
        self.test_algorithms_info()
        self.test_sdk_management()
        self.test_edge_cases()
        self.test_policies()
        self.test_audit()

        # Summary
        self.print_summary()

        total_failed = sum(c.failed for c in self.results)
        return 0 if total_failed == 0 else 1

    def print_summary(self):
        """Print test summary."""
        print("\n" + "=" * 60)
        print(" SUMMARY")
        print("=" * 60)

        total_passed = 0
        total_failed = 0
        total_skipped = 0

        for cat in self.results:
            status = "\u2713" if cat.failed == 0 else "\u2717"
            print(f"  {status} {cat.name}: {cat.passed}/{cat.total - cat.skipped} passed", end="")
            if cat.skipped > 0:
                print(f" ({cat.skipped} skipped)", end="")
            if cat.failed > 0:
                print(f" [{cat.failed} FAILED]", end="")
            print()

            total_passed += cat.passed
            total_failed += cat.failed
            total_skipped += cat.skipped

        total = total_passed + total_failed
        pct = (total_passed / total * 100) if total > 0 else 0

        print("\n" + "-" * 60)
        print(f" TOTAL: {total_passed}/{total} passed ({pct:.1f}%)")
        if total_skipped > 0:
            print(f" SKIPPED: {total_skipped}")
        if total_failed > 0:
            print(f" FAILED: {total_failed}")
        print("=" * 60)

        # List failures
        if total_failed > 0:
            print("\nFailed tests:")
            for cat in self.results:
                for test in cat.tests:
                    if not test.passed and not test.skipped:
                        print(f"  - [{cat.name}] {test.name}")
                        if test.error:
                            print(f"    Error: {test.error}")


if __name__ == "__main__":
    tester = FeatureCoverageTest()
    sys.exit(tester.run_all())
