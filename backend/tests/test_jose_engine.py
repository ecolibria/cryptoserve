"""Tests for the JOSE engine."""

import pytest
import json
import os

from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from app.core.jose_engine import (
    jose_engine,
    JOSEEngine,
    JWSAlgorithm,
    JWEAlgorithm,
    JWEEncryption,
    JWK,
    InvalidJWSError,
    InvalidJWEError,
    UnsupportedAlgorithmError,
)


@pytest.fixture
def fresh_engine():
    """Create a fresh JOSE engine for each test."""
    return JOSEEngine()


class TestJWSCreationAndVerification:
    """Tests for JWS (JSON Web Signature)."""

    def test_jws_hmac_hs256(self, fresh_engine):
        """Test JWS with HMAC-SHA256."""
        key = os.urandom(32)
        payload = b'{"sub":"1234567890","name":"John Doe"}'

        result = fresh_engine.create_jws(payload, key, JWSAlgorithm.HS256)

        assert result.compact.count(".") == 2
        assert result.header["alg"] == "HS256"
        assert result.payload == payload

        # Verify
        verified_payload, header = fresh_engine.verify_jws(result.compact, key)
        assert verified_payload == payload
        assert header["alg"] == "HS256"

    def test_jws_hmac_hs384(self, fresh_engine):
        """Test JWS with HMAC-SHA384."""
        key = os.urandom(48)
        payload = b"test payload"

        result = fresh_engine.create_jws(payload, key, JWSAlgorithm.HS384)
        verified_payload, _ = fresh_engine.verify_jws(result.compact, key)
        assert verified_payload == payload

    def test_jws_hmac_hs512(self, fresh_engine):
        """Test JWS with HMAC-SHA512."""
        key = os.urandom(64)
        payload = b"test payload"

        result = fresh_engine.create_jws(payload, key, JWSAlgorithm.HS512)
        verified_payload, _ = fresh_engine.verify_jws(result.compact, key)
        assert verified_payload == payload

    def test_jws_eddsa(self, fresh_engine):
        """Test JWS with EdDSA (Ed25519)."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        payload = b"test payload"

        result = fresh_engine.create_jws(payload, private_key, JWSAlgorithm.EDDSA)
        assert result.header["alg"] == "EdDSA"

        verified_payload, _ = fresh_engine.verify_jws(result.compact, public_key)
        assert verified_payload == payload

    def test_jws_es256(self, fresh_engine):
        """Test JWS with ECDSA P-256."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        payload = b"test payload"

        result = fresh_engine.create_jws(payload, private_key, JWSAlgorithm.ES256)
        assert result.header["alg"] == "ES256"
        assert len(result.signature) == 64  # 32 + 32

        verified_payload, _ = fresh_engine.verify_jws(result.compact, public_key)
        assert verified_payload == payload

    def test_jws_es384(self, fresh_engine):
        """Test JWS with ECDSA P-384."""
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
        payload = b"test payload"

        result = fresh_engine.create_jws(payload, private_key, JWSAlgorithm.ES384)
        assert result.header["alg"] == "ES384"
        assert len(result.signature) == 96  # 48 + 48

        verified_payload, _ = fresh_engine.verify_jws(result.compact, public_key)
        assert verified_payload == payload

    def test_jws_with_kid(self, fresh_engine):
        """Test JWS with key ID in header."""
        key = os.urandom(32)
        payload = b"test"

        result = fresh_engine.create_jws(payload, key, JWSAlgorithm.HS256, kid="key-123")
        assert result.header["kid"] == "key-123"

    def test_jws_with_extra_headers(self, fresh_engine):
        """Test JWS with custom headers."""
        key = os.urandom(32)
        payload = b"test"

        result = fresh_engine.create_jws(
            payload, key, JWSAlgorithm.HS256,
            extra_headers={"custom": "value"}
        )
        assert result.header["custom"] == "value"

    def test_jws_verify_wrong_key(self, fresh_engine):
        """Test JWS verification fails with wrong key."""
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        payload = b"test"

        result = fresh_engine.create_jws(payload, key1, JWSAlgorithm.HS256)

        with pytest.raises(InvalidJWSError, match="verification failed"):
            fresh_engine.verify_jws(result.compact, key2)

    def test_jws_verify_tampered(self, fresh_engine):
        """Test JWS verification fails with tampered payload."""
        key = os.urandom(32)
        payload = b"test"

        result = fresh_engine.create_jws(payload, key, JWSAlgorithm.HS256)

        # Tamper with the JWS
        parts = result.compact.split(".")
        parts[1] = parts[1][:-1] + "X"  # Modify payload
        tampered = ".".join(parts)

        with pytest.raises(InvalidJWSError):
            fresh_engine.verify_jws(tampered, key)

    def test_jws_verify_invalid_format(self, fresh_engine):
        """Test JWS verification fails with invalid format."""
        key = os.urandom(32)

        with pytest.raises(InvalidJWSError, match="Invalid JWS format"):
            fresh_engine.verify_jws("not.a.valid.jws", key)

    def test_jws_verify_allowed_algorithms(self, fresh_engine):
        """Test JWS verification respects algorithm allowlist."""
        key = os.urandom(32)
        payload = b"test"

        result = fresh_engine.create_jws(payload, key, JWSAlgorithm.HS256)

        # Should work with HS256 allowed
        fresh_engine.verify_jws(result.compact, key, algorithms=[JWSAlgorithm.HS256])

        # Should fail with only HS384 allowed
        with pytest.raises(InvalidJWSError, match="not allowed"):
            fresh_engine.verify_jws(result.compact, key, algorithms=[JWSAlgorithm.HS384])


class TestJWECreationAndDecryption:
    """Tests for JWE (JSON Web Encryption)."""

    def test_jwe_direct_a256gcm(self, fresh_engine):
        """Test JWE with direct encryption and AES-256-GCM."""
        key = os.urandom(32)
        plaintext = b"Hello, World!"

        result = fresh_engine.create_jwe(
            plaintext, key,
            JWEAlgorithm.DIR, JWEEncryption.A256GCM
        )

        assert result.compact.count(".") == 4
        assert result.header["alg"] == "dir"
        assert result.header["enc"] == "A256GCM"
        assert result.encrypted_key == b""  # Direct = no encrypted key

        decrypted, header = fresh_engine.decrypt_jwe(result.compact, key)
        assert decrypted == plaintext

    def test_jwe_direct_a128gcm(self, fresh_engine):
        """Test JWE with direct encryption and AES-128-GCM."""
        key = os.urandom(16)
        plaintext = b"Hello, World!"

        result = fresh_engine.create_jwe(
            plaintext, key,
            JWEAlgorithm.DIR, JWEEncryption.A128GCM
        )

        decrypted, _ = fresh_engine.decrypt_jwe(result.compact, key)
        assert decrypted == plaintext

    def test_jwe_direct_chacha20(self, fresh_engine):
        """Test JWE with direct encryption and ChaCha20-Poly1305."""
        key = os.urandom(32)
        plaintext = b"Hello, World!"

        result = fresh_engine.create_jwe(
            plaintext, key,
            JWEAlgorithm.DIR, JWEEncryption.C20P
        )

        assert result.header["enc"] == "C20P"

        decrypted, _ = fresh_engine.decrypt_jwe(result.compact, key)
        assert decrypted == plaintext

    def test_jwe_a256kw_a256gcm(self, fresh_engine):
        """Test JWE with AES-256 key wrap."""
        key = os.urandom(32)
        plaintext = b"Hello, World!"

        result = fresh_engine.create_jwe(
            plaintext, key,
            JWEAlgorithm.A256KW, JWEEncryption.A256GCM
        )

        assert result.header["alg"] == "A256KW"
        assert len(result.encrypted_key) > 0  # CEK is wrapped

        decrypted, _ = fresh_engine.decrypt_jwe(result.compact, key)
        assert decrypted == plaintext

    def test_jwe_a128kw_a128gcm(self, fresh_engine):
        """Test JWE with AES-128 key wrap."""
        key = os.urandom(16)
        plaintext = b"Hello, World!"

        result = fresh_engine.create_jwe(
            plaintext, key,
            JWEAlgorithm.A128KW, JWEEncryption.A128GCM
        )

        decrypted, _ = fresh_engine.decrypt_jwe(result.compact, key)
        assert decrypted == plaintext

    def test_jwe_ecdh_es_a256gcm(self, fresh_engine):
        """Test JWE with ECDH-ES key agreement."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        plaintext = b"Hello, World!"

        result = fresh_engine.create_jwe(
            plaintext, public_key,
            JWEAlgorithm.ECDH_ES, JWEEncryption.A256GCM
        )

        assert result.header["alg"] == "ECDH-ES"
        assert "epk" in result.header  # Ephemeral public key
        assert result.encrypted_key == b""  # Direct key agreement

        decrypted, _ = fresh_engine.decrypt_jwe(result.compact, private_key)
        assert decrypted == plaintext

    def test_jwe_ecdh_es_a128kw(self, fresh_engine):
        """Test JWE with ECDH-ES+A128KW."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        plaintext = b"Hello, World!"

        result = fresh_engine.create_jwe(
            plaintext, public_key,
            JWEAlgorithm.ECDH_ES_A128KW, JWEEncryption.A256GCM
        )

        assert result.header["alg"] == "ECDH-ES+A128KW"
        assert len(result.encrypted_key) > 0  # Wrapped CEK

        decrypted, _ = fresh_engine.decrypt_jwe(result.compact, private_key)
        assert decrypted == plaintext

    def test_jwe_ecdh_es_p384(self, fresh_engine):
        """Test JWE with ECDH-ES using P-384 curve."""
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
        plaintext = b"Hello, World!"

        result = fresh_engine.create_jwe(
            plaintext, public_key,
            JWEAlgorithm.ECDH_ES, JWEEncryption.A256GCM
        )

        assert result.header["epk"]["crv"] == "P-384"

        decrypted, _ = fresh_engine.decrypt_jwe(result.compact, private_key)
        assert decrypted == plaintext

    def test_jwe_cbc_hs256(self, fresh_engine):
        """Test JWE with AES-CBC + HMAC-SHA256."""
        key = os.urandom(32)  # 128-bit enc + 128-bit mac
        plaintext = b"Hello, World!"

        result = fresh_engine.create_jwe(
            plaintext, key,
            JWEAlgorithm.DIR, JWEEncryption.A128CBC_HS256
        )

        assert result.header["enc"] == "A128CBC-HS256"

        decrypted, _ = fresh_engine.decrypt_jwe(result.compact, key)
        assert decrypted == plaintext

    def test_jwe_cbc_hs512(self, fresh_engine):
        """Test JWE with AES-CBC + HMAC-SHA512."""
        key = os.urandom(64)  # 256-bit enc + 256-bit mac
        plaintext = b"Hello, World!"

        result = fresh_engine.create_jwe(
            plaintext, key,
            JWEAlgorithm.DIR, JWEEncryption.A256CBC_HS512
        )

        decrypted, _ = fresh_engine.decrypt_jwe(result.compact, key)
        assert decrypted == plaintext

    def test_jwe_with_kid(self, fresh_engine):
        """Test JWE with key ID in header."""
        key = os.urandom(32)
        plaintext = b"test"

        result = fresh_engine.create_jwe(
            plaintext, key,
            JWEAlgorithm.DIR, JWEEncryption.A256GCM,
            kid="key-123"
        )
        assert result.header["kid"] == "key-123"

    def test_jwe_decrypt_wrong_key(self, fresh_engine):
        """Test JWE decryption fails with wrong key."""
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        plaintext = b"test"

        result = fresh_engine.create_jwe(
            plaintext, key1,
            JWEAlgorithm.DIR, JWEEncryption.A256GCM
        )

        with pytest.raises(InvalidJWEError):
            fresh_engine.decrypt_jwe(result.compact, key2)

    def test_jwe_decrypt_tampered(self, fresh_engine):
        """Test JWE decryption fails with tampered ciphertext."""
        key = os.urandom(32)
        plaintext = b"test data for tampering test"

        result = fresh_engine.create_jwe(
            plaintext, key,
            JWEAlgorithm.DIR, JWEEncryption.A256GCM
        )

        # Tamper with ciphertext more aggressively - flip multiple characters
        parts = result.compact.split(".")
        ciphertext = parts[3]
        # Flip characters to ensure tampering is detected
        if len(ciphertext) > 10:
            tampered_ct = ciphertext[:5] + "XXXX" + ciphertext[9:]
        else:
            tampered_ct = "XXXX" + ciphertext[4:]
        parts[3] = tampered_ct
        tampered = ".".join(parts)

        with pytest.raises(InvalidJWEError):
            fresh_engine.decrypt_jwe(tampered, key)

    def test_jwe_large_payload(self, fresh_engine):
        """Test JWE with large payload."""
        key = os.urandom(32)
        plaintext = os.urandom(1024 * 100)  # 100 KB

        result = fresh_engine.create_jwe(
            plaintext, key,
            JWEAlgorithm.DIR, JWEEncryption.A256GCM
        )

        decrypted, _ = fresh_engine.decrypt_jwe(result.compact, key)
        assert decrypted == plaintext


class TestJWKOperations:
    """Tests for JWK (JSON Web Key) operations."""

    def test_generate_symmetric_jwk(self, fresh_engine):
        """Test generating symmetric JWK."""
        public_jwk, private_jwk = fresh_engine.generate_jwk("oct", key_size=32)

        assert public_jwk.kty == "oct"
        assert public_jwk.k is not None
        assert len(public_jwk.k) > 0
        assert private_jwk is None  # Symmetric = no separate private

    def test_generate_ec_p256_jwk(self, fresh_engine):
        """Test generating EC P-256 JWK pair."""
        public_jwk, private_jwk = fresh_engine.generate_jwk("EC", crv="P-256")

        assert public_jwk.kty == "EC"
        assert public_jwk.crv == "P-256"
        assert public_jwk.x is not None
        assert public_jwk.y is not None
        assert public_jwk.d is None  # Public key

        assert private_jwk.d is not None  # Private key

    def test_generate_ec_p384_jwk(self, fresh_engine):
        """Test generating EC P-384 JWK pair."""
        public_jwk, private_jwk = fresh_engine.generate_jwk("EC", crv="P-384")

        assert public_jwk.crv == "P-384"
        assert private_jwk.d is not None

    def test_generate_ed25519_jwk(self, fresh_engine):
        """Test generating Ed25519 JWK pair."""
        public_jwk, private_jwk = fresh_engine.generate_jwk("OKP", crv="Ed25519")

        assert public_jwk.kty == "OKP"
        assert public_jwk.crv == "Ed25519"
        assert public_jwk.x is not None
        assert public_jwk.d is None

        assert private_jwk.d is not None

    def test_jwk_to_key_symmetric(self, fresh_engine):
        """Test converting symmetric JWK to key."""
        public_jwk, _ = fresh_engine.generate_jwk("oct", key_size=32)

        key = fresh_engine.jwk_to_key(public_jwk)
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_jwk_to_key_ec_public(self, fresh_engine):
        """Test converting EC public JWK to key."""
        public_jwk, _ = fresh_engine.generate_jwk("EC", crv="P-256")

        key = fresh_engine.jwk_to_key(public_jwk)
        assert isinstance(key, ec.EllipticCurvePublicKey)

    def test_jwk_to_key_ec_private(self, fresh_engine):
        """Test converting EC private JWK to key."""
        _, private_jwk = fresh_engine.generate_jwk("EC", crv="P-256")

        key = fresh_engine.jwk_to_key(private_jwk)
        assert isinstance(key, ec.EllipticCurvePrivateKey)

    def test_jwk_to_key_ed25519_public(self, fresh_engine):
        """Test converting Ed25519 public JWK to key."""
        public_jwk, _ = fresh_engine.generate_jwk("OKP", crv="Ed25519")

        key = fresh_engine.jwk_to_key(public_jwk)
        assert isinstance(key, ed25519.Ed25519PublicKey)

    def test_jwk_to_key_ed25519_private(self, fresh_engine):
        """Test converting Ed25519 private JWK to key."""
        _, private_jwk = fresh_engine.generate_jwk("OKP", crv="Ed25519")

        key = fresh_engine.jwk_to_key(private_jwk)
        assert isinstance(key, ed25519.Ed25519PrivateKey)

    def test_key_to_jwk_symmetric(self, fresh_engine):
        """Test converting bytes to JWK."""
        key = os.urandom(32)

        jwk = fresh_engine.key_to_jwk(key)
        assert jwk.kty == "oct"
        assert jwk.k is not None

        # Roundtrip
        recovered = fresh_engine.jwk_to_key(jwk)
        assert recovered == key

    def test_key_to_jwk_ec(self, fresh_engine):
        """Test converting EC key to JWK."""
        private_key = ec.generate_private_key(ec.SECP256R1())

        jwk = fresh_engine.key_to_jwk(private_key)
        assert jwk.kty == "EC"
        assert jwk.crv == "P-256"
        assert jwk.d is not None

        # Roundtrip
        recovered = fresh_engine.jwk_to_key(jwk)
        assert isinstance(recovered, ec.EllipticCurvePrivateKey)

    def test_key_to_jwk_ed25519(self, fresh_engine):
        """Test converting Ed25519 key to JWK."""
        private_key = ed25519.Ed25519PrivateKey.generate()

        jwk = fresh_engine.key_to_jwk(private_key)
        assert jwk.kty == "OKP"
        assert jwk.crv == "Ed25519"

        # Roundtrip
        recovered = fresh_engine.jwk_to_key(jwk)
        assert isinstance(recovered, ed25519.Ed25519PrivateKey)

    def test_jwk_to_dict(self, fresh_engine):
        """Test JWK to dictionary conversion."""
        public_jwk, _ = fresh_engine.generate_jwk("EC", crv="P-256")

        d = public_jwk.to_dict()
        assert d["kty"] == "EC"
        assert "d" not in d  # None values excluded

    def test_jwk_from_dict(self, fresh_engine):
        """Test JWK from dictionary."""
        d = {
            "kty": "EC",
            "crv": "P-256",
            "x": "test_x",
            "y": "test_y",
        }

        jwk = JWK.from_dict(d)
        assert jwk.kty == "EC"
        assert jwk.crv == "P-256"
        assert jwk.x == "test_x"


class TestJWKWithJWSJWE:
    """Test using JWK for JWS and JWE operations."""

    def test_jws_with_jwk(self, fresh_engine):
        """Test JWS creation and verification using JWK."""
        public_jwk, private_jwk = fresh_engine.generate_jwk("OKP", crv="Ed25519")

        private_key = fresh_engine.jwk_to_key(private_jwk)
        public_key = fresh_engine.jwk_to_key(public_jwk)

        payload = b'{"test": "data"}'

        result = fresh_engine.create_jws(
            payload, private_key, JWSAlgorithm.EDDSA,
            kid=private_jwk.kid
        )

        verified, header = fresh_engine.verify_jws(result.compact, public_key)
        assert verified == payload
        assert header["kid"] == private_jwk.kid

    def test_jwe_with_jwk(self, fresh_engine):
        """Test JWE creation and decryption using JWK."""
        public_jwk, private_jwk = fresh_engine.generate_jwk("EC", crv="P-256", use="enc")

        public_key = fresh_engine.jwk_to_key(public_jwk)
        private_key = fresh_engine.jwk_to_key(private_jwk)

        plaintext = b"secret message"

        result = fresh_engine.create_jwe(
            plaintext, public_key,
            JWEAlgorithm.ECDH_ES, JWEEncryption.A256GCM,
            kid=public_jwk.kid
        )

        decrypted, header = fresh_engine.decrypt_jwe(result.compact, private_key)
        assert decrypted == plaintext
        assert header["kid"] == public_jwk.kid


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_payload_jws(self, fresh_engine):
        """Test JWS with empty payload."""
        key = os.urandom(32)
        result = fresh_engine.create_jws(b"", key, JWSAlgorithm.HS256)

        verified, _ = fresh_engine.verify_jws(result.compact, key)
        assert verified == b""

    def test_empty_plaintext_jwe(self, fresh_engine):
        """Test JWE with empty plaintext."""
        key = os.urandom(32)
        result = fresh_engine.create_jwe(
            b"", key, JWEAlgorithm.DIR, JWEEncryption.A256GCM
        )

        decrypted, _ = fresh_engine.decrypt_jwe(result.compact, key)
        assert decrypted == b""

    def test_binary_payload_jws(self, fresh_engine):
        """Test JWS with binary payload."""
        key = os.urandom(32)
        payload = bytes(range(256))  # All byte values

        result = fresh_engine.create_jws(payload, key, JWSAlgorithm.HS256)
        verified, _ = fresh_engine.verify_jws(result.compact, key)
        assert verified == payload

    def test_unicode_in_header(self, fresh_engine):
        """Test JWS with unicode in custom header."""
        key = os.urandom(32)
        result = fresh_engine.create_jws(
            b"test", key, JWSAlgorithm.HS256,
            extra_headers={"name": "Test"}
        )

        _, header = fresh_engine.verify_jws(result.compact, key)
        assert header["name"] == "Test"
