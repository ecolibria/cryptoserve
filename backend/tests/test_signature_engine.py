"""Tests for the signature engine."""

import pytest
import base64

from app.core.signature_engine import (
    signature_engine,
    SignatureEngine,
    SignatureAlgorithm,
    SignatureFormat,
    KeyNotFoundError,
    UnsupportedAlgorithmError,
)


@pytest.fixture
def fresh_engine():
    """Create a fresh signature engine for each test."""
    return SignatureEngine()


class TestKeyGeneration:
    """Tests for key pair generation."""

    def test_generate_ed25519_key(self, fresh_engine):
        """Test Ed25519 key generation."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=SignatureAlgorithm.ED25519,
            context="test",
        )

        assert key_pair.key_id.startswith("sig_test_")
        assert key_pair.algorithm == SignatureAlgorithm.ED25519
        # Private key is now encrypted in memory (not PEM format)
        assert len(key_pair.private_key_pem) > 0
        assert key_pair.public_key_pem.startswith(b"-----BEGIN PUBLIC KEY-----")
        assert key_pair.public_key_jwk["kty"] == "OKP"
        assert key_pair.public_key_jwk["crv"] == "Ed25519"
        assert key_pair.public_key_jwk["alg"] == "EdDSA"

    def test_generate_ecdsa_p256_key(self, fresh_engine):
        """Test ECDSA P-256 key generation."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=SignatureAlgorithm.ECDSA_P256,
            context="test",
        )

        assert key_pair.algorithm == SignatureAlgorithm.ECDSA_P256
        assert key_pair.public_key_jwk["kty"] == "EC"
        assert key_pair.public_key_jwk["crv"] == "P-256"
        assert key_pair.public_key_jwk["alg"] == "ES256"

    def test_generate_ecdsa_p384_key(self, fresh_engine):
        """Test ECDSA P-384 key generation."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=SignatureAlgorithm.ECDSA_P384,
            context="test",
        )

        assert key_pair.algorithm == SignatureAlgorithm.ECDSA_P384
        assert key_pair.public_key_jwk["kty"] == "EC"
        assert key_pair.public_key_jwk["crv"] == "P-384"
        assert key_pair.public_key_jwk["alg"] == "ES384"

    def test_keys_are_unique(self, fresh_engine):
        """Test that each generated key is unique."""
        key1 = fresh_engine.generate_key_pair(context="test")
        key2 = fresh_engine.generate_key_pair(context="test")

        assert key1.key_id != key2.key_id
        assert key1.private_key_pem != key2.private_key_pem
        assert key1.public_key_pem != key2.public_key_pem


class TestSigningAndVerification:
    """Tests for signing and verification."""

    def test_sign_verify_ed25519(self, fresh_engine):
        """Test Ed25519 sign and verify roundtrip."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=SignatureAlgorithm.ED25519,
            context="test",
        )

        message = b"Hello, World!"
        result = fresh_engine.sign(message, key_pair.key_id)

        assert result.algorithm == SignatureAlgorithm.ED25519
        assert len(result.signature) == 64  # Ed25519 signature size

        # Verify
        verification = fresh_engine.verify(message, result.signature, key_pair.key_id)
        assert verification.valid
        assert verification.message == "Signature is valid"

    def test_sign_verify_ecdsa_p256(self, fresh_engine):
        """Test ECDSA P-256 sign and verify roundtrip."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=SignatureAlgorithm.ECDSA_P256,
            context="test",
        )

        message = b"Hello, World!"
        result = fresh_engine.sign(message, key_pair.key_id)

        assert result.algorithm == SignatureAlgorithm.ECDSA_P256
        assert len(result.signature) == 64  # r + s, each 32 bytes

        # Verify
        verification = fresh_engine.verify(message, result.signature, key_pair.key_id)
        assert verification.valid

    def test_sign_verify_ecdsa_p384(self, fresh_engine):
        """Test ECDSA P-384 sign and verify roundtrip."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=SignatureAlgorithm.ECDSA_P384,
            context="test",
        )

        message = b"Hello, World!"
        result = fresh_engine.sign(message, key_pair.key_id)

        assert result.algorithm == SignatureAlgorithm.ECDSA_P384
        assert len(result.signature) == 96  # r + s, each 48 bytes

        # Verify
        verification = fresh_engine.verify(message, result.signature, key_pair.key_id)
        assert verification.valid

    def test_verify_tampered_message(self, fresh_engine):
        """Test that verification fails for tampered message."""
        key_pair = fresh_engine.generate_key_pair(context="test")

        message = b"Hello, World!"
        result = fresh_engine.sign(message, key_pair.key_id)

        # Tamper with message
        tampered = b"Hello, World?"
        verification = fresh_engine.verify(tampered, result.signature, key_pair.key_id)
        assert not verification.valid
        assert verification.message == "Signature verification failed"

    def test_verify_tampered_signature(self, fresh_engine):
        """Test that verification fails for tampered signature."""
        key_pair = fresh_engine.generate_key_pair(context="test")

        message = b"Hello, World!"
        result = fresh_engine.sign(message, key_pair.key_id)

        # Tamper with signature
        tampered_sig = bytearray(result.signature)
        tampered_sig[0] ^= 0xFF
        verification = fresh_engine.verify(message, bytes(tampered_sig), key_pair.key_id)
        assert not verification.valid

    def test_sign_base64_format(self, fresh_engine):
        """Test signing with base64 output format."""
        key_pair = fresh_engine.generate_key_pair(context="test")

        message = b"Hello, World!"
        result = fresh_engine.sign(
            message, key_pair.key_id, output_format=SignatureFormat.BASE64
        )

        assert result.format == SignatureFormat.BASE64
        # Should be valid base64
        decoded = base64.b64decode(result.signature)
        assert len(decoded) == 64  # Ed25519 signature

        # Verify with base64 format
        verification = fresh_engine.verify(
            message,
            result.signature,
            key_pair.key_id,
            signature_format=SignatureFormat.BASE64,
        )
        assert verification.valid

    def test_sign_der_format_ecdsa(self, fresh_engine):
        """Test ECDSA signing with DER output format."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=SignatureAlgorithm.ECDSA_P256,
            context="test",
        )

        message = b"Hello, World!"
        result = fresh_engine.sign(
            message, key_pair.key_id, output_format=SignatureFormat.DER
        )

        assert result.format == SignatureFormat.DER
        # DER format starts with 0x30 (SEQUENCE)
        assert result.signature[0] == 0x30

        # Verify with DER format
        verification = fresh_engine.verify(
            message,
            result.signature,
            key_pair.key_id,
            signature_format=SignatureFormat.DER,
        )
        assert verification.valid


class TestKeyNotFound:
    """Tests for key not found errors."""

    def test_sign_unknown_key(self, fresh_engine):
        """Test signing with unknown key fails."""
        with pytest.raises(KeyNotFoundError):
            fresh_engine.sign(b"test", "unknown_key_id")

    def test_verify_unknown_key(self, fresh_engine):
        """Test verification with unknown key fails."""
        with pytest.raises(KeyNotFoundError):
            fresh_engine.verify(b"test", b"signature", "unknown_key_id")

    def test_get_public_key_unknown(self, fresh_engine):
        """Test getting public key for unknown key fails."""
        with pytest.raises(KeyNotFoundError):
            fresh_engine.get_public_key("unknown_key_id")


class TestPublicKeyExport:
    """Tests for public key export."""

    def test_export_pem(self, fresh_engine):
        """Test exporting public key as PEM."""
        key_pair = fresh_engine.generate_key_pair(context="test")

        pem = fresh_engine.get_public_key(key_pair.key_id, format="pem")
        assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")

    def test_export_jwk(self, fresh_engine):
        """Test exporting public key as JWK."""
        key_pair = fresh_engine.generate_key_pair(context="test")

        jwk = fresh_engine.get_public_key(key_pair.key_id, format="jwk")
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert "x" in jwk

    def test_export_raw(self, fresh_engine):
        """Test exporting public key as raw bytes."""
        key_pair = fresh_engine.generate_key_pair(context="test")

        raw = fresh_engine.get_public_key(key_pair.key_id, format="raw")
        assert isinstance(raw, bytes)
        assert len(raw) == 32  # Ed25519 public key size

    def test_export_ec_raw(self, fresh_engine):
        """Test exporting EC public key as raw bytes (uncompressed point)."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=SignatureAlgorithm.ECDSA_P256,
            context="test",
        )

        raw = fresh_engine.get_public_key(key_pair.key_id, format="raw")
        assert isinstance(raw, bytes)
        assert len(raw) == 65  # Uncompressed point (0x04 + x + y)
        assert raw[0] == 0x04


class TestPublicKeyImport:
    """Tests for public key import."""

    def test_import_pem(self, fresh_engine):
        """Test importing public key from PEM."""
        # Generate a key pair to get a valid PEM
        original = fresh_engine.generate_key_pair(context="test")
        pem = fresh_engine.get_public_key(original.key_id, format="pem")

        # Create new engine and import
        new_engine = SignatureEngine()
        imported_id = new_engine.import_public_key(pem, format="pem")

        # Should be able to verify signatures
        message = b"test message"
        result = fresh_engine.sign(message, original.key_id)

        verification = new_engine.verify(message, result.signature, imported_id)
        assert verification.valid

    def test_import_jwk(self, fresh_engine):
        """Test importing public key from JWK."""
        original = fresh_engine.generate_key_pair(context="test")
        jwk = fresh_engine.get_public_key(original.key_id, format="jwk")

        new_engine = SignatureEngine()
        imported_id = new_engine.import_public_key(jwk, format="jwk")

        # Verify
        message = b"test message"
        result = fresh_engine.sign(message, original.key_id)

        verification = new_engine.verify(message, result.signature, imported_id)
        assert verification.valid

    def test_import_ec_jwk(self, fresh_engine):
        """Test importing EC public key from JWK."""
        original = fresh_engine.generate_key_pair(
            algorithm=SignatureAlgorithm.ECDSA_P256,
            context="test",
        )
        jwk = fresh_engine.get_public_key(original.key_id, format="jwk")

        new_engine = SignatureEngine()
        imported_id = new_engine.import_public_key(jwk, format="jwk")

        # Verify
        message = b"test message"
        result = fresh_engine.sign(message, original.key_id)

        verification = new_engine.verify(message, result.signature, imported_id)
        assert verification.valid


class TestKeyManagement:
    """Tests for key management operations."""

    def test_list_keys(self, fresh_engine):
        """Test listing keys."""
        fresh_engine.generate_key_pair(context="ctx1")
        fresh_engine.generate_key_pair(context="ctx2")
        fresh_engine.generate_key_pair(context="ctx1")

        all_keys = fresh_engine.list_keys()
        assert len(all_keys) == 3

        ctx1_keys = fresh_engine.list_keys(context="ctx1")
        assert len(ctx1_keys) == 2

        ctx2_keys = fresh_engine.list_keys(context="ctx2")
        assert len(ctx2_keys) == 1

    def test_delete_key(self, fresh_engine):
        """Test deleting a key."""
        key_pair = fresh_engine.generate_key_pair(context="test")

        assert fresh_engine.delete_key(key_pair.key_id)
        assert len(fresh_engine.list_keys()) == 0

        # Should return False for non-existent key
        assert not fresh_engine.delete_key(key_pair.key_id)

    def test_cannot_sign_after_delete(self, fresh_engine):
        """Test that signing fails after key deletion."""
        key_pair = fresh_engine.generate_key_pair(context="test")
        fresh_engine.delete_key(key_pair.key_id)

        with pytest.raises(KeyNotFoundError):
            fresh_engine.sign(b"test", key_pair.key_id)


class TestDeterministicSignatures:
    """Tests for Ed25519 deterministic signatures."""

    def test_ed25519_deterministic(self, fresh_engine):
        """Test that Ed25519 signatures are deterministic."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=SignatureAlgorithm.ED25519,
            context="test",
        )

        message = b"Hello, World!"
        sig1 = fresh_engine.sign(message, key_pair.key_id)
        sig2 = fresh_engine.sign(message, key_pair.key_id)

        # Ed25519 is deterministic - same message = same signature
        assert sig1.signature == sig2.signature

    def test_ecdsa_non_deterministic(self, fresh_engine):
        """Test that ECDSA signatures may differ (uses random k)."""
        key_pair = fresh_engine.generate_key_pair(
            algorithm=SignatureAlgorithm.ECDSA_P256,
            context="test",
        )

        message = b"Hello, World!"
        sig1 = fresh_engine.sign(message, key_pair.key_id)
        sig2 = fresh_engine.sign(message, key_pair.key_id)

        # ECDSA uses random k, so signatures may differ
        # Both should verify though
        assert fresh_engine.verify(message, sig1.signature, key_pair.key_id).valid
        assert fresh_engine.verify(message, sig2.signature, key_pair.key_id).valid


class TestEmptyAndLargeMessages:
    """Tests for edge cases."""

    def test_sign_empty_message(self, fresh_engine):
        """Test signing an empty message."""
        key_pair = fresh_engine.generate_key_pair(context="test")

        result = fresh_engine.sign(b"", key_pair.key_id)
        verification = fresh_engine.verify(b"", result.signature, key_pair.key_id)
        assert verification.valid

    def test_sign_large_message(self, fresh_engine):
        """Test signing a large message."""
        key_pair = fresh_engine.generate_key_pair(context="test")

        # 1 MB message
        message = b"x" * (1024 * 1024)
        result = fresh_engine.sign(message, key_pair.key_id)
        verification = fresh_engine.verify(message, result.signature, key_pair.key_id)
        assert verification.valid
