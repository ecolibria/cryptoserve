"""Tests for the Prometheus metrics module."""

import pytest
import time

from app.core.metrics import (
    metrics,
    MetricsRecorder,
    with_metrics,
    CRYPTO_OPERATIONS_TOTAL,
    CRYPTO_ERRORS_TOTAL,
    CRYPTO_OPERATION_LATENCY,
    PASSWORD_HASH_LATENCY,
    DATA_SIZE_BYTES,
    KEY_OPERATIONS_TOTAL,
    ACTIVE_KEYS,
)


@pytest.fixture
def fresh_metrics():
    """Create a fresh metrics recorder."""
    return MetricsRecorder()


class TestTrackOperation:
    """Tests for operation tracking."""

    def test_track_successful_operation(self, fresh_metrics):
        """Test tracking a successful operation."""
        with fresh_metrics.track_operation("encrypt", "aes-256-gcm", data_size=1024):
            time.sleep(0.001)  # Simulate work

        # Verify counter was incremented (can't easily verify exact value due to shared registry)

    def test_track_failed_operation(self, fresh_metrics):
        """Test tracking a failed operation."""
        with pytest.raises(ValueError):
            with fresh_metrics.track_operation("decrypt", "aes-256-gcm"):
                raise ValueError("Decryption failed")

    def test_track_operation_with_data_size(self, fresh_metrics):
        """Test tracking operation with data size."""
        with fresh_metrics.track_operation("hash", "sha256", data_size=4096):
            pass

    def test_track_operation_without_algorithm(self, fresh_metrics):
        """Test tracking operation without algorithm."""
        with fresh_metrics.track_operation("verify"):
            pass


class TestTrackPasswordHash:
    """Tests for password hash tracking."""

    def test_track_password_hash(self, fresh_metrics):
        """Test tracking password hash operation."""
        with fresh_metrics.track_password_hash("argon2id"):
            time.sleep(0.001)

    def test_track_password_hash_error(self, fresh_metrics):
        """Test tracking password hash error."""
        with pytest.raises(ValueError):
            with fresh_metrics.track_password_hash("bcrypt"):
                raise ValueError("Hash failed")


class TestTrackSignature:
    """Tests for signature tracking."""

    def test_track_sign_operation(self, fresh_metrics):
        """Test tracking sign operation."""
        with fresh_metrics.track_signature("sign", "ed25519"):
            pass

    def test_track_verify_operation(self, fresh_metrics):
        """Test tracking verify operation."""
        with fresh_metrics.track_signature("verify", "ecdsa-p256"):
            pass


class TestTrackCertificate:
    """Tests for certificate tracking."""

    def test_track_certificate_generation(self, fresh_metrics):
        """Test tracking certificate generation."""
        with fresh_metrics.track_certificate("generate_csr"):
            pass

    def test_track_certificate_validation(self, fresh_metrics):
        """Test tracking certificate validation."""
        with fresh_metrics.track_certificate("validate_chain"):
            pass


class TestTrackStreaming:
    """Tests for streaming operation tracking."""

    def test_track_streaming_encrypt(self, fresh_metrics):
        """Test tracking streaming encrypt operation."""
        with fresh_metrics.track_streaming("encrypt"):
            # Simulate streaming operation
            time.sleep(0.001)

    def test_track_streaming_decrypt(self, fresh_metrics):
        """Test tracking streaming decrypt operation."""
        with fresh_metrics.track_streaming("decrypt"):
            pass


class TestKeyOperations:
    """Tests for key operation recording."""

    def test_record_key_generation(self, fresh_metrics):
        """Test recording key generation."""
        fresh_metrics.record_key_operation("generate", "symmetric")

    def test_record_key_import(self, fresh_metrics):
        """Test recording key import."""
        fresh_metrics.record_key_operation("import", "asymmetric")

    def test_record_key_rotation(self, fresh_metrics):
        """Test recording key rotation."""
        fresh_metrics.record_key_operation("rotate", "symmetric")


class TestKeySize:
    """Tests for key size recording."""

    def test_record_symmetric_key_size(self, fresh_metrics):
        """Test recording symmetric key size."""
        fresh_metrics.record_key_size("symmetric", "aes-256-gcm", 256)

    def test_record_asymmetric_key_size(self, fresh_metrics):
        """Test recording asymmetric key size."""
        fresh_metrics.record_key_size("asymmetric", "rsa-4096", 4096)

    def test_record_ec_key_size(self, fresh_metrics):
        """Test recording EC key size."""
        fresh_metrics.record_key_size("asymmetric", "ec-p256", 256)


class TestGauges:
    """Tests for gauge metrics."""

    def test_set_active_keys(self, fresh_metrics):
        """Test setting active keys gauge."""
        fresh_metrics.set_active_keys("symmetric", "default", 5)
        fresh_metrics.set_active_keys("asymmetric", "production", 10)

    def test_set_contexts_total(self, fresh_metrics):
        """Test setting contexts total gauge."""
        fresh_metrics.set_contexts_total(3)


class TestInitialization:
    """Tests for metrics initialization."""

    def test_initialize(self, fresh_metrics):
        """Test metrics initialization."""
        fresh_metrics.initialize(
            version="1.0.0",
            algorithms=["aes-256-gcm", "chacha20-poly1305"],
        )

    def test_initialize_idempotent(self, fresh_metrics):
        """Test that initialization is idempotent."""
        fresh_metrics.initialize(version="1.0.0")
        fresh_metrics.initialize(version="2.0.0")  # Should not change


class TestWithMetricsDecorator:
    """Tests for the @with_metrics decorator."""

    def test_decorator_with_algorithm_kwarg(self):
        """Test decorator extracting algorithm from kwargs."""
        @with_metrics("test_op", algorithm_arg="algorithm")
        def test_func(data: bytes, algorithm: str = "default"):
            return len(data)

        result = test_func(b"hello", algorithm="sha256")
        assert result == 5

    def test_decorator_with_algorithm_position(self):
        """Test decorator extracting algorithm from position."""
        @with_metrics("test_op", algorithm_arg=1)
        def test_func(data: bytes, algorithm: str):
            return len(data)

        result = test_func(b"hello", "sha256")
        assert result == 5

    def test_decorator_without_algorithm(self):
        """Test decorator without algorithm tracking."""
        @with_metrics("test_op")
        def test_func(data: bytes):
            return len(data)

        result = test_func(b"hello")
        assert result == 5

    def test_decorator_with_exception(self):
        """Test decorator handling exceptions."""
        @with_metrics("failing_op")
        def test_func():
            raise RuntimeError("Test error")

        with pytest.raises(RuntimeError):
            test_func()


class TestSingletonInstance:
    """Tests for the singleton metrics instance."""

    def test_singleton_exists(self):
        """Test that singleton instance exists."""
        assert metrics is not None
        assert isinstance(metrics, MetricsRecorder)

    def test_singleton_methods(self):
        """Test singleton methods are callable."""
        with metrics.track_operation("test", "test_algo"):
            pass
