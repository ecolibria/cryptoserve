"""Integration tests for hybrid PQC encryption through the API."""

import pytest
from app.core.hybrid_crypto import is_pqc_available
from app.schemas.context import AlgorithmOverride, CipherMode


# Skip all tests if liboqs is not available
pytestmark = pytest.mark.skipif(
    not is_pqc_available(),
    reason="liboqs not installed"
)


@pytest.fixture
async def test_db():
    """Get test database session."""
    from app.database import get_session_maker
    session_maker = get_session_maker()
    async with session_maker() as session:
        yield session


class TestHybridEncryptionAPI:
    """Tests for hybrid encryption through the crypto engine."""

    @pytest.mark.asyncio
    async def test_hybrid_encrypt_decrypt_direct(self, test_db):
        """Test hybrid encrypt/decrypt directly through crypto engine."""
        from app.core.crypto_engine import crypto_engine
        from app.models.identity import IdentityType, IdentityStatus
        from datetime import datetime, timezone

        # Create a mock identity for testing
        class MockIdentity:
            id = "test-identity"
            user_id = "test-user"
            type = IdentityType.SERVICE
            name = "Test Service"
            team = "test-team"
            environment = "development"
            allowed_contexts = ["user-pii"]
            status = IdentityStatus.ACTIVE
            created_at = datetime.now(timezone.utc)
            expires_at = None
            last_used_at = None

            @property
            def is_active(self):
                return True

        identity = MockIdentity()
        plaintext = b"Secret data for hybrid PQC encryption test"

        # Encrypt with hybrid algorithm override
        result = await crypto_engine.encrypt(
            db=test_db,
            plaintext=plaintext,
            context_name="user-pii",
            identity=identity,
            algorithm_override=AlgorithmOverride(
                cipher="AES",
                mode=CipherMode.HYBRID,
                key_bits=256
            ),
        )

        assert result.ciphertext is not None
        assert result.mode == CipherMode.HYBRID
        assert result.is_quantum_safe is True

        # Decrypt
        decrypted = await crypto_engine.decrypt(
            db=test_db,
            ciphertext=result.ciphertext,
            context_name="user-pii",
            identity=identity,
        )

        assert decrypted.plaintext == plaintext

    @pytest.mark.asyncio
    async def test_hybrid_encrypt_with_aad(self, test_db):
        """Test hybrid encryption with associated authenticated data."""
        from app.core.crypto_engine import crypto_engine
        from app.models.identity import IdentityType, IdentityStatus
        from datetime import datetime, timezone

        class MockIdentity:
            id = "test-identity"
            user_id = "test-user"
            type = IdentityType.SERVICE
            name = "Test Service"
            team = "test-team"
            environment = "development"
            allowed_contexts = ["user-pii"]
            status = IdentityStatus.ACTIVE
            created_at = datetime.now(timezone.utc)
            expires_at = None
            last_used_at = None
            is_active = True

        identity = MockIdentity()
        plaintext = b"PII data with authenticated context"
        aad = b"context:user-pii:version:1"

        # Encrypt with AAD
        result = await crypto_engine.encrypt(
            db=test_db,
            plaintext=plaintext,
            context_name="user-pii",
            identity=identity,
            algorithm_override=AlgorithmOverride(
                cipher="AES",
                mode=CipherMode.HYBRID,
                key_bits=256
            ),
            associated_data=aad,
        )

        assert result.mode == CipherMode.HYBRID

        # Decrypt with same AAD
        decrypted = await crypto_engine.decrypt(
            db=test_db,
            ciphertext=result.ciphertext,
            context_name="user-pii",
            identity=identity,
            associated_data=aad,
        )

        assert decrypted.plaintext == plaintext

    @pytest.mark.asyncio
    async def test_hybrid_wrong_aad_fails(self, test_db):
        """Test that wrong AAD fails decryption."""
        from app.core.crypto_engine import crypto_engine
        from app.models.identity import IdentityType, IdentityStatus
        from datetime import datetime, timezone

        class MockIdentity:
            id = "test-identity"
            user_id = "test-user"
            type = IdentityType.SERVICE
            name = "Test Service"
            team = "test-team"
            environment = "development"
            allowed_contexts = ["user-pii"]
            status = IdentityStatus.ACTIVE
            created_at = datetime.now(timezone.utc)
            expires_at = None
            last_used_at = None
            is_active = True

        identity = MockIdentity()
        plaintext = b"Protected data"
        aad = b"correct-aad"

        # Encrypt with correct AAD
        result = await crypto_engine.encrypt(
            db=test_db,
            plaintext=plaintext,
            context_name="user-pii",
            identity=identity,
            algorithm_override=AlgorithmOverride(
                cipher="AES",
                mode=CipherMode.HYBRID,
                key_bits=256
            ),
            associated_data=aad,
        )

        # Decrypt with wrong AAD should fail
        with pytest.raises(ValueError):
            await crypto_engine.decrypt(
                db=test_db,
                ciphertext=result.ciphertext,
                context_name="user-pii",
                identity=identity,
                associated_data=b"wrong-aad",
            )

    @pytest.mark.asyncio
    async def test_hybrid_ciphertext_has_pqc_prefix(self, test_db):
        """Test that hybrid ciphertext has correct format with PQC prefix."""
        from app.core.crypto_engine import crypto_engine
        from app.models.identity import IdentityType, IdentityStatus
        from datetime import datetime, timezone

        class MockIdentity:
            id = "test-identity"
            user_id = "test-user"
            type = IdentityType.SERVICE
            name = "Test Service"
            team = "test-team"
            environment = "development"
            allowed_contexts = ["user-pii"]
            status = IdentityStatus.ACTIVE
            created_at = datetime.now(timezone.utc)
            expires_at = None
            last_used_at = None
            is_active = True

        identity = MockIdentity()
        plaintext = b"Test data"

        result = await crypto_engine.encrypt(
            db=test_db,
            plaintext=plaintext,
            context_name="user-pii",
            identity=identity,
            algorithm_override=AlgorithmOverride(
                cipher="AES",
                mode=CipherMode.HYBRID,
                key_bits=256
            ),
        )

        # Hybrid ciphertext should start with PQC marker
        assert result.ciphertext.startswith(b"PQC:")

        # Should contain ML-KEM ciphertext (1088 bytes for ML-KEM-768)
        # Plus other metadata and encrypted content
        assert len(result.ciphertext) > 1088

    @pytest.mark.asyncio
    async def test_classical_vs_hybrid_ciphertext_sizes(self, test_db):
        """Compare ciphertext sizes between classical and hybrid encryption."""
        from app.core.crypto_engine import crypto_engine
        from app.models.identity import IdentityType, IdentityStatus
        from datetime import datetime, timezone

        class MockIdentity:
            id = "test-identity"
            user_id = "test-user"
            type = IdentityType.SERVICE
            name = "Test Service"
            team = "test-team"
            environment = "development"
            allowed_contexts = ["user-pii"]
            status = IdentityStatus.ACTIVE
            created_at = datetime.now(timezone.utc)
            expires_at = None
            last_used_at = None
            is_active = True

        identity = MockIdentity()
        plaintext = b"Test data for size comparison"

        # Classical encryption
        classical = await crypto_engine.encrypt(
            db=test_db,
            plaintext=plaintext,
            context_name="user-pii",
            identity=identity,
            algorithm_override=AlgorithmOverride(
                cipher="AES",
                mode=CipherMode.GCM,
                key_bits=256
            ),
        )

        # Hybrid encryption
        hybrid = await crypto_engine.encrypt(
            db=test_db,
            plaintext=plaintext,
            context_name="user-pii",
            identity=identity,
            algorithm_override=AlgorithmOverride(
                cipher="AES",
                mode=CipherMode.HYBRID,
                key_bits=256
            ),
        )

        # Hybrid should be larger due to ML-KEM ciphertext
        assert len(hybrid.ciphertext) > len(classical.ciphertext)

        # The difference should be approximately the ML-KEM ciphertext size
        # ML-KEM-768 ciphertext is 1088 bytes
        size_diff = len(hybrid.ciphertext) - len(classical.ciphertext)
        assert size_diff >= 1000  # At least 1000 bytes larger
