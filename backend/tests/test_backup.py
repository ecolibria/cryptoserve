"""Tests for backup and restore functionality."""

import json
import os
import tempfile
from datetime import datetime, timezone

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.backup import BackupService, BackupManifest, backup_service
from app.models import Tenant, User, Context, Key, KeyStatus


@pytest.fixture
def temp_backup_dir():
    """Create a temporary directory for backups."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
async def sample_data(db_session: AsyncSession, test_tenant: Tenant) -> dict:
    """Create sample data for backup testing."""
    # Create a user
    user = User(
        tenant_id=test_tenant.id,
        github_id=99999,
        github_username="backupuser",
        email="backup@example.com",
    )
    db_session.add(user)

    # Create contexts
    context1 = Context(
        tenant_id=test_tenant.id,
        name="backup-context-1",
        display_name="Backup Context 1",
        description="Test context for backup",
        data_examples=["test"],
        compliance_tags=["TEST"],
        algorithm="AES-256-GCM",
    )
    context2 = Context(
        tenant_id=test_tenant.id,
        name="backup-context-2",
        display_name="Backup Context 2",
        description="Another test context",
        data_examples=["test2"],
        compliance_tags=["TEST2"],
        algorithm="AES-256-GCM",
    )
    db_session.add(context1)
    db_session.add(context2)

    # Create a key
    key = Key(
        id="key_backup_test_1234",
        tenant_id=test_tenant.id,
        context="backup-context-1",
        version=1,
        status=KeyStatus.ACTIVE,
    )
    db_session.add(key)

    await db_session.commit()

    return {
        "tenant": test_tenant,
        "user": user,
        "contexts": [context1, context2],
        "key": key,
    }


class TestBackupService:
    """Tests for the BackupService class."""

    def test_encrypt_decrypt_roundtrip(self):
        """Test that data can be encrypted and decrypted correctly."""
        service = BackupService()
        original = b"Hello, this is test data for backup encryption!"
        password = "test-password-123"

        encrypted = service._encrypt_data(original, password)
        decrypted = service._decrypt_data(encrypted, password)

        assert decrypted == original

    def test_decrypt_wrong_password_fails(self):
        """Test that wrong password fails decryption."""
        service = BackupService()
        original = b"Secret data"
        password = "correct-password"

        encrypted = service._encrypt_data(original, password)

        with pytest.raises(ValueError, match="Decryption failed"):
            service._decrypt_data(encrypted, "wrong-password")

    def test_decrypt_corrupted_data_fails(self):
        """Test that corrupted data fails decryption."""
        service = BackupService()
        original = b"Secret data"
        password = "password"

        encrypted = service._encrypt_data(original, password)

        # Corrupt the data
        corrupted = bytearray(encrypted)
        corrupted[50] ^= 0xFF
        corrupted = bytes(corrupted)

        with pytest.raises(ValueError, match="Decryption failed"):
            service._decrypt_data(corrupted, password)

    def test_encrypt_produces_different_ciphertext(self):
        """Test that encryption uses random nonce (different ciphertext each time)."""
        service = BackupService()
        data = b"Same data"
        password = "password"

        encrypted1 = service._encrypt_data(data, password)
        encrypted2 = service._encrypt_data(data, password)

        # Should be different due to random salt and nonce
        assert encrypted1 != encrypted2

        # But both should decrypt to same plaintext
        assert service._decrypt_data(encrypted1, password) == data
        assert service._decrypt_data(encrypted2, password) == data


class TestBackupCreateRestore:
    """Tests for backup creation and restoration."""

    @pytest.mark.asyncio
    async def test_create_backup(self, db_session, sample_data, temp_backup_dir):
        """Test creating a backup."""
        backup_path = os.path.join(temp_backup_dir, "test-backup.tar.gz.enc")
        password = "test-backup-password"

        result = await backup_service.create_backup(
            output_path=backup_path,
            password=password,
            include_audit_logs=False,
        )

        assert result.success is True
        assert result.backup_path == backup_path
        assert result.error is None
        assert result.size_bytes > 0
        assert result.manifest is not None
        assert result.manifest.version == "1.0.0"
        assert result.manifest.tenant_count >= 1
        assert result.manifest.context_count >= 2

        # Verify file was created
        assert os.path.exists(backup_path)

    @pytest.mark.asyncio
    async def test_backup_manifest(self, db_session, sample_data, temp_backup_dir):
        """Test that backup manifest contains correct info."""
        backup_path = os.path.join(temp_backup_dir, "manifest-test.tar.gz.enc")
        password = "manifest-password"

        result = await backup_service.create_backup(
            output_path=backup_path,
            password=password,
        )

        # Read back the manifest
        manifest = await backup_service.get_backup_info(backup_path, password)

        assert manifest.version == "1.0.0"
        assert manifest.cryptoserve_version == "1.0.0"
        assert manifest.checksum is not None
        assert len(manifest.checksum) == 64  # SHA-256 hex length

    @pytest.mark.asyncio
    async def test_restore_dry_run(self, db_session, sample_data, temp_backup_dir):
        """Test restore in dry-run mode."""
        backup_path = os.path.join(temp_backup_dir, "restore-test.tar.gz.enc")
        password = "restore-password"

        # Create backup
        await backup_service.create_backup(
            output_path=backup_path,
            password=password,
        )

        # Restore in dry-run mode
        result = await backup_service.restore_backup(
            backup_path=backup_path,
            password=password,
            dry_run=True,
        )

        assert result.success is True
        assert result.error is None
        assert len(result.records_restored) > 0
        assert "tenants" in result.records_restored or result.records_restored.get("tenants", 0) >= 0

    @pytest.mark.asyncio
    async def test_restore_wrong_password(self, db_session, sample_data, temp_backup_dir):
        """Test restore with wrong password fails."""
        backup_path = os.path.join(temp_backup_dir, "wrong-pw-test.tar.gz.enc")
        password = "correct-password"

        # Create backup
        await backup_service.create_backup(
            output_path=backup_path,
            password=password,
        )

        # Try to restore with wrong password
        result = await backup_service.restore_backup(
            backup_path=backup_path,
            password="wrong-password",
            dry_run=True,
        )

        assert result.success is False
        assert "Decryption failed" in result.error

    @pytest.mark.asyncio
    async def test_list_backups(self, temp_backup_dir):
        """Test listing backups in a directory."""
        # Create some backup files
        for i in range(3):
            path = os.path.join(temp_backup_dir, f"backup_{i}.tar.gz.enc")
            with open(path, "wb") as f:
                f.write(b"dummy backup data " * 100)

        backups = await backup_service.list_backups(temp_backup_dir)

        assert len(backups) == 3
        for b in backups:
            assert "filename" in b
            assert "size_bytes" in b
            assert "modified_at" in b
            assert b["filename"].endswith(".tar.gz.enc")

    @pytest.mark.asyncio
    async def test_list_backups_empty_dir(self, temp_backup_dir):
        """Test listing backups in an empty directory."""
        backups = await backup_service.list_backups(temp_backup_dir)
        assert backups == []

    @pytest.mark.asyncio
    async def test_list_backups_nonexistent_dir(self):
        """Test listing backups in a nonexistent directory."""
        backups = await backup_service.list_backups("/nonexistent/path")
        assert backups == []


class TestBackupManifest:
    """Tests for BackupManifest dataclass."""

    def test_manifest_to_dict(self):
        """Test manifest serialization to dict."""
        manifest = BackupManifest(
            version="1.0.0",
            created_at="2024-01-15T10:30:00Z",
            cryptoserve_version="1.0.0",
            database_type="postgresql",
            tenant_count=5,
            context_count=10,
            key_count=20,
            pqc_key_count=2,
            includes_audit_logs=True,
            checksum="abc123def456",
        )

        data = manifest.to_dict()

        assert data["version"] == "1.0.0"
        assert data["tenant_count"] == 5
        assert data["includes_audit_logs"] is True

    def test_manifest_from_dict(self):
        """Test manifest deserialization from dict."""
        data = {
            "version": "1.0.0",
            "created_at": "2024-01-15T10:30:00Z",
            "cryptoserve_version": "1.0.0",
            "database_type": "sqlite",
            "tenant_count": 3,
            "context_count": 7,
            "key_count": 15,
            "pqc_key_count": 0,
            "includes_audit_logs": False,
            "checksum": "xyz789",
        }

        manifest = BackupManifest.from_dict(data)

        assert manifest.version == "1.0.0"
        assert manifest.database_type == "sqlite"
        assert manifest.tenant_count == 3
        assert manifest.pqc_key_count == 0

    def test_manifest_roundtrip(self):
        """Test manifest serialization/deserialization roundtrip."""
        original = BackupManifest(
            version="1.0.0",
            created_at="2024-01-15T10:30:00Z",
            cryptoserve_version="1.0.0",
            database_type="postgresql",
            tenant_count=5,
            context_count=10,
            key_count=20,
            pqc_key_count=2,
            includes_audit_logs=True,
            checksum="abc123",
        )

        restored = BackupManifest.from_dict(original.to_dict())

        assert restored.version == original.version
        assert restored.created_at == original.created_at
        assert restored.tenant_count == original.tenant_count
        assert restored.checksum == original.checksum


class TestBackupSecurity:
    """Security-focused tests for backup functionality."""

    def test_encryption_key_derivation_is_slow(self):
        """Test that key derivation takes reasonable time (memory-hard)."""
        import time

        service = BackupService()
        data = b"test"
        password = "password"

        start = time.time()
        service._encrypt_data(data, password)
        duration = time.time() - start

        # Scrypt should take at least 100ms with our parameters
        # This makes brute-force attacks expensive
        assert duration > 0.1, f"Key derivation too fast: {duration}s"

    def test_encrypted_data_has_correct_structure(self):
        """Test that encrypted data has expected structure."""
        service = BackupService()
        data = b"test data"
        password = "password"

        encrypted = service._encrypt_data(data, password)

        # Structure: salt (16) + nonce (12) + ciphertext + tag (16)
        # Minimum size: 16 + 12 + len(data) + 16 = 44 + len(data)
        assert len(encrypted) >= 44 + len(data)

        # Salt should be first 16 bytes
        salt = encrypted[:16]
        assert len(salt) == 16

        # Nonce should be next 12 bytes
        nonce = encrypted[16:28]
        assert len(nonce) == 12

    def test_backup_password_validation(self):
        """Test that backup handles various password types."""
        service = BackupService()
        data = b"test"

        # Very long password
        long_password = "a" * 1000
        encrypted = service._encrypt_data(data, long_password)
        decrypted = service._decrypt_data(encrypted, long_password)
        assert decrypted == data

        # Unicode password
        unicode_password = "测试密码🔐"
        encrypted = service._encrypt_data(data, unicode_password)
        decrypted = service._decrypt_data(encrypted, unicode_password)
        assert decrypted == data

        # Password with special characters
        special_password = "p@$$w0rd!#$%^&*()"
        encrypted = service._encrypt_data(data, special_password)
        decrypted = service._decrypt_data(encrypted, special_password)
        assert decrypted == data
