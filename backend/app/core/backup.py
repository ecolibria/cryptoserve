"""Backup and restore service for CryptoServe.

Provides encrypted backup/restore capabilities for:
- Database records (tenants, contexts, keys, users, etc.)
- PQC key material (already encrypted at rest)
- Configuration and policies

Classical keys are NOT backed up - they are derived from the master key.
To restore, you need:
1. The backup archive
2. The backup password (used to decrypt the backup)
3. The original master key (CRYPTOSERVE_MASTER_KEY)

Security:
- Backups are encrypted with AES-256-GCM
- Backup encryption key derived from password via Argon2
- Each backup file includes a SHA-256 checksum
- Backup manifest includes creation time and version info
"""

import asyncio
import gzip
import hashlib
import io
import json
import logging
import os
import secrets
import tarfile
import tempfile
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TYPE_CHECKING

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from sqlalchemy import select, inspect
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import Base, get_session_maker
from app.models import (
    Tenant, User, Context, Key, PQCKey, AuditLog,
    Policy, CryptoInventoryReport, Application, Identity, OrganizationSettings
)

if TYPE_CHECKING:
    from sqlalchemy.orm import DeclarativeBase

logger = logging.getLogger(__name__)
settings = get_settings()

# Backup format version
BACKUP_VERSION = "1.0.0"

# Models to backup (in order for restore to handle foreign keys)
BACKUP_MODELS = [
    OrganizationSettings,
    Tenant,
    User,
    Application,
    Context,
    Key,
    PQCKey,
    Identity,
    Policy,
    CryptoInventoryReport,
    # AuditLog excluded by default - too large, optional
]

# Size limit for including audit logs (10MB compressed)
AUDIT_LOG_SIZE_LIMIT = 10 * 1024 * 1024


@dataclass
class BackupManifest:
    """Metadata about a backup."""
    version: str
    created_at: str
    cryptoserve_version: str
    database_type: str
    tenant_count: int
    context_count: int
    key_count: int
    pqc_key_count: int
    includes_audit_logs: bool
    checksum: str  # SHA-256 of all data files

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "BackupManifest":
        return cls(**data)


@dataclass
class BackupResult:
    """Result of a backup operation."""
    success: bool
    backup_path: str | None
    manifest: BackupManifest | None
    error: str | None
    size_bytes: int
    duration_seconds: float


@dataclass
class RestoreResult:
    """Result of a restore operation."""
    success: bool
    error: str | None
    records_restored: dict[str, int]
    duration_seconds: float
    warnings: list[str]


class BackupService:
    """Handles backup and restore operations for CryptoServe.

    Usage:
        backup_service = BackupService()

        # Create backup
        result = await backup_service.create_backup(
            output_path="/backups/cryptoserve-backup.tar.gz.enc",
            password="secure-backup-password",
            include_audit_logs=False
        )

        # Restore from backup
        result = await backup_service.restore_backup(
            backup_path="/backups/cryptoserve-backup.tar.gz.enc",
            password="secure-backup-password",
            dry_run=True  # Preview what would be restored
        )
    """

    def __init__(self):
        self._salt_size = 16  # 128-bit salt for key derivation
        self._nonce_size = 12  # 96-bit nonce for AES-GCM

    def _derive_backup_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using Scrypt.

        Scrypt is memory-hard, making brute-force attacks expensive.
        """
        kdf = Scrypt(
            salt=salt,
            length=32,  # 256-bit key
            n=2**17,    # CPU/memory cost (128MB)
            r=8,
            p=1,
        )
        return kdf.derive(password.encode())

    def _encrypt_data(self, data: bytes, password: str) -> bytes:
        """Encrypt data with password-derived key.

        Format: salt (16 bytes) || nonce (12 bytes) || ciphertext
        """
        salt = secrets.token_bytes(self._salt_size)
        nonce = secrets.token_bytes(self._nonce_size)
        key = self._derive_backup_key(password, salt)

        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, associated_data=b"cryptoserve-backup")

        return salt + nonce + ciphertext

    def _decrypt_data(self, encrypted: bytes, password: str) -> bytes:
        """Decrypt password-encrypted data."""
        if len(encrypted) < self._salt_size + self._nonce_size + 16:
            raise ValueError("Invalid encrypted data: too short")

        salt = encrypted[:self._salt_size]
        nonce = encrypted[self._salt_size:self._salt_size + self._nonce_size]
        ciphertext = encrypted[self._salt_size + self._nonce_size:]

        key = self._derive_backup_key(password, salt)
        aesgcm = AESGCM(key)

        try:
            return aesgcm.decrypt(nonce, ciphertext, associated_data=b"cryptoserve-backup")
        except Exception as e:
            raise ValueError(f"Decryption failed - wrong password or corrupted backup: {e}")

    async def _export_model(
        self,
        db: AsyncSession,
        model: type,
        tenant_id: str | None = None
    ) -> list[dict]:
        """Export all records of a model to dictionaries."""
        query = select(model)

        # Filter by tenant if model has tenant_id and tenant specified
        if tenant_id and hasattr(model, 'tenant_id'):
            query = query.where(model.tenant_id == tenant_id)

        result = await db.execute(query)
        records = result.scalars().all()

        exported = []
        mapper = inspect(model)

        for record in records:
            row_dict = {}
            for column in mapper.columns:
                value = getattr(record, column.key)
                # Handle special types
                if isinstance(value, datetime):
                    value = value.isoformat()
                elif isinstance(value, bytes):
                    # Base64 encode binary data
                    import base64
                    value = base64.b64encode(value).decode('ascii')
                elif hasattr(value, 'value'):  # Enum
                    value = value.value
                row_dict[column.key] = value
            exported.append(row_dict)

        return exported

    async def _import_model(
        self,
        db: AsyncSession,
        model: type,
        records: list[dict],
        dry_run: bool = False
    ) -> int:
        """Import records into a model table."""
        if dry_run:
            return len(records)

        import base64
        mapper = inspect(model)
        imported = 0

        for record_dict in records:
            # Convert values back to proper types
            for column in mapper.columns:
                if column.key not in record_dict:
                    continue

                value = record_dict[column.key]
                if value is None:
                    continue

                # Handle datetime
                if hasattr(column.type, 'python_type'):
                    if column.type.python_type == datetime and isinstance(value, str):
                        record_dict[column.key] = datetime.fromisoformat(value)

                # Handle binary (base64)
                if hasattr(column.type, '__class__') and 'LargeBinary' in str(column.type.__class__):
                    if isinstance(value, str):
                        record_dict[column.key] = base64.b64decode(value)

            # Check if record exists
            pk_column = mapper.primary_key[0]
            pk_value = record_dict.get(pk_column.key)

            existing = await db.execute(
                select(model).where(pk_column == pk_value)
            )
            if existing.scalar_one_or_none():
                # Update existing record
                # For now, skip existing records to avoid conflicts
                continue

            try:
                record = model(**record_dict)
                db.add(record)
                imported += 1
            except Exception as e:
                logger.warning(f"Failed to import {model.__name__} record: {e}")

        return imported

    async def create_backup(
        self,
        output_path: str,
        password: str,
        tenant_id: str | None = None,
        include_audit_logs: bool = False,
    ) -> BackupResult:
        """Create an encrypted backup of the database.

        Args:
            output_path: Path for the encrypted backup file
            password: Password to encrypt the backup
            tenant_id: Optional - backup only this tenant's data
            include_audit_logs: Include audit logs (can be very large)

        Returns:
            BackupResult with details about the backup
        """
        start_time = datetime.now(timezone.utc)
        logger.info(f"Starting backup to {output_path}")

        try:
            async with get_session_maker()() as db:
                # Export all models to JSON
                backup_data = {}
                checksums = {}

                models_to_backup = BACKUP_MODELS.copy()
                if include_audit_logs:
                    models_to_backup.append(AuditLog)

                for model in models_to_backup:
                    model_name = model.__tablename__
                    logger.info(f"Exporting {model_name}...")

                    records = await self._export_model(db, model, tenant_id)
                    backup_data[model_name] = records

                    # Calculate checksum for this table
                    table_json = json.dumps(records, sort_keys=True)
                    checksums[model_name] = hashlib.sha256(table_json.encode()).hexdigest()

                    logger.info(f"Exported {len(records)} {model_name} records")

                # Calculate overall checksum
                overall_checksum = hashlib.sha256(
                    json.dumps(checksums, sort_keys=True).encode()
                ).hexdigest()

                # Create manifest
                manifest = BackupManifest(
                    version=BACKUP_VERSION,
                    created_at=datetime.now(timezone.utc).isoformat(),
                    cryptoserve_version="1.0.0",  # TODO: Get from package
                    database_type="postgresql" if "postgresql" in settings.database_url else "sqlite",
                    tenant_count=len(backup_data.get("tenants", [])),
                    context_count=len(backup_data.get("contexts", [])),
                    key_count=len(backup_data.get("keys", [])),
                    pqc_key_count=len(backup_data.get("pqc_keys", [])),
                    includes_audit_logs=include_audit_logs,
                    checksum=overall_checksum,
                )

                # Create tar archive in memory
                tar_buffer = io.BytesIO()
                with tarfile.open(fileobj=tar_buffer, mode='w:gz') as tar:
                    # Add manifest
                    manifest_json = json.dumps(manifest.to_dict(), indent=2)
                    manifest_bytes = manifest_json.encode()
                    manifest_info = tarfile.TarInfo(name="manifest.json")
                    manifest_info.size = len(manifest_bytes)
                    tar.addfile(manifest_info, io.BytesIO(manifest_bytes))

                    # Add data files
                    for table_name, records in backup_data.items():
                        data_json = json.dumps(records, indent=2, default=str)
                        data_bytes = data_json.encode()
                        data_info = tarfile.TarInfo(name=f"data/{table_name}.json")
                        data_info.size = len(data_bytes)
                        tar.addfile(data_info, io.BytesIO(data_bytes))

                    # Add checksums
                    checksums_json = json.dumps(checksums, indent=2)
                    checksums_bytes = checksums_json.encode()
                    checksums_info = tarfile.TarInfo(name="checksums.json")
                    checksums_info.size = len(checksums_bytes)
                    tar.addfile(checksums_info, io.BytesIO(checksums_bytes))

                # Encrypt the archive
                tar_data = tar_buffer.getvalue()
                encrypted_data = self._encrypt_data(tar_data, password)

                # Write to file
                output = Path(output_path)
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(encrypted_data)

                duration = (datetime.now(timezone.utc) - start_time).total_seconds()

                logger.info(
                    f"Backup completed: {len(encrypted_data)} bytes, "
                    f"{duration:.2f}s, checksum={overall_checksum[:16]}..."
                )

                return BackupResult(
                    success=True,
                    backup_path=str(output_path),
                    manifest=manifest,
                    error=None,
                    size_bytes=len(encrypted_data),
                    duration_seconds=duration,
                )

        except Exception as e:
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            logger.error(f"Backup failed: {e}")
            return BackupResult(
                success=False,
                backup_path=None,
                manifest=None,
                error=str(e),
                size_bytes=0,
                duration_seconds=duration,
            )

    async def restore_backup(
        self,
        backup_path: str,
        password: str,
        dry_run: bool = True,
        skip_existing: bool = True,
    ) -> RestoreResult:
        """Restore from an encrypted backup.

        Args:
            backup_path: Path to the encrypted backup file
            password: Password to decrypt the backup
            dry_run: If True, only validate and report what would be restored
            skip_existing: If True, skip records that already exist

        Returns:
            RestoreResult with details about the restore
        """
        start_time = datetime.now(timezone.utc)
        warnings = []
        records_restored = {}

        logger.info(f"Starting {'dry run ' if dry_run else ''}restore from {backup_path}")

        try:
            # Read and decrypt backup
            backup_file = Path(backup_path)
            if not backup_file.exists():
                raise FileNotFoundError(f"Backup file not found: {backup_path}")

            encrypted_data = backup_file.read_bytes()
            tar_data = self._decrypt_data(encrypted_data, password)

            # Extract tar archive
            tar_buffer = io.BytesIO(tar_data)
            with tarfile.open(fileobj=tar_buffer, mode='r:gz') as tar:
                # Read manifest
                manifest_file = tar.extractfile("manifest.json")
                if not manifest_file:
                    raise ValueError("Invalid backup: missing manifest.json")
                manifest = BackupManifest.from_dict(json.load(manifest_file))

                logger.info(
                    f"Backup manifest: version={manifest.version}, "
                    f"created={manifest.created_at}, "
                    f"tenants={manifest.tenant_count}, contexts={manifest.context_count}"
                )

                # Read checksums
                checksums_file = tar.extractfile("checksums.json")
                if not checksums_file:
                    raise ValueError("Invalid backup: missing checksums.json")
                checksums = json.load(checksums_file)

                # Validate checksums and read data
                backup_data = {}
                for member in tar.getmembers():
                    if member.name.startswith("data/") and member.name.endswith(".json"):
                        table_name = member.name[5:-5]  # Remove "data/" and ".json"
                        data_file = tar.extractfile(member)
                        if data_file:
                            data_bytes = data_file.read()

                            # Verify checksum
                            records = json.loads(data_bytes)
                            calculated_checksum = hashlib.sha256(
                                json.dumps(records, sort_keys=True).encode()
                            ).hexdigest()

                            if table_name in checksums:
                                if calculated_checksum != checksums[table_name]:
                                    raise ValueError(
                                        f"Checksum mismatch for {table_name}: "
                                        f"backup may be corrupted"
                                    )

                            backup_data[table_name] = records

                # Verify overall checksum
                calculated_overall = hashlib.sha256(
                    json.dumps(checksums, sort_keys=True).encode()
                ).hexdigest()
                if calculated_overall != manifest.checksum:
                    raise ValueError("Overall checksum mismatch: backup may be corrupted")

                logger.info(f"Checksums verified, {len(backup_data)} tables to restore")

                if dry_run:
                    # Just report what would be restored
                    for table_name, records in backup_data.items():
                        records_restored[table_name] = len(records)
                        logger.info(f"Would restore {len(records)} {table_name} records")
                else:
                    # Actually restore data
                    async with get_session_maker()() as db:
                        # Restore in order of BACKUP_MODELS to handle foreign keys
                        for model in BACKUP_MODELS:
                            table_name = model.__tablename__
                            if table_name in backup_data:
                                records = backup_data[table_name]
                                count = await self._import_model(db, model, records)
                                records_restored[table_name] = count
                                logger.info(f"Restored {count} {table_name} records")

                        # Handle audit logs if present
                        if "audit_logs" in backup_data:
                            count = await self._import_model(
                                db, AuditLog, backup_data["audit_logs"]
                            )
                            records_restored["audit_logs"] = count

                        await db.commit()

            duration = (datetime.now(timezone.utc) - start_time).total_seconds()

            return RestoreResult(
                success=True,
                error=None,
                records_restored=records_restored,
                duration_seconds=duration,
                warnings=warnings,
            )

        except Exception as e:
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            logger.error(f"Restore failed: {e}")
            return RestoreResult(
                success=False,
                error=str(e),
                records_restored=records_restored,
                duration_seconds=duration,
                warnings=warnings,
            )

    async def list_backups(self, backup_dir: str) -> list[dict]:
        """List available backups in a directory.

        Args:
            backup_dir: Directory containing backup files

        Returns:
            List of backup info dicts (filename, size, modified time)
        """
        backups = []
        backup_path = Path(backup_dir)

        if not backup_path.exists():
            return []

        for file in backup_path.glob("*.tar.gz.enc"):
            stat = file.stat()
            backups.append({
                "filename": file.name,
                "path": str(file),
                "size_bytes": stat.st_size,
                "modified_at": datetime.fromtimestamp(
                    stat.st_mtime, tz=timezone.utc
                ).isoformat(),
            })

        # Sort by modified time, newest first
        backups.sort(key=lambda x: x["modified_at"], reverse=True)
        return backups

    async def get_backup_info(self, backup_path: str, password: str) -> BackupManifest:
        """Get manifest info from a backup without full restore.

        Args:
            backup_path: Path to backup file
            password: Backup password

        Returns:
            BackupManifest with backup metadata
        """
        encrypted_data = Path(backup_path).read_bytes()
        tar_data = self._decrypt_data(encrypted_data, password)

        tar_buffer = io.BytesIO(tar_data)
        with tarfile.open(fileobj=tar_buffer, mode='r:gz') as tar:
            manifest_file = tar.extractfile("manifest.json")
            if not manifest_file:
                raise ValueError("Invalid backup: missing manifest.json")
            return BackupManifest.from_dict(json.load(manifest_file))


# Singleton instance
backup_service = BackupService()
