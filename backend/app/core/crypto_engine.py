"""Cryptographic operations engine.

Handles encryption and decryption with policy enforcement.
"""

import os
import json
import base64
from dataclasses import dataclass
from datetime import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Context, Identity, AuditLog, PolicyViolationLog
from app.core.key_manager import key_manager
from app.core.policy_engine import (
    policy_engine,
    PolicyViolation,
    PolicySeverity,
    build_evaluation_context,
)


class CryptoError(Exception):
    """Base crypto exception."""
    pass


class ContextNotFoundError(CryptoError):
    """Context does not exist."""
    pass


class AuthorizationError(CryptoError):
    """Identity not authorized for context."""
    pass


class DecryptionError(CryptoError):
    """Failed to decrypt data."""
    pass


class PolicyError(CryptoError):
    """Policy violation blocked the operation."""

    def __init__(self, policy_name: str, message: str):
        self.policy_name = policy_name
        super().__init__(f"Policy violation [{policy_name}]: {message}")


@dataclass
class EncryptResult:
    """Result of encryption operation."""
    ciphertext: bytes
    algorithm: str
    key_id: str
    nonce: bytes
    context: str


class CryptoEngine:
    """Handles encryption and decryption operations with policy enforcement."""

    HEADER_VERSION = 1

    def __init__(self):
        # Load default policies on startup
        policy_engine.load_default_policies()

    async def encrypt(
        self,
        db: AsyncSession,
        plaintext: bytes,
        context_name: str,
        identity: Identity,
        ip_address: str | None = None,
        user_agent: str | None = None,
        enforce_policies: bool = True,
    ) -> bytes:
        """Encrypt data and return self-describing ciphertext.

        Args:
            db: Database session
            plaintext: Data to encrypt
            context_name: Encryption context
            identity: Calling identity
            ip_address: Request IP for audit
            user_agent: Request user agent for audit
            enforce_policies: If True, evaluate and enforce policies

        Returns:
            Self-describing ciphertext

        Raises:
            ContextNotFoundError: If context doesn't exist
            AuthorizationError: If identity not authorized
            PolicyError: If a blocking policy is violated
        """
        start_time = datetime.utcnow()
        success = False
        error_message = None
        packed = b""

        try:
            # Validate context exists
            result = await db.execute(
                select(Context).where(Context.name == context_name)
            )
            context = result.scalar_one_or_none()
            if not context:
                raise ContextNotFoundError(f"Unknown context: {context_name}")

            # Validate identity has access to context
            if context_name not in identity.allowed_contexts:
                raise AuthorizationError(
                    f"Identity not authorized for context: {context_name}"
                )

            # Evaluate policies
            if enforce_policies:
                await self._evaluate_policies(
                    db=db,
                    context=context,
                    identity=identity,
                    operation="encrypt",
                    ip_address=ip_address,
                    user_agent=user_agent,
                )

            # Get key for context
            key, key_id = await key_manager.get_or_create_key(db, context_name)

            # Encrypt with AES-256-GCM
            nonce = os.urandom(12)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)

            # Pack into self-describing format
            packed = self._pack_ciphertext(
                ciphertext=ciphertext,
                nonce=nonce,
                key_id=key_id,
                context=context_name,
                algorithm=context.algorithm,
            )

            success = True
            return packed

        except PolicyViolation as e:
            error_message = str(e)
            raise PolicyError(e.policy_name, e.args[0])

        except Exception as e:
            error_message = str(e)
            raise

        finally:
            # Log to audit
            latency_ms = int(
                (datetime.utcnow() - start_time).total_seconds() * 1000
            )
            audit = AuditLog(
                operation="encrypt",
                context=context_name,
                success=success,
                error_message=error_message,
                identity_id=identity.id,
                identity_name=identity.name,
                team=identity.team,
                input_size_bytes=len(plaintext),
                output_size_bytes=len(packed) if success else None,
                latency_ms=latency_ms,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            db.add(audit)
            await db.commit()

    async def decrypt(
        self,
        db: AsyncSession,
        packed_ciphertext: bytes,
        context_name: str,
        identity: Identity,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> bytes:
        """Decrypt self-describing ciphertext."""
        start_time = datetime.utcnow()
        success = False
        error_message = None
        plaintext = b""

        try:
            # Validate identity has access to context
            if context_name not in identity.allowed_contexts:
                raise AuthorizationError(
                    f"Identity not authorized for context: {context_name}"
                )

            # Unpack ciphertext
            header, ciphertext = self._unpack_ciphertext(packed_ciphertext)

            # Validate context matches
            if header["ctx"] != context_name:
                raise DecryptionError(
                    f"Context mismatch: expected {context_name}, got {header['ctx']}"
                )

            # Get key
            key = await key_manager.get_key_by_id(db, header["kid"])
            if not key:
                raise DecryptionError(f"Key not found: {header['kid']}")

            # Decrypt
            nonce = base64.b64decode(header["nonce"])
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)

            success = True
            return plaintext

        except Exception as e:
            error_message = str(e)
            raise

        finally:
            # Log to audit
            latency_ms = int(
                (datetime.utcnow() - start_time).total_seconds() * 1000
            )
            audit = AuditLog(
                operation="decrypt",
                context=context_name,
                success=success,
                error_message=error_message,
                identity_id=identity.id,
                identity_name=identity.name,
                team=identity.team,
                input_size_bytes=len(packed_ciphertext),
                output_size_bytes=len(plaintext) if success else None,
                latency_ms=latency_ms,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            db.add(audit)
            await db.commit()

    def _pack_ciphertext(
        self,
        ciphertext: bytes,
        nonce: bytes,
        key_id: str,
        context: str,
        algorithm: str,
    ) -> bytes:
        """Pack ciphertext with header for self-describing format."""
        header = {
            "v": self.HEADER_VERSION,
            "ctx": context,
            "kid": key_id,
            "alg": algorithm,
            "nonce": base64.b64encode(nonce).decode("ascii"),
        }
        header_json = json.dumps(header, separators=(",", ":")).encode()
        header_len = len(header_json).to_bytes(2, "big")

        return header_len + header_json + ciphertext

    def _unpack_ciphertext(self, packed: bytes) -> tuple[dict, bytes]:
        """Unpack self-describing ciphertext."""
        if len(packed) < 3:
            raise DecryptionError("Invalid ciphertext: too short")

        header_len = int.from_bytes(packed[:2], "big")

        if len(packed) < 2 + header_len:
            raise DecryptionError("Invalid ciphertext: header truncated")

        header_json = packed[2:2 + header_len]
        ciphertext = packed[2 + header_len:]

        try:
            header = json.loads(header_json.decode())
        except json.JSONDecodeError as e:
            raise DecryptionError(f"Invalid ciphertext header: {e}")

        if header.get("v") != self.HEADER_VERSION:
            raise DecryptionError(
                f"Unsupported ciphertext version: {header.get('v')}"
            )

        return header, ciphertext

    async def _evaluate_policies(
        self,
        db: AsyncSession,
        context: Context,
        identity: Identity,
        operation: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        """Evaluate policies for a crypto operation.

        This is where the magic happens: policies are automatically evaluated
        based on the context configuration. Developers don't need to know the
        details - the system handles enforcement intelligently.

        Args:
            db: Database session
            context: The encryption context
            identity: The calling identity
            operation: "encrypt" or "decrypt"
            ip_address: Request IP for logging
            user_agent: Request user agent for logging

        Raises:
            PolicyViolation: If a blocking policy is violated
        """
        # Build evaluation context from the 5-layer context model
        # This maps context configuration → policy evaluation automatically
        eval_context = build_evaluation_context(
            context_config=context.config,  # 5-layer configuration
            context_derived=context.derived,  # Derived requirements (algorithm, etc.)
            context_name=context.name,
            identity_data={
                "id": identity.id,
                "name": identity.name,
                "team": identity.team,
                "type": identity.type.value if identity.type else None,
                "environment": identity.environment,
            },
            operation=operation,
        )

        # Evaluate all applicable policies
        # The policy engine knows which policies apply based on context and operation
        results = policy_engine.evaluate(eval_context, raise_on_block=True)

        # Log any violations (warn or info level)
        for result in results:
            if not result.passed:
                # Log the violation for audit trail
                violation = PolicyViolationLog(
                    policy_name=result.policy_name,
                    severity=result.severity.value,
                    message=result.message,
                    blocked=(result.severity == PolicySeverity.BLOCK),
                    context_name=context.name,
                    operation=operation,
                    identity_id=str(identity.id) if identity.id else None,
                    identity_name=identity.name,
                    team=identity.team,
                    rule=result.details.get("rule", ""),
                    evaluation_context={
                        "algorithm": eval_context.algorithm,
                        "context": eval_context.context,
                        "identity": eval_context.identity,
                    },
                    ip_address=ip_address,
                    user_agent=user_agent,
                )
                db.add(violation)

        # Commit any logged violations
        if any(not r.passed for r in results):
            await db.commit()


# Singleton instance
crypto_engine = CryptoEngine()
