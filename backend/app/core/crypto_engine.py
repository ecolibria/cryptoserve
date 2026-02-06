"""Cryptographic operations engine.

Handles encryption and decryption with policy enforcement and multi-mode support.

Phase 1 enhancements:
- Multiple cipher mode support (GCM, CBC, CTR, CCM, XTS)
- Algorithm override capability
- Structured result with algorithm info
- Deprecation warnings
"""

import os
import json
import base64
import hmac
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305, AESCCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
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
from app.schemas.context import AlgorithmOverride, CipherMode, EncryptionUsageContext
from app.core.algorithm_resolver import ALGORITHMS
from app.core.secure_memory import secure_zero
from app.core.hybrid_crypto import (
    HybridCryptoEngine,
    HybridMode,
    HybridCiphertext,
    is_pqc_available,
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


class UnsupportedModeError(CryptoError):
    """Requested cipher mode is not supported."""

    pass


@dataclass
class EncryptResult:
    """Result of encryption operation with full metadata."""

    ciphertext: bytes
    algorithm: str
    mode: CipherMode
    key_bits: int
    key_id: str
    nonce: bytes
    context: str
    usage: EncryptionUsageContext | None = None
    description: str | None = None
    warnings: list[str] = field(default_factory=list)
    is_quantum_safe: bool = False


class CipherFactory:
    """Factory for creating cipher instances based on mode."""

    # Message size limits (in bytes)
    GCM_MAX_SIZE = 64 * 1024 * 1024 * 1024  # 64 GiB
    CCM_MAX_SIZE = 65536  # 64 KiB per CCM spec

    @staticmethod
    def get_key_size(algorithm: str) -> int:
        """Get key size in bytes for an algorithm."""
        props = ALGORITHMS.get(algorithm, {})
        key_bits = props.get("key_bits", 256)
        return key_bits // 8

    @staticmethod
    def derive_enc_mac_keys(master_key: bytes) -> tuple[bytes, bytes]:
        """Derive separate encryption and MAC keys from master key.

        This prevents related-key attacks when using the same key for
        both encryption and authentication in CBC/CTR modes.

        Args:
            master_key: The master key material

        Returns:
            Tuple of (encryption_key, mac_key)
        """
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes

        enc_key = HKDF(
            algorithm=hashes.SHA256(),
            length=len(master_key),
            salt=b"crypto-serve-v1",
            info=b"encryption",
        ).derive(master_key)

        mac_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # HMAC-SHA256 key
            salt=b"crypto-serve-v1",
            info=b"authentication",
        ).derive(master_key)

        return enc_key, mac_key

    @staticmethod
    def compute_key_commitment(key: bytes) -> bytes:
        """Compute key commitment for multi-key attack prevention.

        This binds the ciphertext to a specific key, preventing
        "invisible salamanders" style attacks on AES-GCM.

        Args:
            key: The encryption key

        Returns:
            32-byte commitment value
        """
        return hmac.new(key, b"key-commitment-v1", hashlib.sha256).digest()

    @staticmethod
    def encrypt_gcm(
        key: bytes,
        plaintext: bytes,
        nonce: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Encrypt using AES-GCM with optional AAD."""
        if len(plaintext) > CipherFactory.GCM_MAX_SIZE:
            raise CryptoError(
                f"Plaintext too large for GCM: {len(plaintext)} bytes " f"(max: {CipherFactory.GCM_MAX_SIZE})"
            )
        aesgcm = AESGCM(key)
        return aesgcm.encrypt(nonce, plaintext, associated_data)

    @staticmethod
    def decrypt_gcm(
        key: bytes,
        ciphertext: bytes,
        nonce: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Decrypt using AES-GCM with optional AAD."""
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)

    @staticmethod
    def encrypt_ccm(
        key: bytes,
        plaintext: bytes,
        nonce: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Encrypt using AES-CCM with optional AAD."""
        if len(plaintext) > CipherFactory.CCM_MAX_SIZE:
            raise CryptoError(
                f"Plaintext too large for CCM: {len(plaintext)} bytes " f"(max: {CipherFactory.CCM_MAX_SIZE})"
            )
        # CCM requires 7-13 byte nonce, we use 12
        aesccm = AESCCM(key, tag_length=16)
        return aesccm.encrypt(nonce[:12], plaintext, associated_data)

    @staticmethod
    def decrypt_ccm(
        key: bytes,
        ciphertext: bytes,
        nonce: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Decrypt using AES-CCM with optional AAD."""
        aesccm = AESCCM(key, tag_length=16)
        return aesccm.decrypt(nonce[:12], ciphertext, associated_data)

    @staticmethod
    def encrypt_cbc(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
        """Encrypt using AES-CBC with PKCS7 padding and HMAC.

        Uses separate derived keys for encryption and authentication
        to prevent related-key attacks.

        Returns: ciphertext + hmac (IV stored in header)
        """
        # Derive separate keys for encryption and MAC
        enc_key_bytes, mac_key_bytes = CipherFactory.derive_enc_mac_keys(key)
        enc_key = bytearray(enc_key_bytes)
        mac_key = bytearray(mac_key_bytes)
        try:
            # Pad plaintext to block size (PKCS7)
            block_size = 16
            padding_len = block_size - (len(plaintext) % block_size)
            padded = plaintext + bytes([padding_len] * padding_len)

            # Encrypt with derived encryption key
            cipher = Cipher(algorithms.AES(bytes(enc_key)), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded) + encryptor.finalize()

            # Authenticate with derived MAC key (Encrypt-then-MAC)
            mac = hmac.new(bytes(mac_key), iv + ciphertext, hashlib.sha256).digest()

            return ciphertext + mac
        finally:
            secure_zero(enc_key)
            secure_zero(mac_key)

    @staticmethod
    def decrypt_cbc(key: bytes, data: bytes, iv: bytes) -> bytes:
        """Decrypt AES-CBC with HMAC verification.

        Uses separate derived keys for decryption and authentication.
        """
        # Derive separate keys for encryption and MAC
        enc_key_bytes, mac_key_bytes = CipherFactory.derive_enc_mac_keys(key)
        enc_key = bytearray(enc_key_bytes)
        mac_key = bytearray(mac_key_bytes)
        try:
            # Split ciphertext and MAC
            ciphertext = data[:-32]
            mac = data[-32:]

            # Verify HMAC first (before any decryption)
            expected_mac = hmac.new(bytes(mac_key), iv + ciphertext, hashlib.sha256).digest()
            if not hmac.compare_digest(mac, expected_mac):
                raise DecryptionError("HMAC verification failed")

            # Decrypt with derived encryption key
            cipher = Cipher(algorithms.AES(bytes(enc_key)), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()

            # Remove PKCS7 padding with validation
            padding_len = padded[-1]
            if padding_len > 16 or padding_len == 0:
                raise DecryptionError("Invalid padding")
            # Verify all padding bytes are correct
            if padded[-padding_len:] != bytes([padding_len] * padding_len):
                raise DecryptionError("Invalid padding")
            return padded[:-padding_len]
        finally:
            secure_zero(enc_key)
            secure_zero(mac_key)

    @staticmethod
    def encrypt_ctr(key: bytes, plaintext: bytes, nonce: bytes) -> bytes:
        """Encrypt using AES-CTR with HMAC.

        Uses separate derived keys for encryption and authentication
        to prevent related-key attacks.

        Returns: ciphertext + hmac
        """
        # Derive separate keys for encryption and MAC
        enc_key_bytes, mac_key_bytes = CipherFactory.derive_enc_mac_keys(key)
        enc_key = bytearray(enc_key_bytes)
        mac_key = bytearray(mac_key_bytes)
        try:
            cipher = Cipher(
                algorithms.AES(bytes(enc_key)),
                modes.CTR(nonce + b"\x00" * 4),  # 12-byte nonce + 4-byte counter
                backend=default_backend(),
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()

            # Authenticate with derived MAC key (Encrypt-then-MAC)
            mac = hmac.new(bytes(mac_key), nonce + ciphertext, hashlib.sha256).digest()

            return ciphertext + mac
        finally:
            secure_zero(enc_key)
            secure_zero(mac_key)

    @staticmethod
    def decrypt_ctr(key: bytes, data: bytes, nonce: bytes) -> bytes:
        """Decrypt AES-CTR with HMAC verification.

        Uses separate derived keys for decryption and authentication.
        """
        # Derive separate keys for encryption and MAC
        enc_key_bytes, mac_key_bytes = CipherFactory.derive_enc_mac_keys(key)
        enc_key = bytearray(enc_key_bytes)
        mac_key = bytearray(mac_key_bytes)
        try:
            ciphertext = data[:-32]
            mac = data[-32:]

            # Verify HMAC first (before any decryption)
            expected_mac = hmac.new(bytes(mac_key), nonce + ciphertext, hashlib.sha256).digest()
            if not hmac.compare_digest(mac, expected_mac):
                raise DecryptionError("HMAC verification failed")

            cipher = Cipher(algorithms.AES(bytes(enc_key)), modes.CTR(nonce + b"\x00" * 4), backend=default_backend())
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
        finally:
            secure_zero(enc_key)
            secure_zero(mac_key)

    @staticmethod
    def encrypt_chacha20(
        key: bytes,
        plaintext: bytes,
        nonce: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Encrypt using ChaCha20-Poly1305 with optional AAD."""
        chacha = ChaCha20Poly1305(key)
        return chacha.encrypt(nonce[:12], plaintext, associated_data)

    @staticmethod
    def decrypt_chacha20(
        key: bytes,
        ciphertext: bytes,
        nonce: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Decrypt using ChaCha20-Poly1305 with optional AAD."""
        chacha = ChaCha20Poly1305(key)
        return chacha.decrypt(nonce[:12], ciphertext, associated_data)

    @staticmethod
    def encrypt_xts(key: bytes, plaintext: bytes, tweak: bytes) -> bytes:
        """Encrypt using AES-XTS with HMAC for integrity.

        XTS (IEEE 1619) is designed for sector-based encryption and doesn't provide
        authentication. We add HMAC for integrity verification.

        Args:
            key: 64-byte key (two 256-bit keys for XTS)
            plaintext: Data to encrypt (must be >= 16 bytes)
            tweak: 16-byte tweak value (like sector number)

        Returns:
            ciphertext + hmac (32 bytes)
        """
        if len(key) != 64:
            raise CryptoError("XTS requires 64-byte key (two 256-bit keys)")
        if len(tweak) != 16:
            raise CryptoError("XTS requires 16-byte tweak")
        if len(plaintext) < 16:
            raise CryptoError("XTS requires plaintext >= 16 bytes")

        # Derive MAC key and wrap in bytearray for secure zeroing
        mac_key_bytes = CipherFactory.derive_enc_mac_keys(key[:32])[1]
        mac_key = bytearray(mac_key_bytes)
        try:
            # XTS encryption using cryptography library
            # XTS mode uses the full 64-byte key internally (splits into two 256-bit keys)
            cipher = Cipher(
                algorithms.AES(key),
                modes.XTS(tweak),
                backend=default_backend(),
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()

            # Add HMAC for integrity (XTS doesn't provide authentication)
            mac = hmac.new(bytes(mac_key), tweak + ciphertext, hashlib.sha256).digest()

            return ciphertext + mac
        finally:
            secure_zero(mac_key)

    @staticmethod
    def decrypt_xts(key: bytes, data: bytes, tweak: bytes) -> bytes:
        """Decrypt AES-XTS with HMAC verification.

        Args:
            key: 64-byte key (two 256-bit keys)
            data: ciphertext + hmac
            tweak: 16-byte tweak value (must match encryption)

        Returns:
            Decrypted plaintext
        """
        if len(key) != 64:
            raise CryptoError("XTS requires 64-byte key (two 256-bit keys)")
        if len(tweak) != 16:
            raise CryptoError("XTS requires 16-byte tweak")
        if len(data) < 48:  # Minimum: 16-byte ciphertext + 32-byte HMAC
            raise CryptoError("XTS ciphertext too short")

        # Derive MAC key and wrap in bytearray for secure zeroing
        mac_key_bytes = CipherFactory.derive_enc_mac_keys(key[:32])[1]
        mac_key = bytearray(mac_key_bytes)
        try:
            ciphertext = data[:-32]
            mac = data[-32:]

            # Verify HMAC first
            expected_mac = hmac.new(bytes(mac_key), tweak + ciphertext, hashlib.sha256).digest()
            if not hmac.compare_digest(mac, expected_mac):
                raise DecryptionError("HMAC verification failed")

            # XTS decryption
            cipher = Cipher(
                algorithms.AES(key),
                modes.XTS(tweak),
                backend=default_backend(),
            )
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
        finally:
            secure_zero(mac_key)


class CryptoEngine:
    """Handles encryption and decryption operations with policy enforcement."""

    HEADER_VERSION = 3  # v3: Added key commitment and AAD support

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
        algorithm_override: AlgorithmOverride | None = None,
        associated_data: bytes | None = None,
        usage: EncryptionUsageContext | None = None,
    ) -> EncryptResult:
        """Encrypt data and return structured result with metadata.

        Args:
            db: Database session
            plaintext: Data to encrypt
            context_name: Encryption context
            identity: Calling identity
            ip_address: Request IP for audit
            user_agent: Request user agent for audit
            enforce_policies: If True, evaluate and enforce policies
            algorithm_override: Optional explicit algorithm selection
            associated_data: Optional additional authenticated data (AAD)
                for AEAD modes. This data is authenticated but not encrypted.
            usage: Runtime usage hint (at_rest, in_transit, streaming, etc.)
                Combines with context policy to select optimal encryption.
                If not provided, uses the context's default usage_context.

        Returns:
            EncryptResult with ciphertext and metadata

        Raises:
            ContextNotFoundError: If context doesn't exist
            AuthorizationError: If identity not authorized
            PolicyError: If a blocking policy is violated
            UnsupportedModeError: If requested mode is not supported
            CryptoError: If plaintext exceeds size limits
        """
        start_time = datetime.now(timezone.utc)
        success = False
        error_message = None
        packed = b""
        warnings: list[str] = []
        policy_violated = False
        effective_usage: EncryptionUsageContext | None = None

        try:
            # Validate context exists
            result = await db.execute(select(Context).where(Context.name == context_name))
            context = result.scalar_one_or_none()
            if not context:
                raise ContextNotFoundError(f"Unknown context: {context_name}")

            # Validate identity has access to context
            if context_name not in identity.allowed_contexts:
                raise AuthorizationError(f"Identity not authorized for context: {context_name}")

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

            # Determine algorithm, mode, and key size
            # Runtime usage hint overrides context's default usage_context
            algorithm, mode, key_bits, description, effective_usage = self._resolve_algorithm(
                context, algorithm_override, warnings, usage
            )

            # Enforce FIPS compliance if enabled
            from app.core.fips import enforce_fips_algorithm

            # Extract cipher name (e.g., "AES" from "AES-256-GCM")
            cipher = algorithm.split("-")[0] if "-" in algorithm else algorithm
            enforce_fips_algorithm(cipher, mode.value, key_bits)

            # Check algorithm policy enforcement
            # Note: This updates the outer-scoped policy_violated for audit logging
            if self._check_algorithm_policy(context, algorithm, mode, key_bits, warnings):
                policy_violated = True

            # Handle hybrid PQC mode separately
            if mode == CipherMode.HYBRID:
                packed, key_id, algorithm = await self._encrypt_hybrid(
                    db, plaintext, context_name, identity.tenant_id, algorithm, associated_data
                )
                # For hybrid, we don't have a nonce in the same sense - it's embedded
                nonce = b""  # Nonce is internal to the hybrid ciphertext

                success = True
                return EncryptResult(
                    ciphertext=packed,
                    algorithm=algorithm,
                    mode=mode,
                    key_bits=key_bits,
                    key_id=key_id,
                    nonce=nonce,
                    context=context_name,
                    usage=effective_usage,
                    description=description,
                    warnings=warnings,
                    is_quantum_safe=True,
                )

            # Classical encryption path
            # Get key for context
            key_size_bytes = key_bits // 8
            key_bytes, key_id = await key_manager.get_or_create_key(
                db, context_name, identity.tenant_id, key_size=key_size_bytes
            )

            # Convert to mutable bytearray for secure zeroing after use
            key = bytearray(key_bytes)
            try:
                # Generate nonce/IV (12 bytes for GCM/CCM/ChaCha20, 16 for CBC/CTR)
                nonce_size = 16 if mode in [CipherMode.CBC, CipherMode.CTR] else 12
                nonce = os.urandom(nonce_size)

                # Compute key commitment for multi-key attack prevention
                key_commitment = CipherFactory.compute_key_commitment(bytes(key))

                # Encrypt based on mode (with AAD support for AEAD modes)
                ciphertext = self._encrypt_with_mode(bytes(key), plaintext, nonce, mode, algorithm, associated_data)

                # Pack into self-describing format with key commitment
                packed = self._pack_ciphertext(
                    ciphertext=ciphertext,
                    nonce=nonce,
                    key_id=key_id,
                    context=context_name,
                    algorithm=algorithm,
                    mode=mode,
                    key_commitment=key_commitment,
                    has_aad=associated_data is not None,
                )

                success = True
                return EncryptResult(
                    ciphertext=packed,
                    algorithm=algorithm,
                    mode=mode,
                    key_bits=key_bits,
                    key_id=key_id,
                    nonce=nonce,
                    context=context_name,
                    usage=effective_usage,
                    description=description,
                    warnings=warnings,
                )
            finally:
                secure_zero(key)

        except PolicyViolation as e:
            error_message = str(e)
            raise PolicyError(e.policy_name, e.args[0])

        except Exception as e:
            error_message = str(e)
            raise

        finally:
            # Log to audit
            latency_ms = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)

            # Extract algorithm details for metrics (if available)
            audit_algorithm = None
            audit_cipher = None
            audit_mode = None
            audit_key_bits = None
            audit_key_id = None
            audit_quantum_safe = False

            if success:
                # Get values from local variables set during encryption
                audit_algorithm = algorithm  # e.g., "AES-256-GCM"
                audit_mode = mode.value if hasattr(mode, "value") else str(mode)
                audit_key_bits = key_bits
                audit_key_id = key_id

                # Extract cipher from algorithm name (e.g., "AES" from "AES-256-GCM")
                if "ChaCha20" in algorithm:
                    audit_cipher = "ChaCha20"
                elif "AES" in algorithm:
                    audit_cipher = "AES"
                elif "ML-KEM" in algorithm or "Kyber" in algorithm:
                    audit_cipher = "ML-KEM"
                else:
                    audit_cipher = algorithm.split("-")[0] if "-" in algorithm else algorithm

                # Check if quantum-safe algorithm
                audit_quantum_safe = any(pqc in algorithm for pqc in ["ML-KEM", "Kyber", "Dilithium", "SPHINCS"])

            audit = AuditLog(
                tenant_id=identity.tenant_id,
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
                # Algorithm tracking fields (for metrics and compliance)
                algorithm=audit_algorithm,
                cipher=audit_cipher,
                mode=audit_mode,
                key_bits=audit_key_bits,
                key_id=audit_key_id,
                quantum_safe=audit_quantum_safe,
                policy_violation=policy_violated,
                # Runtime usage tracking (how devs actually use contexts)
                usage=effective_usage.value if effective_usage else None,
            )
            db.add(audit)
            await db.commit()

    def _resolve_algorithm(
        self,
        context: Context,
        override: AlgorithmOverride | None,
        warnings: list[str],
        runtime_usage: EncryptionUsageContext | None = None,
    ) -> tuple[str, CipherMode, int, str | None, EncryptionUsageContext | None]:
        """Resolve algorithm, mode, and key size from context, override, and runtime usage.

        The runtime_usage parameter allows developers to specify how the data is being
        used (at_rest, in_transit, streaming, etc.) without creating multiple contexts
        for the same data type.

        Algorithm selection priority:
        1. If algorithm_override is provided, use it directly
        2. Otherwise, combine context policy + runtime_usage to select optimal algorithm

        Returns:
            Tuple of (algorithm_name, mode, key_bits, description, effective_usage)
        """
        # Determine effective usage: runtime hint takes precedence over context default
        effective_usage = runtime_usage
        if effective_usage is None:
            # Fall back to context's configured usage_context
            config = context.config or {}
            data_identity = config.get("data_identity", {})
            usage_str = data_identity.get("usage_context")
            if usage_str:
                try:
                    effective_usage = EncryptionUsageContext(usage_str)
                except ValueError:
                    effective_usage = EncryptionUsageContext.AT_REST
            else:
                effective_usage = EncryptionUsageContext.AT_REST

        # If override provided, use it (but still return effective_usage)
        if override and override.cipher:
            algorithm = override.to_algorithm_name() or "AES-256-GCM"
            mode = override.mode or CipherMode.GCM
            key_bits = override.key_bits or 256

            # Check if algorithm exists in registry
            props = ALGORITHMS.get(algorithm)
            if not props:
                # Try to find closest match
                for name, p in ALGORITHMS.items():
                    if override.cipher.upper() in name:
                        algorithm = name
                        props = p
                        break

            if props:
                if props.get("legacy"):
                    warnings.append(
                        f"Algorithm {algorithm} is legacy. Consider using {props.get('replacement', 'AES-256-GCM')}"
                    )
                return algorithm, mode, key_bits, props.get("description"), effective_usage

            # Unknown algorithm - default to AES-GCM with specified key size
            return f"AES-{key_bits}-GCM", mode, key_bits, None, effective_usage

        # Import here to use the enhanced resolver
        from app.core.algorithm_resolver import (
            USAGE_CONTEXT_ALGORITHM_MAP,
            USAGE_CONTEXT_MODE_MAP,
        )

        # Use context's derived algorithm as base
        derived = context.derived or {}
        config = context.config or {}

        # Check if we should use runtime usage to influence algorithm selection
        # This is the key innovation: context defines WHAT, runtime defines HOW
        if effective_usage and effective_usage != EncryptionUsageContext.AT_REST:
            # Use usage-specific algorithm if different from default
            usage_algorithm = USAGE_CONTEXT_ALGORITHM_MAP.get(effective_usage)
            usage_mode = USAGE_CONTEXT_MODE_MAP.get(effective_usage)

            if usage_algorithm:
                # Check if context requires quantum resistance
                threat_model = config.get("threat_model", {})
                quantum_required = derived.get("quantum_resistant", False) or threat_model.get(
                    "quantum_resistant_required", False
                )

                if quantum_required:
                    # Use quantum-safe variant if available
                    if "ChaCha20" in usage_algorithm:
                        algorithm = "ChaCha20-Poly1305+ML-KEM-768"
                    else:
                        algorithm = "AES-256-GCM+ML-KEM-768"
                    mode = CipherMode.HYBRID
                else:
                    algorithm = usage_algorithm
                    mode = usage_mode or CipherMode.GCM

                # Respect minimum key bits from context policy
                key_bits = max(derived.get("resolved_key_bits") or 256, 256)
                props = ALGORITHMS.get(algorithm, {})

                warnings.append(f"Algorithm selected based on runtime usage: {effective_usage.value}")
                return algorithm, mode, key_bits, props.get("description"), effective_usage

        # Default path: use context's derived algorithm
        algorithm = derived.get("resolved_algorithm") or context.algorithm or "AES-256-GCM"
        mode_str = derived.get("resolved_mode")

        # Parse mode from algorithm name or derived
        if mode_str:
            try:
                mode = CipherMode(mode_str)
            except ValueError:
                mode = CipherMode.GCM
        elif "ML-KEM" in algorithm or ("+ML-KEM" in algorithm):
            # Hybrid post-quantum algorithm
            mode = CipherMode.HYBRID
        elif "GCM-SIV" in algorithm:
            mode = CipherMode.GCM_SIV
        elif "GCM" in algorithm and "ML-KEM" not in algorithm:
            mode = CipherMode.GCM
        elif "CBC" in algorithm:
            mode = CipherMode.CBC
        elif "CTR" in algorithm:
            mode = CipherMode.CTR
        elif "CCM" in algorithm:
            mode = CipherMode.CCM
        elif "XTS" in algorithm:
            mode = CipherMode.XTS
        elif "ChaCha20" in algorithm and "ML-KEM" not in algorithm:
            mode = CipherMode.GCM  # ChaCha20-Poly1305 is similar to GCM
        else:
            mode = CipherMode.GCM

        key_bits = derived.get("resolved_key_bits") or 256
        props = ALGORITHMS.get(algorithm, {})

        return algorithm, mode, key_bits, props.get("description"), effective_usage

    def _check_algorithm_policy(
        self,
        context: Context,
        algorithm: str,
        mode: CipherMode,
        key_bits: int,
        warnings: list[str],
    ) -> bool:
        """Check if the resolved algorithm violates the context's policy.

        Args:
            context: The encryption context with policy settings
            algorithm: Resolved algorithm name (e.g., "AES-256-GCM")
            mode: Resolved cipher mode
            key_bits: Resolved key size in bits
            warnings: List to append warnings to

        Returns:
            True if policy was violated (for audit logging)

        Raises:
            CryptoError: If policy_enforcement is "enforce" and policy is violated
        """
        # No policy defined - allow everything
        if not context.algorithm_policy:
            return False

        policy = context.algorithm_policy
        enforcement = context.policy_enforcement or "none"
        violations = []

        # Check allowed ciphers
        allowed_ciphers = policy.get("allowed_ciphers", [])
        if allowed_ciphers:
            cipher_allowed = False
            for allowed in allowed_ciphers:
                if allowed.upper() in algorithm.upper():
                    cipher_allowed = True
                    break
            if not cipher_allowed:
                violations.append(f"Cipher not in allowed list: {allowed_ciphers}")

        # Check allowed modes
        allowed_modes = policy.get("allowed_modes", [])
        if allowed_modes:
            mode_str = mode.value if hasattr(mode, "value") else str(mode)
            if mode_str.lower() not in [m.lower() for m in allowed_modes]:
                violations.append(f"Mode '{mode_str}' not in allowed list: {allowed_modes}")

        # Check minimum key bits
        min_key_bits = policy.get("min_key_bits", 0)
        if min_key_bits and key_bits < min_key_bits:
            violations.append(f"Key size {key_bits} bits below minimum {min_key_bits}")

        # Check quantum-safe requirement
        require_quantum = policy.get("require_quantum_safe", False)
        if require_quantum:
            is_quantum_safe = any(pqc in algorithm for pqc in ["ML-KEM", "Kyber", "Dilithium", "SPHINCS"])
            if not is_quantum_safe:
                violations.append("Algorithm is not quantum-safe (required by policy)")

        if not violations:
            return False

        # Handle based on enforcement level
        violation_msg = "; ".join(violations)

        if enforcement == "enforce":
            raise CryptoError(f"Algorithm policy violation: {violation_msg}")
        elif enforcement == "warn":
            warnings.append(f"Algorithm policy warning: {violation_msg}")
            return True
        else:
            # enforcement == "none" - no action
            return False

    def _get_key_size_from_algorithm(self, algorithm: str) -> int:
        """Extract key size in bytes from algorithm name.

        Args:
            algorithm: Algorithm name like "AES-256-GCM" or "ChaCha20-Poly1305"

        Returns:
            Key size in bytes (16, 24, 32, or 64 for XTS)
        """
        # Check algorithm registry first
        props = ALGORITHMS.get(algorithm)
        if props:
            return props.get("key_bits", 256) // 8

        # Parse from algorithm name (e.g., "AES-128-GCM" -> 128 -> 16 bytes)
        if "128" in algorithm:
            return 16
        elif "192" in algorithm:
            return 24
        elif "XTS" in algorithm:
            return 64  # XTS uses two 256-bit keys
        elif "512" in algorithm:
            return 64
        else:
            return 32  # Default to 256-bit (32 bytes)

    def _encrypt_with_mode(
        self,
        key: bytes,
        plaintext: bytes,
        nonce: bytes,
        mode: CipherMode,
        algorithm: str,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Encrypt plaintext using the specified mode.

        Args:
            key: Encryption key (must be correct size for algorithm)
            plaintext: Data to encrypt
            nonce: Nonce/IV
            mode: Cipher mode
            algorithm: Algorithm name
            associated_data: Optional AAD for AEAD modes

        Returns:
            Ciphertext (includes auth tag for AEAD modes)
        """
        # Key size is validated at derivation - no padding needed
        # The key_size is passed to key_manager which derives correct size

        if "ChaCha20" in algorithm:
            return CipherFactory.encrypt_chacha20(key, plaintext, nonce, associated_data)

        if mode == CipherMode.GCM or mode == CipherMode.GCM_SIV:
            # GCM-SIV would use a different library, fallback to GCM for now
            return CipherFactory.encrypt_gcm(key, plaintext, nonce, associated_data)
        elif mode == CipherMode.CBC:
            # CBC doesn't support AAD natively - it uses separate HMAC
            if associated_data:
                raise UnsupportedModeError("CBC mode does not support AAD. Use GCM or ChaCha20-Poly1305 for AAD.")
            return CipherFactory.encrypt_cbc(key, plaintext, nonce)
        elif mode == CipherMode.CTR:
            # CTR doesn't support AAD natively - it uses separate HMAC
            if associated_data:
                raise UnsupportedModeError("CTR mode does not support AAD. Use GCM or ChaCha20-Poly1305 for AAD.")
            return CipherFactory.encrypt_ctr(key, plaintext, nonce)
        elif mode == CipherMode.CCM:
            return CipherFactory.encrypt_ccm(key, plaintext, nonce, associated_data)
        elif mode == CipherMode.XTS:
            # XTS (IEEE 1619) for disk/storage encryption
            # We add HMAC for integrity since XTS doesn't provide authentication
            # XTS requires 16-byte tweak (we use/pad nonce as tweak)
            if len(nonce) != 16:
                tweak = nonce[:16] if len(nonce) > 16 else nonce + b"\x00" * (16 - len(nonce))
            else:
                tweak = nonce
            return CipherFactory.encrypt_xts(key, plaintext, tweak)
        elif mode == CipherMode.HYBRID:
            # Hybrid PQC mode - handled separately in encrypt()
            # This should not be called directly since hybrid uses different key management
            raise UnsupportedModeError(
                "HYBRID mode must be handled via _encrypt_hybrid(). " "This is an internal error."
            )
        else:
            return CipherFactory.encrypt_gcm(key, plaintext, nonce, associated_data)

    def _decrypt_with_mode(
        self,
        key: bytes,
        ciphertext: bytes,
        nonce: bytes,
        mode: CipherMode,
        algorithm: str,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Decrypt ciphertext using the specified mode.

        Args:
            key: Decryption key (must be correct size for algorithm)
            ciphertext: Data to decrypt
            nonce: Nonce/IV
            mode: Cipher mode
            algorithm: Algorithm name
            associated_data: Optional AAD for AEAD modes (must match encryption)

        Returns:
            Decrypted plaintext
        """
        if "ChaCha20" in algorithm:
            return CipherFactory.decrypt_chacha20(key, ciphertext, nonce, associated_data)

        if mode == CipherMode.GCM or mode == CipherMode.GCM_SIV:
            return CipherFactory.decrypt_gcm(key, ciphertext, nonce, associated_data)
        elif mode == CipherMode.CBC:
            return CipherFactory.decrypt_cbc(key, ciphertext, nonce)
        elif mode == CipherMode.CTR:
            return CipherFactory.decrypt_ctr(key, ciphertext, nonce)
        elif mode == CipherMode.CCM:
            return CipherFactory.decrypt_ccm(key, ciphertext, nonce, associated_data)
        elif mode == CipherMode.XTS:
            # XTS (IEEE 1619) for disk/storage encryption
            # XTS requires 16-byte tweak (we use/pad nonce as tweak)
            if len(nonce) != 16:
                tweak = nonce[:16] if len(nonce) > 16 else nonce + b"\x00" * (16 - len(nonce))
            else:
                tweak = nonce
            return CipherFactory.decrypt_xts(key, ciphertext, tweak)
        elif mode == CipherMode.HYBRID:
            # Hybrid PQC mode - handled separately
            raise UnsupportedModeError(
                "HYBRID mode must be handled via _decrypt_hybrid(). " "This is an internal error."
            )
        else:
            return CipherFactory.decrypt_gcm(key, ciphertext, nonce, associated_data)

    def _is_hybrid_ciphertext(self, data: bytes) -> bool:
        """Check if the data is a hybrid PQC ciphertext.

        Both classical and hybrid ciphertexts use 2-byte length prefix + JSON header.
        The key difference is:
        - Hybrid has "kem_ct_len" field and mode contains ML-KEM
        - Classical has "ctx" and "alg" fields
        """
        if len(data) < 10:
            return False

        try:
            # Both formats use 2-byte header length prefix
            header_len = int.from_bytes(data[:2], "big")
            if len(data) < 2 + header_len:
                return False

            header_json = data[2 : 2 + header_len].decode("utf-8")
            header = json.loads(header_json)

            # Hybrid ciphertexts have "kem_ct_len" field
            if "kem_ct_len" in header:
                return True

            # Also check if mode contains ML-KEM
            mode = header.get("mode", "")
            if "ML-KEM" in mode or "+ML-KEM" in mode:
                return True

            return False
        except Exception:
            return False

    def _get_hybrid_mode(self, algorithm: str) -> HybridMode:
        """Get the hybrid mode from algorithm string."""
        if "ML-KEM-1024" in algorithm:
            return HybridMode.AES_MLKEM_1024
        elif "ChaCha20" in algorithm:
            return HybridMode.CHACHA_MLKEM_768
        else:
            return HybridMode.AES_MLKEM_768

    async def _encrypt_hybrid(
        self,
        db: AsyncSession,
        plaintext: bytes,
        context_name: str,
        tenant_id: str,
        algorithm: str,
        associated_data: bytes | None = None,
    ) -> tuple[bytes, str, str]:
        """Encrypt using hybrid PQC mode (ML-KEM + classical AEAD).

        This method generates a per-operation ML-KEM key pair, encrypts
        the data, and stores the private key for later decryption.

        Args:
            db: Database session
            plaintext: Data to encrypt
            context_name: Encryption context name
            tenant_id: Tenant ID for isolation
            algorithm: Hybrid algorithm (e.g., "AES-256-GCM+ML-KEM-768")
            associated_data: Optional AAD

        Returns:
            Tuple of (ciphertext, key_id, algorithm)
        """
        if not is_pqc_available():
            raise CryptoError(
                "Post-quantum cryptography not available. " "Install liboqs-python: pip install liboqs-python"
            )

        hybrid_mode = self._get_hybrid_mode(algorithm)
        engine = HybridCryptoEngine(hybrid_mode)

        # Generate a new key pair for this encryption
        keypair = engine.generate_keypair()

        # Encrypt using the public key
        hybrid_ct = engine.encrypt(
            plaintext,
            keypair.public_key,
            keypair.key_id,
            associated_data,
        )

        # Store the private key for later decryption
        # We use the key_manager to store PQC keys
        await key_manager.store_pqc_key(
            db,
            context_name,
            tenant_id,
            keypair.key_id,
            keypair.private_key,
            keypair.public_key,
            hybrid_mode.value,
        )

        return hybrid_ct.serialize(), keypair.key_id, algorithm

    async def _decrypt_hybrid(
        self,
        db: AsyncSession,
        ciphertext: bytes,
        context_name: str,
        key_id: str,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Decrypt hybrid PQC ciphertext.

        Args:
            db: Database session
            ciphertext: Serialized hybrid ciphertext
            context_name: Encryption context name
            key_id: Key identifier
            associated_data: Optional AAD (must match encryption)

        Returns:
            Decrypted plaintext
        """
        if not is_pqc_available():
            raise CryptoError(
                "Post-quantum cryptography not available. " "Install liboqs-python: pip install liboqs-python"
            )

        # Retrieve the private key
        private_key = await key_manager.get_pqc_key(db, context_name, key_id)
        if not private_key:
            raise DecryptionError(f"PQC key not found: {key_id}")

        # Deserialize and decrypt
        hybrid_ct = HybridCiphertext.deserialize(ciphertext)
        engine = HybridCryptoEngine(hybrid_ct.mode)

        try:
            return engine.decrypt(hybrid_ct, private_key, associated_data)
        except Exception as e:
            raise DecryptionError(f"Hybrid decryption failed: {e}")

    async def decrypt(
        self,
        db: AsyncSession,
        packed_ciphertext: bytes,
        context_name: str,
        identity: Identity,
        ip_address: str | None = None,
        user_agent: str | None = None,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Decrypt self-describing ciphertext.

        Args:
            db: Database session
            packed_ciphertext: Self-describing ciphertext from encrypt()
            context_name: Expected context name
            identity: Calling identity
            ip_address: Request IP for audit
            user_agent: Request user agent for audit
            associated_data: Optional AAD (must match what was used during encryption)

        Returns:
            Decrypted plaintext

        Raises:
            AuthorizationError: If identity not authorized
            DecryptionError: If decryption fails or key commitment mismatch
        """
        start_time = datetime.now(timezone.utc)
        success = False
        error_message = None
        plaintext = b""
        header = None

        try:
            # Validate identity has access to context
            if context_name not in identity.allowed_contexts:
                raise AuthorizationError(f"Identity not authorized for context: {context_name}")

            # Check if this is a hybrid ciphertext (starts with JSON object)
            if self._is_hybrid_ciphertext(packed_ciphertext):
                # Deserialize to get the key_id
                hybrid_ct = HybridCiphertext.deserialize(packed_ciphertext)
                plaintext = await self._decrypt_hybrid(
                    db, packed_ciphertext, context_name, hybrid_ct.key_id, associated_data
                )
                success = True
                return plaintext

            # Unpack classical ciphertext
            header, ciphertext = self._unpack_ciphertext(packed_ciphertext)

            # Validate context matches
            if header["ctx"] != context_name:
                raise DecryptionError(f"Context mismatch: expected {context_name}, got {header['ctx']}")

            # Check if AAD was used during encryption
            if header.get("aad") and not associated_data:
                raise DecryptionError("Ciphertext was encrypted with AAD but no AAD provided for decryption")

            # Extract key size from algorithm (e.g., "AES-256-GCM" -> 32 bytes)
            algorithm = header.get("alg", "AES-256-GCM")
            key_size_bytes = self._get_key_size_from_algorithm(algorithm)

            # Get key with correct size
            key_bytes = await key_manager.get_key_by_id(db, header["kid"], key_size=key_size_bytes)
            if not key_bytes:
                raise DecryptionError(f"Key not found: {header['kid']}")

            # Convert to mutable bytearray for secure zeroing after use
            key = bytearray(key_bytes)
            try:
                # Verify key commitment if present (prevents multi-key attacks)
                if "kc" in header:
                    expected_commitment = CipherFactory.compute_key_commitment(bytes(key))
                    stored_commitment = base64.b64decode(header["kc"])
                    if not hmac.compare_digest(expected_commitment, stored_commitment):
                        raise DecryptionError("Key commitment verification failed - possible key mismatch")

                # Get mode from header
                mode_str = header.get("mode", "gcm")
                try:
                    mode = CipherMode(mode_str)
                except ValueError:
                    mode = CipherMode.GCM

                # Decrypt with AAD if applicable
                nonce = base64.b64decode(header["nonce"])
                plaintext = self._decrypt_with_mode(bytes(key), ciphertext, nonce, mode, algorithm, associated_data)

                success = True
                return plaintext
            finally:
                secure_zero(key)

        except Exception as e:
            error_message = str(e)
            raise

        finally:
            # Log to audit
            latency_ms = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)

            # Extract algorithm details for metrics (if available from header)
            audit_algorithm = None
            audit_cipher = None
            audit_mode = None
            audit_key_bits = None
            audit_key_id = None
            audit_quantum_safe = False

            # Try to extract from header (set during unpack if we got that far)
            try:
                if "header" in dir() and header:
                    audit_algorithm = header.get("alg")
                    audit_mode = header.get("mode")
                    audit_key_id = header.get("kid")

                    if audit_algorithm:
                        # Extract cipher from algorithm name
                        if "ChaCha20" in audit_algorithm:
                            audit_cipher = "ChaCha20"
                        elif "AES" in audit_algorithm:
                            audit_cipher = "AES"
                        elif "ML-KEM" in audit_algorithm or "Kyber" in audit_algorithm:
                            audit_cipher = "ML-KEM"
                        else:
                            audit_cipher = audit_algorithm.split("-")[0] if "-" in audit_algorithm else audit_algorithm

                        # Extract key bits from algorithm name
                        if "128" in audit_algorithm:
                            audit_key_bits = 128
                        elif "192" in audit_algorithm:
                            audit_key_bits = 192
                        elif "256" in audit_algorithm:
                            audit_key_bits = 256

                        # Check if quantum-safe algorithm
                        audit_quantum_safe = any(
                            pqc in audit_algorithm for pqc in ["ML-KEM", "Kyber", "Dilithium", "SPHINCS"]
                        )
            except Exception:
                pass  # If we can't extract header info, use None values

            audit = AuditLog(
                tenant_id=identity.tenant_id,
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
                # Algorithm tracking fields (for metrics and compliance)
                algorithm=audit_algorithm,
                cipher=audit_cipher,
                mode=audit_mode,
                key_bits=audit_key_bits,
                key_id=audit_key_id,
                quantum_safe=audit_quantum_safe,
                policy_violation=False,
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
        mode: CipherMode,
        key_commitment: bytes | None = None,
        has_aad: bool = False,
    ) -> bytes:
        """Pack ciphertext with header for self-describing format.

        Args:
            ciphertext: The encrypted data
            nonce: Nonce/IV used for encryption
            key_id: Key identifier
            context: Context name
            algorithm: Algorithm name (e.g., "AES-256-GCM")
            mode: Cipher mode
            key_commitment: Optional key commitment value for multi-key attack prevention
            has_aad: Whether AAD was used (caller must provide same AAD for decryption)

        Returns:
            Packed ciphertext with self-describing header
        """
        header = {
            "v": self.HEADER_VERSION,
            "ctx": context,
            "kid": key_id,
            "alg": algorithm,
            "mode": mode.value,
            "nonce": base64.b64encode(nonce).decode("ascii"),
        }

        # Add key commitment if provided (v3+ feature)
        if key_commitment:
            header["kc"] = base64.b64encode(key_commitment).decode("ascii")

        # Flag if AAD was used (caller must provide same AAD for decryption)
        if has_aad:
            header["aad"] = True

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

        header_json = packed[2 : 2 + header_len]
        ciphertext = packed[2 + header_len :]

        try:
            header = json.loads(header_json.decode())
        except json.JSONDecodeError as e:
            raise DecryptionError(f"Invalid ciphertext header: {e}")

        # Support v1, v2, and v3 headers for backward compatibility
        if header.get("v") not in [1, 2, 3]:
            raise DecryptionError(f"Unsupported ciphertext version: {header.get('v')}")

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
        """Evaluate policies for a crypto operation."""
        # Build evaluation context from the 5-layer context model
        eval_context = build_evaluation_context(
            context_config=context.config,
            context_derived=context.derived,
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
        results = policy_engine.evaluate(eval_context, raise_on_block=True)

        # Log any violations (warn or info level)
        for result in results:
            if not result.passed:
                violation = PolicyViolationLog(
                    tenant_id=identity.tenant_id,
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

        if any(not r.passed for r in results):
            await db.commit()


# Singleton instance
crypto_engine = CryptoEngine()
