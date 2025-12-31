"""Cryptographic Hash and MAC Engine.

Provides hash functions and message authentication codes:
- SHA-2: SHA-256, SHA-384, SHA-512, SHA-512/256
- SHA-3: SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256
- BLAKE2: BLAKE2b, BLAKE2s
- BLAKE3: Fast, parallel, secure
- HMAC: HMAC-SHA256, HMAC-SHA384, HMAC-SHA512, HMAC-SHA3
- KMAC: KMAC128, KMAC256 (NIST SP 800-185)
"""

import base64
import hashlib
import hmac as std_hmac
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import BinaryIO

from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac

# KMAC support (from pycryptodome)
try:
    from Crypto.Hash import KMAC128, KMAC256
    KMAC_AVAILABLE = True
except ImportError:
    KMAC_AVAILABLE = False

# BLAKE3 support (optional)
try:
    import blake3
    BLAKE3_AVAILABLE = True
except ImportError:
    BLAKE3_AVAILABLE = False


class HashAlgorithm(str, Enum):
    """Supported hash algorithms."""
    # SHA-2 family
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"
    SHA512_256 = "sha512-256"

    # SHA-3 family
    SHA3_256 = "sha3-256"
    SHA3_384 = "sha3-384"
    SHA3_512 = "sha3-512"
    SHAKE128 = "shake128"
    SHAKE256 = "shake256"

    # BLAKE family
    BLAKE2B = "blake2b"
    BLAKE2S = "blake2s"
    BLAKE3 = "blake3"


class MACAlgorithm(str, Enum):
    """Supported MAC algorithms."""
    # HMAC family
    HMAC_SHA256 = "hmac-sha256"
    HMAC_SHA384 = "hmac-sha384"
    HMAC_SHA512 = "hmac-sha512"
    HMAC_SHA3_256 = "hmac-sha3-256"
    HMAC_BLAKE2B = "hmac-blake2b"

    # KMAC family (NIST SP 800-185)
    KMAC128 = "kmac128"  # Based on cSHAKE128
    KMAC256 = "kmac256"  # Based on cSHAKE256


@dataclass
class HashResult:
    """Result of a hash operation."""
    digest: bytes
    algorithm: HashAlgorithm
    length: int  # bits
    hex: str
    base64: str


@dataclass
class MACResult:
    """Result of a MAC operation."""
    tag: bytes
    algorithm: MACAlgorithm
    length: int  # bits
    hex: str
    base64: str


class HashError(Exception):
    """Hash operation failed."""
    pass


class MACError(Exception):
    """MAC operation failed."""
    pass


class UnsupportedAlgorithmError(Exception):
    """Algorithm not supported."""
    pass


class HashEngine:
    """Handles cryptographic hash operations."""

    # Algorithm metadata
    ALGORITHMS = {
        HashAlgorithm.SHA256: {"bits": 256, "block_size": 64},
        HashAlgorithm.SHA384: {"bits": 384, "block_size": 128},
        HashAlgorithm.SHA512: {"bits": 512, "block_size": 128},
        HashAlgorithm.SHA512_256: {"bits": 256, "block_size": 128},
        HashAlgorithm.SHA3_256: {"bits": 256, "block_size": 136},
        HashAlgorithm.SHA3_384: {"bits": 384, "block_size": 104},
        HashAlgorithm.SHA3_512: {"bits": 512, "block_size": 72},
        HashAlgorithm.SHAKE128: {"bits": 128, "block_size": 168, "xof": True},
        HashAlgorithm.SHAKE256: {"bits": 256, "block_size": 136, "xof": True},
        HashAlgorithm.BLAKE2B: {"bits": 512, "block_size": 128},
        HashAlgorithm.BLAKE2S: {"bits": 256, "block_size": 64},
        HashAlgorithm.BLAKE3: {"bits": 256, "block_size": 64},
    }

    def hash(
        self,
        data: bytes,
        algorithm: HashAlgorithm = HashAlgorithm.SHA256,
        output_length: int | None = None,
    ) -> HashResult:
        """Compute hash of data.

        Args:
            data: Data to hash
            algorithm: Hash algorithm to use
            output_length: Output length in bytes (for XOF algorithms)

        Returns:
            HashResult with digest
        """
        if algorithm == HashAlgorithm.SHA256:
            digest = hashlib.sha256(data).digest()
        elif algorithm == HashAlgorithm.SHA384:
            digest = hashlib.sha384(data).digest()
        elif algorithm == HashAlgorithm.SHA512:
            digest = hashlib.sha512(data).digest()
        elif algorithm == HashAlgorithm.SHA512_256:
            digest = hashlib.new("sha512_256", data).digest()
        elif algorithm == HashAlgorithm.SHA3_256:
            digest = hashlib.sha3_256(data).digest()
        elif algorithm == HashAlgorithm.SHA3_384:
            digest = hashlib.sha3_384(data).digest()
        elif algorithm == HashAlgorithm.SHA3_512:
            digest = hashlib.sha3_512(data).digest()
        elif algorithm == HashAlgorithm.SHAKE128:
            length = output_length or 16
            digest = hashlib.shake_128(data).digest(length)
        elif algorithm == HashAlgorithm.SHAKE256:
            length = output_length or 32
            digest = hashlib.shake_256(data).digest(length)
        elif algorithm == HashAlgorithm.BLAKE2B:
            length = output_length or 64
            digest = hashlib.blake2b(data, digest_size=length).digest()
        elif algorithm == HashAlgorithm.BLAKE2S:
            length = output_length or 32
            digest = hashlib.blake2s(data, digest_size=length).digest()
        elif algorithm == HashAlgorithm.BLAKE3:
            if not BLAKE3_AVAILABLE:
                raise UnsupportedAlgorithmError(
                    "blake3 is not installed. Install with: pip install blake3"
                )
            length = output_length or 32
            digest = blake3.blake3(data).digest(length)
        else:
            raise UnsupportedAlgorithmError(f"Unknown algorithm: {algorithm}")

        return HashResult(
            digest=digest,
            algorithm=algorithm,
            length=len(digest) * 8,
            hex=digest.hex(),
            base64=base64.b64encode(digest).decode("ascii"),
        )

    def hash_file(
        self,
        file: BinaryIO | str,
        algorithm: HashAlgorithm = HashAlgorithm.SHA256,
        chunk_size: int = 8192,
    ) -> HashResult:
        """Compute hash of a file.

        Args:
            file: File path or file-like object
            algorithm: Hash algorithm to use
            chunk_size: Read chunk size

        Returns:
            HashResult with digest
        """
        hasher = self._get_hasher(algorithm)

        if isinstance(file, str):
            with open(file, "rb") as f:
                for chunk in iter(lambda: f.read(chunk_size), b""):
                    hasher.update(chunk)
        else:
            for chunk in iter(lambda: file.read(chunk_size), b""):
                hasher.update(chunk)

        digest = hasher.digest()

        return HashResult(
            digest=digest,
            algorithm=algorithm,
            length=len(digest) * 8,
            hex=digest.hex(),
            base64=base64.b64encode(digest).decode("ascii"),
        )

    def verify(
        self,
        data: bytes,
        expected_digest: bytes | str,
        algorithm: HashAlgorithm = HashAlgorithm.SHA256,
    ) -> bool:
        """Verify a hash.

        Args:
            data: Data to verify
            expected_digest: Expected digest (bytes or hex string)
            algorithm: Hash algorithm

        Returns:
            True if valid
        """
        if isinstance(expected_digest, str):
            expected_digest = bytes.fromhex(expected_digest)

        result = self.hash(data, algorithm)

        # Constant-time comparison
        return std_hmac.compare_digest(result.digest, expected_digest)

    def _get_hasher(self, algorithm: HashAlgorithm):
        """Get a hashlib hasher for streaming."""
        if algorithm == HashAlgorithm.SHA256:
            return hashlib.sha256()
        elif algorithm == HashAlgorithm.SHA384:
            return hashlib.sha384()
        elif algorithm == HashAlgorithm.SHA512:
            return hashlib.sha512()
        elif algorithm == HashAlgorithm.SHA512_256:
            return hashlib.new("sha512_256")
        elif algorithm == HashAlgorithm.SHA3_256:
            return hashlib.sha3_256()
        elif algorithm == HashAlgorithm.SHA3_384:
            return hashlib.sha3_384()
        elif algorithm == HashAlgorithm.SHA3_512:
            return hashlib.sha3_512()
        elif algorithm == HashAlgorithm.BLAKE2B:
            return hashlib.blake2b()
        elif algorithm == HashAlgorithm.BLAKE2S:
            return hashlib.blake2s()
        elif algorithm == HashAlgorithm.BLAKE3:
            if not BLAKE3_AVAILABLE:
                raise UnsupportedAlgorithmError("blake3 not installed")
            return blake3.blake3()
        else:
            raise UnsupportedAlgorithmError(f"Streaming not supported: {algorithm}")


class MACEngine:
    """Handles message authentication code operations."""

    # Algorithm to hash mapping
    HASH_ALGORITHMS = {
        MACAlgorithm.HMAC_SHA256: hashes.SHA256(),
        MACAlgorithm.HMAC_SHA384: hashes.SHA384(),
        MACAlgorithm.HMAC_SHA512: hashes.SHA512(),
        MACAlgorithm.HMAC_SHA3_256: hashes.SHA3_256(),
    }

    # Minimum key sizes (bytes)
    MIN_KEY_SIZES = {
        MACAlgorithm.HMAC_SHA256: 32,
        MACAlgorithm.HMAC_SHA384: 48,
        MACAlgorithm.HMAC_SHA512: 64,
        MACAlgorithm.HMAC_SHA3_256: 32,
        MACAlgorithm.HMAC_BLAKE2B: 32,
        MACAlgorithm.KMAC128: 16,  # 128-bit security
        MACAlgorithm.KMAC256: 32,  # 256-bit security
    }

    # Default KMAC output sizes (bytes)
    KMAC_OUTPUT_SIZES = {
        MACAlgorithm.KMAC128: 16,  # 128 bits
        MACAlgorithm.KMAC256: 32,  # 256 bits
    }

    def mac(
        self,
        data: bytes,
        key: bytes,
        algorithm: MACAlgorithm = MACAlgorithm.HMAC_SHA256,
        customization: bytes = b"",
        output_length: int | None = None,
    ) -> MACResult:
        """Compute MAC of data.

        Args:
            data: Data to authenticate
            key: MAC key
            algorithm: MAC algorithm
            customization: Customization string for KMAC (optional)
            output_length: Output length in bytes for KMAC (optional)

        Returns:
            MACResult with tag
        """
        if algorithm in self.HASH_ALGORITHMS:
            h = crypto_hmac.HMAC(key, self.HASH_ALGORITHMS[algorithm])
            h.update(data)
            tag = h.finalize()

        elif algorithm == MACAlgorithm.HMAC_BLAKE2B:
            # BLAKE2b has built-in MAC mode
            tag = hashlib.blake2b(data, key=key, digest_size=64).digest()

        elif algorithm == MACAlgorithm.KMAC128:
            if not KMAC_AVAILABLE:
                raise UnsupportedAlgorithmError(
                    "KMAC requires pycryptodome. Install with: pip install pycryptodome"
                )
            mac_len = output_length or self.KMAC_OUTPUT_SIZES[algorithm]
            h = KMAC128.new(key=key, mac_len=mac_len, custom=customization)
            h.update(data)
            tag = h.digest()

        elif algorithm == MACAlgorithm.KMAC256:
            if not KMAC_AVAILABLE:
                raise UnsupportedAlgorithmError(
                    "KMAC requires pycryptodome. Install with: pip install pycryptodome"
                )
            mac_len = output_length or self.KMAC_OUTPUT_SIZES[algorithm]
            h = KMAC256.new(key=key, mac_len=mac_len, custom=customization)
            h.update(data)
            tag = h.digest()

        else:
            raise UnsupportedAlgorithmError(f"Unknown algorithm: {algorithm}")

        return MACResult(
            tag=tag,
            algorithm=algorithm,
            length=len(tag) * 8,
            hex=tag.hex(),
            base64=base64.b64encode(tag).decode("ascii"),
        )

    def verify(
        self,
        data: bytes,
        key: bytes,
        expected_tag: bytes | str,
        algorithm: MACAlgorithm = MACAlgorithm.HMAC_SHA256,
        customization: bytes = b"",
    ) -> bool:
        """Verify a MAC.

        Args:
            data: Data to verify
            key: MAC key
            expected_tag: Expected tag (bytes or hex string)
            algorithm: MAC algorithm
            customization: Customization string for KMAC (optional)

        Returns:
            True if valid
        """
        if isinstance(expected_tag, str):
            expected_tag = bytes.fromhex(expected_tag)

        if algorithm in self.HASH_ALGORITHMS:
            h = crypto_hmac.HMAC(key, self.HASH_ALGORITHMS[algorithm])
            h.update(data)
            try:
                h.verify(expected_tag)
                return True
            except Exception:
                return False

        elif algorithm == MACAlgorithm.HMAC_BLAKE2B:
            computed = hashlib.blake2b(data, key=key, digest_size=len(expected_tag)).digest()
            return std_hmac.compare_digest(computed, expected_tag)

        elif algorithm == MACAlgorithm.KMAC128:
            if not KMAC_AVAILABLE:
                raise UnsupportedAlgorithmError("KMAC requires pycryptodome")
            h = KMAC128.new(key=key, mac_len=len(expected_tag), custom=customization)
            h.update(data)
            computed = h.digest()
            return std_hmac.compare_digest(computed, expected_tag)

        elif algorithm == MACAlgorithm.KMAC256:
            if not KMAC_AVAILABLE:
                raise UnsupportedAlgorithmError("KMAC requires pycryptodome")
            h = KMAC256.new(key=key, mac_len=len(expected_tag), custom=customization)
            h.update(data)
            computed = h.digest()
            return std_hmac.compare_digest(computed, expected_tag)

        else:
            raise UnsupportedAlgorithmError(f"Unknown algorithm: {algorithm}")

    def generate_key(
        self,
        algorithm: MACAlgorithm = MACAlgorithm.HMAC_SHA256,
    ) -> bytes:
        """Generate a random MAC key.

        Args:
            algorithm: MAC algorithm (determines key size)

        Returns:
            Random key bytes
        """
        size = self.MIN_KEY_SIZES.get(algorithm, 32)
        return os.urandom(size)


class HashStreamer:
    """Streaming hash computation."""

    def __init__(self, algorithm: HashAlgorithm = HashAlgorithm.SHA256):
        self.algorithm = algorithm
        self._hasher = HashEngine()._get_hasher(algorithm)
        self._finalized = False

    def update(self, data: bytes) -> None:
        """Add data to hash."""
        if self._finalized:
            raise HashError("Hash already finalized")
        self._hasher.update(data)

    def digest(self) -> bytes:
        """Get final digest."""
        self._finalized = True
        return self._hasher.digest()

    def hexdigest(self) -> str:
        """Get final digest as hex string."""
        return self.digest().hex()


class MACStreamer:
    """Streaming MAC computation."""

    def __init__(self, key: bytes, algorithm: MACAlgorithm = MACAlgorithm.HMAC_SHA256):
        self.algorithm = algorithm
        self._key = key

        if algorithm in MACEngine.HASH_ALGORITHMS:
            self._hmac = crypto_hmac.HMAC(key, MACEngine.HASH_ALGORITHMS[algorithm])
        else:
            raise UnsupportedAlgorithmError(f"Streaming not supported: {algorithm}")

        self._finalized = False

    def update(self, data: bytes) -> None:
        """Add data to MAC."""
        if self._finalized:
            raise MACError("MAC already finalized")
        self._hmac.update(data)

    def finalize(self) -> bytes:
        """Get final MAC tag."""
        self._finalized = True
        return self._hmac.finalize()

    def verify(self, expected_tag: bytes) -> bool:
        """Verify MAC tag."""
        self._finalized = True
        try:
            self._hmac.verify(expected_tag)
            return True
        except Exception:
            return False


# Singleton instances
hash_engine = HashEngine()
mac_engine = MACEngine()
