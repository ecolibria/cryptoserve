"""Shamir Secret Sharing Engine.

Implements Shamir's Secret Sharing Scheme (SSSS) for splitting secrets
into multiple shares where a threshold number is required for reconstruction.

Security Properties:
- Information-theoretic security: k-1 shares reveal nothing about the secret
- Perfect secrecy: Any k shares reconstruct the secret exactly
- No computational assumptions required

Use Cases:
- Distributed key management
- Multi-party authorization
- Backup and recovery
- Key escrow with multiple custodians

References:
- Shamir, A. "How to share a secret." Communications of the ACM, 1979
"""

import os
import secrets
from dataclasses import dataclass
from typing import List, Tuple


# GF(256) field operations for byte-level sharing
# Using the AES/Rijndael polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B)
class GF256:
    """Galois Field GF(2^8) arithmetic.

    Operations are done modulo the irreducible polynomial
    x^8 + x^4 + x^3 + x + 1 (0x11B).
    """

    # Precomputed tables for fast multiplication
    _EXP_TABLE: List[int] = []
    _LOG_TABLE: List[int] = []

    @classmethod
    def _init_tables(cls):
        """Initialize logarithm and exponential tables."""
        if cls._EXP_TABLE:
            return

        cls._EXP_TABLE = [0] * 512
        cls._LOG_TABLE = [0] * 256

        x = 1
        for i in range(255):
            cls._EXP_TABLE[i] = x
            cls._LOG_TABLE[x] = i
            # Multiply by generator (3 = x + 1)
            x = cls._multiply_slow(x, 3)

        # Extend exp table for easy modular lookup
        for i in range(255, 512):
            cls._EXP_TABLE[i] = cls._EXP_TABLE[i - 255]

    @classmethod
    def _multiply_slow(cls, a: int, b: int) -> int:
        """Slow multiplication (used only for table init)."""
        result = 0
        while b:
            if b & 1:
                result ^= a
            a <<= 1
            if a & 0x100:
                a ^= 0x11B
            b >>= 1
        return result

    @classmethod
    def multiply(cls, a: int, b: int) -> int:
        """Fast multiplication using lookup tables."""
        cls._init_tables()
        if a == 0 or b == 0:
            return 0
        return cls._EXP_TABLE[cls._LOG_TABLE[a] + cls._LOG_TABLE[b]]

    @classmethod
    def divide(cls, a: int, b: int) -> int:
        """Division in GF(256)."""
        cls._init_tables()
        if b == 0:
            raise ZeroDivisionError("Division by zero in GF(256)")
        if a == 0:
            return 0
        return cls._EXP_TABLE[cls._LOG_TABLE[a] - cls._LOG_TABLE[b] + 255]

    @classmethod
    def add(cls, a: int, b: int) -> int:
        """Addition in GF(256) (same as XOR)."""
        return a ^ b

    @classmethod
    def subtract(cls, a: int, b: int) -> int:
        """Subtraction in GF(256) (same as XOR)."""
        return a ^ b

    @classmethod
    def power(cls, base: int, exp: int) -> int:
        """Exponentiation in GF(256)."""
        cls._init_tables()
        if exp == 0:
            return 1
        if base == 0:
            return 0
        return cls._EXP_TABLE[(cls._LOG_TABLE[base] * exp) % 255]


@dataclass
class Share:
    """A single share of a secret."""

    x: int  # Share index (1-255)
    y: bytes  # Share data
    threshold: int  # Minimum shares needed
    total: int  # Total shares created

    def to_bytes(self) -> bytes:
        """Serialize share to bytes."""
        # Format: [x:1][threshold:1][total:1][len:2][data:len]
        data_len = len(self.y)
        header = bytes([self.x, self.threshold, self.total])
        length = data_len.to_bytes(2, "big")
        return header + length + self.y

    @classmethod
    def from_bytes(cls, data: bytes) -> "Share":
        """Deserialize share from bytes."""
        if len(data) < 5:
            raise ValueError("Share data too short")

        x = data[0]
        threshold = data[1]
        total = data[2]
        data_len = int.from_bytes(data[3:5], "big")

        if len(data) < 5 + data_len:
            raise ValueError("Share data truncated")

        y = data[5:5 + data_len]

        return cls(x=x, y=y, threshold=threshold, total=total)

    def to_hex(self) -> str:
        """Convert share to hex string."""
        return self.to_bytes().hex()

    @classmethod
    def from_hex(cls, hex_str: str) -> "Share":
        """Create share from hex string."""
        return cls.from_bytes(bytes.fromhex(hex_str))


class SecretSharingError(Exception):
    """Secret sharing operation failed."""
    pass


class InsufficientSharesError(SecretSharingError):
    """Not enough shares to reconstruct."""
    pass


class InvalidShareError(SecretSharingError):
    """Share is invalid or corrupted."""
    pass


class SecretSharingEngine:
    """Shamir Secret Sharing implementation.

    Splits a secret into n shares where any k shares can reconstruct
    the original secret (k-of-n threshold scheme).

    Usage:
        engine = SecretSharingEngine()

        # Split a secret into 5 shares, 3 required to reconstruct
        secret = b"my secret key"
        shares = engine.split(secret, threshold=3, total_shares=5)

        # Reconstruct from any 3 shares
        recovered = engine.combine([shares[0], shares[2], shares[4]])
        assert recovered == secret
    """

    MAX_SHARES = 255  # Limited by GF(256) field size
    MAX_SECRET_SIZE = 1024 * 1024  # 1 MB limit to prevent memory exhaustion

    def split(
        self,
        secret: bytes,
        threshold: int,
        total_shares: int,
    ) -> List[Share]:
        """Split a secret into multiple shares.

        Args:
            secret: The secret to split
            threshold: Minimum shares needed to reconstruct (k)
            total_shares: Total number of shares to create (n)

        Returns:
            List of Share objects

        Raises:
            SecretSharingError: If parameters are invalid
        """
        if threshold < 2:
            raise SecretSharingError("Threshold must be at least 2")
        if total_shares < threshold:
            raise SecretSharingError("Total shares must be >= threshold")
        if total_shares > self.MAX_SHARES:
            raise SecretSharingError(f"Maximum {self.MAX_SHARES} shares supported")
        if not secret:
            raise SecretSharingError("Secret cannot be empty")
        if len(secret) > self.MAX_SECRET_SIZE:
            raise SecretSharingError(
                f"Secret size {len(secret)} exceeds maximum {self.MAX_SECRET_SIZE} bytes"
            )

        # Initialize GF256 tables
        GF256._init_tables()

        # Generate random coefficients for each byte's polynomial
        # For each byte position, we create a polynomial of degree (threshold - 1)
        # where the constant term is the secret byte
        shares_data = [bytearray() for _ in range(total_shares)]

        for byte_val in secret:
            # Generate random coefficients (a1, a2, ..., a_{k-1})
            # The polynomial is: f(x) = secret + a1*x + a2*x^2 + ... + a_{k-1}*x^{k-1}
            coefficients = [byte_val]  # Constant term is the secret byte
            for _ in range(threshold - 1):
                coefficients.append(secrets.randbelow(256))

            # Evaluate polynomial at x = 1, 2, ..., n
            for i in range(total_shares):
                x = i + 1  # x values are 1-indexed
                y = self._evaluate_polynomial(coefficients, x)
                shares_data[i].append(y)

        # Create Share objects
        shares = []
        for i in range(total_shares):
            share = Share(
                x=i + 1,
                y=bytes(shares_data[i]),
                threshold=threshold,
                total=total_shares,
            )
            shares.append(share)

        return shares

    def combine(self, shares: List[Share]) -> bytes:
        """Combine shares to reconstruct the secret.

        Args:
            shares: List of shares (at least threshold number)

        Returns:
            The reconstructed secret

        Raises:
            InsufficientSharesError: If not enough shares provided
            InvalidShareError: If shares are incompatible or corrupted
        """
        if not shares:
            raise InsufficientSharesError("No shares provided")

        # Validate shares are compatible
        threshold = shares[0].threshold
        secret_len = len(shares[0].y)

        if len(shares) < threshold:
            raise InsufficientSharesError(
                f"Need at least {threshold} shares, got {len(shares)}"
            )

        for share in shares[1:]:
            if share.threshold != threshold:
                raise InvalidShareError("Shares have different thresholds")
            if len(share.y) != secret_len:
                raise InvalidShareError("Shares have different lengths")

        # Check for duplicate x values
        x_values = [share.x for share in shares]
        if len(set(x_values)) != len(x_values):
            raise InvalidShareError("Duplicate share indices")

        # Initialize GF256 tables
        GF256._init_tables()

        # Use Lagrange interpolation to recover each byte
        secret = bytearray()

        for byte_idx in range(secret_len):
            # Get y values for this byte position
            points = [(share.x, share.y[byte_idx]) for share in shares[:threshold]]

            # Evaluate at x=0 to get the secret byte
            secret_byte = self._lagrange_interpolate(points, 0)
            secret.append(secret_byte)

        return bytes(secret)

    def _evaluate_polynomial(self, coefficients: List[int], x: int) -> int:
        """Evaluate polynomial at point x using Horner's method."""
        result = 0
        for coef in reversed(coefficients):
            result = GF256.add(GF256.multiply(result, x), coef)
        return result

    def _lagrange_interpolate(
        self,
        points: List[Tuple[int, int]],
        x: int,
    ) -> int:
        """Lagrange interpolation in GF(256)."""
        result = 0

        for i, (xi, yi) in enumerate(points):
            # Compute Lagrange basis polynomial L_i(x)
            basis = 1

            for j, (xj, _) in enumerate(points):
                if i != j:
                    # basis *= (x - xj) / (xi - xj)
                    numerator = GF256.subtract(x, xj)
                    denominator = GF256.subtract(xi, xj)
                    basis = GF256.multiply(basis, GF256.divide(numerator, denominator))

            # result += yi * L_i(x)
            term = GF256.multiply(yi, basis)
            result = GF256.add(result, term)

        return result

    def verify_shares(self, shares: List[Share]) -> bool:
        """Verify that shares are valid and compatible.

        Args:
            shares: List of shares to verify

        Returns:
            True if shares are valid
        """
        if not shares:
            return False

        try:
            threshold = shares[0].threshold
            total = shares[0].total
            length = len(shares[0].y)

            for share in shares:
                if share.threshold != threshold:
                    return False
                if share.total != total:
                    return False
                if len(share.y) != length:
                    return False
                if share.x < 1 or share.x > self.MAX_SHARES:
                    return False

            # Check for duplicates
            x_values = [s.x for s in shares]
            if len(set(x_values)) != len(x_values):
                return False

            return True
        except Exception:
            return False

    def recover_share(
        self,
        shares: List[Share],
        target_x: int,
    ) -> Share:
        """Recover a missing share using existing shares.

        If you have k shares and need to reconstruct a lost share,
        you can use Lagrange interpolation to compute it.

        Args:
            shares: List of existing shares (at least threshold)
            target_x: The x value of the share to recover (1-255)

        Returns:
            The recovered share

        Raises:
            InsufficientSharesError: If not enough shares
            SecretSharingError: If target_x already exists
        """
        if not shares:
            raise InsufficientSharesError("No shares provided")

        threshold = shares[0].threshold
        if len(shares) < threshold:
            raise InsufficientSharesError(
                f"Need at least {threshold} shares"
            )

        if any(s.x == target_x for s in shares):
            raise SecretSharingError(
                f"Share with x={target_x} already exists"
            )

        if target_x < 1 or target_x > self.MAX_SHARES:
            raise SecretSharingError(
                f"target_x must be between 1 and {self.MAX_SHARES}"
            )

        GF256._init_tables()

        # Interpolate each byte
        recovered_data = bytearray()
        secret_len = len(shares[0].y)

        for byte_idx in range(secret_len):
            points = [(s.x, s.y[byte_idx]) for s in shares[:threshold]]
            y_val = self._lagrange_interpolate(points, target_x)
            recovered_data.append(y_val)

        return Share(
            x=target_x,
            y=bytes(recovered_data),
            threshold=threshold,
            total=shares[0].total,
        )


# Singleton instance
secret_sharing_engine = SecretSharingEngine()
