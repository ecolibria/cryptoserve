"""Threshold Cryptography Engine.

Implements threshold cryptographic operations where multiple parties
must cooperate to perform cryptographic operations.

Features:
- Distributed Key Generation (DKG)
- Threshold Signatures (t-of-n EdDSA/Schnorr)
- Threshold Decryption (t-of-n ElGamal-style)
- Verifiable Secret Sharing (Feldman's VSS)

Use Cases:
- Multi-party authorization for high-value operations
- Distributed signing for certificates/documents
- Key escrow with multiple custodians
- Eliminating single points of compromise

Security Properties:
- No single party learns the complete private key
- t-1 colluding parties learn nothing
- Verifiable: participants can verify shares are correct

References:
- Feldman, P. "A Practical Scheme for Non-interactive VSS" (1987)
- Gennaro et al. "Secure Distributed Key Generation" (1999)
- Komlo & Goldberg "FROST: Flexible Round-Optimized Schnorr Threshold Signatures"
"""

import hashlib
import os
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)


class ThresholdScheme(str, Enum):
    """Supported threshold schemes."""

    FROST_ED25519 = "frost-ed25519"  # FROST-style EdDSA threshold signatures
    THRESHOLD_ECDSA_P256 = "threshold-ecdsa-p256"  # Threshold ECDSA on P-256
    THRESHOLD_ELGAMAL = "threshold-elgamal"  # Threshold decryption


class ThresholdError(Exception):
    """Threshold cryptography error."""

    pass


class InsufficientParticipantsError(ThresholdError):
    """Not enough participants for threshold operation."""

    pass


class InvalidShareError(ThresholdError):
    """Share verification failed."""

    pass


class InvalidCommitmentError(ThresholdError):
    """Commitment verification failed."""

    pass


# Curve parameters for secp256k1 (used for demonstrations)
# In production, use proper curve implementations
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_G_X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP256K1_G_Y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


@dataclass
class FieldElement:
    """Element in a prime field."""

    value: int
    modulus: int

    def __add__(self, other: "FieldElement") -> "FieldElement":
        return FieldElement((self.value + other.value) % self.modulus, self.modulus)

    def __sub__(self, other: "FieldElement") -> "FieldElement":
        return FieldElement((self.value - other.value) % self.modulus, self.modulus)

    def __mul__(self, other: "FieldElement") -> "FieldElement":
        return FieldElement((self.value * other.value) % self.modulus, self.modulus)

    def __neg__(self) -> "FieldElement":
        return FieldElement((-self.value) % self.modulus, self.modulus)

    def inverse(self) -> "FieldElement":
        """Compute modular inverse using extended Euclidean algorithm."""
        return FieldElement(pow(self.value, -1, self.modulus), self.modulus)

    def __eq__(self, other) -> bool:
        if isinstance(other, FieldElement):
            return self.value == other.value and self.modulus == other.modulus
        return self.value == other


@dataclass
class Point:
    """Point on an elliptic curve (simplified for demonstration)."""

    x: Optional[int]
    y: Optional[int]
    curve_order: int = SECP256K1_ORDER

    @property
    def is_identity(self) -> bool:
        return self.x is None and self.y is None

    @classmethod
    def identity(cls, curve_order: int = SECP256K1_ORDER) -> "Point":
        return cls(None, None, curve_order)

    @classmethod
    def generator(cls) -> "Point":
        return cls(SECP256K1_G_X, SECP256K1_G_Y, SECP256K1_ORDER)

    def __eq__(self, other) -> bool:
        if isinstance(other, Point):
            return self.x == other.x and self.y == other.y
        return False

    def to_bytes(self) -> bytes:
        """Serialize point to compressed format."""
        if self.is_identity:
            return b"\x00"
        prefix = b"\x02" if self.y % 2 == 0 else b"\x03"
        return prefix + self.x.to_bytes(32, "big")


@dataclass
class ThresholdKeyShare:
    """A participant's share of a threshold key."""

    participant_id: int  # 1-indexed participant ID
    share_value: int  # The secret share (scalar)
    public_key: bytes  # Combined public key
    verification_points: list[bytes]  # Feldman VSS commitments
    threshold: int
    total_participants: int
    scheme: ThresholdScheme

    def to_bytes(self) -> bytes:
        """Serialize key share."""
        parts = [
            bytes([self.participant_id]),
            bytes([self.threshold]),
            bytes([self.total_participants]),
            self.scheme.value.encode().ljust(32, b"\x00"),
            self.share_value.to_bytes(32, "big"),
            len(self.public_key).to_bytes(2, "big"),
            self.public_key,
            len(self.verification_points).to_bytes(2, "big"),
        ]
        for vp in self.verification_points:
            parts.extend([len(vp).to_bytes(2, "big"), vp])
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes) -> "ThresholdKeyShare":
        """Deserialize key share."""
        pos = 0
        participant_id = data[pos]
        pos += 1
        threshold = data[pos]
        pos += 1
        total = data[pos]
        pos += 1
        scheme_bytes = data[pos : pos + 32].rstrip(b"\x00")
        scheme = ThresholdScheme(scheme_bytes.decode())
        pos += 32
        share_value = int.from_bytes(data[pos : pos + 32], "big")
        pos += 32
        pk_len = int.from_bytes(data[pos : pos + 2], "big")
        pos += 2
        public_key = data[pos : pos + pk_len]
        pos += pk_len
        vp_count = int.from_bytes(data[pos : pos + 2], "big")
        pos += 2
        verification_points = []
        for _ in range(vp_count):
            vp_len = int.from_bytes(data[pos : pos + 2], "big")
            pos += 2
            verification_points.append(data[pos : pos + vp_len])
            pos += vp_len

        return cls(
            participant_id=participant_id,
            share_value=share_value,
            public_key=public_key,
            verification_points=verification_points,
            threshold=threshold,
            total_participants=total,
            scheme=scheme,
        )


@dataclass
class SignatureShare:
    """A participant's share of a threshold signature."""

    participant_id: int
    r_share: bytes  # Commitment/nonce share
    s_share: int  # Signature share


@dataclass
class ThresholdSignature:
    """A complete threshold signature."""

    r: bytes  # Combined R point
    s: int  # Combined s value
    participants: list[int]  # IDs of participants who contributed


@dataclass
class DKGRound1Output:
    """Output from DKG Round 1 (commitment phase)."""

    participant_id: int
    commitment: bytes  # g^a_i0
    proof: bytes  # Schnorr proof of knowledge


@dataclass
class DKGRound2Output:
    """Output from DKG Round 2 (share distribution)."""

    participant_id: int
    encrypted_shares: dict[int, bytes]  # recipient_id -> encrypted share


@dataclass
class ThresholdKeyGenResult:
    """Result of threshold key generation."""

    public_key: bytes
    shares: list[ThresholdKeyShare]
    threshold: int
    total_participants: int
    scheme: ThresholdScheme


class ThresholdEngine:
    """Threshold cryptography operations.

    Provides distributed key generation and threshold signatures
    where t-of-n participants must cooperate.

    Usage:
        engine = ThresholdEngine()

        # Generate threshold key (3-of-5)
        result = engine.generate_threshold_key(
            threshold=3,
            total_participants=5,
            scheme=ThresholdScheme.FROST_ED25519,
        )

        # Each participant gets their share
        share1, share2, share3 = result.shares[:3]

        # Create signature shares
        message = b"Important document"
        sig_shares = [
            engine.create_signature_share(share1, message, nonce_share1),
            engine.create_signature_share(share2, message, nonce_share2),
            engine.create_signature_share(share3, message, nonce_share3),
        ]

        # Combine signature shares
        signature = engine.combine_signature_shares(sig_shares)

        # Verify threshold signature
        valid = engine.verify_threshold_signature(
            result.public_key, message, signature
        )
    """

    # Curve order for scalar operations
    CURVE_ORDER = SECP256K1_ORDER

    def generate_threshold_key(
        self,
        threshold: int,
        total_participants: int,
        scheme: ThresholdScheme = ThresholdScheme.FROST_ED25519,
    ) -> ThresholdKeyGenResult:
        """Generate a threshold key with shares for all participants.

        This is a trusted dealer setup. For truly distributed key
        generation, use the DKG protocol methods.

        Args:
            threshold: Minimum participants needed (t)
            total_participants: Total number of participants (n)
            scheme: Threshold scheme to use

        Returns:
            ThresholdKeyGenResult with public key and shares

        Raises:
            ThresholdError: If parameters are invalid
        """
        if threshold < 2:
            raise ThresholdError("Threshold must be at least 2")
        if total_participants < threshold:
            raise ThresholdError("Total participants must be >= threshold")
        if total_participants > 255:
            raise ThresholdError("Maximum 255 participants supported")

        # Generate random polynomial of degree (threshold - 1)
        # f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
        # where a_0 is the secret key
        coefficients = [
            secrets.randbelow(self.CURVE_ORDER - 1) + 1
            for _ in range(threshold)
        ]
        secret_key = coefficients[0]

        # Compute public key: g^secret_key
        public_key = self._scalar_mult_g(secret_key)

        # Compute Feldman VSS commitments: g^a_i for each coefficient
        verification_points = [
            self._scalar_mult_g(coef).to_bytes() for coef in coefficients
        ]

        # Generate shares for each participant
        shares = []
        for i in range(1, total_participants + 1):
            # Evaluate polynomial at x = i
            share_value = self._evaluate_polynomial(coefficients, i)

            share = ThresholdKeyShare(
                participant_id=i,
                share_value=share_value,
                public_key=public_key.to_bytes(),
                verification_points=verification_points,
                threshold=threshold,
                total_participants=total_participants,
                scheme=scheme,
            )
            shares.append(share)

        return ThresholdKeyGenResult(
            public_key=public_key.to_bytes(),
            shares=shares,
            threshold=threshold,
            total_participants=total_participants,
            scheme=scheme,
        )

    def verify_share(self, share: ThresholdKeyShare) -> bool:
        """Verify a share using Feldman's VSS.

        Checks that g^share = product(C_j^(i^j)) for j in 0..t-1
        where C_j are the verification commitments.

        Args:
            share: The share to verify

        Returns:
            True if share is valid
        """
        try:
            # Compute g^share
            g_share = self._scalar_mult_g(share.share_value)

            # Compute product of C_j^(i^j)
            result = Point.identity()
            x = share.participant_id

            for j, commitment_bytes in enumerate(share.verification_points):
                commitment = self._point_from_bytes(commitment_bytes)
                # C_j^(x^j)
                exponent = pow(x, j, self.CURVE_ORDER)
                term = self._scalar_mult(commitment, exponent)
                result = self._point_add(result, term)

            return g_share == result
        except Exception:
            return False

    def generate_nonce_share(
        self,
        share: ThresholdKeyShare,
    ) -> tuple[int, bytes]:
        """Generate a nonce share for threshold signing.

        Each participant generates a random nonce and computes
        a commitment to that nonce.

        Args:
            share: The participant's key share

        Returns:
            Tuple of (nonce_value, nonce_commitment)
        """
        # Generate random nonce
        nonce = secrets.randbelow(self.CURVE_ORDER - 1) + 1

        # Compute commitment: g^nonce
        commitment = self._scalar_mult_g(nonce)

        return nonce, commitment.to_bytes()

    def create_signature_share(
        self,
        share: ThresholdKeyShare,
        message: bytes,
        nonce: int,
        nonce_commitments: dict[int, bytes],
    ) -> SignatureShare:
        """Create a signature share.

        Args:
            share: Participant's key share
            message: Message to sign
            nonce: Participant's nonce
            nonce_commitments: Map of participant_id -> nonce commitment

        Returns:
            SignatureShare for this participant
        """
        # Combine all nonce commitments to get R
        R = Point.identity()
        for pid, commitment_bytes in nonce_commitments.items():
            commitment = self._point_from_bytes(commitment_bytes)
            R = self._point_add(R, commitment)

        # Compute challenge: H(R || public_key || message)
        challenge_input = (
            R.to_bytes() + share.public_key + message
        )
        challenge_hash = hashlib.sha256(challenge_input).digest()
        challenge = int.from_bytes(challenge_hash, "big") % self.CURVE_ORDER

        # Compute Lagrange coefficient for this participant
        participant_ids = list(nonce_commitments.keys())
        lagrange = self._lagrange_coefficient(
            share.participant_id, participant_ids
        )

        # Compute signature share: s_i = k_i + c * lambda_i * x_i
        s_share = (
            nonce + challenge * lagrange * share.share_value
        ) % self.CURVE_ORDER

        return SignatureShare(
            participant_id=share.participant_id,
            r_share=nonce_commitments[share.participant_id],
            s_share=s_share,
        )

    def combine_signature_shares(
        self,
        shares: list[SignatureShare],
        nonce_commitments: dict[int, bytes],
    ) -> ThresholdSignature:
        """Combine signature shares into a complete signature.

        Args:
            shares: List of signature shares from participants
            nonce_commitments: Map of participant_id -> nonce commitment

        Returns:
            Complete threshold signature

        Raises:
            ThresholdError: If combination fails
        """
        if not shares:
            raise ThresholdError("No signature shares provided")

        # Combine R from all nonce commitments
        R = Point.identity()
        for commitment_bytes in nonce_commitments.values():
            commitment = self._point_from_bytes(commitment_bytes)
            R = self._point_add(R, commitment)

        # Sum all s shares
        s = 0
        participant_ids = []
        for share in shares:
            s = (s + share.s_share) % self.CURVE_ORDER
            participant_ids.append(share.participant_id)

        return ThresholdSignature(
            r=R.to_bytes(),
            s=s,
            participants=participant_ids,
        )

    def verify_threshold_signature(
        self,
        public_key: bytes,
        message: bytes,
        signature: ThresholdSignature,
    ) -> bool:
        """Verify a threshold signature.

        Args:
            public_key: The threshold public key
            message: The signed message
            signature: The threshold signature

        Returns:
            True if signature is valid
        """
        try:
            R = self._point_from_bytes(signature.r)
            pk = self._point_from_bytes(public_key)

            # Compute challenge: H(R || public_key || message)
            challenge_input = signature.r + public_key + message
            challenge_hash = hashlib.sha256(challenge_input).digest()
            challenge = int.from_bytes(challenge_hash, "big") % self.CURVE_ORDER

            # Verify: g^s == R * pk^c
            lhs = self._scalar_mult_g(signature.s)

            pk_c = self._scalar_mult(pk, challenge)
            rhs = self._point_add(R, pk_c)

            return lhs == rhs
        except Exception:
            return False

    def threshold_decrypt_share(
        self,
        share: ThresholdKeyShare,
        ciphertext_point: bytes,
    ) -> bytes:
        """Create a decryption share for threshold decryption.

        For ElGamal-style threshold decryption.

        Args:
            share: Participant's key share
            ciphertext_point: The C1 point from the ciphertext

        Returns:
            Decryption share (point)
        """
        c1 = self._point_from_bytes(ciphertext_point)

        # Compute share: C1^x_i
        decryption_share = self._scalar_mult(c1, share.share_value)

        return decryption_share.to_bytes()

    def combine_decryption_shares(
        self,
        shares: list[tuple[int, bytes]],
        ciphertext: tuple[bytes, bytes],
    ) -> bytes:
        """Combine decryption shares to recover plaintext.

        For ElGamal-style threshold decryption.

        Args:
            shares: List of (participant_id, decryption_share) tuples
            ciphertext: (C1, C2) ElGamal ciphertext

        Returns:
            Decrypted point as bytes

        Raises:
            ThresholdError: If decryption fails
        """
        if not shares:
            raise ThresholdError("No decryption shares provided")

        c1_bytes, c2_bytes = ciphertext
        c2 = self._point_from_bytes(c2_bytes)

        # Combine shares using Lagrange interpolation
        participant_ids = [s[0] for s in shares]
        combined = Point.identity()

        for participant_id, share_bytes in shares:
            share_point = self._point_from_bytes(share_bytes)
            lagrange = self._lagrange_coefficient(participant_id, participant_ids)

            # share^lagrange
            weighted = self._scalar_mult(share_point, lagrange)
            combined = self._point_add(combined, weighted)

        # Plaintext = C2 - combined
        neg_combined = Point(
            combined.x,
            (-combined.y) % SECP256K1_P if combined.y else None,
            combined.curve_order,
        )
        plaintext_point = self._point_add(c2, neg_combined)

        return plaintext_point.to_bytes()

    # DKG Protocol Methods

    def dkg_round1(
        self,
        participant_id: int,
        threshold: int,
        total_participants: int,
    ) -> tuple[DKGRound1Output, list[int]]:
        """Execute DKG Round 1: Generate and commit to polynomial.

        Each participant generates a random polynomial and broadcasts
        a commitment to it.

        Args:
            participant_id: This participant's ID (1-indexed)
            threshold: Required threshold
            total_participants: Total number of participants

        Returns:
            Tuple of (round1_output, polynomial_coefficients)
        """
        # Generate random polynomial
        coefficients = [
            secrets.randbelow(self.CURVE_ORDER - 1) + 1
            for _ in range(threshold)
        ]

        # Compute commitment to constant term: g^a_0
        commitment = self._scalar_mult_g(coefficients[0])

        # Generate Schnorr proof of knowledge
        k = secrets.randbelow(self.CURVE_ORDER - 1) + 1
        R = self._scalar_mult_g(k)

        challenge_input = (
            commitment.to_bytes() + R.to_bytes() +
            participant_id.to_bytes(4, "big")
        )
        challenge = int.from_bytes(
            hashlib.sha256(challenge_input).digest(), "big"
        ) % self.CURVE_ORDER

        response = (k + challenge * coefficients[0]) % self.CURVE_ORDER

        proof = R.to_bytes() + response.to_bytes(32, "big")

        output = DKGRound1Output(
            participant_id=participant_id,
            commitment=commitment.to_bytes(),
            proof=proof,
        )

        return output, coefficients

    def dkg_verify_round1(
        self,
        output: DKGRound1Output,
    ) -> bool:
        """Verify a Round 1 DKG output.

        Args:
            output: The round 1 output to verify

        Returns:
            True if proof is valid
        """
        try:
            commitment = self._point_from_bytes(output.commitment)

            # Parse proof
            R = self._point_from_bytes(output.proof[:33])
            response = int.from_bytes(output.proof[33:65], "big")

            # Recompute challenge
            challenge_input = (
                output.commitment + R.to_bytes() +
                output.participant_id.to_bytes(4, "big")
            )
            challenge = int.from_bytes(
                hashlib.sha256(challenge_input).digest(), "big"
            ) % self.CURVE_ORDER

            # Verify: g^response == R * commitment^challenge
            lhs = self._scalar_mult_g(response)
            rhs = self._point_add(R, self._scalar_mult(commitment, challenge))

            return lhs == rhs
        except Exception:
            return False

    def dkg_round2(
        self,
        participant_id: int,
        coefficients: list[int],
        total_participants: int,
        recipient_public_keys: dict[int, bytes],
    ) -> DKGRound2Output:
        """Execute DKG Round 2: Distribute shares.

        Each participant evaluates their polynomial at each other
        participant's index and encrypts the share.

        Args:
            participant_id: This participant's ID
            coefficients: This participant's polynomial coefficients
            total_participants: Total participants
            recipient_public_keys: Map of participant_id -> encryption public key

        Returns:
            Round 2 output with encrypted shares
        """
        encrypted_shares = {}

        for recipient_id in range(1, total_participants + 1):
            if recipient_id == participant_id:
                continue

            # Evaluate polynomial at recipient's index
            share_value = self._evaluate_polynomial(coefficients, recipient_id)

            # In practice, encrypt with recipient's public key
            # For simplicity, we'll just use a basic XOR with hash
            pk = recipient_public_keys.get(recipient_id, b"\x00" * 33)
            key = hashlib.sha256(pk + participant_id.to_bytes(4, "big")).digest()
            share_bytes = share_value.to_bytes(32, "big")
            encrypted = bytes(a ^ b for a, b in zip(share_bytes, key))

            encrypted_shares[recipient_id] = encrypted

        return DKGRound2Output(
            participant_id=participant_id,
            encrypted_shares=encrypted_shares,
        )

    # Helper methods

    def _evaluate_polynomial(self, coefficients: list[int], x: int) -> int:
        """Evaluate polynomial at point x using Horner's method."""
        result = 0
        for coef in reversed(coefficients):
            result = (result * x + coef) % self.CURVE_ORDER
        return result

    def _lagrange_coefficient(
        self, i: int, participant_ids: list[int]
    ) -> int:
        """Compute Lagrange coefficient for participant i."""
        numerator = 1
        denominator = 1

        for j in participant_ids:
            if i == j:
                continue
            numerator = (numerator * (-j)) % self.CURVE_ORDER
            denominator = (denominator * (i - j)) % self.CURVE_ORDER

        # Compute numerator / denominator mod CURVE_ORDER
        return (numerator * pow(denominator, -1, self.CURVE_ORDER)) % self.CURVE_ORDER

    def _scalar_mult_g(self, scalar: int) -> Point:
        """Multiply generator by scalar."""
        return self._scalar_mult(Point.generator(), scalar)

    def _scalar_mult(self, point: Point, scalar: int) -> Point:
        """Scalar multiplication using double-and-add."""
        if point.is_identity:
            return Point.identity()

        result = Point.identity()
        addend = point
        scalar = scalar % self.CURVE_ORDER

        while scalar > 0:
            if scalar & 1:
                result = self._point_add(result, addend)
            addend = self._point_double(addend)
            scalar >>= 1

        return result

    def _point_add(self, p1: Point, p2: Point) -> Point:
        """Add two points on the curve."""
        if p1.is_identity:
            return p2
        if p2.is_identity:
            return p1
        if p1.x == p2.x and p1.y != p2.y:
            return Point.identity()
        if p1 == p2:
            return self._point_double(p1)

        # Compute slope
        dx = (p2.x - p1.x) % SECP256K1_P
        dy = (p2.y - p1.y) % SECP256K1_P
        slope = (dy * pow(dx, -1, SECP256K1_P)) % SECP256K1_P

        # Compute new point
        x3 = (slope * slope - p1.x - p2.x) % SECP256K1_P
        y3 = (slope * (p1.x - x3) - p1.y) % SECP256K1_P

        return Point(x3, y3, p1.curve_order)

    def _point_double(self, p: Point) -> Point:
        """Double a point on the curve."""
        if p.is_identity or p.y == 0:
            return Point.identity()

        # Compute slope (3x^2 + a) / 2y, where a = 0 for secp256k1
        numerator = (3 * p.x * p.x) % SECP256K1_P
        denominator = (2 * p.y) % SECP256K1_P
        slope = (numerator * pow(denominator, -1, SECP256K1_P)) % SECP256K1_P

        # Compute new point
        x3 = (slope * slope - 2 * p.x) % SECP256K1_P
        y3 = (slope * (p.x - x3) - p.y) % SECP256K1_P

        return Point(x3, y3, p.curve_order)

    def _point_from_bytes(self, data: bytes) -> Point:
        """Deserialize a point from compressed format."""
        if len(data) == 1 and data[0] == 0:
            return Point.identity()

        if len(data) != 33:
            raise ValueError(f"Invalid point length: {len(data)}")

        prefix = data[0]
        x = int.from_bytes(data[1:], "big")

        # Compute y from x: y^2 = x^3 + 7 (secp256k1)
        y_squared = (pow(x, 3, SECP256K1_P) + 7) % SECP256K1_P

        # Compute square root using Tonelli-Shanks (simplified for p ≡ 3 mod 4)
        y = pow(y_squared, (SECP256K1_P + 1) // 4, SECP256K1_P)

        # Choose correct y based on prefix
        if prefix == 0x02 and y % 2 != 0:
            y = SECP256K1_P - y
        elif prefix == 0x03 and y % 2 == 0:
            y = SECP256K1_P - y

        return Point(x, y, SECP256K1_ORDER)


# Singleton instance
threshold_engine = ThresholdEngine()
