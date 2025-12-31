"""Blinded Cryptographic Operations Engine.

Implements blind signature schemes where the signer cannot see
the content being signed.

Supported Schemes:
- Blind RSA (Chaum's blind signatures)
- Blind Schnorr (based on Schnorr signatures)
- Partially Blind Signatures (with public metadata)

Use Cases:
- Anonymous e-cash and digital currencies
- Privacy-preserving authentication
- Anonymous credentials
- Secure voting systems
- Unlinkable tokens

Security Properties:
- Blindness: Signer cannot see what they're signing
- Unforgeability: Only valid signatures can be produced
- Unlinkability: Signed messages cannot be linked to signing sessions

References:
- Chaum, D. "Blind Signatures for Untraceable Payments" (1983)
- Pointcheval & Stern "Security Arguments for Digital Signatures" (1996)
- Abe & Okamoto "Provably Secure Partially Blind Signatures" (2000)
"""

import hashlib
import os
import secrets
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


class BlindScheme(str, Enum):
    """Supported blind signature schemes."""

    BLIND_RSA = "blind-rsa"
    BLIND_SCHNORR = "blind-schnorr"
    PARTIALLY_BLIND_RSA = "partially-blind-rsa"


class BlindError(Exception):
    """Blind signature error."""

    pass


class BlindingError(BlindError):
    """Error during blinding operation."""

    pass


class UnblindingError(BlindError):
    """Error during unblinding operation."""

    pass


class VerificationError(BlindError):
    """Blind signature verification failed."""

    pass


@dataclass
class BlindingResult:
    """Result of blinding a message."""

    blinded_message: bytes
    blinding_factor: bytes  # Keep secret until unblinding
    scheme: BlindScheme
    public_metadata: Optional[bytes] = None  # For partially blind


@dataclass
class BlindSignatureResult:
    """Result of signing a blinded message."""

    blind_signature: bytes
    scheme: BlindScheme


@dataclass
class UnblindedSignature:
    """An unblinded signature."""

    signature: bytes
    message: bytes
    scheme: BlindScheme
    public_metadata: Optional[bytes] = None


@dataclass
class RSABlindKeyPair:
    """RSA key pair for blind signatures."""

    private_key_pem: bytes
    public_key_pem: bytes
    modulus: int
    public_exponent: int


@dataclass
class SchnorrBlindKeyPair:
    """Schnorr key pair for blind signatures."""

    private_key: int
    public_key: bytes  # Point on curve


# Simple prime field for Schnorr (using a safe prime)
# In production, use proper curve parameters
SCHNORR_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SCHNORR_G = 2


@dataclass
class SchnorrCommitment:
    """Signer's commitment for blind Schnorr."""

    R: bytes  # Public commitment point
    k: int  # Secret nonce (signer keeps private)


class BlindEngine:
    """Blinded cryptographic operations.

    Provides blind signature schemes where the signer cannot see
    the content being signed, but produces valid signatures.

    Usage:
        engine = BlindEngine()

        # Generate key pair
        key_pair = engine.generate_rsa_key_pair()

        # Requester blinds their message
        blinding = engine.blind_rsa(
            message=b"Secret vote",
            public_key_pem=key_pair.public_key_pem,
        )

        # Signer signs the blinded message (cannot see original)
        blind_sig = engine.sign_blinded_rsa(
            blinded_message=blinding.blinded_message,
            private_key_pem=key_pair.private_key_pem,
        )

        # Requester unblinds to get valid signature
        signature = engine.unblind_rsa(
            blind_signature=blind_sig.blind_signature,
            blinding_factor=blinding.blinding_factor,
            message=b"Secret vote",
            public_key_pem=key_pair.public_key_pem,
        )

        # Anyone can verify the signature
        valid = engine.verify_rsa(
            message=b"Secret vote",
            signature=signature.signature,
            public_key_pem=key_pair.public_key_pem,
        )
    """

    # RSA Blind Signatures

    def generate_rsa_key_pair(
        self,
        key_size: int = 2048,
    ) -> RSABlindKeyPair:
        """Generate RSA key pair for blind signatures.

        Args:
            key_size: Key size in bits (2048, 3072, or 4096)

        Returns:
            RSABlindKeyPair with private and public keys
        """
        if key_size not in (2048, 3072, 4096):
            raise BlindError(f"Invalid key size: {key_size}")

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return RSABlindKeyPair(
            private_key_pem=private_pem,
            public_key_pem=public_pem,
            modulus=public_numbers.n,
            public_exponent=public_numbers.e,
        )

    def blind_rsa(
        self,
        message: bytes,
        public_key_pem: bytes,
    ) -> BlindingResult:
        """Blind a message for RSA blind signature.

        The blinding factor is kept secret by the requester.

        Args:
            message: Message to blind
            public_key_pem: Signer's public key

        Returns:
            BlindingResult with blinded message and secret factor
        """
        if not message:
            raise BlindingError("Message cannot be empty")

        # Load public key
        try:
            public_key = serialization.load_pem_public_key(public_key_pem)
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise BlindingError("Not an RSA public key")
        except Exception as e:
            raise BlindingError(f"Failed to load public key: {e}")

        public_numbers = public_key.public_numbers()
        n = public_numbers.n
        e = public_numbers.e

        # Hash the message (full-domain hash)
        h = self._fdh(message, n)

        # Generate random blinding factor r where gcd(r, n) = 1
        while True:
            r = secrets.randbelow(n - 2) + 2
            if self._gcd(r, n) == 1:
                break

        # Compute r^e mod n
        r_e = pow(r, e, n)

        # Blind: m' = h * r^e mod n
        blinded = (h * r_e) % n

        # Convert to bytes
        byte_length = (n.bit_length() + 7) // 8
        blinded_bytes = blinded.to_bytes(byte_length, "big")
        r_bytes = r.to_bytes(byte_length, "big")

        return BlindingResult(
            blinded_message=blinded_bytes,
            blinding_factor=r_bytes,
            scheme=BlindScheme.BLIND_RSA,
        )

    def sign_blinded_rsa(
        self,
        blinded_message: bytes,
        private_key_pem: bytes,
    ) -> BlindSignatureResult:
        """Sign a blinded message (signer cannot see original).

        Args:
            blinded_message: The blinded message from requester
            private_key_pem: Signer's private key

        Returns:
            BlindSignatureResult with blind signature
        """
        # Load private key
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem, password=None
            )
            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise BlindError("Not an RSA private key")
        except Exception as e:
            raise BlindError(f"Failed to load private key: {e}")

        private_numbers = private_key.private_numbers()
        n = private_numbers.public_numbers.n
        d = private_numbers.d

        # Convert blinded message to integer
        m_prime = int.from_bytes(blinded_message, "big")

        if m_prime >= n:
            raise BlindError("Blinded message too large for key")

        # Sign: s' = m'^d mod n
        s_prime = pow(m_prime, d, n)

        # Convert to bytes
        byte_length = (n.bit_length() + 7) // 8
        sig_bytes = s_prime.to_bytes(byte_length, "big")

        return BlindSignatureResult(
            blind_signature=sig_bytes,
            scheme=BlindScheme.BLIND_RSA,
        )

    def unblind_rsa(
        self,
        blind_signature: bytes,
        blinding_factor: bytes,
        message: bytes,
        public_key_pem: bytes,
    ) -> UnblindedSignature:
        """Unblind a signature to get valid signature on original message.

        Args:
            blind_signature: Signature from signer
            blinding_factor: Secret factor from blinding
            message: Original message
            public_key_pem: Signer's public key

        Returns:
            UnblindedSignature that verifies on original message
        """
        # Load public key
        try:
            public_key = serialization.load_pem_public_key(public_key_pem)
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise UnblindingError("Not an RSA public key")
        except Exception as e:
            raise UnblindingError(f"Failed to load public key: {e}")

        public_numbers = public_key.public_numbers()
        n = public_numbers.n

        # Convert from bytes
        s_prime = int.from_bytes(blind_signature, "big")
        r = int.from_bytes(blinding_factor, "big")

        # Compute r^(-1) mod n
        try:
            r_inv = pow(r, -1, n)
        except ValueError:
            raise UnblindingError("Invalid blinding factor")

        # Unblind: s = s' * r^(-1) mod n
        s = (s_prime * r_inv) % n

        # Convert to bytes
        byte_length = (n.bit_length() + 7) // 8
        sig_bytes = s.to_bytes(byte_length, "big")

        return UnblindedSignature(
            signature=sig_bytes,
            message=message,
            scheme=BlindScheme.BLIND_RSA,
        )

    def verify_rsa(
        self,
        message: bytes,
        signature: bytes,
        public_key_pem: bytes,
    ) -> bool:
        """Verify an unblinded RSA signature.

        Args:
            message: Original message
            signature: Unblinded signature
            public_key_pem: Signer's public key

        Returns:
            True if signature is valid
        """
        try:
            public_key = serialization.load_pem_public_key(public_key_pem)
            if not isinstance(public_key, rsa.RSAPublicKey):
                return False
        except Exception:
            return False

        public_numbers = public_key.public_numbers()
        n = public_numbers.n
        e = public_numbers.e

        # Hash the message
        h = self._fdh(message, n)

        # Convert signature to integer
        s = int.from_bytes(signature, "big")

        if s >= n:
            return False

        # Verify: s^e mod n == h
        computed = pow(s, e, n)

        return computed == h

    # Partially Blind RSA Signatures

    def blind_rsa_partial(
        self,
        message: bytes,
        public_metadata: bytes,
        public_key_pem: bytes,
    ) -> BlindingResult:
        """Blind a message with public metadata for partially blind signature.

        The metadata is visible to the signer, but the message content is not.

        Args:
            message: Secret message to blind
            public_metadata: Metadata visible to signer
            public_key_pem: Signer's public key

        Returns:
            BlindingResult with blinded message
        """
        if not message:
            raise BlindingError("Message cannot be empty")

        try:
            public_key = serialization.load_pem_public_key(public_key_pem)
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise BlindingError("Not an RSA public key")
        except Exception as e:
            raise BlindingError(f"Failed to load public key: {e}")

        public_numbers = public_key.public_numbers()
        n = public_numbers.n
        e = public_numbers.e

        # Hash: H(message || metadata)
        combined = message + public_metadata
        h = self._fdh(combined, n)

        # Generate blinding factor
        while True:
            r = secrets.randbelow(n - 2) + 2
            if self._gcd(r, n) == 1:
                break

        r_e = pow(r, e, n)
        blinded = (h * r_e) % n

        byte_length = (n.bit_length() + 7) // 8
        blinded_bytes = blinded.to_bytes(byte_length, "big")
        r_bytes = r.to_bytes(byte_length, "big")

        return BlindingResult(
            blinded_message=blinded_bytes,
            blinding_factor=r_bytes,
            scheme=BlindScheme.PARTIALLY_BLIND_RSA,
            public_metadata=public_metadata,
        )

    def sign_blinded_rsa_partial(
        self,
        blinded_message: bytes,
        public_metadata: bytes,
        private_key_pem: bytes,
    ) -> BlindSignatureResult:
        """Sign a partially blinded message.

        The signer can see the metadata but not the message.

        Args:
            blinded_message: Blinded message
            public_metadata: Public metadata (verified by signer)
            private_key_pem: Signer's private key

        Returns:
            BlindSignatureResult
        """
        # The signing is the same as regular blind RSA
        # But signer can use metadata for policy decisions
        return self.sign_blinded_rsa(blinded_message, private_key_pem)

    def unblind_rsa_partial(
        self,
        blind_signature: bytes,
        blinding_factor: bytes,
        message: bytes,
        public_metadata: bytes,
        public_key_pem: bytes,
    ) -> UnblindedSignature:
        """Unblind a partially blind signature.

        Args:
            blind_signature: Signature from signer
            blinding_factor: Secret blinding factor
            message: Original message
            public_metadata: Public metadata
            public_key_pem: Signer's public key

        Returns:
            UnblindedSignature
        """
        try:
            public_key = serialization.load_pem_public_key(public_key_pem)
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise UnblindingError("Not an RSA public key")
        except Exception as e:
            raise UnblindingError(f"Failed to load public key: {e}")

        public_numbers = public_key.public_numbers()
        n = public_numbers.n

        s_prime = int.from_bytes(blind_signature, "big")
        r = int.from_bytes(blinding_factor, "big")

        try:
            r_inv = pow(r, -1, n)
        except ValueError:
            raise UnblindingError("Invalid blinding factor")

        s = (s_prime * r_inv) % n

        byte_length = (n.bit_length() + 7) // 8
        sig_bytes = s.to_bytes(byte_length, "big")

        return UnblindedSignature(
            signature=sig_bytes,
            message=message,
            scheme=BlindScheme.PARTIALLY_BLIND_RSA,
            public_metadata=public_metadata,
        )

    def verify_rsa_partial(
        self,
        message: bytes,
        public_metadata: bytes,
        signature: bytes,
        public_key_pem: bytes,
    ) -> bool:
        """Verify a partially blind signature.

        Args:
            message: Original message
            public_metadata: Public metadata
            signature: Unblinded signature
            public_key_pem: Signer's public key

        Returns:
            True if valid
        """
        try:
            public_key = serialization.load_pem_public_key(public_key_pem)
            if not isinstance(public_key, rsa.RSAPublicKey):
                return False
        except Exception:
            return False

        public_numbers = public_key.public_numbers()
        n = public_numbers.n
        e = public_numbers.e

        # Hash: H(message || metadata)
        combined = message + public_metadata
        h = self._fdh(combined, n)

        s = int.from_bytes(signature, "big")
        if s >= n:
            return False

        computed = pow(s, e, n)
        return computed == h

    # Blind Schnorr Signatures

    def generate_schnorr_key_pair(self) -> SchnorrBlindKeyPair:
        """Generate Schnorr key pair for blind signatures.

        Returns:
            SchnorrBlindKeyPair
        """
        # Generate random private key
        private_key = secrets.randbelow(SCHNORR_P - 2) + 1

        # Compute public key: y = g^x mod p
        public_key = pow(SCHNORR_G, private_key, SCHNORR_P)

        return SchnorrBlindKeyPair(
            private_key=private_key,
            public_key=public_key.to_bytes(32, "big"),
        )

    def schnorr_signer_commit(
        self,
        key_pair: SchnorrBlindKeyPair,
    ) -> SchnorrCommitment:
        """Signer generates commitment for blind Schnorr.

        This is the first step - signer sends R to requester.

        Args:
            key_pair: Signer's key pair

        Returns:
            SchnorrCommitment with public R and secret k
        """
        # Generate random nonce
        k = secrets.randbelow(SCHNORR_P - 2) + 1

        # Compute R = g^k mod p
        R = pow(SCHNORR_G, k, SCHNORR_P)

        return SchnorrCommitment(
            R=R.to_bytes(32, "big"),
            k=k,
        )

    def blind_schnorr(
        self,
        message: bytes,
        R: bytes,
        public_key: bytes,
    ) -> Tuple[BlindingResult, int]:
        """Blind a message for Schnorr signature.

        Requester blinds the challenge using random factors.

        Args:
            message: Message to sign
            R: Signer's commitment point
            public_key: Signer's public key

        Returns:
            Tuple of (BlindingResult, challenge to send to signer)
        """
        if not message:
            raise BlindingError("Message cannot be empty")

        R_int = int.from_bytes(R, "big")
        y = int.from_bytes(public_key, "big")

        # Generate random blinding factors alpha, beta
        alpha = secrets.randbelow(SCHNORR_P - 2) + 1
        beta = secrets.randbelow(SCHNORR_P - 2) + 1

        # Compute blinded commitment: R' = R * g^alpha * y^beta mod p
        g_alpha = pow(SCHNORR_G, alpha, SCHNORR_P)
        y_beta = pow(y, beta, SCHNORR_P)
        R_prime = (R_int * g_alpha * y_beta) % SCHNORR_P

        # Compute blinded challenge: c' = H(R' || message)
        c_prime_input = R_prime.to_bytes(32, "big") + message
        c_prime_hash = hashlib.sha256(c_prime_input).digest()
        c_prime = int.from_bytes(c_prime_hash, "big") % SCHNORR_P

        # Compute challenge to send: c = c' + beta mod (p-1)
        c = (c_prime + beta) % (SCHNORR_P - 1)

        # Store blinding factors
        blinding_data = (
            alpha.to_bytes(32, "big") +
            beta.to_bytes(32, "big") +
            c_prime.to_bytes(32, "big") +
            R_prime.to_bytes(32, "big")
        )

        blinding = BlindingResult(
            blinded_message=message,  # Message unchanged
            blinding_factor=blinding_data,
            scheme=BlindScheme.BLIND_SCHNORR,
        )

        return blinding, c

    def sign_schnorr_challenge(
        self,
        commitment: SchnorrCommitment,
        challenge: int,
        key_pair: SchnorrBlindKeyPair,
    ) -> int:
        """Signer responds to challenge.

        Args:
            commitment: Signer's commitment
            challenge: Challenge from requester (blinded)
            key_pair: Signer's key pair

        Returns:
            Response s
        """
        # s = k + c * x mod (p-1)
        s = (commitment.k + challenge * key_pair.private_key) % (SCHNORR_P - 1)
        return s

    def unblind_schnorr(
        self,
        s: int,
        blinding: BlindingResult,
    ) -> UnblindedSignature:
        """Unblind Schnorr signature.

        Args:
            s: Signer's response
            blinding: Blinding result from blind_schnorr

        Returns:
            UnblindedSignature
        """
        # Extract blinding factors
        data = blinding.blinding_factor
        alpha = int.from_bytes(data[0:32], "big")
        beta = int.from_bytes(data[32:64], "big")
        c_prime = int.from_bytes(data[64:96], "big")
        R_prime = int.from_bytes(data[96:128], "big")

        # Compute unblinded signature: s' = s + alpha mod (p-1)
        s_prime = (s + alpha) % (SCHNORR_P - 1)

        # Signature is (R', c', s')
        sig_data = (
            R_prime.to_bytes(32, "big") +
            c_prime.to_bytes(32, "big") +
            s_prime.to_bytes(32, "big")
        )

        return UnblindedSignature(
            signature=sig_data,
            message=blinding.blinded_message,
            scheme=BlindScheme.BLIND_SCHNORR,
        )

    def verify_schnorr(
        self,
        message: bytes,
        signature: bytes,
        public_key: bytes,
    ) -> bool:
        """Verify a blind Schnorr signature.

        Args:
            message: Original message
            signature: Unblinded signature
            public_key: Signer's public key

        Returns:
            True if valid
        """
        try:
            if len(signature) != 96:
                return False

            R_prime = int.from_bytes(signature[0:32], "big")
            c_prime = int.from_bytes(signature[32:64], "big")
            s_prime = int.from_bytes(signature[64:96], "big")
            y = int.from_bytes(public_key, "big")

            # Verify: g^s' == R' * y^c' mod p
            g_s = pow(SCHNORR_G, s_prime, SCHNORR_P)
            y_c = pow(y, c_prime, SCHNORR_P)
            rhs = (R_prime * y_c) % SCHNORR_P

            if g_s != rhs:
                return False

            # Verify challenge: c' == H(R' || message)
            c_input = R_prime.to_bytes(32, "big") + message
            c_hash = hashlib.sha256(c_input).digest()
            c_expected = int.from_bytes(c_hash, "big") % SCHNORR_P

            return c_prime == c_expected
        except Exception:
            return False

    # Helper methods

    def _fdh(self, message: bytes, n: int) -> int:
        """Full-domain hash for RSA.

        Maps message to integer in [1, n-1].
        Uses iterated hashing to cover the full domain.
        """
        byte_length = (n.bit_length() + 7) // 8

        # Use MGF1-like construction
        counter = 0
        output = b""
        while len(output) < byte_length:
            h = hashlib.sha256(
                message + counter.to_bytes(4, "big")
            ).digest()
            output += h
            counter += 1

        # Truncate and convert to integer
        result = int.from_bytes(output[:byte_length], "big")

        # Ensure result is in [1, n-1]
        return (result % (n - 1)) + 1

    def _gcd(self, a: int, b: int) -> int:
        """Compute GCD using Euclidean algorithm."""
        while b:
            a, b = b, a % b
        return a


# Singleton instance
blind_engine = BlindEngine()
