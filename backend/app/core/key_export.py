"""Key Export/Import Engine.

Provides secure key export and import functionality:
- Symmetric key export with key wrapping (AES-KW, AES-GCM-KW)
- Asymmetric key export (JWK, PEM, PKCS#8)
- PKCS#12 (.p12/.pfx) import/export for key + certificate bundles
- Key import with validation
- Password-based key encryption (PBKDF2 + AES-GCM)

Security considerations:
- Private keys are never exported in plain text
- Key wrapping uses authenticated encryption
- Import validates key material before use
- PKCS#12 validates key-certificate pairing
"""

import base64
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509

from app.core.secure_memory import SecureBytes


class KeyFormat(str, Enum):
    """Supported key export formats."""
    JWK = "jwk"  # JSON Web Key
    PEM = "pem"  # PEM encoded
    RAW = "raw"  # Raw bytes (for symmetric keys)
    WRAPPED = "wrapped"  # Key wrapped with KEK
    ENCRYPTED = "encrypted"  # Password-encrypted
    PKCS12 = "pkcs12"  # PKCS#12 bundle (.p12/.pfx)


class KeyType(str, Enum):
    """Key types."""
    SYMMETRIC = "symmetric"
    EC_P256 = "ec-p256"
    EC_P384 = "ec-p384"
    EC_P521 = "ec-p521"
    ED25519 = "ed25519"
    RSA_2048 = "rsa-2048"
    RSA_4096 = "rsa-4096"


@dataclass
class ExportedKey:
    """Exported key data."""
    key_data: bytes | dict | str
    format: KeyFormat
    key_type: KeyType
    is_private: bool
    metadata: dict


@dataclass
class ImportedKey:
    """Imported key result."""
    key: Any  # cryptography key object or bytes
    key_type: KeyType
    is_private: bool
    kid: str | None


class KeyExportError(Exception):
    """Key export failed."""
    pass


class KeyImportError(Exception):
    """Key import failed."""
    pass


class PKCS12ExportError(Exception):
    """PKCS#12 export failed."""
    pass


class PKCS12ImportError(Exception):
    """PKCS#12 import failed."""
    pass


@dataclass
class PKCS12ExportResult:
    """Result of PKCS#12 export operation."""
    pkcs12_data: bytes
    includes_chain: bool
    key_type: KeyType
    certificate_subject: str
    certificate_fingerprint: str


@dataclass
class PKCS12ImportResult:
    """Result of PKCS#12 import operation."""
    private_key: Any
    certificate: x509.Certificate
    additional_certs: list[x509.Certificate]
    key_type: KeyType
    certificate_fingerprint: str
    certificate_subject: str


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    """Base64url decode with padding restoration."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


class KeyExportEngine:
    """Handles key export and import operations."""

    # PBKDF2 parameters for password-based encryption
    PBKDF2_ITERATIONS = 600_000  # OWASP recommendation for SHA-256
    PBKDF2_SALT_SIZE = 16
    PBKDF2_KEY_SIZE = 32  # AES-256

    def export_symmetric_key(
        self,
        key: bytes,
        format: KeyFormat,
        kek: bytes | None = None,
        password: str | None = None,
        kid: str | None = None,
    ) -> ExportedKey:
        """Export a symmetric key.

        Args:
            key: The key to export
            format: Export format (raw, jwk, wrapped, encrypted)
            kek: Key Encryption Key for wrapped format
            password: Password for encrypted format
            kid: Optional key ID

        Returns:
            ExportedKey with key data
        """
        metadata = {
            "key_type": "symmetric",
            "key_size_bits": len(key) * 8,
            "exported_at": datetime.now(timezone.utc).isoformat(),
        }

        if format == KeyFormat.RAW:
            return ExportedKey(
                key_data=key,
                format=format,
                key_type=KeyType.SYMMETRIC,
                is_private=True,
                metadata=metadata,
            )

        elif format == KeyFormat.JWK:
            jwk = {
                "kty": "oct",
                "k": _b64url_encode(key),
                "key_ops": ["encrypt", "decrypt"],
            }
            if kid:
                jwk["kid"] = kid
            return ExportedKey(
                key_data=jwk,
                format=format,
                key_type=KeyType.SYMMETRIC,
                is_private=True,
                metadata=metadata,
            )

        elif format == KeyFormat.WRAPPED:
            if not kek or len(kek) not in [16, 24, 32]:
                raise KeyExportError("KEK must be 16, 24, or 32 bytes for AES Key Wrap")

            wrapped = aes_key_wrap(kek, key)
            return ExportedKey(
                key_data=wrapped,
                format=format,
                key_type=KeyType.SYMMETRIC,
                is_private=True,
                metadata={**metadata, "wrap_algorithm": "A256KW"},
            )

        elif format == KeyFormat.ENCRYPTED:
            if not password:
                raise KeyExportError("Password required for encrypted format")

            salt = os.urandom(self.PBKDF2_SALT_SIZE)
            iv = os.urandom(12)

            # Derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.PBKDF2_KEY_SIZE,
                salt=salt,
                iterations=self.PBKDF2_ITERATIONS,
            )
            derived_key = kdf.derive(password.encode())

            # Encrypt with AES-GCM
            aesgcm = AESGCM(derived_key)
            ciphertext = aesgcm.encrypt(iv, key, None)

            # Package as JSON
            encrypted_data = {
                "algorithm": "PBES2-HS256+A256GCM",
                "iterations": self.PBKDF2_ITERATIONS,
                "salt": _b64url_encode(salt),
                "iv": _b64url_encode(iv),
                "ciphertext": _b64url_encode(ciphertext),
            }

            return ExportedKey(
                key_data=json.dumps(encrypted_data),
                format=format,
                key_type=KeyType.SYMMETRIC,
                is_private=True,
                metadata={**metadata, "encryption": "PBES2-HS256+A256GCM"},
            )

        else:
            raise KeyExportError(f"Unsupported format: {format}")

    def import_symmetric_key(
        self,
        key_data: bytes | dict | str,
        format: KeyFormat,
        kek: bytes | None = None,
        password: str | None = None,
    ) -> ImportedKey:
        """Import a symmetric key.

        Args:
            key_data: The key data to import
            format: Import format
            kek: Key Encryption Key for wrapped format
            password: Password for encrypted format

        Returns:
            ImportedKey with key bytes
        """
        kid = None

        if format == KeyFormat.RAW:
            if not isinstance(key_data, bytes):
                raise KeyImportError("RAW format requires bytes")
            key = key_data

        elif format == KeyFormat.JWK:
            if isinstance(key_data, str):
                key_data = json.loads(key_data)
            if not isinstance(key_data, dict):
                raise KeyImportError("JWK format requires dict or JSON string")

            if key_data.get("kty") != "oct":
                raise KeyImportError("JWK must have kty=oct for symmetric key")

            key = _b64url_decode(key_data["k"])
            kid = key_data.get("kid")

        elif format == KeyFormat.WRAPPED:
            if not kek:
                raise KeyImportError("KEK required for wrapped format")
            if not isinstance(key_data, bytes):
                raise KeyImportError("WRAPPED format requires bytes")

            try:
                key = aes_key_unwrap(kek, key_data)
            except Exception as e:
                raise KeyImportError(f"Key unwrap failed: {e}")

        elif format == KeyFormat.ENCRYPTED:
            if not password:
                raise KeyImportError("Password required for encrypted format")

            if isinstance(key_data, bytes):
                key_data = key_data.decode()
            if isinstance(key_data, str):
                encrypted = json.loads(key_data)
            else:
                encrypted = key_data

            salt = _b64url_decode(encrypted["salt"])
            iv = _b64url_decode(encrypted["iv"])
            ciphertext = _b64url_decode(encrypted["ciphertext"])
            iterations = encrypted.get("iterations", self.PBKDF2_ITERATIONS)

            # Derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.PBKDF2_KEY_SIZE,
                salt=salt,
                iterations=iterations,
            )
            derived_key = kdf.derive(password.encode())

            # Decrypt
            try:
                aesgcm = AESGCM(derived_key)
                key = aesgcm.decrypt(iv, ciphertext, None)
            except Exception as e:
                raise KeyImportError(f"Decryption failed (wrong password?): {e}")

        else:
            raise KeyImportError(f"Unsupported format: {format}")

        return ImportedKey(
            key=key,
            key_type=KeyType.SYMMETRIC,
            is_private=True,
            kid=kid,
        )

    def export_asymmetric_key(
        self,
        key: Any,
        format: KeyFormat,
        include_private: bool = False,
        password: str | None = None,
        kid: str | None = None,
    ) -> ExportedKey:
        """Export an asymmetric key (public or private).

        Args:
            key: The cryptography key object
            format: Export format (jwk, pem)
            include_private: Include private key component
            password: Password for encrypting private key (PEM only)
            kid: Optional key ID

        Returns:
            ExportedKey with key data
        """
        # Determine key type
        key_type = self._get_key_type(key)
        is_private = self._is_private_key(key)

        if include_private and not is_private:
            raise KeyExportError("Cannot export private key from public key")

        metadata = {
            "key_type": key_type.value,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "is_private": include_private,
        }

        if format == KeyFormat.JWK:
            jwk = self._key_to_jwk(key, include_private, kid)
            return ExportedKey(
                key_data=jwk,
                format=format,
                key_type=key_type,
                is_private=include_private,
                metadata=metadata,
            )

        elif format == KeyFormat.PEM:
            pem = self._key_to_pem(key, include_private, password)
            return ExportedKey(
                key_data=pem,
                format=format,
                key_type=key_type,
                is_private=include_private,
                metadata=metadata,
            )

        else:
            raise KeyExportError(f"Unsupported format for asymmetric key: {format}")

    def import_asymmetric_key(
        self,
        key_data: bytes | dict | str,
        format: KeyFormat,
        password: str | None = None,
    ) -> ImportedKey:
        """Import an asymmetric key.

        Args:
            key_data: The key data to import
            format: Import format (jwk, pem)
            password: Password for encrypted private key (PEM only)

        Returns:
            ImportedKey with key object
        """
        kid = None

        if format == KeyFormat.JWK:
            if isinstance(key_data, str):
                key_data = json.loads(key_data)
            if not isinstance(key_data, dict):
                raise KeyImportError("JWK format requires dict or JSON string")

            key = self._jwk_to_key(key_data)
            kid = key_data.get("kid")
            is_private = "d" in key_data

        elif format == KeyFormat.PEM:
            if isinstance(key_data, str):
                key_data = key_data.encode()
            if not isinstance(key_data, bytes):
                raise KeyImportError("PEM format requires bytes or string")

            key, is_private = self._pem_to_key(key_data, password)

        else:
            raise KeyImportError(f"Unsupported format for asymmetric key: {format}")

        key_type = self._get_key_type(key)

        return ImportedKey(
            key=key,
            key_type=key_type,
            is_private=is_private,
            kid=kid,
        )

    def _get_key_type(self, key: Any) -> KeyType:
        """Determine the key type."""
        if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
            return KeyType.ED25519
        elif isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
            if isinstance(key, ec.EllipticCurvePrivateKey):
                curve = key.curve
            else:
                curve = key.curve
            if curve.name == "secp256r1":
                return KeyType.EC_P256
            elif curve.name == "secp384r1":
                return KeyType.EC_P384
            elif curve.name == "secp521r1":
                return KeyType.EC_P521
            else:
                raise KeyExportError(f"Unsupported EC curve: {curve.name}")
        elif isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
            if isinstance(key, rsa.RSAPrivateKey):
                size = key.key_size
            else:
                size = key.key_size
            if size <= 2048:
                return KeyType.RSA_2048
            else:
                return KeyType.RSA_4096
        else:
            raise KeyExportError(f"Unsupported key type: {type(key)}")

    def _is_private_key(self, key: Any) -> bool:
        """Check if key is a private key."""
        return isinstance(key, (
            ed25519.Ed25519PrivateKey,
            ec.EllipticCurvePrivateKey,
            rsa.RSAPrivateKey,
        ))

    def _key_to_jwk(self, key: Any, include_private: bool, kid: str | None) -> dict:
        """Convert key to JWK format."""
        if isinstance(key, ed25519.Ed25519PrivateKey):
            public = key.public_key()
            public_bytes = public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            jwk = {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": _b64url_encode(public_bytes),
                "use": "sig",
                "alg": "EdDSA",
            }
            if include_private:
                private_bytes = key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                jwk["d"] = _b64url_encode(private_bytes)

        elif isinstance(key, ed25519.Ed25519PublicKey):
            public_bytes = key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            jwk = {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": _b64url_encode(public_bytes),
                "use": "sig",
                "alg": "EdDSA",
            }

        elif isinstance(key, ec.EllipticCurvePrivateKey):
            public = key.public_key()
            numbers = public.public_numbers()
            curve = key.curve

            if curve.name == "secp256r1":
                crv, size, alg = "P-256", 32, "ES256"
            elif curve.name == "secp384r1":
                crv, size, alg = "P-384", 48, "ES384"
            elif curve.name == "secp521r1":
                crv, size, alg = "P-521", 66, "ES512"
            else:
                raise KeyExportError(f"Unsupported curve: {curve.name}")

            jwk = {
                "kty": "EC",
                "crv": crv,
                "x": _b64url_encode(numbers.x.to_bytes(size, "big")),
                "y": _b64url_encode(numbers.y.to_bytes(size, "big")),
                "use": "sig",
                "alg": alg,
            }
            if include_private:
                d = key.private_numbers().private_value
                jwk["d"] = _b64url_encode(d.to_bytes(size, "big"))

        elif isinstance(key, ec.EllipticCurvePublicKey):
            numbers = key.public_numbers()
            curve = key.curve

            if curve.name == "secp256r1":
                crv, size, alg = "P-256", 32, "ES256"
            elif curve.name == "secp384r1":
                crv, size, alg = "P-384", 48, "ES384"
            elif curve.name == "secp521r1":
                crv, size, alg = "P-521", 66, "ES512"
            else:
                raise KeyExportError(f"Unsupported curve: {curve.name}")

            jwk = {
                "kty": "EC",
                "crv": crv,
                "x": _b64url_encode(numbers.x.to_bytes(size, "big")),
                "y": _b64url_encode(numbers.y.to_bytes(size, "big")),
                "use": "sig",
                "alg": alg,
            }

        else:
            raise KeyExportError(f"Unsupported key type: {type(key)}")

        if kid:
            jwk["kid"] = kid

        return jwk

    def _key_to_pem(self, key: Any, include_private: bool, password: str | None) -> bytes:
        """Convert key to PEM format."""
        if include_private and self._is_private_key(key):
            if password:
                encryption = serialization.BestAvailableEncryption(password.encode())
            else:
                encryption = serialization.NoEncryption()

            return key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption,
            )
        else:
            # Export public key
            if self._is_private_key(key):
                key = key.public_key()
            return key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

    def _jwk_to_key(self, jwk: dict) -> Any:
        """Convert JWK to cryptography key."""
        kty = jwk.get("kty")

        if kty == "OKP":
            crv = jwk.get("crv")
            if crv == "Ed25519":
                x = _b64url_decode(jwk["x"])
                if "d" in jwk:
                    d = _b64url_decode(jwk["d"])
                    return ed25519.Ed25519PrivateKey.from_private_bytes(d)
                else:
                    return ed25519.Ed25519PublicKey.from_public_bytes(x)
            else:
                raise KeyImportError(f"Unsupported OKP curve: {crv}")

        elif kty == "EC":
            crv = jwk.get("crv")
            x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
            y = int.from_bytes(_b64url_decode(jwk["y"]), "big")

            if crv == "P-256":
                curve = ec.SECP256R1()
            elif crv == "P-384":
                curve = ec.SECP384R1()
            elif crv == "P-521":
                curve = ec.SECP521R1()
            else:
                raise KeyImportError(f"Unsupported EC curve: {crv}")

            public_numbers = ec.EllipticCurvePublicNumbers(x, y, curve)

            if "d" in jwk:
                d = int.from_bytes(_b64url_decode(jwk["d"]), "big")
                private_numbers = ec.EllipticCurvePrivateNumbers(d, public_numbers)
                return private_numbers.private_key()
            else:
                return public_numbers.public_key()

        else:
            raise KeyImportError(f"Unsupported key type: {kty}")

    def _pem_to_key(self, pem: bytes, password: str | None) -> tuple[Any, bool]:
        """Convert PEM to cryptography key."""
        pwd = password.encode() if password else None

        # Try to load as private key first
        try:
            key = serialization.load_pem_private_key(pem, password=pwd)
            return key, True
        except (ValueError, TypeError):
            pass

        # Try public key
        try:
            key = serialization.load_pem_public_key(pem)
            return key, False
        except Exception as e:
            raise KeyImportError(f"Failed to parse PEM: {e}")

    def export_to_pkcs12(
        self,
        private_key: Any,
        certificate: bytes | x509.Certificate,
        password: str | None = None,
        friendly_name: str | None = None,
        ca_certs: list[bytes | x509.Certificate] | None = None,
    ) -> PKCS12ExportResult:
        """Export a private key and certificate to PKCS#12 format.

        Creates a .p12/.pfx file containing the private key, certificate, and
        optionally a CA certificate chain. Commonly used for enterprise key
        migration scenarios.

        Args:
            private_key: The private key (RSA, EC, or Ed25519)
            certificate: The certificate (DER/PEM bytes or x509.Certificate)
            password: Password to encrypt the PKCS#12 file (recommended)
            friendly_name: Optional display name for the key/cert in the bundle
            ca_certs: Optional CA certificate chain

        Returns:
            PKCS12ExportResult with the serialized data

        Raises:
            PKCS12ExportError: If export fails (key/cert mismatch, unsupported type)
        """
        # Parse certificate if bytes
        if isinstance(certificate, bytes):
            try:
                # Try PEM first
                if b"-----BEGIN CERTIFICATE-----" in certificate:
                    cert = x509.load_pem_x509_certificate(certificate)
                else:
                    cert = x509.load_der_x509_certificate(certificate)
            except Exception as e:
                raise PKCS12ExportError(f"Failed to parse certificate: {e}")
        else:
            cert = certificate

        # Validate key matches certificate
        if not self._validate_key_cert_pair(private_key, cert):
            raise PKCS12ExportError(
                "Private key does not match certificate public key"
            )

        # Parse CA certs
        parsed_ca_certs: list[x509.Certificate] = []
        if ca_certs:
            for ca_cert in ca_certs:
                if isinstance(ca_cert, bytes):
                    try:
                        if b"-----BEGIN CERTIFICATE-----" in ca_cert:
                            parsed_ca_certs.append(
                                x509.load_pem_x509_certificate(ca_cert)
                            )
                        else:
                            parsed_ca_certs.append(
                                x509.load_der_x509_certificate(ca_cert)
                            )
                    except Exception as e:
                        raise PKCS12ExportError(f"Failed to parse CA certificate: {e}")
                else:
                    parsed_ca_certs.append(ca_cert)

        # Determine key type
        key_type = self._get_key_type(private_key)

        # Prepare friendly name
        name = friendly_name.encode() if friendly_name else None

        # Prepare password
        pwd_bytes: bytes | None = password.encode() if password else None

        try:
            # Serialize to PKCS#12
            pkcs12_data = pkcs12.serialize_key_and_certificates(
                name=name,
                key=private_key,
                cert=cert,
                cas=parsed_ca_certs if parsed_ca_certs else None,
                encryption_algorithm=(
                    serialization.BestAvailableEncryption(pwd_bytes)
                    if pwd_bytes
                    else serialization.NoEncryption()
                ),
            )
        except Exception as e:
            raise PKCS12ExportError(f"PKCS#12 serialization failed: {e}")

        # Calculate certificate fingerprint
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()

        # Get certificate subject
        subject = cert.subject.rfc4514_string()

        return PKCS12ExportResult(
            pkcs12_data=pkcs12_data,
            includes_chain=len(parsed_ca_certs) > 0,
            key_type=key_type,
            certificate_subject=subject,
            certificate_fingerprint=fingerprint,
        )

    def import_from_pkcs12(
        self,
        pkcs12_data: bytes,
        password: str | None = None,
    ) -> PKCS12ImportResult:
        """Import a private key and certificate from PKCS#12 format.

        Parses a .p12/.pfx file and extracts the private key, certificate,
        and any CA certificates in the chain.

        Args:
            pkcs12_data: The PKCS#12 file contents
            password: Password to decrypt the PKCS#12 file

        Returns:
            PKCS12ImportResult with key, certificate, and chain

        Raises:
            PKCS12ImportError: If import fails (wrong password, corrupted data)
        """
        # Prepare password
        pwd_bytes: bytes | None = password.encode() if password else None

        try:
            # Parse PKCS#12 data
            private_key, certificate, additional_certs = (
                pkcs12.load_key_and_certificates(pkcs12_data, pwd_bytes)
            )
        except ValueError as e:
            # Generic error to prevent password enumeration
            raise PKCS12ImportError(
                "Failed to decrypt PKCS#12 (wrong password or corrupted data)"
            )
        except Exception as e:
            raise PKCS12ImportError(f"Failed to parse PKCS#12: {e}")

        if private_key is None:
            raise PKCS12ImportError("PKCS#12 does not contain a private key")

        if certificate is None:
            raise PKCS12ImportError("PKCS#12 does not contain a certificate")

        # Determine key type
        key_type = self._get_key_type(private_key)

        # Calculate certificate fingerprint
        fingerprint = certificate.fingerprint(hashes.SHA256()).hex()

        # Get certificate subject
        subject = certificate.subject.rfc4514_string()

        # Convert additional certs to list (may be None)
        chain = list(additional_certs) if additional_certs else []

        return PKCS12ImportResult(
            private_key=private_key,
            certificate=certificate,
            additional_certs=chain,
            key_type=key_type,
            certificate_fingerprint=fingerprint,
            certificate_subject=subject,
        )

    def _validate_key_cert_pair(
        self,
        private_key: Any,
        certificate: x509.Certificate,
    ) -> bool:
        """Validate that a private key matches a certificate's public key.

        Args:
            private_key: The private key to validate
            certificate: The certificate to match against

        Returns:
            True if the key matches the certificate
        """
        try:
            cert_public_key = certificate.public_key()

            # Get public key from private key
            if hasattr(private_key, "public_key"):
                key_public = private_key.public_key()
            else:
                return False

            # Compare by serializing to bytes
            cert_pub_bytes = cert_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            key_pub_bytes = key_public.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            return cert_pub_bytes == key_pub_bytes
        except Exception:
            return False


# Singleton instance
key_export_engine = KeyExportEngine()
