"""
CryptoServe Core - Pure cryptographic primitives.

This package provides low-level encryption/decryption without any network
dependencies. Use this if you want to bring your own key management.

For the full CryptoServe experience with managed keys, use the `cryptoserve` package.
"""

from cryptoserve_core.ciphers import (
    AESGCMCipher,
    ChaCha20Cipher,
    CipherError,
)
from cryptoserve_core.keys import (
    KeyDerivation,
    CryptoKeyError,
)
# Deprecated alias — use CryptoKeyError instead
KeyError = CryptoKeyError
from cryptoserve_core.encoding import (
    encode_ciphertext,
    decode_ciphertext,
    to_base64,
    from_base64,
)
from cryptoserve_core.easy import (
    encrypt,
    decrypt,
    encrypt_string,
    decrypt_string,
    encrypt_file,
    decrypt_file,
    EasyEncryptionError,
)
from cryptoserve_core.passwords import (
    hash_password,
    verify_password,
    check_strength,
    PasswordStrength,
    PasswordHashError,
)
from cryptoserve_core.tokens import (
    create_token,
    verify_token,
    decode_token,
    TokenError,
    TokenExpiredError,
    TokenVerificationError,
    TokenDecodeError,
)

__version__ = "0.4.1"

__all__ = [
    # Ciphers
    "AESGCMCipher",
    "ChaCha20Cipher",
    "CipherError",
    # Key management
    "KeyDerivation",
    "CryptoKeyError",
    "KeyError",  # Deprecated alias for CryptoKeyError
    # Encoding
    "encode_ciphertext",
    "decode_ciphertext",
    "to_base64",
    "from_base64",
    # Easy encryption
    "encrypt",
    "decrypt",
    "encrypt_string",
    "decrypt_string",
    "encrypt_file",
    "decrypt_file",
    "EasyEncryptionError",
    # Password hashing
    "hash_password",
    "verify_password",
    "check_strength",
    "PasswordStrength",
    "PasswordHashError",
    # JWT tokens
    "create_token",
    "verify_token",
    "decode_token",
    "TokenError",
    "TokenExpiredError",
    "TokenVerificationError",
    "TokenDecodeError",
]
