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
    KeyError,
)
from cryptoserve_core.encoding import (
    encode_ciphertext,
    decode_ciphertext,
    to_base64,
    from_base64,
)

__version__ = "0.2.0"

__all__ = [
    # Ciphers
    "AESGCMCipher",
    "ChaCha20Cipher",
    "CipherError",
    # Key management
    "KeyDerivation",
    "KeyError",
    # Encoding
    "encode_ciphertext",
    "decode_ciphertext",
    "to_base64",
    "from_base64",
]
