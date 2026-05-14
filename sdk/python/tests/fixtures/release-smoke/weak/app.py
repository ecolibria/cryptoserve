"""Weak crypto fixture for release smoke.

Each line below maps to a finding ID the scanner must surface:
    - hashlib.new("md5", ...)    -> MD5-001 (CRITICAL, quantumRisk=VULNERABLE)
    - Crypto.Cipher.DES          -> DES-001 (CRITICAL, quantumRisk=VULNERABLE)
    - rsa.generate_private_key   -> RSA-001 + KEYSIZE-001 (RSA-1024 is weak)

AKIAIOSFODNN7EXAMPLE is AWS' own documented example access key — recognized
as a placeholder by GitHub push protection. Do NOT replace it with a real
key shape (sk_live_*, AKIA[...]N7REAL, etc.).
"""
from __future__ import annotations

import hashlib

from Crypto.Cipher import DES
from cryptography.hazmat.primitives.asymmetric import rsa

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"


def issue_key():
    # 1024-bit RSA is below the 2048-bit floor — surfaces KEYSIZE-001.
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


def fingerprint(value: bytes) -> str:
    # cryptoscan matches the algorithm name in the constructor string —
    # `hashlib.md5(value)` does not trigger MD5-001, but `hashlib.new("md5")`
    # does. Use the string form so the smoke runner can assert on the ID.
    h = hashlib.new("md5")
    h.update(value)
    return h.hexdigest()


def legacy_cipher():
    return DES.new(b"12345678", DES.MODE_ECB)
