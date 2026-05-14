"""PQC fixture for release smoke.

Imports the NIST FIPS 203 / 204 standardized algorithms so cryptoscan
surfaces PQC-MLKEM and PQC-MLDSA findings with quantumRisk=SAFE.
"""
from __future__ import annotations

import pqcrypto.kem.ml_kem_768 as kem
import pqcrypto.sign.ml_dsa_65 as sig

ALGORITHMS = ("ML-KEM-768", "ML-DSA-65")


def new_kem():
    return kem.generate_keypair()


def new_signer():
    return sig.generate_keypair()
