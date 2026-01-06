"""Algorithm Resolution Engine.

Computes optimal cryptographic settings based on the 5-layer context model.
Takes data identity, regulatory, threat model, and access patterns as input,
and outputs derived requirements including the resolved algorithm.

Phase 1 enhancements:
- Usage context drives mode selection (at_rest, in_transit, streaming, etc.)
- Explicit cipher mode selection (GCM, CBC, CTR, CCM, XTS)
- Key size selection per algorithm family
- Enhanced rationale with factors and alternatives
"""

from app.schemas.context import (
    ContextConfig,
    DerivedRequirements,
    Sensitivity,
    Adversary,
    AccessFrequency,
    EncryptionUsageContext,
    CipherMode,
    AlgorithmRationale,
    AlgorithmAlternative,
    AlgorithmSuite,
)


# =============================================================================
# Algorithm Registry with Mode & Key Size Information
# =============================================================================

ALGORITHMS = {
    # AEAD Algorithms (Authenticated Encryption)
    "AES-128-GCM": {
        "family": "AES",
        "mode": CipherMode.GCM,
        "key_bits": 128,
        "security_bits": 128,
        "quantum_resistant": False,
        "latency_ms": 0.1,
        "hw_accelerated": True,
        "description": "AES-128 in GCM mode (FIPS 197, SP 800-38D)",
        "standards": ["FIPS 197", "NIST SP 800-38D"],
        "use_cases": [EncryptionUsageContext.AT_REST, EncryptionUsageContext.IN_TRANSIT],
    },
    "AES-256-GCM": {
        "family": "AES",
        "mode": CipherMode.GCM,
        "key_bits": 256,
        "security_bits": 256,
        "quantum_resistant": False,
        "latency_ms": 0.15,
        "hw_accelerated": True,
        "description": "AES-256 in GCM mode (FIPS 197, SP 800-38D)",
        "standards": ["FIPS 197", "NIST SP 800-38D"],
        "use_cases": [EncryptionUsageContext.AT_REST, EncryptionUsageContext.IN_TRANSIT],
    },
    "AES-256-GCM-SIV": {
        "family": "AES",
        "mode": CipherMode.GCM_SIV,
        "key_bits": 256,
        "security_bits": 256,
        "quantum_resistant": False,
        "latency_ms": 0.2,
        "hw_accelerated": True,
        "description": "AES-256 in GCM-SIV mode - nonce-misuse resistant (RFC 8452)",
        "standards": ["RFC 8452"],
        "use_cases": [EncryptionUsageContext.IN_USE, EncryptionUsageContext.AT_REST],
    },
    "AES-256-CBC": {
        "family": "AES",
        "mode": CipherMode.CBC,
        "key_bits": 256,
        "security_bits": 256,
        "quantum_resistant": False,
        "latency_ms": 0.12,
        "hw_accelerated": True,
        "description": "AES-256 in CBC mode - legacy, requires HMAC (FIPS 197, SP 800-38A)",
        "standards": ["FIPS 197", "NIST SP 800-38A"],
        "use_cases": [EncryptionUsageContext.AT_REST],
        "requires_mac": True,
        "legacy": True,
    },
    "AES-256-CTR": {
        "family": "AES",
        "mode": CipherMode.CTR,
        "key_bits": 256,
        "security_bits": 256,
        "quantum_resistant": False,
        "latency_ms": 0.1,
        "hw_accelerated": True,
        "description": "AES-256 in CTR mode - streaming, requires HMAC (FIPS 197, SP 800-38A)",
        "standards": ["FIPS 197", "NIST SP 800-38A"],
        "use_cases": [EncryptionUsageContext.STREAMING],
        "requires_mac": True,
    },
    "AES-256-CCM": {
        "family": "AES",
        "mode": CipherMode.CCM,
        "key_bits": 256,
        "security_bits": 256,
        "quantum_resistant": False,
        "latency_ms": 0.18,
        "hw_accelerated": True,
        "description": "AES-256 in CCM mode - AEAD for constrained devices (SP 800-38C)",
        "standards": ["NIST SP 800-38C"],
        "use_cases": [EncryptionUsageContext.IN_TRANSIT],
    },
    "AES-256-XTS": {
        "family": "AES",
        "mode": CipherMode.XTS,
        "key_bits": 512,  # XTS uses two 256-bit keys
        "security_bits": 256,
        "quantum_resistant": False,
        "latency_ms": 0.2,
        "hw_accelerated": True,
        "description": "AES-256 in XTS mode - disk encryption (IEEE 1619)",
        "standards": ["IEEE 1619", "NIST SP 800-38E"],
        "use_cases": [EncryptionUsageContext.DISK],
    },
    "ChaCha20-Poly1305": {
        "family": "ChaCha20",
        "mode": CipherMode.GCM,  # Poly1305 is similar to GCM's auth
        "key_bits": 256,
        "security_bits": 256,
        "quantum_resistant": False,
        "latency_ms": 0.12,
        "hw_accelerated": False,
        "description": "ChaCha20 with Poly1305 - good for non-AES-NI (RFC 8439)",
        "standards": ["RFC 8439"],
        "use_cases": [
            EncryptionUsageContext.IN_TRANSIT,
            EncryptionUsageContext.STREAMING,
            EncryptionUsageContext.AT_REST,
        ],
    },
    # Post-Quantum Hybrid Algorithms
    "AES-256-GCM+ML-KEM-768": {
        "family": "Hybrid",
        "mode": CipherMode.HYBRID,
        "classical_mode": CipherMode.GCM,
        "key_bits": 256,
        "security_bits": 256,
        "quantum_resistant": True,
        "quantum_security_bits": 192,
        "kem_algorithm": "ML-KEM-768",
        "latency_ms": 0.5,
        "hw_accelerated": True,
        "description": "Hybrid classical + post-quantum, NIST PQC Level 3 (FIPS 203)",
        "standards": ["FIPS 197", "FIPS 203"],
        "use_cases": [EncryptionUsageContext.AT_REST, EncryptionUsageContext.IN_TRANSIT],
    },
    "AES-256-GCM+ML-KEM-1024": {
        "family": "Hybrid",
        "mode": CipherMode.HYBRID,
        "classical_mode": CipherMode.GCM,
        "key_bits": 256,
        "security_bits": 256,
        "quantum_resistant": True,
        "quantum_security_bits": 256,
        "kem_algorithm": "ML-KEM-1024",
        "latency_ms": 0.7,
        "hw_accelerated": True,
        "description": "Hybrid classical + post-quantum, NIST PQC Level 5 (FIPS 203)",
        "standards": ["FIPS 197", "FIPS 203"],
        "use_cases": [EncryptionUsageContext.AT_REST, EncryptionUsageContext.IN_TRANSIT],
    },
    "ChaCha20-Poly1305+ML-KEM-768": {
        "family": "Hybrid",
        "mode": CipherMode.HYBRID,
        "classical_mode": CipherMode.GCM,  # ChaCha20-Poly1305 acts like GCM
        "key_bits": 256,
        "security_bits": 256,
        "quantum_resistant": True,
        "quantum_security_bits": 192,
        "kem_algorithm": "ML-KEM-768",
        "latency_ms": 0.55,
        "hw_accelerated": False,
        "description": "Hybrid ChaCha20-Poly1305 + ML-KEM-768, for non-AES-NI systems",
        "standards": ["RFC 8439", "FIPS 203"],
        "use_cases": [EncryptionUsageContext.AT_REST, EncryptionUsageContext.IN_TRANSIT],
    },
}

# Default algorithm when no special requirements
DEFAULT_ALGORITHM = "AES-256-GCM"

# Usage context to recommended mode mapping
USAGE_CONTEXT_MODE_MAP: dict[EncryptionUsageContext, CipherMode] = {
    EncryptionUsageContext.AT_REST: CipherMode.GCM,
    EncryptionUsageContext.IN_TRANSIT: CipherMode.GCM,
    EncryptionUsageContext.IN_USE: CipherMode.GCM_SIV,
    EncryptionUsageContext.STREAMING: CipherMode.CTR,
    EncryptionUsageContext.DISK: CipherMode.XTS,
}

# Usage context to recommended algorithm mapping
USAGE_CONTEXT_ALGORITHM_MAP: dict[EncryptionUsageContext, str] = {
    EncryptionUsageContext.AT_REST: "AES-256-GCM",
    EncryptionUsageContext.IN_TRANSIT: "AES-256-GCM",
    EncryptionUsageContext.IN_USE: "AES-256-GCM-SIV",
    EncryptionUsageContext.STREAMING: "ChaCha20-Poly1305",
    EncryptionUsageContext.DISK: "AES-256-XTS",
}

# Sensitivity to security requirements mapping
SENSITIVITY_REQUIREMENTS = {
    Sensitivity.CRITICAL: {
        "min_bits": 256,
        "audit_level": "full",
        "key_rotation_days": 30,
    },
    Sensitivity.HIGH: {
        "min_bits": 256,
        "audit_level": "detailed",
        "key_rotation_days": 90,
    },
    Sensitivity.MEDIUM: {
        "min_bits": 128,
        "audit_level": "standard",
        "key_rotation_days": 180,
    },
    Sensitivity.LOW: {
        "min_bits": 128,
        "audit_level": "minimal",
        "key_rotation_days": 365,
    },
}

# =============================================================================
# Signing Algorithm Registry
# =============================================================================

SIGNING_ALGORITHMS = {
    "ECDSA-P256": {
        "family": "ECDSA",
        "curve": "P-256",
        "key_bits": 256,
        "security_bits": 128,
        "quantum_resistant": False,
        "description": "ECDSA with NIST P-256 curve (FIPS 186-5)",
        "standards": ["FIPS 186-5"],
    },
    "ECDSA-P384": {
        "family": "ECDSA",
        "curve": "P-384",
        "key_bits": 384,
        "security_bits": 192,
        "quantum_resistant": False,
        "description": "ECDSA with NIST P-384 curve (FIPS 186-5)",
        "standards": ["FIPS 186-5"],
    },
    "Ed25519": {
        "family": "EdDSA",
        "curve": "Curve25519",
        "key_bits": 256,
        "security_bits": 128,
        "quantum_resistant": False,
        "description": "EdDSA with Curve25519 (RFC 8032)",
        "standards": ["RFC 8032"],
    },
    "ML-DSA-44": {
        "family": "ML-DSA",
        "key_bits": 1312,  # Public key size in bytes
        "security_bits": 128,
        "quantum_resistant": True,
        "nist_level": 2,
        "description": "ML-DSA Level 2 (FIPS 204)",
        "standards": ["FIPS 204"],
    },
    "ML-DSA-65": {
        "family": "ML-DSA",
        "key_bits": 1952,
        "security_bits": 192,
        "quantum_resistant": True,
        "nist_level": 3,
        "description": "ML-DSA Level 3 (FIPS 204)",
        "standards": ["FIPS 204"],
    },
    "ML-DSA-87": {
        "family": "ML-DSA",
        "key_bits": 2592,
        "security_bits": 256,
        "quantum_resistant": True,
        "nist_level": 5,
        "description": "ML-DSA Level 5 (FIPS 204)",
        "standards": ["FIPS 204"],
    },
}

# =============================================================================
# Hash Algorithm Registry
# =============================================================================

HASH_ALGORITHMS = {
    "SHA-256": {
        "family": "SHA-2",
        "output_bits": 256,
        "security_bits": 128,
        "description": "SHA-256 (FIPS 180-4)",
        "standards": ["FIPS 180-4"],
    },
    "SHA-384": {
        "family": "SHA-2",
        "output_bits": 384,
        "security_bits": 192,
        "description": "SHA-384 (FIPS 180-4)",
        "standards": ["FIPS 180-4"],
    },
    "SHA-512": {
        "family": "SHA-2",
        "output_bits": 512,
        "security_bits": 256,
        "description": "SHA-512 (FIPS 180-4)",
        "standards": ["FIPS 180-4"],
    },
    "SHA3-256": {
        "family": "SHA-3",
        "output_bits": 256,
        "security_bits": 128,
        "description": "SHA3-256 (FIPS 202)",
        "standards": ["FIPS 202"],
    },
    "SHA3-384": {
        "family": "SHA-3",
        "output_bits": 384,
        "security_bits": 192,
        "description": "SHA3-384 (FIPS 202)",
        "standards": ["FIPS 202"],
    },
    "SHA3-512": {
        "family": "SHA-3",
        "output_bits": 512,
        "security_bits": 256,
        "description": "SHA3-512 (FIPS 202)",
        "standards": ["FIPS 202"],
    },
}

# =============================================================================
# Key Derivation Function Registry
# =============================================================================

KDF_ALGORITHMS = {
    "HKDF-SHA256": {
        "family": "HKDF",
        "hash": "SHA-256",
        "security_bits": 128,
        "iterations": None,  # HKDF doesn't use iterations
        "description": "HKDF with SHA-256 (RFC 5869)",
        "standards": ["RFC 5869"],
        "use_case": "key_derivation",
    },
    "HKDF-SHA384": {
        "family": "HKDF",
        "hash": "SHA-384",
        "security_bits": 192,
        "iterations": None,
        "description": "HKDF with SHA-384 (RFC 5869)",
        "standards": ["RFC 5869"],
        "use_case": "key_derivation",
    },
    "HKDF-SHA512": {
        "family": "HKDF",
        "hash": "SHA-512",
        "security_bits": 256,
        "iterations": None,
        "description": "HKDF with SHA-512 (RFC 5869)",
        "standards": ["RFC 5869"],
        "use_case": "key_derivation",
    },
    "Argon2id": {
        "family": "Argon2",
        "hash": None,
        "security_bits": 256,
        "iterations": 3,  # Default: 3 iterations, 64MB memory, 4 parallelism
        "description": "Argon2id password hashing (RFC 9106)",
        "standards": ["RFC 9106"],
        "use_case": "password_hashing",
    },
    "PBKDF2-SHA256": {
        "family": "PBKDF2",
        "hash": "SHA-256",
        "security_bits": 128,
        "iterations": 600000,  # OWASP 2023 recommendation
        "description": "PBKDF2 with SHA-256 (NIST SP 800-132)",
        "standards": ["NIST SP 800-132"],
        "use_case": "password_hashing",
    },
}

# Sensitivity to algorithm suite mapping
SENSITIVITY_SUITE_MAP = {
    Sensitivity.CRITICAL: {
        "signing": "ECDSA-P384",
        "signing_pqc": "ML-DSA-87",
        "hash": "SHA-384",
        "kdf": "HKDF-SHA384",
    },
    Sensitivity.HIGH: {
        "signing": "ECDSA-P256",
        "signing_pqc": "ML-DSA-65",
        "hash": "SHA-256",
        "kdf": "HKDF-SHA256",
    },
    Sensitivity.MEDIUM: {
        "signing": "ECDSA-P256",
        "signing_pqc": "ML-DSA-44",
        "hash": "SHA-256",
        "kdf": "HKDF-SHA256",
    },
    Sensitivity.LOW: {
        "signing": "ECDSA-P256",
        "signing_pqc": "ML-DSA-44",
        "hash": "SHA-256",
        "kdf": "HKDF-SHA256",
    },
}


class AlgorithmResolver:
    """Resolves optimal cryptographic algorithm based on context configuration.

    The resolver analyzes all 5 layers of the context model and produces
    a comprehensive DerivedRequirements with detailed rationale.
    """

    def __init__(self, config: ContextConfig):
        self.config = config
        self.factors: list[str] = []
        self.alternatives: list[AlgorithmAlternative] = []

    def resolve(self) -> DerivedRequirements:
        """Compute derived requirements from context configuration."""
        self.factors = []
        self.alternatives = []

        # Step 1: Get base requirements from sensitivity
        sensitivity_req = SENSITIVITY_REQUIREMENTS[self.config.data_identity.sensitivity]
        min_bits = sensitivity_req["min_bits"]
        audit_level = sensitivity_req["audit_level"]
        key_rotation_days = sensitivity_req["key_rotation_days"]

        self.factors.append(
            f"Data sensitivity: {self.config.data_identity.sensitivity.value.upper()} " f"→ {min_bits}-bit minimum"
        )

        # Step 2: Determine usage context and preferred mode
        usage_context = self.config.data_identity.usage_context
        preferred_mode = USAGE_CONTEXT_MODE_MAP.get(usage_context, CipherMode.GCM)
        USAGE_CONTEXT_ALGORITHM_MAP.get(usage_context, DEFAULT_ALGORITHM)

        self.factors.append(f"Usage context: {usage_context.value} → {preferred_mode.value.upper()} mode recommended")

        # Step 3: Check for quantum resistance requirement
        quantum_resistant = self._needs_quantum_resistance()

        # Step 4: Adjust key rotation based on compliance
        if self.config.regulatory.frameworks:
            if any(f.upper() in ["PCI-DSS", "HIPAA"] for f in self.config.regulatory.frameworks):
                key_rotation_days = min(key_rotation_days, 90)
                self.factors.append(
                    f"Compliance: {', '.join(self.config.regulatory.frameworks)} "
                    f"→ {key_rotation_days}-day max rotation"
                )

        # Step 5: Consider adversary strength
        if Adversary.NATION_STATE in self.config.threat_model.adversaries:
            min_bits = max(min_bits, 256)
            self.factors.append("Threat model: Nation-state adversary → 256-bit minimum")

        # Step 6: Determine hardware acceleration
        hw_acceleration = self._should_use_hw_acceleration()

        # Step 7: Select algorithm considering all factors
        algorithm, mode, key_bits = self._select_algorithm(
            min_bits=min_bits,
            quantum_resistant=quantum_resistant,
            hw_acceleration=hw_acceleration,
            preferred_mode=preferred_mode,
            usage_context=usage_context,
        )

        # Build detailed rationale
        summary = self._build_summary(algorithm, usage_context)
        detailed_rationale = AlgorithmRationale(
            summary=summary,
            factors=self.factors,
            alternatives=self.alternatives,
        )

        # Step 8: Resolve full algorithm suite
        algorithm_suite = self._resolve_algorithm_suite(
            algorithm=algorithm,
            mode=mode,
            key_bits=key_bits,
            quantum_resistant=quantum_resistant,
        )

        return DerivedRequirements(
            minimum_security_bits=min_bits,
            quantum_resistant=quantum_resistant,
            key_rotation_days=key_rotation_days,
            resolved_algorithm=algorithm,
            resolved_mode=mode,
            resolved_key_bits=key_bits,
            audit_level=audit_level,
            hardware_acceleration=hw_acceleration,
            rationale=self.factors,  # Legacy compatibility
            detailed_rationale=detailed_rationale,
            algorithm_suite=algorithm_suite,
        )

    def _needs_quantum_resistance(self) -> bool:
        """Determine if quantum-resistant algorithms are needed."""
        # Explicit quantum adversary
        if Adversary.QUANTUM in self.config.threat_model.adversaries:
            self.factors.append("Threat model: Quantum computer adversary → post-quantum algorithms required")
            return True

        # Long protection lifetime (harvest now, decrypt later)
        if self.config.threat_model.protection_lifetime_years > 10:
            self.factors.append(
                f"Protection lifetime: {self.config.threat_model.protection_lifetime_years} years "
                "→ exceeds quantum threat horizon, post-quantum required"
            )
            return True

        # Nation-state adversary with long-term data
        if (
            Adversary.NATION_STATE in self.config.threat_model.adversaries
            and self.config.threat_model.protection_lifetime_years > 5
        ):
            self.factors.append("Threat model: Nation-state with 5+ year protection → quantum resistance recommended")
            return True

        return False

    def _should_use_hw_acceleration(self) -> bool:
        """Determine if hardware acceleration should be used."""
        # High frequency access benefits from AES-NI
        if self.config.access_patterns.frequency == AccessFrequency.HIGH:
            self.factors.append("Access pattern: High frequency → hardware acceleration beneficial")
            return True

        # Low latency requirements need hardware acceleration
        if (
            self.config.access_patterns.latency_requirement_ms is not None
            and self.config.access_patterns.latency_requirement_ms < 10
        ):
            self.factors.append(
                f"Latency requirement: {self.config.access_patterns.latency_requirement_ms}ms "
                "→ hardware acceleration required"
            )
            return True

        # High throughput needs hardware acceleration
        if (
            self.config.access_patterns.operations_per_second is not None
            and self.config.access_patterns.operations_per_second > 1000
        ):
            self.factors.append(
                f"Throughput: {self.config.access_patterns.operations_per_second} ops/sec "
                "→ hardware acceleration required"
            )
            return True

        return False

    def _select_algorithm(
        self,
        min_bits: int,
        quantum_resistant: bool,
        hw_acceleration: bool,
        preferred_mode: CipherMode,
        usage_context: EncryptionUsageContext,
    ) -> tuple[str, CipherMode, int]:
        """Select the optimal algorithm based on requirements.

        Returns:
            Tuple of (algorithm_name, mode, key_bits)
        """
        candidates = []

        for name, props in ALGORITHMS.items():
            # Filter by minimum security bits
            if props["security_bits"] < min_bits:
                continue

            # Filter by quantum resistance
            if quantum_resistant and not props["quantum_resistant"]:
                continue

            # Score by how well it matches usage context
            context_score = 0
            if usage_context in props.get("use_cases", []):
                context_score = 10

            # Score by mode preference
            mode_score = 5 if props["mode"] == preferred_mode else 0

            # Score by hardware acceleration
            hw_score = 3 if hw_acceleration and props.get("hw_accelerated", False) else 0

            # Penalize legacy algorithms
            legacy_penalty = -5 if props.get("legacy", False) else 0

            total_score = context_score + mode_score + hw_score + legacy_penalty

            candidates.append((name, props, total_score))

        if not candidates:
            # Fallback to strongest available
            self.factors.append("No algorithm meets all requirements, using strongest available")
            fallback = "AES-256-GCM+ML-KEM-1024" if quantum_resistant else "AES-256-GCM"
            props = ALGORITHMS[fallback]
            return fallback, props["mode"], props["key_bits"]

        # Sort by score (descending), then by latency (ascending)
        candidates.sort(key=lambda x: (-x[2], x[1]["latency_ms"]))

        selected_name, selected_props, _ = candidates[0]

        # Add alternatives
        for alt_name, alt_props, _ in candidates[1:4]:  # Top 3 alternatives
            reason = self._get_alternative_reason(alt_name, alt_props, selected_name)
            self.alternatives.append(AlgorithmAlternative(algorithm=alt_name, reason=reason))

        # Add specific alternatives based on context
        self._add_contextual_alternatives(selected_name, usage_context, hw_acceleration)

        self.factors.append(f"Selected: {selected_name} ({selected_props['description']})")

        return selected_name, selected_props["mode"], selected_props["key_bits"]

    def _get_alternative_reason(self, alt_name: str, alt_props: dict, selected_name: str) -> str:
        """Generate reason for considering an alternative algorithm."""
        if "ChaCha20" in alt_name and "AES" in selected_name:
            return "Better on systems without AES-NI hardware acceleration"
        if "GCM-SIV" in alt_name:
            return "Consider if nonce-misuse is a concern in your system"
        if "XTS" in alt_name:
            return "Recommended for full-disk or volume encryption"
        if "ML-KEM" in alt_name:
            return "Provides post-quantum security for long-term data protection"
        if "CTR" in alt_name:
            return "Better for streaming data or when parallelization is critical"
        if "CCM" in alt_name:
            return "Good for constrained/embedded devices with limited resources"
        return f"Alternative with similar security properties to {selected_name}"

    def _add_contextual_alternatives(
        self,
        selected: str,
        usage_context: EncryptionUsageContext,
        hw_acceleration: bool,
    ) -> None:
        """Add alternatives based on specific context."""
        # If AES selected but no HW accel, suggest ChaCha20
        if "AES" in selected and not hw_acceleration:
            if not any(a.algorithm == "ChaCha20-Poly1305" for a in self.alternatives):
                self.alternatives.append(
                    AlgorithmAlternative(
                        algorithm="ChaCha20-Poly1305",
                        reason="No hardware acceleration detected - may offer better performance",
                    )
                )

        # If streaming context, ensure CTR is mentioned
        if usage_context == EncryptionUsageContext.STREAMING:
            if not any("CTR" in a.algorithm for a in self.alternatives):
                self.alternatives.append(
                    AlgorithmAlternative(
                        algorithm="AES-256-CTR",
                        reason="Native streaming mode - pair with HMAC for authentication",
                    )
                )

        # If in_use context, ensure GCM-SIV is mentioned
        if usage_context == EncryptionUsageContext.IN_USE:
            if not any("GCM-SIV" in a.algorithm for a in self.alternatives):
                self.alternatives.append(
                    AlgorithmAlternative(
                        algorithm="AES-256-GCM-SIV",
                        reason="Nonce-misuse resistant - safer for in-memory operations",
                    )
                )

    def _build_summary(self, algorithm: str, usage_context: EncryptionUsageContext) -> str:
        """Build a human-readable summary of the selection."""
        props = ALGORITHMS.get(algorithm, {})
        mode = props.get("mode", CipherMode.GCM)

        context_descriptions = {
            EncryptionUsageContext.AT_REST: "database and file storage",
            EncryptionUsageContext.IN_TRANSIT: "API and network traffic",
            EncryptionUsageContext.IN_USE: "in-memory operations",
            EncryptionUsageContext.STREAMING: "real-time data streams",
            EncryptionUsageContext.DISK: "full disk encryption",
        }

        context_desc = context_descriptions.get(usage_context, "general use")

        if props.get("quantum_resistant"):
            return f"Post-quantum hybrid encryption for {context_desc} with {mode.value.upper()} mode"

        return f"AEAD encryption for {context_desc} with {mode.value.upper()} mode"

    def _resolve_algorithm_suite(
        self,
        algorithm: str,
        mode: CipherMode,
        key_bits: int,
        quantum_resistant: bool,
    ) -> AlgorithmSuite:
        """Resolve the complete cryptographic algorithm suite.

        Based on sensitivity, quantum requirements, and the selected symmetric algorithm,
        this method chooses appropriate signing, hash, and KDF algorithms.
        """
        sensitivity = self.config.data_identity.sensitivity
        suite_map = SENSITIVITY_SUITE_MAP.get(sensitivity, SENSITIVITY_SUITE_MAP[Sensitivity.MEDIUM])

        # Select signing algorithm
        if quantum_resistant:
            signing = suite_map["signing_pqc"]
        else:
            signing = suite_map["signing"]
        signing_props = SIGNING_ALGORITHMS.get(signing, SIGNING_ALGORITHMS["ECDSA-P256"])
        signing_key_bits = signing_props["key_bits"]

        # Select hash algorithm
        hash_algo = suite_map["hash"]
        hash_props = HASH_ALGORITHMS.get(hash_algo, HASH_ALGORITHMS["SHA-256"])
        hash_bits = hash_props["output_bits"]

        # Select KDF algorithm
        kdf = suite_map["kdf"]
        kdf_props = KDF_ALGORITHMS.get(kdf, KDF_ALGORITHMS["HKDF-SHA256"])
        kdf_iterations = kdf_props.get("iterations")

        return AlgorithmSuite(
            symmetric=algorithm,
            symmetric_mode=mode,
            symmetric_key_bits=key_bits,
            signing=signing,
            signing_key_bits=signing_key_bits,
            hash=hash_algo,
            hash_bits=hash_bits,
            kdf=kdf,
            kdf_iterations=kdf_iterations,
        )


def resolve_algorithm(config: ContextConfig) -> DerivedRequirements:
    """Convenience function to resolve algorithm for a context config."""
    resolver = AlgorithmResolver(config)
    return resolver.resolve()
