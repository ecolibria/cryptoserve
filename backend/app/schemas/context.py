"""Context schemas with 5-layer model.

Layers:
1. Data Identity - What is this data, and how bad if it leaks?
2. Regulatory Mapping - What rules govern this data?
3. Threat Model - What are we protecting against?
4. Access Patterns - How is this data used?
5. Derived Requirements - Computed optimal cryptography
"""

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field


class Sensitivity(str, Enum):
    """Data sensitivity levels that drive encryption strength."""

    CRITICAL = "critical"  # 256-bit, full audit
    HIGH = "high"  # 256-bit, detailed audit
    MEDIUM = "medium"  # 128-bit, standard audit
    LOW = "low"  # 128-bit, minimal audit


class DataCategory(str, Enum):
    """Categories of data for classification."""

    PERSONAL_IDENTIFIER = "personal_identifier"
    FINANCIAL = "financial"
    HEALTH = "health"
    AUTHENTICATION = "authentication"
    BUSINESS_CONFIDENTIAL = "business_confidential"
    GENERAL = "general"


class Adversary(str, Enum):
    """Types of adversaries to protect against."""

    OPPORTUNISTIC = "opportunistic_attacker"
    ORGANIZED_CRIME = "organized_crime"
    NATION_STATE = "nation_state"
    INSIDER = "insider_threat"
    QUANTUM = "quantum_computer"


class AccessFrequency(str, Enum):
    """How often the data is accessed."""

    HIGH = "high"  # > 1000 ops/sec
    MEDIUM = "medium"  # 100-1000 ops/sec
    LOW = "low"  # 10-100 ops/sec
    RARE = "rare"  # < 10 ops/sec


class PolicyEnforcement(str, Enum):
    """Policy enforcement levels for algorithm override control."""

    NONE = "none"  # Developer overrides allowed (current behavior)
    WARN = "warn"  # Allow override but log warning + return in response
    ENFORCE = "enforce"  # Reject requests that violate policy


class AlgorithmPolicy(BaseModel):
    """Admin-defined algorithm policy for a context.

    This allows admins to constrain which algorithms developers can use,
    regardless of any algorithm_override in the API request.
    """

    allowed_ciphers: list[str] = Field(
        default_factory=lambda: ["AES", "ChaCha20"], description="Allowed cipher families (e.g., AES, ChaCha20)"
    )
    allowed_modes: list[str] = Field(
        default_factory=lambda: ["gcm", "gcm-siv", "ccm"], description="Allowed cipher modes (e.g., gcm, cbc, ctr)"
    )
    min_key_bits: int = Field(default=128, ge=128, le=512, description="Minimum key size in bits")
    require_quantum_safe: bool = Field(default=False, description="Require quantum-safe/hybrid algorithms")


# =============================================================================
# Encryption Context & Cipher Modes (Phase 1 - Core Completeness)
# =============================================================================


class EncryptionUsageContext(str, Enum):
    """Where/how the encryption is being used.

    This eliminates the "AES is vague" problem by explicitly specifying
    the operational context, which drives mode and algorithm selection.
    """

    AT_REST = "at_rest"  # Databases, file storage, backups
    IN_TRANSIT = "in_transit"  # API calls, network traffic
    IN_USE = "in_use"  # Memory encryption, processing
    STREAMING = "streaming"  # Real-time data feeds
    DISK = "disk"  # Full volume/disk encryption


class CipherMode(str, Enum):
    """Cipher block modes for symmetric encryption.

    Each mode has specific properties and use cases:
    - GCM: Authenticated encryption, parallelizable, most common
    - GCM_SIV: Nonce-misuse resistant, safer in complex systems
    - CBC: Legacy compatibility, requires separate MAC
    - CTR: Stream mode, parallelizable, requires separate MAC
    - CCM: Authenticated, for constrained devices
    - XTS: Disk encryption, tweakable block cipher
    - HYBRID: Post-quantum hybrid (ML-KEM + AES-GCM)
    """

    GCM = "gcm"  # Galois/Counter Mode - AEAD, fast, hardware accelerated
    GCM_SIV = "gcm-siv"  # GCM with SIV - nonce-misuse resistant
    CBC = "cbc"  # Cipher Block Chaining - legacy, needs HMAC
    CTR = "ctr"  # Counter Mode - streaming, needs HMAC
    CCM = "ccm"  # Counter with CBC-MAC - constrained devices
    XTS = "xts"  # XEX-based Tweaked-codebook - disk encryption
    HYBRID = "hybrid"  # Post-quantum hybrid (ML-KEM + classical AEAD)


class KeySize(int, Enum):
    """Standard cryptographic key sizes in bits."""

    AES_128 = 128
    AES_192 = 192
    AES_256 = 256
    RSA_2048 = 2048
    RSA_3072 = 3072
    RSA_4096 = 4096
    ECC_256 = 256  # P-256, X25519
    ECC_384 = 384  # P-384
    ECC_521 = 521  # P-521


class AlgorithmOverride(BaseModel):
    """Explicit algorithm configuration for advanced users.

    Allows overriding the automatic algorithm selection when specific
    requirements demand it. Use with caution - the automatic selection
    is usually optimal.
    """

    cipher: str | None = Field(default=None, description="Cipher family (AES, ChaCha20)")
    mode: CipherMode | None = Field(default=None, description="Cipher mode (GCM, CBC, CTR, CCM, XTS)")
    key_bits: int | None = Field(default=None, description="Key size in bits (128, 192, 256 for AES)")

    def to_algorithm_name(self) -> str | None:
        """Convert override to standard algorithm name."""
        if not self.cipher:
            return None

        cipher = self.cipher.upper()
        if self.key_bits and self.mode:
            return f"{cipher}-{self.key_bits}-{self.mode.value.upper()}"
        elif self.key_bits:
            return f"{cipher}-{self.key_bits}"
        elif self.mode:
            return f"{cipher}-{self.mode.value.upper()}"
        return cipher


# =============================================================================
# Layer 1: Data Identity
# =============================================================================


class DataIdentity(BaseModel):
    """Layer 1: What is this data, and how bad if it leaks?"""

    category: DataCategory = Field(default=DataCategory.GENERAL, description="Primary data category")
    subcategory: str | None = Field(default=None, description="Specific classification within category")
    sensitivity: Sensitivity = Field(
        default=Sensitivity.MEDIUM, description="Sensitivity level - drives encryption strength"
    )
    usage_context: EncryptionUsageContext = Field(
        default=EncryptionUsageContext.AT_REST, description="Where/how encryption is used - drives mode selection"
    )
    pii: bool = Field(default=False, description="Contains personally identifiable information")
    phi: bool = Field(default=False, description="Contains protected health information")
    pci: bool = Field(default=False, description="Contains payment card data")
    notification_required: bool = Field(default=False, description="Must notify regulators if breached")
    examples: list[str] = Field(default_factory=list, description="Example data types for developer guidance")


# =============================================================================
# Layer 2: Regulatory Mapping
# =============================================================================


class RetentionPolicy(BaseModel):
    """Data retention requirements."""

    minimum_days: int | None = Field(default=None, description="Minimum retention period in days")
    maximum_days: int | None = Field(default=None, description="Maximum retention period in days")
    deletion_method: Literal["crypto_shred", "secure_delete", "standard"] = Field(
        default="standard", description="How to delete data when retention expires"
    )


class DataResidency(BaseModel):
    """Geographic restrictions on data storage."""

    allowed_regions: list[str] = Field(default_factory=list, description="AWS/cloud regions where data can be stored")
    prohibited_regions: list[str] = Field(default_factory=list, description="Regions where data must not be stored")


class RegulatoryMapping(BaseModel):
    """Layer 2: What rules govern this data?"""

    frameworks: list[str] = Field(
        default_factory=list, description="Compliance frameworks (GDPR, CCPA, PCI-DSS, HIPAA, SOX)"
    )
    data_residency: DataResidency | None = Field(default=None, description="Geographic restrictions")
    retention: RetentionPolicy | None = Field(default=None, description="Data retention requirements")
    cross_border_allowed: bool = Field(default=True, description="Whether data can cross national borders")


# =============================================================================
# Layer 3: Threat Model
# =============================================================================


class ThreatModel(BaseModel):
    """Layer 3: What are we protecting against?"""

    adversaries: list[Adversary] = Field(
        default_factory=lambda: [Adversary.OPPORTUNISTIC], description="Expected threat actors"
    )
    attack_vectors: list[str] = Field(default_factory=list, description="Expected attack vectors")
    protection_lifetime_years: float = Field(default=5.0, ge=0, description="How long data must stay protected")

    @computed_field
    @property
    def quantum_resistant_required(self) -> bool:
        """Quantum resistance needed if protection > 10 years or quantum adversary."""
        return self.protection_lifetime_years > 10 or Adversary.QUANTUM in self.adversaries


# =============================================================================
# Layer 4: Access Patterns
# =============================================================================


class AccessPatterns(BaseModel):
    """Layer 4: How is this data used?"""

    frequency: AccessFrequency = Field(default=AccessFrequency.MEDIUM, description="How often data is accessed")
    operations_per_second: int | None = Field(default=None, ge=0, description="Expected throughput")
    latency_requirement_ms: int | None = Field(
        default=None, ge=0, description="Maximum acceptable latency in milliseconds"
    )
    batch_operations: bool = Field(default=False, description="Whether bulk encrypt/decrypt is needed")
    search_required: bool = Field(default=False, description="Whether encrypted search is needed")


# =============================================================================
# Layer 5: Derived Requirements (Computed)
# =============================================================================


class AlgorithmAlternative(BaseModel):
    """An alternative algorithm that could be used."""

    algorithm: str = Field(description="Alternative algorithm name")
    reason: str = Field(description="When to consider this alternative")


class AlgorithmRationale(BaseModel):
    """Detailed explanation of why an algorithm was selected.

    Provides transparency into the decision-making process, showing
    factors considered and alternatives available.
    """

    summary: str = Field(description="One-line summary of the selection")
    factors: list[str] = Field(default_factory=list, description="Factors that influenced the selection")
    alternatives: list[AlgorithmAlternative] = Field(
        default_factory=list, description="Alternative algorithms and when to use them"
    )


class AlgorithmSuite(BaseModel):
    """Complete cryptographic algorithm suite for a context.

    Provides the full set of algorithms resolved for symmetric encryption,
    digital signatures, hashing, and key derivation.
    """

    # Symmetric encryption
    symmetric: str = Field(description="Symmetric encryption algorithm (e.g., AES-256-GCM)")
    symmetric_mode: CipherMode = Field(default=CipherMode.GCM, description="Cipher mode")
    symmetric_key_bits: int = Field(default=256, description="Key size in bits")

    # Digital signatures
    signing: str = Field(default="ECDSA-P256", description="Digital signature algorithm")
    signing_key_bits: int = Field(default=256, description="Signing key size in bits")

    # Hashing
    hash: str = Field(default="SHA-256", description="Hash algorithm")
    hash_bits: int = Field(default=256, description="Hash output size in bits")

    # Key derivation
    kdf: str = Field(default="HKDF-SHA256", description="Key derivation function")
    kdf_iterations: int | None = Field(default=None, description="KDF iterations (for PBKDF2/Argon2)")


class DerivedRequirements(BaseModel):
    """Layer 5: Computed optimal cryptography settings.

    This layer is automatically computed based on the other 4 layers.
    Users don't configure this directly.
    """

    minimum_security_bits: int = Field(description="Minimum key size in bits")
    quantum_resistant: bool = Field(description="Whether post-quantum algorithms are required")
    key_rotation_days: int = Field(description="How often to rotate keys")
    resolved_algorithm: str = Field(description="Final algorithm selection")
    resolved_mode: CipherMode = Field(default=CipherMode.GCM, description="Selected cipher mode")
    resolved_key_bits: int = Field(default=256, description="Selected key size in bits")
    audit_level: Literal["full", "detailed", "standard", "minimal"] = Field(
        description="Level of audit logging required"
    )
    hardware_acceleration: bool = Field(description="Whether to use hardware acceleration")
    rationale: list[str] = Field(default_factory=list, description="Legacy: Simple explanation list")
    detailed_rationale: AlgorithmRationale | None = Field(
        default=None, description="Detailed explanation with factors and alternatives"
    )
    # Full algorithm suite (new in v1.3.7)
    algorithm_suite: AlgorithmSuite | None = Field(
        default=None, description="Complete cryptographic algorithm suite"
    )


# =============================================================================
# Complete Context Configuration
# =============================================================================


class ContextConfig(BaseModel):
    """Complete 5-layer context configuration."""

    data_identity: DataIdentity = Field(default_factory=DataIdentity)
    regulatory: RegulatoryMapping = Field(default_factory=RegulatoryMapping)
    threat_model: ThreatModel = Field(default_factory=ThreatModel)
    access_patterns: AccessPatterns = Field(default_factory=AccessPatterns)

    # Derived requirements are computed, not stored
    # See algorithm_resolver.py for computation logic


# =============================================================================
# API Request/Response Schemas
# =============================================================================


class ContextCreate(BaseModel):
    """Schema for creating a new context."""

    name: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9-]*$",
        description="Unique context identifier (lowercase, hyphens allowed)",
    )
    display_name: str = Field(min_length=1, max_length=128, description="Human-readable name")
    description: str = Field(min_length=1, description="Detailed description of what this context protects")
    config: ContextConfig = Field(default_factory=ContextConfig, description="5-layer context configuration")


class ContextUpdate(BaseModel):
    """Schema for updating an existing context."""

    display_name: str | None = None
    description: str | None = None
    config: ContextConfig | None = None

    # Algorithm policy (admin-only)
    algorithm_policy: AlgorithmPolicy | None = None
    policy_enforcement: PolicyEnforcement | None = None


class ContextResponse(BaseModel):
    """Schema for context API responses."""

    model_config = ConfigDict(from_attributes=True)

    name: str
    display_name: str
    description: str
    config: ContextConfig
    derived: DerivedRequirements

    # Legacy fields for backward compatibility
    algorithm: str
    compliance_tags: list[str]
    data_examples: list[str]

    # Algorithm policy enforcement
    algorithm_policy: AlgorithmPolicy | None = None
    policy_enforcement: PolicyEnforcement = PolicyEnforcement.NONE

    created_at: datetime
    updated_at: datetime | None = None
