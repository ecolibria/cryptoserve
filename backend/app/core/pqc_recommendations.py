"""PQC Recommendations Service.

Generates post-quantum cryptography migration recommendations based on
detected crypto inventory. Uses threat-driven prioritization (SNDL analysis)
to help organizations plan their quantum migration journey.

Based on the pqc-bench project patterns for PQC recommendation generation.

Key concepts:
- SNDL (Store Now, Decrypt Later): Threat where adversaries store encrypted
  data today to decrypt with future quantum computers
- Migration Timeline: How long it takes to migrate to PQC
- Data Lifespan: How long data needs to remain confidential
- Quantum Threat Timeline: When quantum computers can break current crypto

Usage:
    from app.core.pqc_recommendations import pqc_recommendation_service

    # Generate recommendations from inventory
    result = pqc_recommendation_service.recommend(inventory)
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from app.core.crypto_inventory import (
    CryptoInventory,
    DetectedLibrary,
    QuantumRisk,
)


class ThreatUrgency(str, Enum):
    """Migration urgency level based on SNDL analysis."""
    CRITICAL = "critical"  # Already at risk, immediate action required
    HIGH = "high"  # At risk within migration timeline
    MEDIUM = "medium"  # Should plan migration soon
    LOW = "low"  # Monitor, no immediate action
    MONITORING = "monitoring"  # Minimal risk, keep watching


class DataProfile(str, Enum):
    """Common data sensitivity profiles with different lifespans."""
    NATIONAL_SECURITY = "national_security"  # 75 years
    HEALTHCARE_RECORDS = "healthcare_records"  # 100 years (lifetime)
    FINANCIAL_LONG_TERM = "financial_long_term"  # 25 years
    INTELLECTUAL_PROPERTY = "intellectual_property"  # 20 years
    LEGAL_DOCUMENTS = "legal_documents"  # 30 years
    PERSONAL_DATA = "personal_data"  # 10 years
    AUTHENTICATION_CREDENTIALS = "authentication_credentials"  # 1 year
    SESSION_TOKENS = "session_tokens"  # Hours/days
    EPHEMERAL_COMMUNICATIONS = "ephemeral_communications"  # 1 year


# Data profile configurations with lifespan and urgency
DATA_PROFILES = {
    DataProfile.NATIONAL_SECURITY: {
        "name": "National Security Data",
        "lifespan_years": 75,
        "description": "Classified information with long-term secrecy requirements",
        "urgency": ThreatUrgency.CRITICAL,
        "crypto_needs": ["kem", "signature"],
    },
    DataProfile.HEALTHCARE_RECORDS: {
        "name": "Healthcare Records",
        "lifespan_years": 100,
        "description": "Medical records that must remain private for patient lifetime",
        "urgency": ThreatUrgency.CRITICAL,
        "crypto_needs": ["kem"],
    },
    DataProfile.FINANCIAL_LONG_TERM: {
        "name": "Long-term Financial Data",
        "lifespan_years": 25,
        "description": "Financial records, contracts, audit trails",
        "urgency": ThreatUrgency.HIGH,
        "crypto_needs": ["kem", "signature"],
    },
    DataProfile.INTELLECTUAL_PROPERTY: {
        "name": "Intellectual Property",
        "lifespan_years": 20,
        "description": "Trade secrets, patents, proprietary algorithms",
        "urgency": ThreatUrgency.HIGH,
        "crypto_needs": ["kem"],
    },
    DataProfile.LEGAL_DOCUMENTS: {
        "name": "Legal Documents",
        "lifespan_years": 30,
        "description": "Contracts, agreements, legal communications",
        "urgency": ThreatUrgency.HIGH,
        "crypto_needs": ["kem", "signature"],
    },
    DataProfile.PERSONAL_DATA: {
        "name": "Personal Data",
        "lifespan_years": 10,
        "description": "PII, user data covered by privacy regulations",
        "urgency": ThreatUrgency.MEDIUM,
        "crypto_needs": ["kem"],
    },
    DataProfile.AUTHENTICATION_CREDENTIALS: {
        "name": "Authentication Credentials",
        "lifespan_years": 1,
        "description": "Passwords, API keys, service credentials",
        "urgency": ThreatUrgency.MEDIUM,
        "crypto_needs": ["kem", "signature"],
    },
    DataProfile.SESSION_TOKENS: {
        "name": "Session Tokens",
        "lifespan_years": 0,  # Hours/days
        "description": "Short-lived session data, JWTs with short expiry",
        "urgency": ThreatUrgency.LOW,
        "crypto_needs": ["signature"],
    },
    DataProfile.EPHEMERAL_COMMUNICATIONS: {
        "name": "Ephemeral Communications",
        "lifespan_years": 1,
        "description": "Real-time communications, temporary messages",
        "urgency": ThreatUrgency.LOW,
        "crypto_needs": ["kem"],
    },
}


# Quantum threat timeline estimates (years until quantum computers can break)
QUANTUM_THREAT_TIMELINE = {
    "rsa_2048": {"min": 10, "median": 15, "max": 25},
    "ecdsa_p256": {"min": 10, "median": 15, "max": 25},
    "aes_256": {"min": 30, "median": 50, "max": 100},  # Grover's quadratic speedup
    "sha_256": {"min": 30, "median": 50, "max": 100},
}


# PQC Algorithm recommendations
PQC_ALGORITHMS = {
    "kem": [
        {
            "id": "ml-kem-768",
            "name": "ML-KEM-768",
            "fips": "FIPS 203",
            "security_level": 3,
            "status": "standardized",
            "description": "Primary NIST KEM standard, balanced security/performance",
            "use_cases": ["tls", "key_exchange", "encryption"],
            "hybrid_with": "X25519Kyber768",
        },
        {
            "id": "ml-kem-1024",
            "name": "ML-KEM-1024",
            "fips": "FIPS 203",
            "security_level": 5,
            "status": "standardized",
            "description": "Highest security KEM for long-term protection",
            "use_cases": ["long_term_secrets", "high_security"],
            "hybrid_with": "X25519Kyber1024",
        },
        {
            "id": "ml-kem-512",
            "name": "ML-KEM-512",
            "fips": "FIPS 203",
            "security_level": 1,
            "status": "standardized",
            "description": "Smallest/fastest KEM for constrained environments",
            "use_cases": ["iot", "embedded", "performance_critical"],
            "hybrid_with": "X25519Kyber512",
        },
    ],
    "signature": [
        {
            "id": "ml-dsa-65",
            "name": "ML-DSA-65",
            "fips": "FIPS 204",
            "security_level": 3,
            "status": "standardized",
            "description": "Primary NIST signature standard, balanced approach",
            "use_cases": ["code_signing", "document_signing", "certificates"],
        },
        {
            "id": "ml-dsa-87",
            "name": "ML-DSA-87",
            "fips": "FIPS 204",
            "security_level": 5,
            "status": "standardized",
            "description": "Highest security signatures for critical applications",
            "use_cases": ["ca_certificates", "long_term_signing"],
        },
        {
            "id": "slh-dsa-128f",
            "name": "SLH-DSA-128f",
            "fips": "FIPS 205",
            "security_level": 1,
            "status": "standardized",
            "description": "Hash-based signatures, conservative security assumptions",
            "use_cases": ["firmware_signing", "high_assurance"],
        },
    ],
}


@dataclass
class SNDLAssessment:
    """SNDL (Store Now, Decrypt Later) risk assessment."""
    is_at_risk: bool
    urgency: ThreatUrgency
    years_margin: int  # Positive = safe margin, Negative = already at risk
    risk_explanation: str
    recommended_action: str


@dataclass
class AlgorithmRecommendation:
    """A recommended PQC algorithm."""
    algorithm_id: str
    name: str
    fips: str | None
    security_level: int
    type: str  # kem or signature
    score: float  # 0-100
    reasons: list[str]
    warnings: list[str]
    hybrid_option: str | None = None


@dataclass
class MigrationStep:
    """A step in the migration plan."""
    order: int
    action: str
    description: str
    priority: str
    affected_libraries: list[str]
    target_algorithm: str | None
    estimated_effort: str  # low, medium, high


@dataclass
class PQCRecommendationResult:
    """Complete PQC recommendation result."""
    generated_at: str
    identity_id: str
    identity_name: str

    # Current state
    current_crypto_summary: dict
    sndl_assessment: SNDLAssessment

    # Recommendations
    kem_recommendations: list[AlgorithmRecommendation]
    signature_recommendations: list[AlgorithmRecommendation]
    migration_plan: list[MigrationStep]

    # Summary
    overall_urgency: ThreatUrgency
    quantum_readiness_score: float
    key_findings: list[str]
    next_steps: list[str]

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)


class PQCRecommendationService:
    """Service for generating PQC migration recommendations."""

    def __init__(
        self,
        migration_timeline_years: int = 2,
        quantum_threat_years: int = 15,
    ):
        """
        Initialize recommendation service.

        Args:
            migration_timeline_years: Estimated time to complete migration
            quantum_threat_years: Estimated years until quantum threat is real
        """
        self.migration_timeline_years = migration_timeline_years
        self.quantum_threat_years = quantum_threat_years

    def recommend(
        self,
        inventory: CryptoInventory,
        data_profile: DataProfile | None = None,
    ) -> PQCRecommendationResult:
        """
        Generate PQC migration recommendations.

        Args:
            inventory: CryptoInventory from scanner
            data_profile: Optional data sensitivity profile for SNDL analysis

        Returns:
            Complete recommendation result
        """
        # Analyze current crypto state
        current_summary = self._analyze_current_crypto(inventory)

        # Perform SNDL assessment
        sndl = self._assess_sndl_risk(inventory, data_profile)

        # Generate algorithm recommendations
        kem_recs = self._recommend_kem(inventory)
        sig_recs = self._recommend_signatures(inventory)

        # Generate migration plan
        migration_plan = self._generate_migration_plan(inventory, sndl)

        # Calculate overall urgency
        overall_urgency = self._calculate_overall_urgency(inventory, sndl)

        # Calculate quantum readiness score
        quantum_score = self._calculate_quantum_score(inventory)

        # Generate findings and next steps
        findings = self._generate_key_findings(inventory, sndl)
        next_steps = self._generate_next_steps(inventory, sndl, migration_plan)

        return PQCRecommendationResult(
            generated_at=datetime.now(timezone.utc).isoformat(),
            identity_id=inventory.identity_id,
            identity_name=inventory.identity_name,
            current_crypto_summary=current_summary,
            sndl_assessment=sndl,
            kem_recommendations=kem_recs,
            signature_recommendations=sig_recs,
            migration_plan=migration_plan,
            overall_urgency=overall_urgency,
            quantum_readiness_score=quantum_score,
            key_findings=findings,
            next_steps=next_steps,
        )

    def _analyze_current_crypto(self, inventory: CryptoInventory) -> dict:
        """Analyze current cryptographic state."""
        vulnerable_libs = [
            lib for lib in inventory.libraries
            if lib.quantum_risk in [QuantumRisk.HIGH, QuantumRisk.CRITICAL]
        ]

        deprecated_libs = [
            lib for lib in inventory.libraries
            if lib.is_deprecated
        ]

        pqc_libs = [
            lib for lib in inventory.libraries
            if lib.category == "pqc"
        ]

        # Categorize algorithms
        asymmetric_algos = []
        symmetric_algos = []
        hash_algos = []

        for algo in inventory.algorithms:
            if algo.category in ["asymmetric", "token", "tls"]:
                asymmetric_algos.append(algo.name)
            elif algo.category in ["symmetric", "kdf"]:
                symmetric_algos.append(algo.name)
            elif algo.category in ["hashing", "mac"]:
                hash_algos.append(algo.name)

        return {
            "total_libraries": len(inventory.libraries),
            "vulnerable_libraries": len(vulnerable_libs),
            "deprecated_libraries": len(deprecated_libs),
            "pqc_libraries": len(pqc_libs),
            "has_pqc": len(pqc_libs) > 0,
            "vulnerable_library_names": [lib.name for lib in vulnerable_libs],
            "deprecated_library_names": [lib.name for lib in deprecated_libs],
            "asymmetric_algorithms": list(set(asymmetric_algos)),
            "symmetric_algorithms": list(set(symmetric_algos)),
            "hash_algorithms": list(set(hash_algos)),
        }

    def _assess_sndl_risk(
        self,
        inventory: CryptoInventory,
        data_profile: DataProfile | None,
    ) -> SNDLAssessment:
        """
        Assess SNDL (Store Now, Decrypt Later) risk.

        The core formula:
        Risk = Data Lifespan + Migration Timeline > Quantum Threat Timeline
        """
        # Default to medium sensitivity if not specified
        if data_profile is None:
            # Infer from detected crypto usage
            if any(lib.category == "token" for lib in inventory.libraries):
                data_profile = DataProfile.AUTHENTICATION_CREDENTIALS
            else:
                data_profile = DataProfile.PERSONAL_DATA

        profile_config = DATA_PROFILES.get(data_profile, DATA_PROFILES[DataProfile.PERSONAL_DATA])
        data_lifespan = profile_config["lifespan_years"]

        # Calculate risk margin
        # years_margin = quantum_threat - (data_lifespan + migration_timeline)
        # Positive = safe, Negative = at risk
        years_margin = self.quantum_threat_years - (data_lifespan + self.migration_timeline_years)

        # Determine if at risk
        is_at_risk = years_margin < 0

        # Determine urgency based on margin and current state
        has_vulnerable = inventory.quantum_summary.get("quantum_vulnerable", 0) > 0
        has_pqc = inventory.quantum_summary.get("has_pqc", False)
        has_deprecated = inventory.risk_summary.get("deprecated_libraries", 0) > 0

        if has_deprecated:
            urgency = ThreatUrgency.CRITICAL
        elif is_at_risk and has_vulnerable and not has_pqc:
            urgency = ThreatUrgency.CRITICAL
        elif is_at_risk:
            urgency = ThreatUrgency.HIGH
        elif years_margin < 5 and has_vulnerable:
            urgency = ThreatUrgency.MEDIUM
        elif has_vulnerable:
            urgency = ThreatUrgency.LOW
        else:
            urgency = ThreatUrgency.MONITORING

        # Generate explanation
        if is_at_risk:
            explanation = (
                f"CRITICAL: Your data ({profile_config['name']}) with {data_lifespan}-year "
                f"lifespan is already at risk. Quantum computers may be able to decrypt "
                f"this data before its confidentiality period expires."
            )
            action = "Begin hybrid PQC deployment immediately. Prioritize re-encrypting sensitive data."
        elif years_margin < 5:
            explanation = (
                f"HIGH RISK: Only {years_margin} years margin before SNDL risk. "
                f"Data encrypted today may be vulnerable before expiration."
            )
            action = "Plan PQC migration within 12 months. Evaluate hybrid deployment options."
        elif years_margin < 10:
            explanation = (
                f"MEDIUM RISK: {years_margin} years margin. Time to plan migration."
            )
            action = "Begin PQC pilot projects. Test ML-KEM/ML-DSA in non-production environments."
        else:
            explanation = (
                f"LOW RISK: {years_margin} years margin. Monitor quantum computing developments."
            )
            action = "Stay informed about PQC standards. Plan long-term crypto agility."

        return SNDLAssessment(
            is_at_risk=is_at_risk,
            urgency=urgency,
            years_margin=years_margin,
            risk_explanation=explanation,
            recommended_action=action,
        )

    def _recommend_kem(self, inventory: CryptoInventory) -> list[AlgorithmRecommendation]:
        """Generate KEM (key encapsulation) recommendations."""
        recommendations = []

        # Check if KEM is needed
        has_asymmetric = any(
            lib.category in ["general", "token", "tls"]
            and lib.quantum_risk in [QuantumRisk.HIGH, QuantumRisk.CRITICAL]
            for lib in inventory.libraries
        )

        if not has_asymmetric:
            return recommendations

        for algo in PQC_ALGORITHMS["kem"]:
            score = self._score_algorithm(algo, inventory, "kem")
            reasons = self._generate_reasons(algo, inventory, "kem")
            warnings = self._generate_warnings(algo, inventory)

            recommendations.append(AlgorithmRecommendation(
                algorithm_id=algo["id"],
                name=algo["name"],
                fips=algo.get("fips"),
                security_level=algo["security_level"],
                type="kem",
                score=score,
                reasons=reasons,
                warnings=warnings,
                hybrid_option=algo.get("hybrid_with"),
            ))

        # Sort by score
        recommendations.sort(key=lambda r: r.score, reverse=True)
        return recommendations

    def _recommend_signatures(self, inventory: CryptoInventory) -> list[AlgorithmRecommendation]:
        """Generate signature algorithm recommendations."""
        recommendations = []

        # Check if signatures are needed
        has_signing = any(
            lib.category in ["token", "tls"]
            or any(algo in ["RSA", "ECDSA", "Ed25519"] for algo in lib.algorithms)
            for lib in inventory.libraries
        )

        if not has_signing:
            return recommendations

        for algo in PQC_ALGORITHMS["signature"]:
            score = self._score_algorithm(algo, inventory, "signature")
            reasons = self._generate_reasons(algo, inventory, "signature")
            warnings = self._generate_warnings(algo, inventory)

            recommendations.append(AlgorithmRecommendation(
                algorithm_id=algo["id"],
                name=algo["name"],
                fips=algo.get("fips"),
                security_level=algo["security_level"],
                type="signature",
                score=score,
                reasons=reasons,
                warnings=warnings,
            ))

        recommendations.sort(key=lambda r: r.score, reverse=True)
        return recommendations

    def _score_algorithm(self, algo: dict, inventory: CryptoInventory, algo_type: str) -> float:
        """Score an algorithm based on context."""
        score = 50.0  # Base score

        # Standardization status (+25)
        if algo.get("status") == "standardized":
            score += 25

        # Security level alignment
        has_high_security = any(
            lib.quantum_risk == QuantumRisk.CRITICAL
            for lib in inventory.libraries
        )

        if has_high_security and algo["security_level"] >= 3:
            score += 15
        elif algo["security_level"] == 3:
            score += 10  # Balanced choice

        # Prefer ML-KEM-768 and ML-DSA-65 as defaults
        if algo["id"] in ["ml-kem-768", "ml-dsa-65"]:
            score += 10  # Recommended defaults

        return min(100, score)

    def _generate_reasons(self, algo: dict, inventory: CryptoInventory, algo_type: str) -> list[str]:
        """Generate reasons for recommending an algorithm."""
        reasons = []

        if algo.get("fips"):
            reasons.append(f"NIST standardized ({algo['fips']})")

        if algo.get("status") == "standardized":
            reasons.append("Production-ready standard")

        if algo["security_level"] == 3:
            reasons.append("Balanced security/performance (NIST Level 3)")
        elif algo["security_level"] == 5:
            reasons.append("Maximum security (NIST Level 5)")
        elif algo["security_level"] == 1:
            reasons.append("Efficient for constrained environments (NIST Level 1)")

        if algo.get("hybrid_with"):
            reasons.append(f"Hybrid mode available ({algo['hybrid_with']})")

        return reasons

    def _generate_warnings(self, algo: dict, inventory: CryptoInventory) -> list[str]:
        """Generate warnings for an algorithm."""
        warnings = []

        if algo["security_level"] == 1:
            warnings.append("Lower security level - verify adequacy for your threat model")

        if "slh-dsa" in algo["id"]:
            warnings.append("Larger signature sizes - may impact bandwidth-constrained systems")

        return warnings

    def _generate_migration_plan(
        self,
        inventory: CryptoInventory,
        sndl: SNDLAssessment,
    ) -> list[MigrationStep]:
        """Generate step-by-step migration plan."""
        steps = []
        step_order = 1

        # Step 1: Address deprecated libraries first (always)
        deprecated = [lib for lib in inventory.libraries if lib.is_deprecated]
        if deprecated:
            steps.append(MigrationStep(
                order=step_order,
                action="Replace deprecated libraries",
                description=f"Remove {', '.join(lib.name for lib in deprecated)} - these have known vulnerabilities",
                priority="critical",
                affected_libraries=[lib.name for lib in deprecated],
                target_algorithm=None,
                estimated_effort="medium",
            ))
            step_order += 1

        # Step 2: Enable crypto agility
        if not inventory.quantum_summary.get("has_pqc", False):
            steps.append(MigrationStep(
                order=step_order,
                action="Enable cryptographic agility",
                description="Refactor to support algorithm negotiation and easy swapping",
                priority="high" if sndl.urgency in [ThreatUrgency.CRITICAL, ThreatUrgency.HIGH] else "medium",
                affected_libraries=[],
                target_algorithm=None,
                estimated_effort="high",
            ))
            step_order += 1

        # Step 3: Deploy hybrid for key exchange (if asymmetric crypto detected)
        has_asymmetric = any(
            lib.category in ["general", "token", "tls"]
            and "RSA" in lib.algorithms or "ECDSA" in lib.algorithms
            for lib in inventory.libraries
        )

        if has_asymmetric:
            steps.append(MigrationStep(
                order=step_order,
                action="Deploy hybrid key exchange",
                description="Implement X25519Kyber768 for TLS and key exchange",
                priority="high" if sndl.is_at_risk else "medium",
                affected_libraries=[lib.name for lib in inventory.libraries if lib.category == "tls"],
                target_algorithm="X25519Kyber768",
                estimated_effort="medium",
            ))
            step_order += 1

        # Step 4: Migrate signatures
        has_signing = any(
            "RSA" in lib.algorithms or "ECDSA" in lib.algorithms or "Ed25519" in lib.algorithms
            for lib in inventory.libraries
        )

        if has_signing:
            steps.append(MigrationStep(
                order=step_order,
                action="Migrate to PQC signatures",
                description="Replace RSA/ECDSA signatures with ML-DSA-65",
                priority="medium",
                affected_libraries=[lib.name for lib in inventory.libraries if lib.category == "token"],
                target_algorithm="ML-DSA-65",
                estimated_effort="medium",
            ))
            step_order += 1

        # Step 5: Full PQC migration
        steps.append(MigrationStep(
            order=step_order,
            action="Complete PQC migration",
            description="Remove classical-only crypto, verify quantum resistance",
            priority="low",
            affected_libraries=[],
            target_algorithm=None,
            estimated_effort="low",
        ))

        return steps

    def _calculate_overall_urgency(
        self,
        inventory: CryptoInventory,
        sndl: SNDLAssessment,
    ) -> ThreatUrgency:
        """Calculate overall migration urgency."""
        # Deprecated libraries always mean critical
        if inventory.risk_summary.get("deprecated_libraries", 0) > 0:
            return ThreatUrgency.CRITICAL

        return sndl.urgency

    def _calculate_quantum_score(self, inventory: CryptoInventory) -> float:
        """Calculate quantum readiness score (0-100)."""
        summary = inventory.quantum_summary

        if summary.get("total_libraries", 0) == 0:
            return 100.0

        safe = summary.get("quantum_safe", 0)
        vulnerable = summary.get("quantum_vulnerable", 0)
        total = safe + vulnerable

        if total == 0:
            return 100.0

        score = (safe / total) * 100

        if summary.get("has_pqc", False):
            score = min(100, score + 20)

        deprecated = inventory.risk_summary.get("deprecated_libraries", 0)
        if deprecated > 0:
            score = max(0, score - (deprecated * 10))

        return round(score, 1)

    def _generate_key_findings(
        self,
        inventory: CryptoInventory,
        sndl: SNDLAssessment,
    ) -> list[str]:
        """Generate key findings from analysis."""
        findings = []

        vulnerable_count = inventory.quantum_summary.get("quantum_vulnerable", 0)
        if vulnerable_count > 0:
            findings.append(f"Found {vulnerable_count} quantum-vulnerable libraries")

        deprecated_count = inventory.risk_summary.get("deprecated_libraries", 0)
        if deprecated_count > 0:
            findings.append(f"Found {deprecated_count} deprecated libraries requiring immediate attention")

        if sndl.is_at_risk:
            findings.append(f"SNDL risk: Data may be decryptable before confidentiality period expires")

        if inventory.quantum_summary.get("has_pqc", False):
            findings.append("Post-quantum cryptography already in use - good progress")
        else:
            findings.append("No post-quantum cryptography detected")

        return findings

    def _generate_next_steps(
        self,
        inventory: CryptoInventory,
        sndl: SNDLAssessment,
        migration_plan: list[MigrationStep],
    ) -> list[str]:
        """Generate actionable next steps."""
        steps = []

        # First priority step
        if migration_plan:
            first_step = migration_plan[0]
            steps.append(f"Priority: {first_step.action}")

        # SNDL-specific steps
        if sndl.urgency == ThreatUrgency.CRITICAL:
            steps.append("Deploy hybrid crypto (X25519Kyber768) within 90 days")
            steps.append("Identify and re-encrypt sensitive long-term data")
        elif sndl.urgency == ThreatUrgency.HIGH:
            steps.append("Begin PQC pilot project within 6 months")
            steps.append("Evaluate liboqs or pqcrypto for Python integration")
        elif sndl.urgency == ThreatUrgency.MEDIUM:
            steps.append("Include PQC migration in next architecture review")
            steps.append("Train development team on PQC concepts")
        else:
            steps.append("Monitor NIST PQC standardization updates")
            steps.append("Evaluate crypto agility improvements")

        return steps


# Singleton instance
pqc_recommendation_service = PQCRecommendationService()
