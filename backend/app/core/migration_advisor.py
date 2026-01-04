"""Algorithm Migration Advisor.

Intelligent engine for analyzing cryptographic algorithm usage
and providing prioritized migration recommendations.

Features:
- Risk scoring based on algorithm status, sensitivity, and compliance
- Smart replacement recommendations with human-readable explanations
- Step-by-step migration plans
- Quantum readiness assessment
"""

from dataclasses import dataclass, field
from typing import Any
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto_registry import (
    crypto_registry,
    SecurityStatus,
    Algorithm,
)
from app.models import Context


class RiskLevel(str):
    """Risk level categories."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Urgency(str):
    """Migration urgency levels."""
    IMMEDIATE = "immediate"
    SOON = "soon"
    PLANNED = "planned"


class Compatibility(str):
    """Migration compatibility types."""
    DIRECT = "direct"  # Simple algorithm swap
    KEY_ROTATION = "requires-key-rotation"  # Needs new keys
    REENCRYPTION = "requires-reencryption"  # Needs data re-encryption


# Response models
class RiskScore(BaseModel):
    """Risk assessment for an algorithm-context pair."""
    score: int  # 0-100
    level: str  # critical, high, medium, low
    factors: list[str]  # What contributes to the score

    @classmethod
    def from_score(cls, score: int, factors: list[str]) -> "RiskScore":
        """Create RiskScore with automatic level determination."""
        if score >= 80:
            level = RiskLevel.CRITICAL
        elif score >= 60:
            level = RiskLevel.HIGH
        elif score >= 40:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW
        return cls(score=score, level=level, factors=factors)


class MigrationStep(BaseModel):
    """A single step in a migration plan."""
    order: int
    action: str
    description: str
    automated: bool = True  # Can be done automatically?


class Recommendation(BaseModel):
    """Migration recommendation for a context."""
    priority: int
    contextName: str
    contextDisplayName: str
    currentAlgorithm: str
    recommendedAlgorithm: str
    reason: str  # Human-readable explanation
    vulnerabilities: list[str]
    urgency: str  # immediate, soon, planned
    compatibility: str  # direct, requires-key-rotation, requires-reencryption
    estimatedImpact: str  # low, medium, high
    riskScore: RiskScore
    steps: list[str]  # Migration steps


class RiskCategory(BaseModel):
    """Contexts grouped by risk level."""
    count: int
    contexts: list[str]


class QuantumReadiness(BaseModel):
    """Quantum readiness summary."""
    percentage: float
    contextsUsingPQC: int
    contextsNeedingPQC: int
    recommendation: str


class MigrationAssessment(BaseModel):
    """Complete migration assessment for a tenant."""
    overallRiskScore: int
    overallLevel: str
    summary: str
    categories: dict[str, RiskCategory]
    recommendations: list[Recommendation]
    quantumReadiness: QuantumReadiness
    totalContexts: int
    contextsNeedingMigration: int


class MigrationPlan(BaseModel):
    """Detailed migration plan for a context."""
    contextName: str
    currentAlgorithm: str
    targetAlgorithm: str
    steps: list[MigrationStep]
    warnings: list[str]
    estimatedDuration: str
    rollbackSteps: list[str]


class MigrationPreview(BaseModel):
    """Preview of migration impact before execution."""
    contextName: str
    currentAlgorithm: str
    newAlgorithm: str
    impactSummary: dict[str, Any]
    warnings: list[str]
    canProceed: bool


class MigrationAdvisor:
    """Intelligent migration recommendation engine."""

    # Risk weights
    ALGORITHM_STATUS_WEIGHTS = {
        SecurityStatus.BROKEN: 100,
        SecurityStatus.DEPRECATED: 70,
        SecurityStatus.LEGACY: 40,
        SecurityStatus.ACCEPTABLE: 10,
        SecurityStatus.RECOMMENDED: 0,
    }

    SENSITIVITY_WEIGHTS = {
        "critical": 100,
        "high": 70,
        "sensitive": 70,
        "medium": 40,
        "internal": 40,
        "low": 20,
        "public": 10,
    }

    # Vulnerability explanations
    VULNERABILITY_EXPLANATIONS = {
        "Sweet32": "Birthday attack on 64-bit block ciphers after ~32GB of data",
        "Padding oracle": "Side-channel attack that can decrypt data through padding error responses",
        "Pattern preservation": "ECB mode preserves plaintext patterns in ciphertext",
        "Brute force": "Key size is small enough to be brute-forced with modern hardware",
        "Length extension": "Hash can be extended without knowing the secret key",
        "Collision attacks": "Two different inputs can produce the same hash output",
    }

    def __init__(self, db: AsyncSession):
        self.db = db

    async def analyze_tenant(self, tenant_id: str) -> MigrationAssessment:
        """Perform full tenant analysis with prioritized recommendations."""
        # Get all contexts for tenant
        result = await self.db.execute(
            select(Context).where(Context.tenant_id == tenant_id)
        )
        contexts = result.scalars().all()

        if not contexts:
            return MigrationAssessment(
                overallRiskScore=0,
                overallLevel=RiskLevel.LOW,
                summary="No contexts found for this tenant.",
                categories={
                    RiskLevel.CRITICAL: RiskCategory(count=0, contexts=[]),
                    RiskLevel.HIGH: RiskCategory(count=0, contexts=[]),
                    RiskLevel.MEDIUM: RiskCategory(count=0, contexts=[]),
                    RiskLevel.LOW: RiskCategory(count=0, contexts=[]),
                },
                recommendations=[],
                quantumReadiness=QuantumReadiness(
                    percentage=0,
                    contextsUsingPQC=0,
                    contextsNeedingPQC=0,
                    recommendation="No contexts to assess.",
                ),
                totalContexts=0,
                contextsNeedingMigration=0,
            )

        # Analyze each context
        recommendations: list[Recommendation] = []
        categories: dict[str, list[str]] = {
            RiskLevel.CRITICAL: [],
            RiskLevel.HIGH: [],
            RiskLevel.MEDIUM: [],
            RiskLevel.LOW: [],
        }

        pqc_count = 0
        needs_pqc_count = 0
        total_risk = 0

        for context in contexts:
            algorithm = context.algorithm or "AES-256-GCM"
            algo_info = crypto_registry.get(algorithm)

            # Check if migration is needed
            needs_migration = False
            if algo_info:
                needs_migration = algo_info.status in [
                    SecurityStatus.DEPRECATED,
                    SecurityStatus.BROKEN,
                    SecurityStatus.LEGACY,
                ]

            # Calculate risk score
            risk = await self.get_risk_score(algorithm, context)
            total_risk += risk.score
            categories[risk.level].append(context.name)

            # Check quantum readiness
            if algo_info and algo_info.quantum_resistant:
                pqc_count += 1
            elif self._context_needs_pqc(context):
                needs_pqc_count += 1

            # Generate recommendation if needed
            if needs_migration:
                rec = await self.recommend_replacement(algorithm, context)
                rec.priority = len(recommendations) + 1
                recommendations.append(rec)

        # Sort recommendations by risk score (highest first)
        recommendations.sort(key=lambda r: r.riskScore.score, reverse=True)
        for i, rec in enumerate(recommendations):
            rec.priority = i + 1

        # Calculate overall risk
        avg_risk = total_risk // len(contexts) if contexts else 0
        overall_level = RiskScore.from_score(avg_risk, []).level

        # Build categories response
        cat_response = {
            level: RiskCategory(count=len(names), contexts=names[:5])  # Top 5 only
            for level, names in categories.items()
        }

        # Quantum readiness
        total = len(contexts)
        pqc_percentage = (pqc_count / total * 100) if total > 0 else 0
        qr_recommendation = self._get_quantum_recommendation(pqc_percentage, needs_pqc_count)

        return MigrationAssessment(
            overallRiskScore=avg_risk,
            overallLevel=overall_level,
            summary=self._generate_summary(len(recommendations), categories),
            categories=cat_response,
            recommendations=recommendations,
            quantumReadiness=QuantumReadiness(
                percentage=round(pqc_percentage, 1),
                contextsUsingPQC=pqc_count,
                contextsNeedingPQC=needs_pqc_count,
                recommendation=qr_recommendation,
            ),
            totalContexts=total,
            contextsNeedingMigration=len(recommendations),
        )

    async def get_risk_score(self, algorithm: str, context: Context) -> RiskScore:
        """Calculate risk score for an algorithm-context pair."""
        factors = []
        score = 0

        # Factor 1: Algorithm security status
        algo = crypto_registry.get(algorithm)
        if algo:
            status_score = self.ALGORITHM_STATUS_WEIGHTS.get(algo.status, 0)
            score += status_score * 0.5  # 50% weight
            if status_score > 0:
                factors.append(f"Algorithm status: {algo.status.value}")

        # Factor 2: Context sensitivity
        sensitivity = self._get_sensitivity(context)
        sens_score = self.SENSITIVITY_WEIGHTS.get(sensitivity.lower(), 20)
        score += sens_score * 0.3  # 30% weight
        if sens_score >= 70:
            factors.append(f"High sensitivity: {sensitivity}")

        # Factor 3: Compliance requirements
        compliance = self._get_compliance_tags(context)
        if "PCI-DSS" in compliance or "HIPAA" in compliance:
            score += 20  # Compliance adds urgency
            factors.append(f"Compliance requirements: {', '.join(compliance)}")

        # Factor 4: Quantum vulnerability for long-term data
        if algo and not algo.quantum_resistant and self._context_needs_pqc(context):
            score += 10
            factors.append("Long-term data may need quantum protection")

        # Cap at 100
        score = min(100, int(score))

        return RiskScore.from_score(score, factors)

    async def recommend_replacement(
        self, algorithm: str, context: Context
    ) -> Recommendation:
        """Generate smart replacement recommendation."""
        algo = crypto_registry.get(algorithm)
        risk = await self.get_risk_score(algorithm, context)

        # Determine replacement
        replacement = "AES-256-GCM"  # Default safe choice
        if algo and algo.replacement:
            replacement = algo.replacement

        # Consider quantum requirements
        if self._context_needs_pqc(context):
            if "AES" in replacement:
                replacement = "AES-256-GCM+ML-KEM-768"  # Hybrid

        # Generate human-readable reason
        reason = self._generate_reason(algo, context)

        # Determine urgency
        urgency = Urgency.PLANNED
        if risk.score >= 80:
            urgency = Urgency.IMMEDIATE
        elif risk.score >= 60:
            urgency = Urgency.SOON

        # Determine compatibility
        compatibility = self._determine_compatibility(algorithm, replacement)

        # Impact assessment
        impact = "low"
        if compatibility == Compatibility.REENCRYPTION:
            impact = "high"
        elif compatibility == Compatibility.KEY_ROTATION:
            impact = "medium"

        # Generate steps
        steps = self._generate_steps(context, algorithm, replacement, compatibility)

        return Recommendation(
            priority=0,  # Will be set by caller
            contextName=context.name,
            contextDisplayName=context.display_name or context.name,
            currentAlgorithm=algorithm,
            recommendedAlgorithm=replacement,
            reason=reason,
            vulnerabilities=algo.vulnerabilities if algo else [],
            urgency=urgency,
            compatibility=compatibility,
            estimatedImpact=impact,
            riskScore=risk,
            steps=steps,
        )

    async def generate_migration_plan(
        self, context: Context, target_algorithm: str
    ) -> MigrationPlan:
        """Generate detailed migration plan with rollback steps."""
        current = context.algorithm or "AES-256-GCM"
        compatibility = self._determine_compatibility(current, target_algorithm)

        steps = []
        warnings = []
        rollback = []

        # Step 1: Backup
        steps.append(MigrationStep(
            order=1,
            action="backup",
            description="Create backup of current context configuration",
            automated=True,
        ))
        rollback.append("Restore context configuration from backup")

        # Step 2: Validate new algorithm
        steps.append(MigrationStep(
            order=2,
            action="validate",
            description=f"Validate {target_algorithm} is available and configured",
            automated=True,
        ))

        # Step 3: Update configuration
        steps.append(MigrationStep(
            order=3,
            action="update_config",
            description=f"Update context algorithm from {current} to {target_algorithm}",
            automated=True,
        ))
        rollback.append(f"Revert context algorithm to {current}")

        # Step 4: Key rotation (if needed)
        if compatibility in [Compatibility.KEY_ROTATION, Compatibility.REENCRYPTION]:
            steps.append(MigrationStep(
                order=4,
                action="rotate_keys",
                description="Generate new encryption keys with new algorithm",
                automated=True,
            ))
            rollback.append("Keep old keys active for decryption")
            warnings.append("Key rotation will generate new keys. Old keys remain for decryption.")

        # Step 5: Verification
        steps.append(MigrationStep(
            order=len(steps) + 1,
            action="verify",
            description="Verify encryption/decryption works with new algorithm",
            automated=True,
        ))

        # Step 6: Notify clients (manual)
        steps.append(MigrationStep(
            order=len(steps) + 1,
            action="notify",
            description="Notify dependent applications of algorithm change",
            automated=False,
        ))

        # Duration estimate
        duration = "~5 minutes"
        if compatibility == Compatibility.REENCRYPTION:
            duration = "Depends on data volume"
            warnings.append("Re-encryption may take significant time for large datasets")

        return MigrationPlan(
            contextName=context.name,
            currentAlgorithm=current,
            targetAlgorithm=target_algorithm,
            steps=steps,
            warnings=warnings,
            estimatedDuration=duration,
            rollbackSteps=rollback,
        )

    async def preview_migration(
        self, context: Context, new_algorithm: str
    ) -> MigrationPreview:
        """Preview migration impact without executing."""
        current = context.algorithm or "AES-256-GCM"
        compatibility = self._determine_compatibility(current, new_algorithm)

        warnings = []
        can_proceed = True

        # Check if new algorithm is valid
        new_algo = crypto_registry.get(new_algorithm)
        if not new_algo:
            warnings.append(f"Algorithm '{new_algorithm}' not found in registry")
            can_proceed = False

        # Check if it's actually an upgrade
        if new_algo and new_algo.status in [SecurityStatus.DEPRECATED, SecurityStatus.BROKEN]:
            warnings.append(f"Target algorithm {new_algorithm} is also deprecated")
            can_proceed = False

        # Determine impact
        requires_key_rederivation = compatibility != Compatibility.DIRECT
        affected_fields = ["encryption_key"]
        if requires_key_rederivation:
            affected_fields.extend(["mac_key", "signing_key"])

        return MigrationPreview(
            contextName=context.name,
            currentAlgorithm=current,
            newAlgorithm=new_algorithm,
            impactSummary={
                "requiresKeyRederivation": requires_key_rederivation,
                "affectedFields": affected_fields,
                "estimatedDowntime": "minimal" if not requires_key_rederivation else "brief",
                "compatibility": compatibility,
            },
            warnings=warnings,
            canProceed=can_proceed,
        )

    # Helper methods

    def _get_sensitivity(self, context: Context) -> str:
        """Extract sensitivity from context config or derived."""
        if context.config:
            data_identity = context.config.get("data_identity", {})
            return data_identity.get("sensitivity", "medium")
        return "medium"

    def _get_compliance_tags(self, context: Context) -> list[str]:
        """Extract compliance tags from context."""
        if hasattr(context, "compliance_tags") and context.compliance_tags:
            return context.compliance_tags
        if context.config:
            data_identity = context.config.get("data_identity", {})
            return data_identity.get("compliance_frameworks", [])
        return []

    def _context_needs_pqc(self, context: Context) -> bool:
        """Determine if context should use post-quantum algorithms."""
        # Check config for protection lifetime
        if context.config:
            threat = context.config.get("threat_model", {})
            lifetime = threat.get("protection_lifetime_years", 5)
            if lifetime > 10:
                return True
            if threat.get("quantum_adversary"):
                return True

        # Critical/high sensitivity data should consider PQC
        sensitivity = self._get_sensitivity(context)
        return sensitivity in ["critical", "high"]

    def _generate_reason(self, algo: Algorithm | None, context: Context) -> str:
        """Generate human-readable explanation for migration."""
        if not algo:
            return "Algorithm not found in registry. Migration recommended for security."

        parts = []

        # Status explanation
        if algo.status == SecurityStatus.BROKEN:
            parts.append(f"{algo.name} is broken and actively exploitable.")
        elif algo.status == SecurityStatus.DEPRECATED:
            parts.append(f"{algo.name} is deprecated due to known weaknesses.")
        elif algo.status == SecurityStatus.LEGACY:
            parts.append(f"{algo.name} is legacy and should be upgraded.")

        # Vulnerability details
        if algo.vulnerabilities:
            vuln = algo.vulnerabilities[0]
            explanation = self.VULNERABILITY_EXPLANATIONS.get(
                vuln.split()[0],  # Get first word
                vuln
            )
            parts.append(explanation)

        # Sensitivity context
        sensitivity = self._get_sensitivity(context)
        if sensitivity in ["critical", "high", "sensitive"]:
            parts.append(f"This context handles {sensitivity} data, requiring immediate attention.")

        return " ".join(parts) if parts else "Migration recommended for improved security."

    def _determine_compatibility(self, current: str, target: str) -> str:
        """Determine migration compatibility type."""
        # Same family = direct swap
        current_algo = crypto_registry.get(current)
        target_algo = crypto_registry.get(target)

        if current_algo and target_algo:
            if current_algo.family == target_algo.family:
                return Compatibility.DIRECT

        # Different key sizes or modes need key rotation
        if "256" not in current and "256" in target:
            return Compatibility.KEY_ROTATION

        # Switching families needs new keys
        return Compatibility.KEY_ROTATION

    def _generate_steps(
        self, context: Context, current: str, target: str, compatibility: str
    ) -> list[str]:
        """Generate migration steps for recommendation."""
        steps = [
            f"Update context '{context.name}' algorithm to {target}",
        ]

        if compatibility in [Compatibility.KEY_ROTATION, Compatibility.REENCRYPTION]:
            steps.append("Schedule key rotation for new algorithm")

        steps.extend([
            "Verify encryption/decryption operations",
            "Update client applications if needed",
        ])

        return steps

    def _generate_summary(
        self, migration_count: int, categories: dict[str, list[str]]
    ) -> str:
        """Generate assessment summary."""
        if migration_count == 0:
            return "All contexts are using recommended algorithms. No migrations needed."

        critical = len(categories.get(RiskLevel.CRITICAL, []))
        high = len(categories.get(RiskLevel.HIGH, []))

        parts = [f"{migration_count} contexts need attention"]
        if critical > 0:
            parts.append(f"{critical} critical priority")
        if high > 0:
            parts.append(f"{high} high priority")

        return ", ".join(parts) + "."

    def _get_quantum_recommendation(self, percentage: float, needs_count: int) -> str:
        """Generate quantum readiness recommendation."""
        if percentage >= 80:
            return "Excellent quantum readiness. Continue monitoring PQC standards."
        elif percentage >= 50:
            return f"Good progress. {needs_count} contexts should consider hybrid PQC."
        elif needs_count > 0:
            return f"Consider ML-KEM hybrid for {needs_count} contexts with long-term sensitive data."
        else:
            return "Evaluate PQC requirements based on data protection lifetime."
