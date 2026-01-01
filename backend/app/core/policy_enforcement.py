"""Policy Enforcement Service.

Bridges crypto inventory (detected libraries/algorithms) to the policy engine.
Enables automated enforcement of policies against detected cryptographic usage.

This service answers: "Does the detected crypto usage in this application
comply with our defined policies?"

Usage:
    from app.core.policy_enforcement import policy_enforcement_service

    # Evaluate inventory against policies
    result = policy_enforcement_service.evaluate_inventory(inventory)
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from app.core.policy_engine import (
    PolicyEngine,
    Policy,
    PolicySeverity,
)
from app.core.crypto_inventory import (
    CryptoInventory,
    DetectedLibrary,
    DetectedAlgorithm,
    QuantumRisk,
)


class EnforcementAction(str, Enum):
    """What action to take based on enforcement result."""
    ALLOW = "allow"  # No policy violations
    WARN = "warn"  # Warnings present, but allowed to proceed
    BLOCK = "block"  # Policy violations prevent deployment


class ViolationType(str, Enum):
    """Type of policy violation."""
    DEPRECATED_LIBRARY = "deprecated_library"
    WEAK_ALGORITHM = "weak_algorithm"
    QUANTUM_VULNERABLE = "quantum_vulnerable"
    POLICY_RULE_FAILED = "policy_rule_failed"


@dataclass
class PolicyViolation:
    """A detected policy violation."""
    violation_type: ViolationType
    severity: PolicySeverity
    policy_name: str
    message: str
    details: dict = field(default_factory=dict)
    library: str | None = None
    algorithm: str | None = None
    recommendation: str | None = None


@dataclass
class EnforcementResult:
    """Result of policy enforcement evaluation."""
    action: EnforcementAction
    violations: list[PolicyViolation]
    warnings: list[PolicyViolation]
    info: list[PolicyViolation]
    summary: dict
    evaluated_at: str
    identity_id: str | None = None
    identity_name: str | None = None


# Static analysis policies for crypto inventory
CRYPTO_POLICIES = [
    Policy(
        name="no-deprecated-libraries",
        description="Block usage of deprecated cryptographic libraries",
        rule="library.is_deprecated == false",
        severity=PolicySeverity.BLOCK,
        message="Deprecated cryptographic library detected",
    ),
    Policy(
        name="quantum-vulnerability-warning",
        description="Warn about quantum-vulnerable algorithms",
        rule="library.quantum_risk not in ['high', 'critical']",
        severity=PolicySeverity.WARN,
        message="Quantum-vulnerable cryptography detected",
    ),
    Policy(
        name="pqc-recommendation",
        description="Recommend post-quantum cryptography",
        rule="inventory.has_pqc == true or inventory.quantum_vulnerable_count == 0",
        severity=PolicySeverity.INFO,
        message="Consider adding post-quantum cryptography support",
    ),
]


class PolicyEnforcementService:
    """
    Evaluates crypto inventory against policies.

    This service bridges:
    - What crypto is detected (from SDK init)
    - What crypto is allowed (policies)
    """

    def __init__(self):
        self.policies = CRYPTO_POLICIES.copy()
        self.custom_policies: list[Policy] = []

    def add_policy(self, policy: Policy) -> None:
        """Add a custom policy."""
        self.custom_policies.append(policy)

    def evaluate_inventory(
        self,
        inventory: CryptoInventory,
    ) -> EnforcementResult:
        """
        Evaluate a crypto inventory against policies.

        Args:
            inventory: CryptoInventory from SDK init

        Returns:
            EnforcementResult with violations and action
        """
        violations = []
        warnings = []
        info = []

        # Check each library
        for lib in inventory.libraries:
            # Check for deprecated libraries
            if lib.is_deprecated:
                violations.append(PolicyViolation(
                    violation_type=ViolationType.DEPRECATED_LIBRARY,
                    severity=PolicySeverity.BLOCK,
                    policy_name="no-deprecated-libraries",
                    message=f"Deprecated library '{lib.name}' detected",
                    details={
                        "library": lib.name,
                        "version": lib.version,
                        "reason": lib.deprecation_reason,
                    },
                    library=lib.name,
                    recommendation=lib.recommendation,
                ))

            # Check for quantum vulnerability
            if lib.quantum_risk in [QuantumRisk.HIGH, QuantumRisk.CRITICAL]:
                warnings.append(PolicyViolation(
                    violation_type=ViolationType.QUANTUM_VULNERABLE,
                    severity=PolicySeverity.WARN,
                    policy_name="quantum-vulnerability-warning",
                    message=f"Quantum-vulnerable library '{lib.name}'",
                    details={
                        "library": lib.name,
                        "algorithms": lib.algorithms,
                        "quantum_risk": lib.quantum_risk.value,
                    },
                    library=lib.name,
                    recommendation="Plan migration to post-quantum cryptography",
                ))

        # Check for weak algorithms
        for algo in inventory.algorithms:
            if algo.is_weak:
                violations.append(PolicyViolation(
                    violation_type=ViolationType.WEAK_ALGORITHM,
                    severity=PolicySeverity.BLOCK,
                    policy_name="no-weak-algorithms",
                    message=f"Weak algorithm '{algo.name}' from '{algo.library}'",
                    details={
                        "algorithm": algo.name,
                        "library": algo.library,
                        "reason": algo.weakness_reason,
                    },
                    algorithm=algo.name,
                    library=algo.library,
                    recommendation="Replace with a modern alternative",
                ))

        # PQC recommendation
        if inventory.quantum_summary.get("quantum_vulnerable", 0) > 0:
            if not inventory.quantum_summary.get("has_pqc", False):
                info.append(PolicyViolation(
                    violation_type=ViolationType.POLICY_RULE_FAILED,
                    severity=PolicySeverity.INFO,
                    policy_name="pqc-recommendation",
                    message="No post-quantum cryptography detected",
                    details=inventory.quantum_summary,
                    recommendation="Consider adding liboqs or pqcrypto for quantum readiness",
                ))

        # Determine action
        action = EnforcementAction.ALLOW
        if violations:
            action = EnforcementAction.BLOCK
        elif warnings:
            action = EnforcementAction.WARN

        return EnforcementResult(
            action=action,
            violations=violations,
            warnings=warnings,
            info=info,
            summary={
                "total_violations": len(violations),
                "total_warnings": len(warnings),
                "total_info": len(info),
                "libraries_checked": len(inventory.libraries),
                "algorithms_checked": len(inventory.algorithms),
                "deployment_allowed": action != EnforcementAction.BLOCK,
            },
            evaluated_at=datetime.now(timezone.utc).isoformat(),
            identity_id=inventory.identity_id,
            identity_name=inventory.identity_name,
        )

    def get_policy_summary(self) -> dict[str, Any]:
        """Get summary of all policies."""
        all_policies = self.policies + self.custom_policies

        return {
            "total_policies": len(all_policies),
            "blocking_policies": sum(1 for p in all_policies if p.severity == PolicySeverity.BLOCK),
            "warning_policies": sum(1 for p in all_policies if p.severity == PolicySeverity.WARN),
            "info_policies": sum(1 for p in all_policies if p.severity == PolicySeverity.INFO),
            "policies": [
                {
                    "name": p.name,
                    "description": p.description,
                    "severity": p.severity.value,
                    "enabled": p.enabled,
                }
                for p in all_policies
            ],
        }


# Singleton instance
policy_enforcement_service = PolicyEnforcementService()
