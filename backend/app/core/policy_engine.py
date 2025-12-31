"""Policy Enforcement Engine.

Evaluates cryptographic operations against defined policies.
Supports runtime validation at encrypt/decrypt time and
static analysis for CI/CD integration.

Policy Severity Levels:
- block: Operation is rejected
- warn: Operation proceeds but logs a warning
- info: Informational only, no enforcement

Example Policy Rules:
- "algorithm.key_bits >= 256" - Require 256-bit keys
- "context.sensitivity == 'critical'" - Check sensitivity level
- "algorithm.quantum_resistant == true" - Require PQC
- "identity.team in ['security', 'platform']" - Team restrictions
"""

import re
import operator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable

from pydantic import BaseModel, Field


class PolicySeverity(str, Enum):
    """Policy enforcement severity levels."""
    BLOCK = "block"    # Reject the operation
    WARN = "warn"      # Allow but log warning
    INFO = "info"      # Informational only


class PolicyViolation(Exception):
    """Raised when a blocking policy is violated."""

    def __init__(self, policy_name: str, message: str, severity: PolicySeverity):
        self.policy_name = policy_name
        self.severity = severity
        super().__init__(f"Policy violation [{policy_name}]: {message}")


@dataclass
class PolicyResult:
    """Result of evaluating a single policy."""
    policy_name: str
    passed: bool
    severity: PolicySeverity
    message: str
    details: dict = field(default_factory=dict)


@dataclass
class EvaluationContext:
    """Context provided for policy evaluation.

    Contains all the data that policy rules can access:
    - algorithm: resolved algorithm properties
    - context: the encryption context config
    - identity: the calling identity
    - operation: encrypt or decrypt
    - data: metadata about the data being processed
    """
    algorithm: dict = field(default_factory=dict)
    context: dict = field(default_factory=dict)
    identity: dict = field(default_factory=dict)
    operation: str = ""
    data: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class Policy(BaseModel):
    """A cryptographic policy rule."""

    name: str = Field(description="Unique policy identifier")
    description: str = Field(default="", description="Human-readable description")
    rule: str = Field(description="Rule expression to evaluate")
    severity: PolicySeverity = Field(
        default=PolicySeverity.WARN,
        description="What to do when rule fails"
    )
    message: str = Field(description="Message shown when rule fails")
    enabled: bool = Field(default=True, description="Whether policy is active")
    contexts: list[str] = Field(
        default_factory=list,
        description="Contexts this policy applies to (empty = all)"
    )
    operations: list[str] = Field(
        default_factory=list,
        description="Operations this applies to: encrypt, decrypt (empty = all)"
    )


class PolicyEngine:
    """Evaluates operations against cryptographic policies."""

    # Supported comparison operators
    # IMPORTANT: "not in" must come before "in" to avoid incorrect matching
    # Using a list of tuples to preserve order (Python 3.7+ dicts preserve order,
    # but explicit ordering is safer for this critical logic)
    OPERATORS = [
        ("not in", lambda a, b: a not in b),
        ("contains", lambda a, b: b in a),
        ("in", lambda a, b: a in b),
        (">=", operator.ge),
        ("<=", operator.le),
        ("!=", operator.ne),
        ("==", operator.eq),
        (">", operator.gt),
        ("<", operator.lt),
    ]

    def __init__(self):
        self.policies: list[Policy] = []

    def add_policy(self, policy: Policy) -> None:
        """Add a policy to the engine."""
        self.policies.append(policy)

    def add_policies(self, policies: list[Policy]) -> None:
        """Add multiple policies."""
        self.policies.extend(policies)

    def clear_policies(self) -> None:
        """Remove all policies."""
        self.policies.clear()

    def load_default_policies(self) -> None:
        """Load the default set of cryptographic policies."""
        defaults = [
            Policy(
                name="minimum-encryption-strength",
                description="Enforce minimum 256-bit encryption for critical data",
                rule="context.sensitivity != 'critical' or algorithm.key_bits >= 256",
                severity=PolicySeverity.BLOCK,
                message="Critical data requires 256-bit encryption minimum",
            ),
            Policy(
                name="no-legacy-algorithms",
                description="Block deprecated cryptographic algorithms",
                rule="algorithm.name not in ['DES', '3DES', 'MD5', 'SHA1', 'RC4', 'AES-128-ECB']",
                severity=PolicySeverity.BLOCK,
                message="Legacy algorithms are prohibited",
            ),
            Policy(
                name="pii-requires-context",
                description="PII data must use a proper context",
                rule="context.pii != true or context.name != 'general'",
                severity=PolicySeverity.BLOCK,
                message="PII data cannot use the general context",
            ),
            Policy(
                name="quantum-readiness-warning",
                description="Warn about non-quantum-resistant encryption for long-term data",
                rule="context.protection_lifetime_years <= 10 or algorithm.quantum_resistant == true",
                severity=PolicySeverity.WARN,
                message="Data with >10 year protection lifetime should use quantum-resistant algorithms",
            ),
            Policy(
                name="high-frequency-hardware-acceleration",
                description="Recommend hardware acceleration for high-frequency access",
                rule="context.frequency != 'high' or algorithm.hardware_acceleration == true",
                severity=PolicySeverity.INFO,
                message="High-frequency contexts should use hardware-accelerated algorithms",
            ),
            Policy(
                name="hipaa-compliance",
                description="HIPAA data requires specific controls",
                rule="'HIPAA' not in context.frameworks or (algorithm.key_bits >= 256 and context.audit_level == 'full')",
                severity=PolicySeverity.BLOCK,
                message="HIPAA data requires 256-bit encryption and full audit logging",
                contexts=["health-data"],
            ),
            Policy(
                name="pci-dss-compliance",
                description="PCI-DSS data requires specific controls",
                rule="'PCI-DSS' not in context.frameworks or algorithm.key_bits >= 256",
                severity=PolicySeverity.BLOCK,
                message="PCI-DSS data requires 256-bit encryption",
                contexts=["payment-data"],
            ),
        ]
        self.add_policies(defaults)

    def evaluate(
        self,
        eval_context: EvaluationContext,
        raise_on_block: bool = True,
    ) -> list[PolicyResult]:
        """Evaluate all applicable policies against the context.

        Args:
            eval_context: The evaluation context with all data
            raise_on_block: If True, raise PolicyViolation on blocking failures

        Returns:
            List of PolicyResult for each evaluated policy

        Raises:
            PolicyViolation: If a blocking policy fails and raise_on_block is True
        """
        results = []

        for policy in self.policies:
            if not policy.enabled:
                continue

            # Check if policy applies to this context
            if policy.contexts and eval_context.context.get("name") not in policy.contexts:
                continue

            # Check if policy applies to this operation
            if policy.operations and eval_context.operation not in policy.operations:
                continue

            # Evaluate the rule
            result = self._evaluate_rule(policy, eval_context)
            results.append(result)

            # Handle blocking violations
            if not result.passed and policy.severity == PolicySeverity.BLOCK:
                if raise_on_block:
                    raise PolicyViolation(
                        policy_name=policy.name,
                        message=policy.message,
                        severity=policy.severity,
                    )

        return results

    def _evaluate_rule(self, policy: Policy, ctx: EvaluationContext) -> PolicyResult:
        """Evaluate a single policy rule."""
        try:
            # Build the evaluation namespace
            namespace = self._build_namespace(ctx)

            # Parse and evaluate the rule
            passed = self._parse_and_eval(policy.rule, namespace)

            return PolicyResult(
                policy_name=policy.name,
                passed=passed,
                severity=policy.severity,
                message=policy.message if not passed else "",
                details={"rule": policy.rule},
            )

        except Exception as e:
            # Rule evaluation error - treat as failed
            return PolicyResult(
                policy_name=policy.name,
                passed=False,
                severity=policy.severity,
                message=f"Rule evaluation error: {e}",
                details={"rule": policy.rule, "error": str(e)},
            )

    def _build_namespace(self, ctx: EvaluationContext) -> dict[str, Any]:
        """Build the namespace for rule evaluation."""
        return {
            "algorithm": DotDict(ctx.algorithm),
            "context": DotDict(ctx.context),
            "identity": DotDict(ctx.identity),
            "operation": ctx.operation,
            "data": DotDict(ctx.data),
            "timestamp": ctx.timestamp,
            # Helper values
            "true": True,
            "false": False,
            "True": True,
            "False": False,
        }

    def _find_top_level_operator(self, rule: str, op: str) -> int | None:
        """Find the position of an operator at the top level (outside parentheses).

        Returns the index where the operator starts, or None if not found at top level.
        """
        depth = 0
        op_with_spaces = f" {op} "
        i = 0
        while i <= len(rule) - len(op_with_spaces):
            char = rule[i]
            if char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
            elif depth == 0 and rule[i:i + len(op_with_spaces)] == op_with_spaces:
                return i
            i += 1
        return None

    def _parse_and_eval(self, rule: str, namespace: dict) -> bool:
        """Parse and evaluate a rule expression.

        Supports:
        - Comparisons: ==, !=, >, >=, <, <=
        - Membership: in, not in, contains
        - Boolean: and, or, not
        - Parentheses for grouping
        - Dot notation for nested access

        Operator precedence (lowest to highest):
        1. or
        2. and
        3. not
        4. comparison operators
        """
        stripped = rule.strip()

        # Handle parentheses wrapping the entire expression first
        if stripped.startswith("(") and stripped.endswith(")"):
            # Check if these are matching parentheses (not separate groups)
            depth = 0
            matched = True
            for i, char in enumerate(stripped):
                if char == '(':
                    depth += 1
                elif char == ')':
                    depth -= 1
                    if depth == 0 and i < len(stripped) - 1:
                        # Closing paren before end means these aren't wrapping parens
                        matched = False
                        break
            if matched and depth == 0:
                return self._parse_and_eval(stripped[1:-1], namespace)

        # Handle 'or' at top level (lowest precedence)
        or_pos = self._find_top_level_operator(stripped, "or")
        if or_pos is not None:
            left = stripped[:or_pos]
            right = stripped[or_pos + 4:]  # len(" or ") = 4
            return self._parse_and_eval(left, namespace) or \
                   self._parse_and_eval(right, namespace)

        # Handle 'and' at top level
        and_pos = self._find_top_level_operator(stripped, "and")
        if and_pos is not None:
            left = stripped[:and_pos]
            right = stripped[and_pos + 5:]  # len(" and ") = 5
            return self._parse_and_eval(left, namespace) and \
                   self._parse_and_eval(right, namespace)

        # Handle 'not' prefix (after checking for 'not in' operator below)
        # Parse comparison expression - check operators BEFORE 'not' prefix
        # This ensures "not in" is treated as a single operator
        for op_str, op_func in self.OPERATORS:
            if f" {op_str} " in stripped:
                parts = stripped.split(f" {op_str} ", 1)
                left = self._resolve_value(parts[0].strip(), namespace)
                right = self._resolve_value(parts[1].strip(), namespace)
                return op_func(left, right)

        # Handle 'not' prefix (only after checking for 'not in' operator above)
        if stripped.startswith("not "):
            return not self._parse_and_eval(stripped[4:], namespace)

        # If no operator, evaluate as boolean
        return bool(self._resolve_value(stripped, namespace))

    def _resolve_value(self, expr: str, namespace: dict) -> Any:
        """Resolve a value expression to its actual value."""
        expr = expr.strip()

        # String literal
        if (expr.startswith("'") and expr.endswith("'")) or \
           (expr.startswith('"') and expr.endswith('"')):
            return expr[1:-1]

        # List literal
        if expr.startswith("[") and expr.endswith("]"):
            items = expr[1:-1].split(",")
            return [self._resolve_value(item.strip(), namespace) for item in items if item.strip()]

        # Number
        if expr.isdigit():
            return int(expr)
        if re.match(r"^-?\d+\.?\d*$", expr):
            return float(expr)

        # Boolean
        if expr.lower() == "true":
            return True
        if expr.lower() == "false":
            return False

        # None
        if expr.lower() == "none" or expr.lower() == "null":
            return None

        # Dot notation path (e.g., context.sensitivity)
        if "." in expr:
            parts = expr.split(".")
            value = namespace.get(parts[0])
            for part in parts[1:]:
                if value is None:
                    return None
                if isinstance(value, dict):
                    value = value.get(part)
                elif hasattr(value, part):
                    value = getattr(value, part)
                else:
                    return None
            return value

        # Simple variable
        return namespace.get(expr)


class DotDict(dict):
    """Dict that supports dot notation access."""

    def __getattr__(self, key: str) -> Any:
        try:
            value = self[key]
            if isinstance(value, dict):
                return DotDict(value)
            return value
        except KeyError:
            return None

    def __setattr__(self, key: str, value: Any) -> None:
        self[key] = value


# =============================================================================
# Helper Functions
# =============================================================================

def build_evaluation_context(
    context_config: dict | None,
    context_derived: dict | None,
    context_name: str,
    identity_data: dict,
    operation: str,
    data_metadata: dict | None = None,
) -> EvaluationContext:
    """Build an EvaluationContext from raw data.

    Args:
        context_config: The 5-layer context configuration
        context_derived: The derived requirements (algorithm info)
        context_name: Name of the context
        identity_data: Identity information
        operation: "encrypt" or "decrypt"
        data_metadata: Optional metadata about the data

    Returns:
        EvaluationContext ready for policy evaluation
    """
    # Extract algorithm info from derived requirements
    algorithm = {}
    if context_derived:
        algorithm = {
            "name": context_derived.get("resolved_algorithm", "AES-256-GCM"),
            "key_bits": context_derived.get("minimum_security_bits", 256),
            "quantum_resistant": context_derived.get("quantum_resistant", False),
            "hardware_acceleration": context_derived.get("hardware_acceleration", False),
        }
    else:
        # Default for legacy contexts
        algorithm = {
            "name": "AES-256-GCM",
            "key_bits": 256,
            "quantum_resistant": False,
            "hardware_acceleration": True,
        }

    # Build context info
    context = {"name": context_name}
    if context_config:
        data_identity = context_config.get("data_identity", {})
        regulatory = context_config.get("regulatory", {})
        threat_model = context_config.get("threat_model", {})
        access_patterns = context_config.get("access_patterns", {})

        context.update({
            "sensitivity": data_identity.get("sensitivity", "medium"),
            "pii": data_identity.get("pii", False),
            "phi": data_identity.get("phi", False),
            "pci": data_identity.get("pci", False),
            "notification_required": data_identity.get("notification_required", False),
            "frameworks": regulatory.get("frameworks", []),
            "protection_lifetime_years": threat_model.get("protection_lifetime_years", 5),
            "frequency": access_patterns.get("frequency", "medium"),
            "audit_level": context_derived.get("audit_level", "standard") if context_derived else "standard",
        })

    return EvaluationContext(
        algorithm=algorithm,
        context=context,
        identity=identity_data,
        operation=operation,
        data=data_metadata or {},
    )


# Singleton instance
policy_engine = PolicyEngine()
