"""
Local policy engine for CryptoServe gate.

Provides built-in policies that work without server connection.
Supports policy presets (strict, standard, permissive) and
custom configuration via .cryptoserve.yml.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml


class Severity(Enum):
    """Finding severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(Enum):
    """Policy action for a finding."""

    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


@dataclass
class PolicyRule:
    """A single policy rule."""

    name: str
    description: str
    condition: str  # "weak", "deprecated", "quantum_vulnerable", "severity:critical"
    action: Action
    message: str | None = None


@dataclass
class Policy:
    """A complete policy configuration."""

    name: str
    description: str
    rules: list[PolicyRule] = field(default_factory=list)


# Algorithm database - which algorithms are weak, deprecated, or quantum vulnerable
ALGORITHM_DATABASE: dict[str, dict[str, Any]] = {
    # Broken/Weak algorithms - BLOCK
    "md5": {
        "weak": True,
        "deprecated": True,
        "quantum_vulnerable": False,
        "severity": "critical",
        "message": "MD5 is cryptographically broken. Use SHA-256 or SHA-3.",
        "cwe": "CWE-328",
    },
    "md4": {
        "weak": True,
        "deprecated": True,
        "quantum_vulnerable": False,
        "severity": "critical",
        "message": "MD4 is cryptographically broken. Use SHA-256 or SHA-3.",
        "cwe": "CWE-328",
    },
    "sha1": {
        "weak": True,
        "deprecated": True,
        "quantum_vulnerable": False,
        "severity": "high",
        "message": "SHA-1 has known collision attacks. Use SHA-256 or SHA-3.",
        "cwe": "CWE-328",
    },
    "des": {
        "weak": True,
        "deprecated": True,
        "quantum_vulnerable": False,
        "severity": "critical",
        "message": "DES has only 56-bit key strength. Use AES-256.",
        "cwe": "CWE-327",
    },
    "3des": {
        "weak": True,
        "deprecated": True,
        "quantum_vulnerable": False,
        "severity": "high",
        "message": "3DES is deprecated due to Sweet32 attacks. Use AES-256.",
        "cwe": "CWE-327",
    },
    "rc4": {
        "weak": True,
        "deprecated": True,
        "quantum_vulnerable": False,
        "severity": "critical",
        "message": "RC4 has multiple cryptographic weaknesses. Use AES-GCM or ChaCha20.",
        "cwe": "CWE-327",
    },
    "rc2": {
        "weak": True,
        "deprecated": True,
        "quantum_vulnerable": False,
        "severity": "critical",
        "message": "RC2 is weak and deprecated. Use AES-256.",
        "cwe": "CWE-327",
    },
    "blowfish": {
        "weak": True,
        "deprecated": True,
        "quantum_vulnerable": False,
        "severity": "medium",
        "message": "Blowfish has a 64-bit block size vulnerable to birthday attacks. Use AES-256.",
        "cwe": "CWE-327",
    },
    # Quantum vulnerable algorithms - WARN (standard) or BLOCK (strict)
    "rsa": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": True,
        "severity": "medium",
        "message": "RSA is vulnerable to quantum attacks (Shor's algorithm). Plan migration to ML-KEM.",
        "cwe": "CWE-310",
    },
    "dsa": {
        "weak": False,
        "deprecated": True,
        "quantum_vulnerable": True,
        "severity": "medium",
        "message": "DSA is deprecated and quantum vulnerable. Use ML-DSA or Ed25519 (short-term).",
        "cwe": "CWE-310",
    },
    "ecdsa": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": True,
        "severity": "low",
        "message": "ECDSA is quantum vulnerable. Plan migration to ML-DSA.",
        "cwe": "CWE-310",
    },
    "ecdh": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": True,
        "severity": "low",
        "message": "ECDH is quantum vulnerable. Plan migration to ML-KEM.",
        "cwe": "CWE-310",
    },
    "x25519": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": True,
        "severity": "low",
        "message": "X25519 is quantum vulnerable. Plan migration to ML-KEM.",
        "cwe": "CWE-310",
    },
    "ed25519": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": True,
        "severity": "low",
        "message": "Ed25519 is quantum vulnerable. Plan migration to ML-DSA.",
        "cwe": "CWE-310",
    },
    "diffie-hellman": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": True,
        "severity": "medium",
        "message": "Diffie-Hellman is quantum vulnerable. Plan migration to ML-KEM.",
        "cwe": "CWE-310",
    },
    "dh": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": True,
        "severity": "medium",
        "message": "Diffie-Hellman is quantum vulnerable. Plan migration to ML-KEM.",
        "cwe": "CWE-310",
    },
    # Safe algorithms - ALLOW
    "aes": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": False,
        "severity": "info",
        "message": None,
    },
    "aes-128": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": False,
        "severity": "info",
        "message": "Consider AES-256 for long-term quantum resistance.",
    },
    "aes-256": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": False,
        "severity": "info",
        "message": None,
    },
    "chacha20": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": False,
        "severity": "info",
        "message": None,
    },
    "chacha20-poly1305": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": False,
        "severity": "info",
        "message": None,
    },
    "sha256": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": False,
        "severity": "info",
        "message": None,
    },
    "sha-256": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": False,
        "severity": "info",
        "message": None,
    },
    "sha384": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": False,
        "severity": "info",
        "message": None,
    },
    "sha512": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": False,
        "severity": "info",
        "message": None,
    },
    "sha3": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": False,
        "severity": "info",
        "message": None,
    },
    "blake2": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": False,
        "severity": "info",
        "message": None,
    },
    "blake3": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": False,
        "severity": "info",
        "message": None,
    },
    "argon2": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": False,
        "severity": "info",
        "message": None,
    },
    "bcrypt": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": False,
        "severity": "info",
        "message": None,
    },
    "scrypt": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": False,
        "severity": "info",
        "message": None,
    },
    "pbkdf2": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": False,
        "severity": "info",
        "message": "Consider Argon2 for new implementations.",
    },
    # Post-quantum algorithms - SAFE
    "kyber": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": False,
        "severity": "info",
        "message": None,
    },
    "ml-kem": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": False,
        "severity": "info",
        "message": None,
    },
    "dilithium": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": False,
        "severity": "info",
        "message": None,
    },
    "ml-dsa": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": False,
        "severity": "info",
        "message": None,
    },
    "sphincs": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": False,
        "severity": "info",
        "message": None,
    },
    "slh-dsa": {
        "weak": False,
        "deprecated": False,
        "quantum_vulnerable": False,
        "severity": "info",
        "message": None,
    },
}


# Policy presets
POLICY_PRESETS: dict[str, Policy] = {
    "strict": Policy(
        name="strict",
        description="Blocks weak, deprecated, and quantum-vulnerable algorithms",
        rules=[
            PolicyRule(
                name="block-weak",
                description="Block all weak/broken algorithms",
                condition="weak",
                action=Action.BLOCK,
            ),
            PolicyRule(
                name="block-deprecated",
                description="Block all deprecated algorithms",
                condition="deprecated",
                action=Action.BLOCK,
            ),
            PolicyRule(
                name="block-quantum-vulnerable",
                description="Block quantum-vulnerable algorithms",
                condition="quantum_vulnerable",
                action=Action.BLOCK,
            ),
        ],
    ),
    "standard": Policy(
        name="standard",
        description="Blocks weak/deprecated, warns on quantum-vulnerable",
        rules=[
            PolicyRule(
                name="block-weak",
                description="Block all weak/broken algorithms",
                condition="weak",
                action=Action.BLOCK,
            ),
            PolicyRule(
                name="block-deprecated",
                description="Block all deprecated algorithms",
                condition="deprecated",
                action=Action.BLOCK,
            ),
            PolicyRule(
                name="warn-quantum-vulnerable",
                description="Warn about quantum-vulnerable algorithms",
                condition="quantum_vulnerable",
                action=Action.WARN,
            ),
        ],
    ),
    "permissive": Policy(
        name="permissive",
        description="Only blocks critical issues, warns on others",
        rules=[
            PolicyRule(
                name="block-critical",
                description="Block only critical severity findings",
                condition="severity:critical",
                action=Action.BLOCK,
            ),
            PolicyRule(
                name="warn-weak",
                description="Warn about weak algorithms",
                condition="weak",
                action=Action.WARN,
            ),
            PolicyRule(
                name="warn-deprecated",
                description="Warn about deprecated algorithms",
                condition="deprecated",
                action=Action.WARN,
            ),
        ],
    ),
}


@dataclass
class Finding:
    """A policy finding from scanning."""

    file: str
    line: int | None
    algorithm: str
    severity: Severity
    action: Action
    message: str
    recommendation: str | None = None
    cwe: str | None = None


@dataclass
class GateResult:
    """Result of running the gate check."""

    passed: bool
    exit_code: int
    files_scanned: int
    scan_time_ms: float
    violations: list[Finding]
    warnings: list[Finding]
    info: list[Finding]
    quantum_readiness_score: float

    @property
    def summary(self) -> dict[str, int]:
        """Return summary counts."""
        return {
            "violations": len(self.violations),
            "warnings": len(self.warnings),
            "info": len(self.info),
            "quantum_vulnerable": sum(
                1
                for f in self.violations + self.warnings
                if ALGORITHM_DATABASE.get(f.algorithm.lower(), {}).get(
                    "quantum_vulnerable", False
                )
            ),
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return {
            "passed": self.passed,
            "exit_code": self.exit_code,
            "files_scanned": self.files_scanned,
            "scan_time_ms": self.scan_time_ms,
            "summary": self.summary,
            "violations": [
                {
                    "file": f.file,
                    "line": f.line,
                    "severity": f.severity.value,
                    "algorithm": f.algorithm,
                    "message": f.message,
                    "recommendation": f.recommendation,
                    "cwe": f.cwe,
                }
                for f in self.violations
            ],
            "warnings": [
                {
                    "file": f.file,
                    "line": f.line,
                    "severity": f.severity.value,
                    "algorithm": f.algorithm,
                    "message": f.message,
                    "recommendation": f.recommendation,
                }
                for f in self.warnings
            ],
            "quantum_readiness_score": self.quantum_readiness_score,
        }

    def to_sarif(self) -> dict[str, Any]:
        """Convert to SARIF format for GitHub Security tab."""
        from cryptoserve import __version__
        rules = []
        results = []
        seen_rules: set[str] = set()

        for finding in self.violations + self.warnings:
            rule_id = f"crypto/{finding.algorithm.lower()}"

            if rule_id not in seen_rules:
                seen_rules.add(rule_id)
                algo_info = ALGORITHM_DATABASE.get(finding.algorithm.lower(), {})
                rules.append(
                    {
                        "id": rule_id,
                        "name": f"Insecure {finding.algorithm.upper()}",
                        "shortDescription": {"text": finding.message},
                        "fullDescription": {"text": finding.message},
                        "help": {
                            "text": finding.recommendation or "Review cryptographic usage"
                        },
                        "properties": {
                            "security-severity": self._severity_to_cvss(finding.severity)
                        },
                    }
                )

            results.append(
                {
                    "ruleId": rule_id,
                    "level": "error" if finding.action == Action.BLOCK else "warning",
                    "message": {"text": finding.message},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": finding.file},
                                "region": {"startLine": finding.line or 1},
                            }
                        }
                    ],
                }
            )

        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CryptoServe",
                            "version": __version__,
                            "informationUri": "https://github.com/ecolibria/cryptoserve",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

    def _severity_to_cvss(self, severity: Severity) -> str:
        """Map severity to CVSS-like score for SARIF."""
        mapping = {
            Severity.CRITICAL: "9.0",
            Severity.HIGH: "7.0",
            Severity.MEDIUM: "5.0",
            Severity.LOW: "3.0",
            Severity.INFO: "1.0",
        }
        return mapping.get(severity, "5.0")


class PolicyEngine:
    """Evaluates findings against a policy."""

    def __init__(self, policy: Policy | str = "standard"):
        """Initialize with a policy preset name or Policy object."""
        if isinstance(policy, str):
            if policy not in POLICY_PRESETS:
                raise ValueError(
                    f"Unknown policy preset: {policy}. "
                    f"Available: {', '.join(POLICY_PRESETS.keys())}"
                )
            self.policy = POLICY_PRESETS[policy]
        else:
            self.policy = policy

    def evaluate_algorithm(
        self, algorithm: str, file: str, line: int | None = None
    ) -> Finding | None:
        """Evaluate a single algorithm against the policy."""
        algo_lower = algorithm.lower()
        algo_info = ALGORITHM_DATABASE.get(algo_lower)

        if not algo_info:
            # Unknown algorithm - allow but note
            return None

        # Check each rule
        for rule in self.policy.rules:
            if self._matches_condition(rule.condition, algo_info):
                severity = Severity(algo_info.get("severity", "info"))
                message = algo_info.get("message") or f"Algorithm {algorithm} flagged by policy"

                return Finding(
                    file=file,
                    line=line,
                    algorithm=algorithm,
                    severity=severity,
                    action=rule.action,
                    message=message,
                    recommendation=self._get_recommendation(algorithm, algo_info),
                    cwe=algo_info.get("cwe"),
                )

        return None

    def _matches_condition(self, condition: str, algo_info: dict) -> bool:
        """Check if an algorithm matches a rule condition."""
        if condition == "weak":
            return algo_info.get("weak", False)
        elif condition == "deprecated":
            return algo_info.get("deprecated", False)
        elif condition == "quantum_vulnerable":
            return algo_info.get("quantum_vulnerable", False)
        elif condition.startswith("severity:"):
            target_severity = condition.split(":")[1]
            return algo_info.get("severity") == target_severity
        return False

    def _get_recommendation(self, algorithm: str, algo_info: dict) -> str:
        """Get recommendation for replacing an algorithm."""
        algo_lower = algorithm.lower()

        recommendations = {
            "md5": "Use SHA-256 or SHA-3 for hashing",
            "md4": "Use SHA-256 or SHA-3 for hashing",
            "sha1": "Use SHA-256 or SHA-3 for hashing",
            "des": "Use AES-256-GCM for encryption",
            "3des": "Use AES-256-GCM for encryption",
            "rc4": "Use AES-256-GCM or ChaCha20-Poly1305",
            "rc2": "Use AES-256-GCM for encryption",
            "blowfish": "Use AES-256-GCM for encryption",
            "rsa": "Plan migration to ML-KEM (FIPS 203) for key exchange",
            "dsa": "Migrate to ML-DSA (FIPS 204) or Ed25519 (short-term)",
            "ecdsa": "Plan migration to ML-DSA (FIPS 204)",
            "ecdh": "Plan migration to ML-KEM (FIPS 203)",
            "x25519": "Plan migration to ML-KEM (FIPS 203)",
            "ed25519": "Plan migration to ML-DSA (FIPS 204)",
            "diffie-hellman": "Plan migration to ML-KEM (FIPS 203)",
            "dh": "Plan migration to ML-KEM (FIPS 203)",
        }

        return recommendations.get(algo_lower, "Review cryptographic usage")


def load_config(project_root: Path | None = None) -> dict[str, Any]:
    """Load configuration from .cryptoserve.yml if it exists."""
    if project_root is None:
        project_root = Path.cwd()

    config_path = project_root / ".cryptoserve.yml"
    if not config_path.exists():
        config_path = project_root / ".cryptoserve.yaml"

    if config_path.exists():
        with open(config_path) as f:
            return yaml.safe_load(f) or {}

    return {}


def get_policy(name: str | None = None, config: dict | None = None) -> Policy:
    """Get a policy by name or from config."""
    if config is None:
        config = load_config()

    # Get policy name from config if not specified
    if name is None:
        name = config.get("policy", "standard")

    if name in POLICY_PRESETS:
        return POLICY_PRESETS[name]

    raise ValueError(f"Unknown policy: {name}")
