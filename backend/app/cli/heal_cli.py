#!/usr/bin/env python3
"""CryptoServe Self-Healing CLI.

A command-line tool for automated cryptographic remediation and re-encryption.
Handles key rotation, algorithm migration, and self-healing operations.

Usage:
    cryptoserve heal status
    cryptoserve heal reencrypt --context user-pii
    cryptoserve heal rotate-keys --context user-pii
    cryptoserve heal upgrade-algorithm --from AES-128-GCM --to AES-256-GCM

Exit Codes:
    0 - Success
    1 - Partial failure (some operations failed)
    2 - Configuration error
    3 - Invalid arguments
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.core.crypto_registry import (
    crypto_registry,
    Algorithm,
    SecurityStatus,
    get_deprecated_algorithms,
)


# =============================================================================
# Terminal Colors
# =============================================================================

class Colors:
    """ANSI color codes for terminal output."""
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls):
        for attr in ['RED', 'GREEN', 'YELLOW', 'BLUE', 'MAGENTA', 'CYAN', 'WHITE', 'BOLD', 'RESET']:
            setattr(cls, attr, "")


def colored(text: str, color: str) -> str:
    return f"{color}{text}{Colors.RESET}"


# =============================================================================
# Health Status Types
# =============================================================================

class HealthStatus(str, Enum):
    """Health status of a cryptographic component."""
    HEALTHY = "healthy"         # All good
    WARNING = "warning"         # Attention needed soon
    DEGRADED = "degraded"       # Performance/security impact
    CRITICAL = "critical"       # Immediate action required
    UNKNOWN = "unknown"         # Cannot determine


class ComponentType(str, Enum):
    """Types of cryptographic components."""
    KEY = "key"
    ALGORITHM = "algorithm"
    CONTEXT = "context"
    POLICY = "policy"
    CERTIFICATE = "certificate"


@dataclass
class HealthIssue:
    """A health issue requiring attention."""
    component_type: ComponentType
    component_id: str
    status: HealthStatus
    message: str
    recommendation: str
    auto_healable: bool = False
    priority: int = 0  # Lower is more urgent

    def to_dict(self) -> dict:
        return {
            "component_type": self.component_type.value,
            "component_id": self.component_id,
            "status": self.status.value,
            "message": self.message,
            "recommendation": self.recommendation,
            "auto_healable": self.auto_healable,
            "priority": self.priority,
        }


@dataclass
class HealthReport:
    """Overall health report."""
    timestamp: datetime
    overall_status: HealthStatus
    issues: list[HealthIssue] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "overall_status": self.overall_status.value,
            "summary": {
                "total_issues": len(self.issues),
                "critical": sum(1 for i in self.issues if i.status == HealthStatus.CRITICAL),
                "warning": sum(1 for i in self.issues if i.status == HealthStatus.WARNING),
                "auto_healable": sum(1 for i in self.issues if i.auto_healable),
            },
            "issues": [i.to_dict() for i in self.issues],
            "stats": self.stats,
        }


# =============================================================================
# Data Store Interface and Implementations
# =============================================================================

import os
import urllib.request
import urllib.error

# Configuration from environment
CRYPTOSERVE_API_URL = os.environ.get("CRYPTOSERVE_API_URL", "").rstrip("/")
CRYPTOSERVE_API_TOKEN = os.environ.get("CRYPTOSERVE_API_TOKEN", "")

# Flag to indicate demo mode is active
_DEMO_MODE = not (CRYPTOSERVE_API_URL and CRYPTOSERVE_API_TOKEN)


class DataStoreInterface:
    """Interface for data stores."""

    def get_keys(self, context: str | None = None) -> list[dict]:
        raise NotImplementedError

    def get_contexts(self) -> list[dict]:
        raise NotImplementedError

    def get_key(self, key_id: str) -> dict | None:
        raise NotImplementedError


class APIDataStore(DataStoreInterface):
    """Live API data store connecting to CryptoServe backend.

    Uses the CryptoServe REST API to fetch real data about keys and contexts.
    Requires CRYPTOSERVE_API_URL and CRYPTOSERVE_API_TOKEN environment variables.
    """

    def __init__(self, base_url: str, token: str):
        self.base_url = base_url
        self.token = token
        self._cache: dict[str, Any] = {}

    def _request(self, endpoint: str) -> dict | list:
        """Make authenticated API request."""
        url = f"{self.base_url}{endpoint}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                return json.loads(response.read().decode())
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"API error {e.code}: {e.reason}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"Connection error: {e.reason}") from e

    def get_keys(self, context: str | None = None) -> list[dict]:
        """Fetch keys from API."""
        # Get all contexts first to build key list
        contexts = self.get_contexts()
        all_keys = []

        for ctx in contexts:
            ctx_name = ctx.get("name")
            if context and ctx_name != context:
                continue

            try:
                # Fetch key bundle for this context
                bundle = self._request(f"/api/v1/contexts/{ctx_name}/keys")

                # Build key entries from bundle
                if bundle.get("encryptionKey"):
                    enc_key = bundle["encryptionKey"]
                    all_keys.append({
                        "id": enc_key.get("id", f"{ctx_name}-enc"),
                        "context": ctx_name,
                        "algorithm": enc_key.get("algorithm", "AES-256-GCM"),
                        "created_at": datetime.fromisoformat(enc_key.get("createdAt", datetime.now(timezone.utc).isoformat()).replace("Z", "+00:00")),
                        "last_rotated": datetime.fromisoformat(enc_key.get("lastRotatedAt", datetime.now(timezone.utc).isoformat()).replace("Z", "+00:00")),
                        "rotation_days": enc_key.get("rotationScheduleDays", 90),
                        "data_encrypted_count": 0,  # Not available from bundle API
                    })
            except Exception as e:
                print(f"Warning: Could not fetch keys for context {ctx_name}: {e}", file=sys.stderr)

        return all_keys

    def get_contexts(self) -> list[dict]:
        """Fetch contexts from API."""
        if "contexts" in self._cache:
            return self._cache["contexts"]

        try:
            response = self._request("/api/v1/contexts")
            contexts = []
            for ctx in response:
                contexts.append({
                    "name": ctx.get("name"),
                    "algorithm": ctx.get("algorithm", "AES-256-GCM"),
                    "quantum_resistant": ctx.get("quantumResistant", False),
                    "compliance": ctx.get("compliance", []),
                })
            self._cache["contexts"] = contexts
            return contexts
        except Exception as e:
            print(f"Warning: Could not fetch contexts: {e}", file=sys.stderr)
            return []

    def get_key(self, key_id: str) -> dict | None:
        """Fetch a specific key by ID."""
        keys = self.get_keys()
        for key in keys:
            if key.get("id") == key_id:
                return key
        return None


class DemoDataStore(DataStoreInterface):
    """Demo data store for testing when API is not configured.

    Provides synthetic data for demonstrating heal CLI capabilities.
    Used automatically when CRYPTOSERVE_API_URL/TOKEN are not set.
    """

    def __init__(self):
        self._keys = {
            "key-001": {
                "id": "key-001",
                "context": "user-pii",
                "algorithm": "AES-256-GCM",
                "created_at": datetime.now(timezone.utc) - timedelta(days=400),
                "last_rotated": datetime.now(timezone.utc) - timedelta(days=400),
                "rotation_days": 365,
                "data_encrypted_count": 50000,
            },
            "key-002": {
                "id": "key-002",
                "context": "payments",
                "algorithm": "AES-256-GCM",
                "created_at": datetime.now(timezone.utc) - timedelta(days=30),
                "last_rotated": datetime.now(timezone.utc) - timedelta(days=30),
                "rotation_days": 90,
                "data_encrypted_count": 10000,
            },
            "key-003": {
                "id": "key-003",
                "context": "legacy-data",
                "algorithm": "AES-128-CBC",
                "created_at": datetime.now(timezone.utc) - timedelta(days=800),
                "last_rotated": datetime.now(timezone.utc) - timedelta(days=500),
                "rotation_days": 180,
                "data_encrypted_count": 100000,
            },
            "key-004": {
                "id": "key-004",
                "context": "archive",
                "algorithm": "3DES",
                "created_at": datetime.now(timezone.utc) - timedelta(days=1500),
                "last_rotated": datetime.now(timezone.utc) - timedelta(days=1000),
                "rotation_days": 365,
                "data_encrypted_count": 25000,
            },
        }

        self._contexts = {
            "user-pii": {
                "name": "user-pii",
                "algorithm": "AES-256-GCM",
                "quantum_resistant": False,
                "compliance": ["GDPR", "CCPA"],
            },
            "payments": {
                "name": "payments",
                "algorithm": "AES-256-GCM",
                "quantum_resistant": False,
                "compliance": ["PCI-DSS"],
            },
            "legacy-data": {
                "name": "legacy-data",
                "algorithm": "AES-128-CBC",
                "quantum_resistant": False,
                "compliance": [],
            },
            "archive": {
                "name": "archive",
                "algorithm": "3DES",
                "quantum_resistant": False,
                "compliance": [],
            },
        }

    def get_keys(self, context: str | None = None) -> list[dict]:
        keys = list(self._keys.values())
        if context:
            keys = [k for k in keys if k["context"] == context]
        return keys

    def get_contexts(self) -> list[dict]:
        return list(self._contexts.values())

    def get_key(self, key_id: str) -> dict | None:
        return self._keys.get(key_id)


def create_data_store() -> DataStoreInterface:
    """Create appropriate data store based on environment configuration."""
    if CRYPTOSERVE_API_URL and CRYPTOSERVE_API_TOKEN:
        return APIDataStore(CRYPTOSERVE_API_URL, CRYPTOSERVE_API_TOKEN)
    return DemoDataStore()


# Global data store - initialized on first use
_data_store: DataStoreInterface | None = None


def get_data_store() -> DataStoreInterface:
    """Get or create the global data store."""
    global _data_store
    if _data_store is None:
        _data_store = create_data_store()
    return _data_store


# =============================================================================
# Health Assessment
# =============================================================================

def assess_key_health(key: dict) -> list[HealthIssue]:
    """Assess the health of a single key."""
    issues = []
    key_id = key["id"]
    context = key["context"]
    algorithm = key["algorithm"]
    last_rotated = key["last_rotated"]
    rotation_days = key["rotation_days"]

    # Check if key needs rotation
    days_since_rotation = (datetime.now(timezone.utc) - last_rotated).days
    days_until_due = rotation_days - days_since_rotation

    if days_until_due < 0:
        issues.append(HealthIssue(
            component_type=ComponentType.KEY,
            component_id=key_id,
            status=HealthStatus.CRITICAL,
            message=f"Key rotation overdue by {abs(days_until_due)} days (context: {context})",
            recommendation=f"Run: cryptoserve heal rotate-keys --key {key_id}",
            auto_healable=True,
            priority=1,
        ))
    elif days_until_due < 30:
        issues.append(HealthIssue(
            component_type=ComponentType.KEY,
            component_id=key_id,
            status=HealthStatus.WARNING,
            message=f"Key rotation due in {days_until_due} days (context: {context})",
            recommendation=f"Schedule key rotation: cryptoserve heal rotate-keys --key {key_id}",
            auto_healable=True,
            priority=2,
        ))

    # Check algorithm status
    algo_info = crypto_registry.get(algorithm)
    if algo_info:
        if algo_info.status == SecurityStatus.BROKEN:
            issues.append(HealthIssue(
                component_type=ComponentType.ALGORITHM,
                component_id=algorithm,
                status=HealthStatus.CRITICAL,
                message=f"Key {key_id} uses BROKEN algorithm: {algorithm}",
                recommendation=f"Migrate immediately: cryptoserve heal reencrypt --context {context} --algorithm AES-256-GCM",
                auto_healable=True,
                priority=0,  # Highest priority
            ))
        elif algo_info.status == SecurityStatus.DEPRECATED:
            issues.append(HealthIssue(
                component_type=ComponentType.ALGORITHM,
                component_id=algorithm,
                status=HealthStatus.DEGRADED,
                message=f"Key {key_id} uses DEPRECATED algorithm: {algorithm}",
                recommendation=f"Migrate: cryptoserve heal reencrypt --context {context} --algorithm AES-256-GCM",
                auto_healable=True,
                priority=1,
            ))
        elif algo_info.status == SecurityStatus.LEGACY:
            issues.append(HealthIssue(
                component_type=ComponentType.ALGORITHM,
                component_id=algorithm,
                status=HealthStatus.WARNING,
                message=f"Key {key_id} uses LEGACY algorithm: {algorithm}",
                recommendation=f"Consider migration: cryptoserve heal reencrypt --context {context}",
                auto_healable=True,
                priority=3,
            ))

    return issues


def assess_system_health() -> HealthReport:
    """Assess overall cryptographic health."""
    issues = []

    # Check all keys
    for key in get_data_store().get_keys():
        key_issues = assess_key_health(key)
        issues.extend(key_issues)

    # Check for quantum readiness
    contexts = get_data_store().get_contexts()
    non_quantum = [c for c in contexts if not c.get("quantum_resistant")]
    if non_quantum:
        issues.append(HealthIssue(
            component_type=ComponentType.CONTEXT,
            component_id="quantum-readiness",
            status=HealthStatus.WARNING,
            message=f"{len(non_quantum)} context(s) not quantum-resistant",
            recommendation="Plan PQC migration: cryptoserve heal upgrade-quantum",
            auto_healable=False,
            priority=5,
        ))

    # Determine overall status
    if any(i.status == HealthStatus.CRITICAL for i in issues):
        overall = HealthStatus.CRITICAL
    elif any(i.status == HealthStatus.DEGRADED for i in issues):
        overall = HealthStatus.DEGRADED
    elif any(i.status == HealthStatus.WARNING for i in issues):
        overall = HealthStatus.WARNING
    elif issues:
        overall = HealthStatus.WARNING
    else:
        overall = HealthStatus.HEALTHY

    # Sort by priority
    issues.sort(key=lambda x: x.priority)

    # Collect stats
    keys = get_data_store().get_keys()
    stats = {
        "total_keys": len(keys),
        "total_contexts": len(contexts),
        "total_data_encrypted": sum(k.get("data_encrypted_count", 0) for k in keys),
        "deprecated_algorithms": len([k for k in keys if crypto_registry.get(k["algorithm"]) and crypto_registry.get(k["algorithm"]).status in [SecurityStatus.DEPRECATED, SecurityStatus.BROKEN]]),
    }

    return HealthReport(
        timestamp=datetime.now(timezone.utc),
        overall_status=overall,
        issues=issues,
        stats=stats,
    )


# =============================================================================
# Command: status
# =============================================================================

def cmd_status(args) -> int:
    """Show system health status."""
    report = assess_system_health()

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
        return 0 if report.overall_status == HealthStatus.HEALTHY else 1

    # Text output
    status_colors = {
        HealthStatus.HEALTHY: Colors.GREEN,
        HealthStatus.WARNING: Colors.YELLOW,
        HealthStatus.DEGRADED: Colors.YELLOW + Colors.BOLD,
        HealthStatus.CRITICAL: Colors.RED + Colors.BOLD,
        HealthStatus.UNKNOWN: Colors.WHITE,
    }

    status_icons = {
        HealthStatus.HEALTHY: "✓",
        HealthStatus.WARNING: "⚠",
        HealthStatus.DEGRADED: "⚡",
        HealthStatus.CRITICAL: "✗",
        HealthStatus.UNKNOWN: "?",
    }

    print(f"\n{colored('CryptoServe Health Status', Colors.BOLD + Colors.CYAN)}")
    print("=" * 60)

    status_color = status_colors[report.overall_status]
    status_icon = status_icons[report.overall_status]
    print(f"\nOverall: {colored(f'{status_icon} {report.overall_status.value.upper()}', status_color)}")

    print(f"\n{colored('Statistics:', Colors.BOLD)}")
    print(f"  Keys: {report.stats.get('total_keys', 0)}")
    print(f"  Contexts: {report.stats.get('total_contexts', 0)}")
    print(f"  Data Records: {report.stats.get('total_data_encrypted', 0):,}")
    print(f"  Deprecated Algorithms: {report.stats.get('deprecated_algorithms', 0)}")

    if report.issues:
        print(f"\n{colored('Issues:', Colors.BOLD)} ({len(report.issues)} total)")
        print()

        for issue in report.issues[:10]:
            issue_color = status_colors[issue.status]
            issue_icon = status_icons[issue.status]
            print(f"  {colored(issue_icon, issue_color)} {colored(f'[{issue.status.value.upper()}]', issue_color)} {issue.message}")
            print(f"    {colored('→', Colors.CYAN)} {issue.recommendation}")
            if issue.auto_healable:
                print(f"    {colored('(auto-healable)', Colors.GREEN)}")
            print()

        if len(report.issues) > 10:
            print(f"  ... and {len(report.issues) - 10} more issues")
    else:
        print(f"\n{colored('No issues found!', Colors.GREEN)}")

    return 0 if report.overall_status == HealthStatus.HEALTHY else 1


# =============================================================================
# Command: reencrypt
# =============================================================================

def cmd_reencrypt(args) -> int:
    """Re-encrypt data with a new algorithm."""
    context = args.context
    target_algorithm = args.algorithm or "AES-256-GCM"

    print(f"\n{colored('Re-encryption Plan', Colors.BOLD + Colors.CYAN)}")
    print("=" * 60)

    # Get keys for context
    keys = get_data_store().get_keys(context)
    if not keys:
        print(colored(f"No keys found for context: {context}", Colors.YELLOW))
        return 2

    # Validate target algorithm
    algo_info = crypto_registry.get(target_algorithm)
    if not algo_info:
        print(colored(f"Unknown algorithm: {target_algorithm}", Colors.RED))
        return 3

    if algo_info.status not in [SecurityStatus.RECOMMENDED, SecurityStatus.ACCEPTABLE]:
        print(colored(f"Warning: {target_algorithm} is not recommended (status: {algo_info.status.value})", Colors.YELLOW))

    print(f"\nContext: {colored(context, Colors.CYAN)}")
    print(f"Target Algorithm: {colored(target_algorithm, Colors.GREEN)}")
    print(f"Keys Affected: {len(keys)}")

    total_records = sum(k.get("data_encrypted_count", 0) for k in keys)
    print(f"Records to Re-encrypt: {total_records:,}")

    if args.dry_run:
        print(f"\n{colored('DRY RUN - No changes made', Colors.YELLOW)}")
        print("\nWould execute:")
        for key in keys:
            print(f"  1. Generate new {target_algorithm} key for {key['id']}")
            print(f"  2. Re-encrypt {key.get('data_encrypted_count', 0):,} records")
            print(f"  3. Rotate old key {key['id']}")
        return 0

    # Simulate re-encryption
    print(f"\n{colored('Executing re-encryption...', Colors.BOLD)}")
    print("(Simulation mode - connect to CryptoServe API for real operations)\n")

    for i, key in enumerate(keys, 1):
        print(f"[{i}/{len(keys)}] Processing key {key['id']}...")
        print(f"  Current algorithm: {key['algorithm']}")
        print(f"  Records: {key.get('data_encrypted_count', 0):,}")
        print(colored("  ✓ Simulation complete", Colors.GREEN))
        print()

    print(colored("Re-encryption plan generated successfully!", Colors.GREEN))
    print("\nTo execute in production:")
    print(f"  POST /api/admin/contexts/{context}/reencrypt")
    print(f"  {{ \"target_algorithm\": \"{target_algorithm}\" }}")

    return 0


# =============================================================================
# Command: rotate-keys
# =============================================================================

def cmd_rotate_keys(args) -> int:
    """Rotate encryption keys."""
    context = args.context
    key_id = args.key

    print(f"\n{colored('Key Rotation', Colors.BOLD + Colors.CYAN)}")
    print("=" * 60)

    if key_id:
        keys = [get_data_store().get_key(key_id)]
        if not keys[0]:
            print(colored(f"Key not found: {key_id}", Colors.RED))
            return 2
    elif context:
        keys = get_data_store().get_keys(context)
    else:
        # Rotate all overdue keys
        keys = get_data_store().get_keys()
        keys = [k for k in keys if (datetime.now(timezone.utc) - k["last_rotated"]).days > k["rotation_days"]]

    if not keys:
        print(colored("No keys need rotation", Colors.GREEN))
        return 0

    print(f"Keys to rotate: {len(keys)}")

    for key in keys:
        days_since = (datetime.now(timezone.utc) - key["last_rotated"]).days
        print(f"\n  {colored(key['id'], Colors.CYAN)}")
        print(f"    Context: {key['context']}")
        print(f"    Algorithm: {key['algorithm']}")
        print(f"    Last rotated: {days_since} days ago")
        print(f"    Policy: every {key['rotation_days']} days")

    if args.dry_run:
        print(f"\n{colored('DRY RUN - No changes made', Colors.YELLOW)}")
        return 0

    print(f"\n{colored('Executing key rotation...', Colors.BOLD)}")
    print("(Simulation mode - connect to CryptoServe API for real operations)\n")

    for key in keys:
        print(f"Rotating {key['id']}...")
        print(colored("  ✓ New key generated", Colors.GREEN))
        print(colored("  ✓ Data re-encrypted", Colors.GREEN))
        print(colored("  ✓ Old key archived", Colors.GREEN))

    print(f"\n{colored('Key rotation complete!', Colors.GREEN)}")

    return 0


# =============================================================================
# Command: upgrade-quantum
# =============================================================================

def cmd_upgrade_quantum(args) -> int:
    """Plan quantum-resistant upgrade."""
    print(f"\n{colored('Quantum Readiness Assessment', Colors.BOLD + Colors.MAGENTA)}")
    print("=" * 60)

    contexts = get_data_store().get_contexts()
    keys = get_data_store().get_keys()

    # Assess current state
    classical_keys = [k for k in keys if not crypto_registry.is_quantum_resistant(k["algorithm"])]
    quantum_keys = [k for k in keys if crypto_registry.is_quantum_resistant(k["algorithm"])]

    print(f"\n{colored('Current State:', Colors.BOLD)}")
    print(f"  Classical keys: {len(classical_keys)}")
    print(f"  Quantum-resistant keys: {len(quantum_keys)}")

    if not classical_keys:
        print(f"\n{colored('All keys are quantum-resistant!', Colors.GREEN)}")
        return 0

    # Group by current algorithm
    by_algo = {}
    for key in classical_keys:
        algo = key["algorithm"]
        if algo not in by_algo:
            by_algo[algo] = []
        by_algo[algo].append(key)

    print(f"\n{colored('Migration Plan:', Colors.BOLD)}")
    print()

    target_hybrid = "AES-256-GCM+ML-KEM-768"

    for algo, algo_keys in by_algo.items():
        total_records = sum(k.get("data_encrypted_count", 0) for k in algo_keys)
        print(f"  {colored(algo, Colors.YELLOW)} → {colored(target_hybrid, Colors.MAGENTA)}")
        print(f"    Keys: {len(algo_keys)}")
        print(f"    Records: {total_records:,}")
        print()

    print(f"\n{colored('Recommended Timeline:', Colors.BOLD)}")
    print("  1. Enable hybrid mode for new encryptions (immediate)")
    print("  2. Re-encrypt critical data (within 6 months)")
    print("  3. Re-encrypt all data (within 2 years)")
    print("  4. Disable classical-only mode (after full migration)")

    print(f"\n{colored('NIST/NSA Timeline:', Colors.CYAN)}")
    print("  • 2025: Begin PQC transition")
    print("  • 2030: All new systems must use PQC")
    print("  • 2033: All systems must use PQC (NSA CNSA 2.0)")

    if args.output:
        plan = {
            "generated": datetime.now(timezone.utc).isoformat(),
            "classical_keys": len(classical_keys),
            "quantum_keys": len(quantum_keys),
            "target_algorithm": target_hybrid,
            "migrations": [
                {
                    "from": algo,
                    "to": target_hybrid,
                    "keys": len(algo_keys),
                    "records": sum(k.get("data_encrypted_count", 0) for k in algo_keys),
                }
                for algo, algo_keys in by_algo.items()
            ],
        }
        Path(args.output).write_text(yaml.dump(plan, default_flow_style=False))
        print(f"\nPlan written to: {args.output}")

    return 0


# =============================================================================
# Command: heal
# =============================================================================

def cmd_heal(args) -> int:
    """Auto-heal all healable issues."""
    report = assess_system_health()

    healable = [i for i in report.issues if i.auto_healable]

    if not healable:
        print(colored("No auto-healable issues found!", Colors.GREEN))
        return 0

    print(f"\n{colored('Auto-Healing', Colors.BOLD + Colors.CYAN)}")
    print("=" * 60)
    print(f"\nFound {len(healable)} auto-healable issue(s)")

    if args.dry_run:
        print(f"\n{colored('DRY RUN - Actions that would be taken:', Colors.YELLOW)}\n")
        for issue in healable:
            print(f"  [{issue.status.value.upper()}] {issue.message}")
            print(f"    → {issue.recommendation}")
            print()
        return 0

    print(f"\n{colored('Executing auto-heal...', Colors.BOLD)}")
    print("(Simulation mode - connect to CryptoServe API for real operations)\n")

    for issue in healable:
        print(f"Healing: {issue.message[:60]}...")
        print(colored("  ✓ Fixed", Colors.GREEN))

    print(f"\n{colored('Auto-healing complete!', Colors.GREEN)}")

    return 0


# =============================================================================
# Main Entry Point
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="cryptoserve-heal",
        description="CryptoServe Self-Healing CLI - Automated cryptographic remediation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check system health
  cryptoserve heal status

  # Auto-heal all issues
  cryptoserve heal auto --dry-run
  cryptoserve heal auto

  # Re-encrypt data with new algorithm
  cryptoserve heal reencrypt --context user-pii --algorithm AES-256-GCM

  # Rotate overdue keys
  cryptoserve heal rotate-keys
  cryptoserve heal rotate-keys --context payments

  # Plan quantum migration
  cryptoserve heal upgrade-quantum --output quantum-plan.yaml
        """
    )

    parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # status command
    status_parser = subparsers.add_parser("status", help="Show system health status")
    status_parser.add_argument("--format", choices=["text", "json"], default="text")

    # auto command
    auto_parser = subparsers.add_parser("auto", help="Auto-heal all issues")
    auto_parser.add_argument("--dry-run", action="store_true", help="Show what would be done")

    # reencrypt command
    reencrypt_parser = subparsers.add_parser("reencrypt", help="Re-encrypt data")
    reencrypt_parser.add_argument("--context", "-c", required=True, help="Context to re-encrypt")
    reencrypt_parser.add_argument("--algorithm", "-a", help="Target algorithm (default: AES-256-GCM)")
    reencrypt_parser.add_argument("--dry-run", action="store_true")

    # rotate-keys command
    rotate_parser = subparsers.add_parser("rotate-keys", help="Rotate encryption keys")
    rotate_parser.add_argument("--context", "-c", help="Context to rotate")
    rotate_parser.add_argument("--key", "-k", help="Specific key ID to rotate")
    rotate_parser.add_argument("--dry-run", action="store_true")

    # upgrade-quantum command
    quantum_parser = subparsers.add_parser("upgrade-quantum", help="Plan quantum-safe upgrade")
    quantum_parser.add_argument("--output", "-o", help="Output plan file")

    return parser


def print_mode_banner():
    """Print mode banner (demo or live)."""
    print()
    if _DEMO_MODE:
        print(colored("=" * 70, Colors.YELLOW))
        print(colored("  DEMO MODE - Using synthetic data for demonstration", Colors.YELLOW))
        print(colored("  For production: set CRYPTOSERVE_API_URL and CRYPTOSERVE_API_TOKEN", Colors.YELLOW))
        print(colored("=" * 70, Colors.YELLOW))
    else:
        print(colored("=" * 70, Colors.GREEN))
        print(colored(f"  LIVE MODE - Connected to {CRYPTOSERVE_API_URL}", Colors.GREEN))
        print(colored("=" * 70, Colors.GREEN))
    print()


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        Colors.disable()

    if not args.command:
        parser.print_help()
        return 0

    # Show mode banner (demo or live)
    print_mode_banner()

    if args.command == "status":
        return cmd_status(args)
    elif args.command == "auto":
        return cmd_heal(args)
    elif args.command == "reencrypt":
        return cmd_reencrypt(args)
    elif args.command == "rotate-keys":
        return cmd_rotate_keys(args)
    elif args.command == "upgrade-quantum":
        return cmd_upgrade_quantum(args)
    else:
        parser.print_help()
        return 3


if __name__ == "__main__":
    sys.exit(main())
