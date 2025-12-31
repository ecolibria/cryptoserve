#!/usr/bin/env python3
"""CryptoServe Migration CLI.

A command-line tool for migrating legacy cryptographic code to modern,
policy-compliant implementations. Designed for guided code transformation.

Usage:
    cryptoserve migrate scan ./src
    cryptoserve migrate plan ./src --output migration-plan.yaml
    cryptoserve migrate apply ./src --plan migration-plan.yaml
    cryptoserve migrate report ./src --format html

Exit Codes:
    0 - Success / No issues found
    1 - Issues found / Migration needed
    2 - File not found or parse error
    3 - Invalid arguments
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.core.crypto_registry import (
    crypto_registry,
    Algorithm,
    AlgorithmType,
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
        """Disable colors."""
        for attr in ['RED', 'GREEN', 'YELLOW', 'BLUE', 'MAGENTA', 'CYAN', 'WHITE', 'BOLD', 'RESET']:
            setattr(cls, attr, "")


def colored(text: str, color: str) -> str:
    return f"{color}{text}{Colors.RESET}"


# =============================================================================
# Severity and Findings
# =============================================================================

class FindingSeverity(str, Enum):
    """Severity of a crypto finding."""
    CRITICAL = "critical"  # Broken/exploitable crypto (MD5, RC4, DES, ECB)
    HIGH = "high"          # Deprecated crypto (3DES, SHA-1 for signatures)
    MEDIUM = "medium"      # Legacy crypto (CBC without HMAC)
    LOW = "low"            # Suboptimal but acceptable (AES-128)
    INFO = "info"          # Informational (already using recommended)


@dataclass
class CryptoFinding:
    """A cryptographic issue found in code."""
    file: str
    line: int
    column: int
    algorithm: str
    severity: FindingSeverity
    message: str
    replacement: str | None = None
    code_snippet: str = ""
    fix_suggestion: str = ""

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "algorithm": self.algorithm,
            "severity": self.severity.value,
            "message": self.message,
            "replacement": self.replacement,
            "code_snippet": self.code_snippet,
            "fix_suggestion": self.fix_suggestion,
        }


@dataclass
class ScanResult:
    """Result of scanning a codebase."""
    directory: str
    files_scanned: int
    findings: list[CryptoFinding] = field(default_factory=list)
    scan_time: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.LOW)

    def to_dict(self) -> dict:
        return {
            "directory": self.directory,
            "files_scanned": self.files_scanned,
            "scan_time_seconds": round(self.scan_time, 2),
            "summary": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "total": len(self.findings),
            },
            "findings": [f.to_dict() for f in self.findings],
        }


# =============================================================================
# Pattern Matching
# =============================================================================

# Patterns to detect various cryptographic algorithms in code
CRYPTO_PATTERNS = [
    # BROKEN - Must migrate immediately
    {
        "name": "MD5",
        "patterns": [
            r'\bmd5\b',
            r'MD5\(',
            r'hashlib\.md5',
            r'Digest::MD5',
            r'MessageDigest\.getInstance\(["\']MD5',
            r'crypto/md5',
        ],
        "severity": FindingSeverity.CRITICAL,
        "message": "MD5 is cryptographically broken - collision attacks are trivial",
        "replacement": "SHA-256",
    },
    {
        "name": "SHA-1",
        "patterns": [
            r'\bsha1\b',
            r'SHA1\(',
            r'hashlib\.sha1',
            r'Digest::SHA1',
            r'MessageDigest\.getInstance\(["\']SHA-?1',
            r'crypto/sha1',
        ],
        "severity": FindingSeverity.CRITICAL,
        "message": "SHA-1 is broken - collision attacks demonstrated (SHAttered, 2017)",
        "replacement": "SHA-256",
    },
    {
        "name": "DES",
        "patterns": [
            r'\bDES\b(?!3)',  # DES but not DES3/3DES
            r'DES\.new\(',
            r'DES/ECB',
            r'DES/CBC',
            r'Cipher\.getInstance\(["\']DES',
        ],
        "severity": FindingSeverity.CRITICAL,
        "message": "DES is broken - 56-bit key is trivially brute-forceable",
        "replacement": "AES-256-GCM",
    },
    {
        "name": "RC4",
        "patterns": [
            r'\bRC4\b',
            r'\bARC4\b',
            r'\barcfour\b',
            r'ARC4\.new\(',
        ],
        "severity": FindingSeverity.CRITICAL,
        "message": "RC4 is broken - multiple practical attacks exist",
        "replacement": "AES-256-GCM or ChaCha20-Poly1305",
    },
    {
        "name": "ECB Mode",
        "patterns": [
            r'MODE_ECB',
            r'/ECB/',
            r'\.ECB\b',
            r'AES/ECB',
            r'cipher.*ecb',
        ],
        "severity": FindingSeverity.CRITICAL,
        "message": "ECB mode preserves patterns - no semantic security",
        "replacement": "AES-256-GCM (authenticated encryption)",
    },

    # DEPRECATED - Should migrate soon
    {
        "name": "3DES",
        "patterns": [
            r'\b3DES\b',
            r'\bDES3\b',
            r'\bTDEA\b',
            r'triple.?des',
            r'DES\.new.*MODE.*EDE',
            r'TripleDES',
        ],
        "severity": FindingSeverity.HIGH,
        "message": "3DES is deprecated by NIST (disallowed after 2023-12-31)",
        "replacement": "AES-256-GCM",
    },
    {
        "name": "Blowfish",
        "patterns": [
            r'\bBlowfish\b',
            r'Blowfish\.new\(',
        ],
        "severity": FindingSeverity.HIGH,
        "message": "Blowfish has 64-bit block size - vulnerable to birthday attacks",
        "replacement": "AES-256-GCM",
    },

    # LEGACY - Consider migrating
    {
        "name": "CBC Mode (without HMAC)",
        "patterns": [
            r'MODE_CBC',
            r'/CBC/',
            r'\.CBC\b',
            r'AES/CBC',
        ],
        "severity": FindingSeverity.MEDIUM,
        "message": "CBC mode without authentication is vulnerable to padding oracle attacks",
        "replacement": "AES-256-GCM (provides authentication)",
    },
    {
        "name": "RSA-1024",
        "patterns": [
            r'RSA.*1024',
            r'rsa.*1024',
            r'KeyPairGenerator.*1024',
        ],
        "severity": FindingSeverity.HIGH,
        "message": "RSA-1024 provides only ~80-bit security - below NIST minimum",
        "replacement": "RSA-3072 or ECDH-P256",
    },
    {
        "name": "PBKDF2 (low iterations)",
        "patterns": [
            r'PBKDF2.*iterations\s*[=:]\s*\d{1,4}\b',
            r'pbkdf2.*\d{1,4}\s*\)',
        ],
        "severity": FindingSeverity.MEDIUM,
        "message": "PBKDF2 with low iterations is vulnerable to brute force",
        "replacement": "Argon2id or PBKDF2 with >= 600,000 iterations",
    },

    # SUBOPTIMAL - Lower priority
    {
        "name": "AES-128",
        "patterns": [
            r'AES-?128(?!-GCM)',
            r'aes128(?!gcm)',
        ],
        "severity": FindingSeverity.LOW,
        "message": "AES-128 is acceptable but AES-256 provides better security margin",
        "replacement": "AES-256-GCM",
    },

    # POST-QUANTUM - Positive finding
    {
        "name": "ML-KEM (Kyber)",
        "patterns": [
            r'ML.KEM',
            r'Kyber',
            r'mlkem',
            r'kyber',
        ],
        "severity": FindingSeverity.INFO,
        "message": "Post-quantum algorithm detected - excellent!",
        "replacement": None,
    },
    {
        "name": "ML-DSA (Dilithium)",
        "patterns": [
            r'ML.DSA',
            r'Dilithium',
            r'mldsa',
            r'dilithium',
        ],
        "severity": FindingSeverity.INFO,
        "message": "Post-quantum signature algorithm detected - excellent!",
        "replacement": None,
    },
]

# File extensions to scan
SCANNABLE_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rs',
    '.c', '.cpp', '.h', '.hpp', '.cs', '.rb', '.php', '.swift',
    '.kt', '.scala', '.m', '.mm',
}


def scan_file(file_path: Path) -> list[CryptoFinding]:
    """Scan a single file for cryptographic issues."""
    findings = []

    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        lines = content.split('\n')
    except Exception:
        return findings

    for pattern_info in CRYPTO_PATTERNS:
        for pattern in pattern_info["patterns"]:
            try:
                regex = re.compile(pattern, re.IGNORECASE)
                for line_num, line in enumerate(lines, 1):
                    for match in regex.finditer(line):
                        # Get context (surrounding lines)
                        start = max(0, line_num - 2)
                        end = min(len(lines), line_num + 2)
                        context = '\n'.join(f"{i}: {lines[i-1]}" for i in range(start + 1, end + 1))

                        finding = CryptoFinding(
                            file=str(file_path),
                            line=line_num,
                            column=match.start() + 1,
                            algorithm=pattern_info["name"],
                            severity=pattern_info["severity"],
                            message=pattern_info["message"],
                            replacement=pattern_info.get("replacement"),
                            code_snippet=context,
                        )
                        findings.append(finding)
            except re.error:
                continue

    return findings


def scan_directory(directory: Path, exclude_patterns: list[str] | None = None) -> ScanResult:
    """Scan a directory for cryptographic issues."""
    import time
    start_time = time.time()

    exclude_patterns = exclude_patterns or [
        '**/node_modules/**',
        '**/.git/**',
        '**/venv/**',
        '**/__pycache__/**',
        '**/dist/**',
        '**/build/**',
        '**/*.min.js',
    ]

    findings = []
    files_scanned = 0

    for file_path in directory.rglob('*'):
        if not file_path.is_file():
            continue

        if file_path.suffix.lower() not in SCANNABLE_EXTENSIONS:
            continue

        # Check exclude patterns
        rel_path = str(file_path.relative_to(directory))
        excluded = False
        for pattern in exclude_patterns:
            if Path(rel_path).match(pattern.replace('**/', '')):
                excluded = True
                break
        if excluded:
            continue

        files_scanned += 1
        file_findings = scan_file(file_path)
        findings.extend(file_findings)

    # Deduplicate findings (same file+line+algorithm)
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f.file, f.line, f.algorithm)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    scan_time = time.time() - start_time

    return ScanResult(
        directory=str(directory),
        files_scanned=files_scanned,
        findings=unique_findings,
        scan_time=scan_time,
    )


# =============================================================================
# Command: scan
# =============================================================================

def cmd_scan(args) -> int:
    """Scan codebase for cryptographic issues."""
    directory = Path(args.directory)

    if not directory.exists():
        print(colored(f"Error: Directory not found: {directory}", Colors.RED))
        return 2

    print(f"\n{colored('Scanning', Colors.BOLD)} {directory}...\n")

    result = scan_directory(directory)

    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2))
        return 0 if result.critical_count == 0 else 1

    # Text output
    print(f"Scanned {colored(str(result.files_scanned), Colors.CYAN)} files in {result.scan_time:.2f}s\n")

    if not result.findings:
        print(colored("No cryptographic issues found!", Colors.GREEN))
        return 0

    # Summary
    print(colored("Summary:", Colors.BOLD))
    if result.critical_count > 0:
        print(f"  {colored('CRITICAL', Colors.RED + Colors.BOLD)}: {result.critical_count}")
    if result.high_count > 0:
        print(f"  {colored('HIGH', Colors.RED)}: {result.high_count}")
    if result.medium_count > 0:
        print(f"  {colored('MEDIUM', Colors.YELLOW)}: {result.medium_count}")
    if result.low_count > 0:
        print(f"  {colored('LOW', Colors.BLUE)}: {result.low_count}")
    print()

    # Group findings by severity
    for severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH, FindingSeverity.MEDIUM, FindingSeverity.LOW]:
        severity_findings = [f for f in result.findings if f.severity == severity]
        if not severity_findings:
            continue

        severity_color = {
            FindingSeverity.CRITICAL: Colors.RED + Colors.BOLD,
            FindingSeverity.HIGH: Colors.RED,
            FindingSeverity.MEDIUM: Colors.YELLOW,
            FindingSeverity.LOW: Colors.BLUE,
        }[severity]

        print(colored(f"\n{'=' * 60}", severity_color))
        print(colored(f" {severity.value.upper()} FINDINGS ({len(severity_findings)})", severity_color))
        print(colored(f"{'=' * 60}", severity_color))

        for finding in severity_findings[:10]:  # Limit output
            rel_file = Path(finding.file).relative_to(directory) if directory in Path(finding.file).parents else finding.file
            print(f"\n{colored(finding.algorithm, Colors.BOLD)} at {colored(str(rel_file), Colors.CYAN)}:{finding.line}")
            print(f"  {finding.message}")
            if finding.replacement:
                print(f"  {colored('Replace with:', Colors.GREEN)} {finding.replacement}")

        if len(severity_findings) > 10:
            print(f"\n  ... and {len(severity_findings) - 10} more {severity.value} findings")

    # CI/CD exit code
    if args.fail_on_critical and result.critical_count > 0:
        print(f"\n{colored('FAILED', Colors.RED + Colors.BOLD)}: {result.critical_count} critical issues found")
        return 1
    if args.fail_on_high and result.high_count > 0:
        print(f"\n{colored('FAILED', Colors.RED)}: {result.high_count} high severity issues found")
        return 1

    return 0


# =============================================================================
# Command: plan
# =============================================================================

def cmd_plan(args) -> int:
    """Generate a migration plan."""
    directory = Path(args.directory)

    if not directory.exists():
        print(colored(f"Error: Directory not found: {directory}", Colors.RED))
        return 2

    print(f"Generating migration plan for {directory}...\n")

    result = scan_directory(directory)

    if not result.findings:
        print(colored("No migration needed - no issues found!", Colors.GREEN))
        return 0

    # Group findings by algorithm
    by_algorithm = {}
    for finding in result.findings:
        if finding.algorithm not in by_algorithm:
            by_algorithm[finding.algorithm] = []
        by_algorithm[finding.algorithm].append(finding)

    # Build migration plan
    plan = {
        "version": "1.0",
        "generated": datetime.now(timezone.utc).isoformat(),
        "source_directory": str(directory),
        "summary": {
            "total_findings": len(result.findings),
            "algorithms_affected": list(by_algorithm.keys()),
        },
        "migrations": [],
    }

    priority = 1
    for severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH, FindingSeverity.MEDIUM, FindingSeverity.LOW]:
        for algo, findings in by_algorithm.items():
            algo_findings = [f for f in findings if f.severity == severity]
            if not algo_findings:
                continue

            replacement = algo_findings[0].replacement
            migration = {
                "priority": priority,
                "algorithm": algo,
                "severity": severity.value,
                "occurrences": len(algo_findings),
                "replacement": replacement,
                "files": list(set(f.file for f in algo_findings)),
                "guidance": get_migration_guidance(algo, replacement),
            }
            plan["migrations"].append(migration)
            priority += 1

    # Output
    if args.output:
        output_path = Path(args.output)
        with open(output_path, 'w') as f:
            yaml.dump(plan, f, default_flow_style=False, sort_keys=False)
        print(colored(f"Migration plan written to: {output_path}", Colors.GREEN))
    else:
        print(yaml.dump(plan, default_flow_style=False, sort_keys=False))

    return 0


def get_migration_guidance(algorithm: str, replacement: str | None) -> list[str]:
    """Get migration guidance for an algorithm."""
    guidance = {
        "MD5": [
            "Replace MD5 hashes with SHA-256",
            "For password hashing, use Argon2id instead",
            "If used for checksums, ensure not security-critical",
        ],
        "SHA-1": [
            "Replace SHA-1 with SHA-256 or SHA-3-256",
            "For Git commit hashes, consider risk assessment",
            "Update certificate chains to use SHA-256",
        ],
        "DES": [
            "Replace DES with AES-256-GCM immediately",
            "Re-encrypt all data encrypted with DES",
            "Update key management to handle 256-bit keys",
        ],
        "3DES": [
            "Replace 3DES with AES-256-GCM",
            "NIST deadline: 2023-12-31 for new encryption",
            "May continue decryption-only through 2030",
        ],
        "RC4": [
            "Replace RC4 with AES-256-GCM or ChaCha20-Poly1305",
            "No transition period - replace immediately",
            "Check TLS configurations for RC4 cipher suites",
        ],
        "ECB Mode": [
            "Replace ECB with authenticated encryption (GCM)",
            "ECB provides no semantic security",
            "Re-encrypt data with proper mode",
        ],
        "CBC Mode (without HMAC)": [
            "Add HMAC-SHA256 for authentication, or",
            "Migrate to AES-GCM which provides built-in authentication",
            "Implement encrypt-then-MAC pattern if staying with CBC",
        ],
        "RSA-1024": [
            "Regenerate keys with minimum 3072 bits",
            "Consider migrating to ECDH-P256 for key exchange",
            "Update all systems that verify signatures",
        ],
        "AES-128": [
            "Consider upgrading to AES-256 for future-proofing",
            "Not urgent - AES-128 is still secure",
            "Ensure using authenticated mode (GCM)",
        ],
    }
    return guidance.get(algorithm, ["Consult CryptoServe documentation for migration guidance"])


# =============================================================================
# Command: report
# =============================================================================

def cmd_report(args) -> int:
    """Generate a detailed migration report."""
    directory = Path(args.directory)

    if not directory.exists():
        print(colored(f"Error: Directory not found: {directory}", Colors.RED))
        return 2

    result = scan_directory(directory)

    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2))
    elif args.format == "html":
        html = generate_html_report(result)
        if args.output:
            Path(args.output).write_text(html)
            print(colored(f"Report written to: {args.output}", Colors.GREEN))
        else:
            print(html)
    elif args.format == "sarif":
        sarif = generate_sarif_report(result)
        print(json.dumps(sarif, indent=2))
    else:
        # Text summary
        print(f"\n{colored('Cryptographic Security Report', Colors.BOLD + Colors.CYAN)}")
        print(f"{'=' * 60}\n")
        print(f"Directory: {result.directory}")
        print(f"Files Scanned: {result.files_scanned}")
        print(f"Scan Time: {result.scan_time:.2f}s")
        print(f"\n{colored('Findings Summary:', Colors.BOLD)}")
        print(f"  Critical: {result.critical_count}")
        print(f"  High: {result.high_count}")
        print(f"  Medium: {result.medium_count}")
        print(f"  Low: {result.low_count}")
        print(f"  Total: {len(result.findings)}")

    return 0 if result.critical_count == 0 else 1


def generate_html_report(result: ScanResult) -> str:
    """Generate an HTML report."""
    findings_html = ""
    for finding in result.findings:
        severity_class = finding.severity.value
        findings_html += f"""
        <tr class="{severity_class}">
            <td>{finding.file}:{finding.line}</td>
            <td>{finding.algorithm}</td>
            <td><span class="badge {severity_class}">{finding.severity.value.upper()}</span></td>
            <td>{finding.message}</td>
            <td>{finding.replacement or '-'}</td>
        </tr>
        """

    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>CryptoServe Migration Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #1a1a1a; border-bottom: 2px solid #3b82f6; padding-bottom: 10px; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat {{ padding: 20px; border-radius: 8px; text-align: center; flex: 1; }}
        .stat.critical {{ background: #fee2e2; color: #991b1b; }}
        .stat.high {{ background: #fef3c7; color: #92400e; }}
        .stat.medium {{ background: #fef9c3; color: #854d0e; }}
        .stat.low {{ background: #dbeafe; color: #1e40af; }}
        .stat-value {{ font-size: 2em; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e5e5e5; }}
        th {{ background: #f8fafc; font-weight: 600; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 0.75em; font-weight: 600; }}
        .badge.critical {{ background: #fee2e2; color: #991b1b; }}
        .badge.high {{ background: #fef3c7; color: #92400e; }}
        .badge.medium {{ background: #fef9c3; color: #854d0e; }}
        .badge.low {{ background: #dbeafe; color: #1e40af; }}
        tr.critical {{ background: #fef2f2; }}
        tr.high {{ background: #fffbeb; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>CryptoServe Migration Report</h1>
        <p>Directory: {result.directory}<br>Files Scanned: {result.files_scanned}<br>Generated: {datetime.now(timezone.utc).isoformat()}</p>

        <div class="summary">
            <div class="stat critical">
                <div class="stat-value">{result.critical_count}</div>
                <div>Critical</div>
            </div>
            <div class="stat high">
                <div class="stat-value">{result.high_count}</div>
                <div>High</div>
            </div>
            <div class="stat medium">
                <div class="stat-value">{result.medium_count}</div>
                <div>Medium</div>
            </div>
            <div class="stat low">
                <div class="stat-value">{result.low_count}</div>
                <div>Low</div>
            </div>
        </div>

        <h2>Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Location</th>
                    <th>Algorithm</th>
                    <th>Severity</th>
                    <th>Issue</th>
                    <th>Replacement</th>
                </tr>
            </thead>
            <tbody>
                {findings_html}
            </tbody>
        </table>
    </div>
</body>
</html>
    """


def generate_sarif_report(result: ScanResult) -> dict:
    """Generate a SARIF report for integration with code analysis tools."""
    rules = []
    seen_rules = set()

    for finding in result.findings:
        rule_id = f"crypto-{finding.algorithm.lower().replace(' ', '-')}"
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": finding.algorithm,
                "shortDescription": {"text": finding.message},
                "defaultConfiguration": {
                    "level": {
                        FindingSeverity.CRITICAL: "error",
                        FindingSeverity.HIGH: "error",
                        FindingSeverity.MEDIUM: "warning",
                        FindingSeverity.LOW: "note",
                        FindingSeverity.INFO: "note",
                    }[finding.severity]
                },
            })

    results = []
    for finding in result.findings:
        rule_id = f"crypto-{finding.algorithm.lower().replace(' ', '-')}"
        results.append({
            "ruleId": rule_id,
            "message": {"text": finding.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file},
                    "region": {
                        "startLine": finding.line,
                        "startColumn": finding.column,
                    }
                }
            }],
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CryptoServe Migration Scanner",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/your-org/cryptoserve",
                    "rules": rules,
                }
            },
            "results": results,
        }]
    }


# =============================================================================
# Main Entry Point
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="cryptoserve-migrate",
        description="CryptoServe Migration CLI - Scan and migrate legacy cryptography",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a directory for cryptographic issues
  cryptoserve migrate scan ./src

  # Scan and fail CI if critical issues found
  cryptoserve migrate scan ./src --fail-on-critical

  # Generate a migration plan
  cryptoserve migrate plan ./src --output migration-plan.yaml

  # Generate an HTML report
  cryptoserve migrate report ./src --format html --output report.html

  # Generate SARIF for GitHub Code Scanning
  cryptoserve migrate report ./src --format sarif > results.sarif
        """
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan codebase for cryptographic issues")
    scan_parser.add_argument("directory", help="Directory to scan")
    scan_parser.add_argument("--format", choices=["text", "json"], default="text")
    scan_parser.add_argument("--fail-on-critical", action="store_true", help="Exit 1 if critical issues found")
    scan_parser.add_argument("--fail-on-high", action="store_true", help="Exit 1 if high+ issues found")

    # plan command
    plan_parser = subparsers.add_parser("plan", help="Generate migration plan")
    plan_parser.add_argument("directory", help="Directory to analyze")
    plan_parser.add_argument("--output", "-o", help="Output file path")

    # report command
    report_parser = subparsers.add_parser("report", help="Generate detailed report")
    report_parser.add_argument("directory", help="Directory to analyze")
    report_parser.add_argument("--format", choices=["text", "json", "html", "sarif"], default="text")
    report_parser.add_argument("--output", "-o", help="Output file path")

    return parser


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        Colors.disable()

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "plan":
        return cmd_plan(args)
    elif args.command == "report":
        return cmd_report(args)
    else:
        parser.print_help()
        return 3


if __name__ == "__main__":
    sys.exit(main())
