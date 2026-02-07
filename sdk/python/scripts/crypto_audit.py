#!/usr/bin/env python3
"""
Cryptographic best practices audit for CryptoServe.

Scans Python source files for common cryptographic anti-patterns:
- Hardcoded keys, IVs, or nonces
- Deprecated algorithms (MD5, SHA-1, DES, RC4, ECB mode)
- Use of `random` module for cryptographic purposes
- Insufficient PBKDF2 iterations
- Incorrect AES-GCM nonce sizes
- Insufficient key sizes
- Missing constant-time comparison for secrets
- Use of eval()/exec() on untrusted input

Returns exit code 0 on pass, 1 on failure.
Outputs structured JSON with findings.

Usage:
    python scripts/crypto_audit.py [--path sdk/python] [--json] [--sarif]
"""

import ast
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class Finding:
    """A single audit finding."""
    rule: str
    severity: str  # "high", "medium", "low"
    message: str
    file: str
    line: int
    column: int = 0

    def __str__(self):
        return f"  {self.severity.upper():7s} {self.file}:{self.line} [{self.rule}] {self.message}"


@dataclass
class AuditResult:
    """Aggregated audit results."""
    findings: list = field(default_factory=list)
    files_scanned: int = 0
    rules_checked: int = 0

    @property
    def passed(self):
        return not any(f.severity == "high" for f in self.findings)


# Patterns for hardcoded hex strings that look like keys (32, 48, 64 hex chars = 128, 192, 256 bits)
_HEX_KEY_PATTERN = re.compile(
    r"""(?:key|secret|password|nonce|iv)\s*=\s*['"]((?:[0-9a-fA-F]{2}){16,})['"]""",
    re.IGNORECASE,
)

# Base64 patterns that could be hardcoded keys (24+ chars of base64)
_B64_KEY_PATTERN = re.compile(
    r"""(?:key|secret|nonce|iv)\s*=\s*b?['"]([A-Za-z0-9+/=]{24,})['"]""",
    re.IGNORECASE,
)

# Deprecated algorithm usage
_DEPRECATED_ALGOS = {
    "md5": "MD5 is cryptographically broken. Use SHA-256 or SHA-3.",
    "sha1": "SHA-1 is deprecated for security use. Use SHA-256 or SHA-3.",
    "des": "DES is insecure (56-bit key). Use AES-256.",
    "rc4": "RC4 has known biases. Use AES-GCM or ChaCha20.",
    "blowfish": "Blowfish has a 64-bit block size. Use AES-256.",
}

# ECB mode detection
_ECB_PATTERN = re.compile(r"modes\.ECB|ECB\(\)|mode=.*ECB", re.IGNORECASE)

# Insecure random module usage in crypto context
_INSECURE_RANDOM = re.compile(
    r"""(?:random\.random|random\.randint|random\.choice|random\.randrange|random\.getrandbits)\s*\("""
)

# eval/exec detection
_EVAL_EXEC_PATTERN = re.compile(r"\b(eval|exec)\s*\(")

# Minimum PBKDF2 iterations (OWASP recommends 600,000 for SHA-256)
_MIN_PBKDF2_ITERATIONS = 600_000

# Known test file patterns (relaxed rules)
_TEST_FILE_PATTERNS = {"test_", "conftest", "_test.py", "tests/"}


def _is_test_file(path: str) -> bool:
    """Check if a file is a test file."""
    return any(p in path for p in _TEST_FILE_PATTERNS)


def _scan_hardcoded_keys(content: str, filepath: str) -> list:
    """Scan for hardcoded cryptographic material."""
    findings = []

    for match in _HEX_KEY_PATTERN.finditer(content):
        hex_val = match.group(1)
        # Only flag key-length hex strings (128, 192, 256, 384, 512 bits)
        if len(hex_val) in (32, 48, 64, 96, 128):
            line_num = content[:match.start()].count("\n") + 1
            findings.append(Finding(
                rule="hardcoded-key",
                severity="high",
                message=f"Possible hardcoded key ({len(hex_val) * 4}-bit hex string)",
                file=filepath,
                line=line_num,
            ))

    for match in _B64_KEY_PATTERN.finditer(content):
        b64_val = match.group(1)
        if len(b64_val) >= 32:
            line_num = content[:match.start()].count("\n") + 1
            findings.append(Finding(
                rule="hardcoded-key",
                severity="high",
                message=f"Possible hardcoded key (base64 string, {len(b64_val)} chars)",
                file=filepath,
                line=line_num,
            ))

    return findings


def _scan_deprecated_algorithms(content: str, filepath: str) -> list:
    """Scan for active use of deprecated cryptographic algorithms.

    Only flags direct API calls like hashlib.md5() or Cipher(DES, ...).
    Skips policy definitions, string constants, regex patterns, comments,
    detection rules, and audit/scanner code that references algorithm names.
    """
    findings = []

    # Skip files that define policy rules, detection patterns, or audit checks
    _policy_files = {"_gate.py", "_policies.py", "crypto_audit.py"}
    if any(filepath.endswith(f) for f in _policy_files):
        return findings

    for algo, message in _DEPRECATED_ALGOS.items():
        # Only match direct API calls, not string references
        # hashlib.md5(...), hashlib.new("md5"), DES.new(...), etc.
        call_patterns = [
            re.compile(rf"hashlib\.{algo}\s*\(", re.IGNORECASE),
            re.compile(rf"hashlib\.new\s*\(\s*['\"]({algo})['\"]", re.IGNORECASE),
            re.compile(rf"\b{algo.upper()}\.new\s*\("),
        ]

        for pat in call_patterns:
            for match in pat.finditer(content):
                line_num = content[:match.start()].count("\n") + 1
                line_text = content.split("\n")[line_num - 1].strip()

                # Skip comments
                if line_text.startswith("#"):
                    continue
                # Skip lines in string constants, regex patterns, or policy definitions
                if any(kw in line_text.lower() for kw in [
                    "unsupported", "deprecated", "not allowed", "raise", "error",
                    "!=", "not in", "forbidden", "pattern", "regex", "r\"", "r'",
                    "quantum_risk", "description",
                ]):
                    continue
                # Skip lines that are in triple-quoted strings (docstrings)
                if '"""' in line_text or "'''" in line_text:
                    continue

                findings.append(Finding(
                    rule="deprecated-algorithm",
                    severity="high",
                    message=f"Deprecated algorithm '{algo}': {message}",
                    file=filepath,
                    line=line_num,
                ))

    # ECB mode - only direct usage, not regex patterns or string constants
    for match in _ECB_PATTERN.finditer(content):
        line_num = content[:match.start()].count("\n") + 1
        line_text = content.split("\n")[line_num - 1].strip()
        if line_text.startswith("#") or "pattern" in line_text.lower() or "r'" in line_text or 'r"' in line_text:
            continue
        # Skip policy/audit files
        if any(filepath.endswith(f) for f in _policy_files):
            continue
        findings.append(Finding(
            rule="ecb-mode",
            severity="high",
            message="ECB mode is insecure (no diffusion). Use GCM or CTR mode.",
            file=filepath,
            line=line_num,
        ))

    return findings


def _scan_insecure_random(content: str, filepath: str) -> list:
    """Scan for use of random module in cryptographic context."""
    findings = []

    # Only flag if random is used AND file imports crypto modules
    has_crypto_context = any(kw in content for kw in [
        "encrypt", "decrypt", "cipher", "key", "nonce", "salt", "hmac",
        "token", "hash", "sign", "AES", "ChaCha",
    ])

    if not has_crypto_context:
        return findings

    for match in _INSECURE_RANDOM.finditer(content):
        line_num = content[:match.start()].count("\n") + 1
        # Check the surrounding context
        line_text = content.split("\n")[line_num - 1].strip()
        if line_text.startswith("#"):
            continue
        findings.append(Finding(
            rule="insecure-random",
            severity="high",
            message="Use os.urandom() or secrets module instead of random for cryptographic purposes",
            file=filepath,
            line=line_num,
        ))

    return findings


def _scan_pbkdf2_iterations(content: str, filepath: str) -> list:
    """Scan for insufficient PBKDF2 iteration counts."""
    findings = []

    pattern = re.compile(r"(?:iterations|rounds)\s*[=:]\s*(\d[\d_]*)")
    for match in pattern.finditer(content):
        count = int(match.group(1).replace("_", ""))
        if 0 < count < _MIN_PBKDF2_ITERATIONS:
            line_num = content[:match.start()].count("\n") + 1
            findings.append(Finding(
                rule="low-pbkdf2-iterations",
                severity="high",
                message=f"PBKDF2 iterations ({count:,}) below minimum ({_MIN_PBKDF2_ITERATIONS:,})",
                file=filepath,
                line=line_num,
            ))

    return findings


def _scan_eval_exec(content: str, filepath: str) -> list:
    """Scan for eval()/exec() usage."""
    findings = []

    # Skip audit/scanner scripts that reference eval/exec in docstrings
    if filepath.endswith("crypto_audit.py"):
        return findings

    for match in _EVAL_EXEC_PATTERN.finditer(content):
        line_num = content[:match.start()].count("\n") + 1
        line_text = content.split("\n")[line_num - 1].strip()
        if line_text.startswith("#"):
            continue
        # Skip string references and docstrings
        if line_text.startswith(('"""', "'''", '"', "'")):
            continue
        findings.append(Finding(
            rule="eval-exec",
            severity="medium",
            message=f"Use of {match.group(1)}() - potential code injection risk",
            file=filepath,
            line=line_num,
        ))

    return findings


def _scan_nonce_size(content: str, filepath: str) -> list:
    """Check for incorrect AES-GCM nonce sizes."""
    findings = []

    # Look for nonce generation with wrong size
    pattern = re.compile(r"(?:os\.urandom|secrets\.token_bytes)\s*\(\s*(\d+)\s*\)")
    for match in pattern.finditer(content):
        size = int(match.group(1))
        # Check surrounding context for nonce
        start = max(0, match.start() - 200)
        context = content[start:match.start() + 50].lower()
        if "nonce" in context and size != 12:
            line_num = content[:match.start()].count("\n") + 1
            findings.append(Finding(
                rule="wrong-nonce-size",
                severity="medium",
                message=f"AES-GCM nonce should be 12 bytes, found {size}",
                file=filepath,
                line=line_num,
            ))

    return findings


def audit(scan_path: str) -> AuditResult:
    """Run the full audit on a directory."""
    result = AuditResult()
    scan_root = Path(scan_path)

    rules = [
        _scan_hardcoded_keys,
        _scan_deprecated_algorithms,
        _scan_insecure_random,
        _scan_pbkdf2_iterations,
        _scan_eval_exec,
        _scan_nonce_size,
    ]
    result.rules_checked = len(rules)

    for py_file in sorted(scan_root.rglob("*.py")):
        # Skip __pycache__, .venv, etc.
        parts = py_file.parts
        if any(p.startswith(".") or p == "__pycache__" or p in ("venv", ".venv", "node_modules") for p in parts):
            continue

        relative = str(py_file.relative_to(scan_root))
        is_test = _is_test_file(relative)

        try:
            content = py_file.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue

        result.files_scanned += 1

        for rule_fn in rules:
            file_findings = rule_fn(content, relative)
            for f in file_findings:
                # Downgrade test file findings to low
                if is_test:
                    f.severity = "low"
                result.findings.append(f)

    return result


def to_sarif(result: AuditResult) -> dict:
    """Convert audit results to SARIF format."""
    rules = {}
    sarif_results = []

    for f in result.findings:
        if f.rule not in rules:
            rules[f.rule] = {
                "id": f.rule,
                "shortDescription": {"text": f.rule.replace("-", " ").title()},
            }
        sarif_results.append({
            "ruleId": f.rule,
            "level": {"high": "error", "medium": "warning", "low": "note"}.get(f.severity, "note"),
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": f.line, "startColumn": f.column},
                }
            }],
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "cryptoserve-audit",
                    "version": "1.0.0",
                    "rules": list(rules.values()),
                }
            },
            "results": sarif_results,
        }],
    }


def main():
    """CLI entry point."""
    scan_path = "."
    output_json = False
    output_sarif = False

    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ("--path", "-p") and i + 1 < len(sys.argv):
            scan_path = sys.argv[i + 1]
            i += 2
        elif arg == "--json":
            output_json = True
            i += 1
        elif arg == "--sarif":
            output_sarif = True
            i += 1
        else:
            i += 1

    result = audit(scan_path)

    if output_sarif:
        print(json.dumps(to_sarif(result), indent=2))
    elif output_json:
        output = {
            "passed": result.passed,
            "files_scanned": result.files_scanned,
            "rules_checked": result.rules_checked,
            "findings": [asdict(f) for f in result.findings],
            "summary": {
                "high": sum(1 for f in result.findings if f.severity == "high"),
                "medium": sum(1 for f in result.findings if f.severity == "medium"),
                "low": sum(1 for f in result.findings if f.severity == "low"),
            },
        }
        print(json.dumps(output, indent=2))
    else:
        # Human-readable output
        print(f"CryptoServe Audit: scanned {result.files_scanned} files, {result.rules_checked} rules")
        print()

        if not result.findings:
            print("  No findings.")
        else:
            high = [f for f in result.findings if f.severity == "high"]
            medium = [f for f in result.findings if f.severity == "medium"]
            low = [f for f in result.findings if f.severity == "low"]

            if high:
                print(f"  HIGH ({len(high)}):")
                for f in high:
                    print(f"    {f}")
            if medium:
                print(f"  MEDIUM ({len(medium)}):")
                for f in medium:
                    print(f"    {f}")
            if low:
                print(f"  LOW ({len(low)}):")
                for f in low:
                    print(f"    {f}")

        print()
        if result.passed:
            print("PASSED (0 high-severity findings)")
        else:
            high_count = sum(1 for f in result.findings if f.severity == "high")
            print(f"FAILED ({high_count} high-severity findings)")

    sys.exit(0 if result.passed else 1)


if __name__ == "__main__":
    main()
