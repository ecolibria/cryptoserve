"""
Sensitive field detection logic.
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any


class PatternType(Enum):
    """Categories of sensitive data."""
    PII = "pii"
    FINANCIAL = "financial"
    AUTH = "auth"
    HEALTH = "health"
    CUSTOM = "custom"


@dataclass
class DetectionResult:
    """Result of sensitive field detection."""
    field_name: str
    pattern_type: PatternType
    confidence: float  # 0.0 - 1.0
    matched_pattern: str | None = None


# Built-in patterns for detecting sensitive values
VALUE_PATTERNS = {
    PatternType.PII: [
        (r"\b\d{3}-\d{2}-\d{4}\b", "ssn"),  # SSN
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "email"),
        (r"\b\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "phone"),
    ],
    PatternType.FINANCIAL: [
        (r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", "credit_card"),
        (r"\b\d{9,18}\b", "bank_account"),  # Potential bank account
    ],
    PatternType.AUTH: [
        (r"\b(Bearer|Basic)\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b", "jwt"),
        (r"\b(sk|pk)_(live|test)_[A-Za-z0-9]{24,}\b", "api_key"),  # Stripe-style keys
    ],
}

# Field names that indicate sensitive data
SENSITIVE_FIELD_NAMES = {
    PatternType.PII: {
        "ssn", "social_security", "social_security_number", "tax_id", "tin",
        "email", "email_address", "e_mail",
        "phone", "phone_number", "telephone", "mobile", "cell",
        "address", "street_address", "home_address", "mailing_address",
        "first_name", "last_name", "full_name", "name",
        "dob", "date_of_birth", "birthdate", "birthday",
        "drivers_license", "passport", "national_id",
    },
    PatternType.FINANCIAL: {
        "credit_card", "card_number", "cc_number", "pan",
        "cvv", "cvc", "security_code",
        "expiry", "expiration", "exp_date", "exp_month", "exp_year",
        "bank_account", "account_number", "routing_number", "iban", "swift",
        "billing_address",
    },
    PatternType.AUTH: {
        "password", "passwd", "pwd", "pass",
        "secret", "secret_key", "api_key", "apikey", "api_secret",
        "token", "access_token", "refresh_token", "auth_token",
        "private_key", "signing_key", "encryption_key",
        "credentials", "credential",
    },
    PatternType.HEALTH: {
        "diagnosis", "prescription", "medication", "medical_record",
        "health_record", "patient_id", "mrn", "insurance_id",
        "blood_type", "allergies", "condition",
    },
}

# Compile patterns for performance
_compiled_patterns: dict[PatternType, list[tuple[re.Pattern, str]]] = {}


def _get_compiled_patterns() -> dict[PatternType, list[tuple[re.Pattern, str]]]:
    """Get or compile regex patterns."""
    global _compiled_patterns
    if not _compiled_patterns:
        for ptype, patterns in VALUE_PATTERNS.items():
            _compiled_patterns[ptype] = [
                (re.compile(pattern, re.IGNORECASE), name)
                for pattern, name in patterns
            ]
    return _compiled_patterns


class SensitiveFieldDetector:
    """
    Detects sensitive fields in data structures.

    Uses both field name matching and value pattern matching
    to identify potentially sensitive data.

    Example:
        detector = SensitiveFieldDetector()
        results = detector.detect({"email": "user@example.com", "name": "John"})
        # Returns [DetectionResult(field_name="email", pattern_type=PII, ...)]
    """

    def __init__(
        self,
        enabled_patterns: list[PatternType] | None = None,
        custom_patterns: dict[str, str] | None = None,
        custom_fields: list[str] | None = None,
    ):
        """
        Initialize detector.

        Args:
            enabled_patterns: Which pattern types to detect (default: all)
            custom_patterns: Additional regex patterns {name: pattern}
            custom_fields: Additional field names to treat as sensitive
        """
        self.enabled_patterns = enabled_patterns or list(PatternType)
        self.custom_patterns = custom_patterns or {}
        self.custom_fields = set(f.lower() for f in (custom_fields or []))

        # Compile custom patterns
        self._custom_compiled = {
            name: re.compile(pattern, re.IGNORECASE)
            for name, pattern in self.custom_patterns.items()
        }

        # Build field name lookup set
        self._sensitive_names: set[str] = set()
        for ptype in self.enabled_patterns:
            if ptype in SENSITIVE_FIELD_NAMES:
                self._sensitive_names.update(SENSITIVE_FIELD_NAMES[ptype])
        self._sensitive_names.update(self.custom_fields)

    def detect(self, data: dict[str, Any]) -> list[DetectionResult]:
        """
        Detect sensitive fields in a dictionary.

        Args:
            data: Dictionary to analyze

        Returns:
            List of detection results for sensitive fields
        """
        results = []

        for key, value in data.items():
            result = self._check_field(key, value)
            if result:
                results.append(result)

            # Recursively check nested dicts
            if isinstance(value, dict):
                nested = self.detect(value)
                for r in nested:
                    r.field_name = f"{key}.{r.field_name}"
                results.extend(nested)

            # Check lists of dicts
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        nested = self.detect(item)
                        for r in nested:
                            r.field_name = f"{key}[{i}].{r.field_name}"
                        results.extend(nested)

        return results

    def _check_field(self, key: str, value: Any) -> DetectionResult | None:
        """Check a single field for sensitivity."""
        key_lower = key.lower()

        # Check field name
        if key_lower in self._sensitive_names:
            pattern_type = self._get_pattern_type_for_name(key_lower)
            return DetectionResult(
                field_name=key,
                pattern_type=pattern_type,
                confidence=0.9,
                matched_pattern=f"field_name:{key_lower}",
            )

        # Check value patterns (only for strings)
        if isinstance(value, str) and len(value) < 1000:
            result = self._check_value_patterns(key, value)
            if result:
                return result

        return None

    def _check_value_patterns(self, key: str, value: str) -> DetectionResult | None:
        """Check if value matches any sensitive patterns."""
        patterns = _get_compiled_patterns()

        for ptype in self.enabled_patterns:
            if ptype not in patterns:
                continue

            for pattern, name in patterns[ptype]:
                if pattern.search(value):
                    return DetectionResult(
                        field_name=key,
                        pattern_type=ptype,
                        confidence=0.8,
                        matched_pattern=f"value:{name}",
                    )

        # Check custom patterns
        for name, pattern in self._custom_compiled.items():
            if pattern.search(value):
                return DetectionResult(
                    field_name=key,
                    pattern_type=PatternType.CUSTOM,
                    confidence=0.8,
                    matched_pattern=f"custom:{name}",
                )

        return None

    def _get_pattern_type_for_name(self, name: str) -> PatternType:
        """Determine pattern type for a field name."""
        for ptype, names in SENSITIVE_FIELD_NAMES.items():
            if name in names:
                return ptype
        if name in self.custom_fields:
            return PatternType.CUSTOM
        return PatternType.PII  # Default

    def is_sensitive(self, key: str, value: Any) -> bool:
        """Quick check if a field is sensitive."""
        return self._check_field(key, value) is not None
