"""
Configuration for Auto-Protect.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


class ProtectionMode(Enum):
    """How to protect sensitive data."""
    ENCRYPT = "encrypt"      # Encrypt the value
    TOKENIZE = "tokenize"    # Replace with token
    LOG_ONLY = "log_only"    # Just log, don't modify


@dataclass
class AutoProtectConfig:
    """
    Configuration for auto-protect behavior.

    Example:
        config = AutoProtectConfig(
            encryption_key=my_key,
            libraries=["requests"],
            patterns=["pii"],
        )
        protect(config=config)
    """

    # Required
    encryption_key: bytes = field(default=b"")

    # What to protect
    libraries: list[str] = field(default_factory=lambda: ["requests", "httpx"])
    patterns: list[str] = field(default_factory=lambda: ["pii", "financial", "auth"])
    endpoints: list[str] = field(default_factory=list)  # Empty = all

    # Custom detection
    custom_patterns: dict[str, str] = field(default_factory=dict)
    custom_fields: list[str] = field(default_factory=list)

    # Protection mode
    mode: ProtectionMode = ProtectionMode.ENCRYPT
    algorithm: str = "AES-256-GCM"

    # Behavior
    fail_open: bool = True  # On error: True=pass through, False=block
    async_logging: bool = True  # Non-blocking audit logging

    # Logging
    log_handler: Callable[[dict], None] | None = None  # Custom log handler

    # Performance
    cache_detection: bool = True  # Cache field detection results
    max_field_size: int = 1024 * 1024  # Max size to encrypt (1MB)

    def __post_init__(self):
        if isinstance(self.mode, str):
            self.mode = ProtectionMode(self.mode)
