"""
Library interception and auto-protection.
"""

import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable
import json
import logging

from cryptoserve_core import AESGCMCipher, encode_ciphertext, to_base64
from cryptoserve_auto.config import AutoProtectConfig, ProtectionMode
from cryptoserve_auto.detectors import SensitiveFieldDetector, PatternType

logger = logging.getLogger("cryptoserve_auto")

# Global state
_config: AutoProtectConfig | None = None
_detector: SensitiveFieldDetector | None = None
_cipher: AESGCMCipher | None = None
_original_functions: dict[str, Callable] = {}
_stats: dict[str, int] = {
    "requests_intercepted": 0,
    "fields_protected": 0,
    "bytes_encrypted": 0,
}
_local = threading.local()


@dataclass
class ProtectionStats:
    """Statistics about auto-protection activity."""
    requests_intercepted: int = 0
    fields_protected: int = 0
    bytes_encrypted: int = 0
    start_time: datetime = field(default_factory=datetime.now)

    @property
    def uptime_seconds(self) -> float:
        return (datetime.now() - self.start_time).total_seconds()


def protect(
    encryption_key: bytes | None = None,
    config: AutoProtectConfig | None = None,
    **kwargs,
) -> None:
    """
    Enable auto-protection for third-party libraries.

    Args:
        encryption_key: Encryption key (required if not in config)
        config: Full configuration object
        **kwargs: Additional config options

    Example:
        # Simple usage
        protect(encryption_key=my_key)

        # With options
        protect(
            encryption_key=my_key,
            libraries=["requests"],
            mode="log_only",
        )

        # With full config
        protect(config=AutoProtectConfig(...))
    """
    global _config, _detector, _cipher

    if config is None:
        config = AutoProtectConfig(
            encryption_key=encryption_key or b"",
            **kwargs,
        )

    if not config.encryption_key and config.mode == ProtectionMode.ENCRYPT:
        raise ValueError("encryption_key is required for encrypt mode")

    _config = config

    # Initialize detector
    pattern_types = []
    for p in config.patterns:
        try:
            pattern_types.append(PatternType(p))
        except ValueError:
            pass

    _detector = SensitiveFieldDetector(
        enabled_patterns=pattern_types or None,
        custom_patterns=config.custom_patterns,
        custom_fields=config.custom_fields,
    )

    # Initialize cipher
    if config.encryption_key:
        _cipher = AESGCMCipher(config.encryption_key)

    # Patch libraries
    for lib in config.libraries:
        _patch_library(lib)

    logger.info(f"Auto-protect enabled for: {config.libraries}")


def unprotect() -> None:
    """
    Disable auto-protection and restore original functions.
    """
    global _config, _detector, _cipher

    for lib, original in _original_functions.items():
        _restore_library(lib, original)

    _original_functions.clear()
    _config = None
    _detector = None
    _cipher = None

    logger.info("Auto-protect disabled")


@contextmanager
def unprotected():
    """
    Context manager to temporarily disable protection.

    Example:
        with unprotected():
            requests.post(url, json=data)  # Not intercepted
    """
    _local.bypass = True
    try:
        yield
    finally:
        _local.bypass = False


def is_protected() -> bool:
    """Check if auto-protection is currently enabled."""
    return _config is not None


def get_stats() -> ProtectionStats:
    """Get protection statistics."""
    return ProtectionStats(**_stats)


def _patch_library(name: str) -> None:
    """Patch a library with interception."""
    if name == "requests":
        _patch_requests()
    elif name == "httpx":
        _patch_httpx()
    else:
        logger.warning(f"Unknown library: {name}")


def _restore_library(name: str, original: Callable) -> None:
    """Restore original library function."""
    if name == "requests.Session.request":
        import requests
        requests.Session.request = original


def _patch_requests() -> None:
    """Patch the requests library."""
    try:
        import requests
    except ImportError:
        logger.debug("requests not installed, skipping")
        return

    original = requests.Session.request
    _original_functions["requests.Session.request"] = original

    def patched_request(self, method: str, url: str, **kwargs) -> Any:
        if getattr(_local, "bypass", False):
            return original(self, method, url, **kwargs)

        if method.upper() in ("POST", "PUT", "PATCH"):
            kwargs = _protect_request_data(kwargs, "requests", url)

        return original(self, method, url, **kwargs)

    requests.Session.request = patched_request
    logger.debug("Patched requests.Session.request")


def _patch_httpx() -> None:
    """Patch the httpx library."""
    try:
        import httpx
    except ImportError:
        logger.debug("httpx not installed, skipping")
        return

    original = httpx.Client.request
    _original_functions["httpx.Client.request"] = original

    def patched_request(self, method: str, url: str, **kwargs) -> Any:
        if getattr(_local, "bypass", False):
            return original(self, method, url, **kwargs)

        if method.upper() in ("POST", "PUT", "PATCH"):
            kwargs = _protect_request_data(kwargs, "httpx", str(url))

        return original(self, method, url, **kwargs)

    httpx.Client.request = patched_request
    logger.debug("Patched httpx.Client.request")


def _protect_request_data(
    kwargs: dict[str, Any],
    library: str,
    url: str,
) -> dict[str, Any]:
    """
    Protect sensitive data in request kwargs.

    Args:
        kwargs: Request kwargs (json, data, etc.)
        library: Name of the library
        url: Destination URL

    Returns:
        Modified kwargs with protected data
    """
    global _stats

    if not _detector or not _config:
        return kwargs

    _stats["requests_intercepted"] += 1

    # Check JSON data
    json_data = kwargs.get("json")
    if json_data and isinstance(json_data, dict):
        protected, count = _protect_dict(json_data)
        if count > 0:
            kwargs["json"] = protected
            _stats["fields_protected"] += count
            _log_protection(library, url, count)

    # Check form data
    data = kwargs.get("data")
    if data and isinstance(data, dict):
        protected, count = _protect_dict(data)
        if count > 0:
            kwargs["data"] = protected
            _stats["fields_protected"] += count
            _log_protection(library, url, count)

    return kwargs


def _protect_dict(data: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """
    Protect sensitive fields in a dictionary.

    Returns:
        Tuple of (protected_dict, fields_protected_count)
    """
    if not _detector or not _config:
        return data, 0

    detections = _detector.detect(data)
    if not detections:
        return data, 0

    # Deep copy to avoid modifying original
    protected = json.loads(json.dumps(data))
    count = 0

    for detection in detections:
        # Navigate to the field
        parts = detection.field_name.replace("[", ".").replace("]", "").split(".")
        obj = protected
        for part in parts[:-1]:
            if part.isdigit():
                obj = obj[int(part)]
            else:
                obj = obj[part]

        final_key = parts[-1]
        if final_key.isdigit():
            final_key = int(final_key)

        value = obj[final_key]
        if isinstance(value, str):
            protected_value = _protect_value(value)
            obj[final_key] = protected_value
            count += 1

    return protected, count


def _protect_value(value: str) -> str:
    """Protect a single value according to config."""
    if not _config:
        return value

    if _config.mode == ProtectionMode.LOG_ONLY:
        return value

    if _config.mode == ProtectionMode.TOKENIZE:
        # Generate a token (simplified - real implementation would use a vault)
        import hashlib
        token = hashlib.sha256(value.encode()).hexdigest()[:16]
        return f"tok_{token}"

    if _config.mode == ProtectionMode.ENCRYPT and _cipher:
        global _stats
        value_bytes = value.encode("utf-8")
        _stats["bytes_encrypted"] += len(value_bytes)

        ciphertext, nonce = _cipher.encrypt(value_bytes)
        encoded = encode_ciphertext("AES-256-GCM", nonce, ciphertext)
        return f"enc:{to_base64(encoded)}"

    return value


def _log_protection(library: str, url: str, count: int) -> None:
    """Log a protection event."""
    if not _config:
        return

    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "library": library,
        "destination": url,
        "fields_protected": count,
        "mode": _config.mode.value,
    }

    if _config.log_handler:
        if _config.async_logging:
            # Fire and forget
            threading.Thread(
                target=_config.log_handler,
                args=(log_entry,),
                daemon=True,
            ).start()
        else:
            _config.log_handler(log_entry)
    else:
        logger.info(f"Protected {count} fields in {library} request to {url}")
