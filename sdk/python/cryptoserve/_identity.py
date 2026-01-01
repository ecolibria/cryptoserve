"""
CryptoServe Identity - Configuration management with environment variable support.

Configuration Priority:
1. Environment variables (highest priority)
2. Embedded configuration (from SDK generation)
3. Default values (lowest priority)

Environment Variables:
    CRYPTOSERVE_TOKEN          - Access token (required)
    CRYPTOSERVE_REFRESH_TOKEN  - Refresh token (optional, enables auto-refresh)
    CRYPTOSERVE_SERVER_URL     - Server URL (default: http://localhost:8000)
    CRYPTOSERVE_APP_ID         - Application ID
    CRYPTOSERVE_AUTO_REFRESH   - Enable auto-refresh (default: true)
"""

import os
from typing import Optional

# Embedded configuration (replaced when SDK is generated for a specific application)
_EMBEDDED_CONFIG = {
    "server_url": "http://localhost:8000",
    "token": None,
    "refresh_token": None,
    "identity_id": None,
    "identity_type": "developer",
    "name": "Development",
    "team": "development",
    "environment": "development",
    "allowed_contexts": ["user-pii", "session-tokens", "general"],
    "created_at": None,
    "expires_at": None,
}


def _load_config() -> dict:
    """
    Load configuration from environment variables with embedded fallback.

    Environment variables take precedence over embedded configuration.
    """
    config = _EMBEDDED_CONFIG.copy()

    # Server URL
    if env_url := os.getenv("CRYPTOSERVE_SERVER_URL"):
        config["server_url"] = env_url.rstrip("/")

    # Access token
    if env_token := os.getenv("CRYPTOSERVE_TOKEN"):
        config["token"] = env_token

    # Refresh token
    if env_refresh := os.getenv("CRYPTOSERVE_REFRESH_TOKEN"):
        config["refresh_token"] = env_refresh

    # Application ID
    if env_app_id := os.getenv("CRYPTOSERVE_APP_ID"):
        config["identity_id"] = env_app_id

    return config


def _get_auto_refresh_enabled() -> bool:
    """Check if auto-refresh is enabled (default: true)."""
    env_value = os.getenv("CRYPTOSERVE_AUTO_REFRESH", "true").lower()
    return env_value in ("true", "1", "yes", "on")


# Loaded configuration (use environment variables if available)
IDENTITY = _load_config()

# Auto-refresh setting
AUTO_REFRESH_ENABLED = _get_auto_refresh_enabled()


def get_token() -> Optional[str]:
    """Get the current access token."""
    return IDENTITY.get("token")


def get_refresh_token() -> Optional[str]:
    """Get the refresh token if available."""
    return IDENTITY.get("refresh_token")


def get_server_url() -> str:
    """Get the server URL."""
    return IDENTITY.get("server_url", "http://localhost:8000")


def is_configured() -> bool:
    """Check if the SDK has valid configuration."""
    return bool(IDENTITY.get("token"))


def get_config_source() -> str:
    """Get the source of the current configuration."""
    if os.getenv("CRYPTOSERVE_TOKEN"):
        return "environment"
    elif IDENTITY.get("token"):
        return "embedded"
    else:
        return "none"


def reload_config():
    """Reload configuration from environment variables."""
    global IDENTITY, AUTO_REFRESH_ENABLED
    IDENTITY = _load_config()
    AUTO_REFRESH_ENABLED = _get_auto_refresh_enabled()
