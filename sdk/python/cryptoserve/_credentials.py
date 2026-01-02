"""
Local credential storage for CryptoServe SDK.

Stores application credentials locally to avoid re-registration on every init.
Credentials are stored per-app per-environment in ~/.cryptoserve/apps/
"""

import json
import os
from typing import Optional
from datetime import datetime, timezone


def _get_credentials_dir() -> str:
    """Get path to credentials directory."""
    home = os.path.expanduser("~")
    creds_dir = os.path.join(home, ".cryptoserve", "apps")
    os.makedirs(creds_dir, exist_ok=True)
    return creds_dir


def _get_app_credentials_path(app_name: str, environment: str) -> str:
    """Get path to app-specific credentials file."""
    # Sanitize app name for filename
    safe_name = app_name.replace("/", "_").replace("\\", "_").replace(":", "_")
    filename = f"{safe_name}_{environment}.json"
    return os.path.join(_get_credentials_dir(), filename)


def _get_user_credentials_path() -> str:
    """Get path to user credentials (from login)."""
    home = os.path.expanduser("~")
    return os.path.join(home, ".cryptoserve", "credentials.json")


def load_user_credentials() -> dict:
    """Load user credentials from login."""
    path = _get_user_credentials_path()
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def get_session_cookie() -> Optional[str]:
    """Get session cookie for authenticated requests."""
    creds = load_user_credentials()
    return creds.get("session_cookie")


def get_server_url() -> str:
    """Get base server URL from user credentials or default."""
    creds = load_user_credentials()
    return creds.get("server_url", os.getenv("CRYPTOSERVE_SERVER_URL", "http://localhost:8000"))


def get_api_url() -> str:
    """Get API URL (server URL with /api suffix) for SDK client.

    The CryptoClient expects paths like /v1/crypto/encrypt,
    so we need to provide the base API URL.
    """
    base_url = get_server_url()
    if not base_url.endswith("/api"):
        return base_url.rstrip("/") + "/api"
    return base_url


def load_app_credentials(app_name: str, environment: str) -> Optional[dict]:
    """Load stored credentials for an application.

    Returns:
        dict with app_id, access_token, refresh_token, contexts, etc.
        None if no credentials stored
    """
    path = _get_app_credentials_path(app_name, environment)
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                creds = json.load(f)
                # Check if credentials are still valid (refresh token not expired)
                if _are_credentials_valid(creds):
                    return creds
        except Exception:
            pass
    return None


def save_app_credentials(
    app_name: str,
    environment: str,
    app_id: str,
    access_token: str,
    refresh_token: str,
    contexts: list[str],
    server_url: str,
) -> None:
    """Save application credentials locally."""
    path = _get_app_credentials_path(app_name, environment)
    creds = {
        "app_id": app_id,
        "app_name": app_name,
        "environment": environment,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "contexts": contexts,
        "server_url": server_url,
        "saved_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(path, "w") as f:
        json.dump(creds, f, indent=2)
    os.chmod(path, 0o600)  # Restrict permissions


def update_app_tokens(
    app_name: str,
    environment: str,
    access_token: str,
    refresh_token: Optional[str] = None,
) -> None:
    """Update tokens for an existing app."""
    creds = load_app_credentials(app_name, environment)
    if creds:
        creds["access_token"] = access_token
        if refresh_token:
            creds["refresh_token"] = refresh_token
        creds["updated_at"] = datetime.now(timezone.utc).isoformat()

        path = _get_app_credentials_path(app_name, environment)
        with open(path, "w") as f:
            json.dump(creds, f, indent=2)


def delete_app_credentials(app_name: str, environment: str) -> bool:
    """Delete stored credentials for an application."""
    path = _get_app_credentials_path(app_name, environment)
    if os.path.exists(path):
        os.remove(path)
        return True
    return False


def _are_credentials_valid(creds: dict) -> bool:
    """Check if stored credentials are still valid.

    We consider credentials valid if they exist and have a refresh token.
    The actual token validity will be checked when making API calls.
    """
    if not creds:
        return False
    if not creds.get("refresh_token"):
        return False
    return True


def is_logged_in() -> bool:
    """Check if user has logged in via CLI."""
    return get_session_cookie() is not None
