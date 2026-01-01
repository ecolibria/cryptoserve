"""Application configuration."""

import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Environment
    environment: str = "development"  # development, staging, production

    # Development mode (bypasses OAuth) - MUST be False in production
    dev_mode: bool = False

    # Database
    database_url: str = "postgresql+asyncpg://cryptoserve:localdev@localhost:5432/cryptoserve"

    # GitHub OAuth
    github_client_id: str = ""
    github_client_secret: str = ""

    # Domain-based access control
    # Comma-separated list of allowed email domains (e.g., "allstate.com,contractor.allstate.com")
    allowed_domains: str = ""
    # Email of the initial admin (becomes admin on first login)
    admin_email: str = ""
    # Whether to require email domain verification (set False for open access)
    require_domain_verification: bool = True

    # Security
    cryptoserve_master_key: str = "dev-master-key-change-in-production"
    jwt_secret_key: str = "dev-jwt-secret-change-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expiration_days: int = 7

    # HKDF salt for key derivation (should be unique per deployment)
    hkdf_salt: str = "cryptoserve-v1-change-in-production"

    # OAuth CSRF secret for state parameter
    oauth_state_secret: str = "oauth-state-secret-change-in-production"

    # Cookie security
    cookie_secure: bool = False  # Set True in production with HTTPS
    cookie_domain: str | None = None

    # URLs
    frontend_url: str = "http://localhost:3003"
    backend_url: str = "http://localhost:8003"

    # Identity defaults
    default_identity_expiration_days: int = 90

    # Rate limiting
    rate_limit_requests: int = 100  # requests per minute
    rate_limit_crypto_ops: int = 500  # crypto operations per minute

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

    @property
    def is_production(self) -> bool:
        """Check if running in production."""
        return self.environment == "production"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
