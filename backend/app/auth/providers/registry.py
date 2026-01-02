"""OAuth Provider Registry.

Central registry for managing OAuth providers. Handles:
- Provider registration
- Configuration from environment
- Provider lookup by name
"""

from typing import Type
import os
import logging

from app.auth.providers.base import OAuthProvider, OAuthConfig

logger = logging.getLogger(__name__)

# Provider registry
_providers: dict[str, OAuthProvider] = {}
_provider_classes: dict[str, Type[OAuthProvider]] = {}


def register_provider_class(name: str, provider_class: Type[OAuthProvider]) -> None:
    """Register a provider class for later instantiation."""
    _provider_classes[name] = provider_class


def register_provider(name: str, provider: OAuthProvider) -> None:
    """Register a configured provider instance."""
    _providers[name] = provider


def get_provider(name: str) -> OAuthProvider | None:
    """Get a registered provider by name."""
    return _providers.get(name)


def get_enabled_providers() -> dict[str, OAuthProvider]:
    """Get all enabled providers."""
    return {name: p for name, p in _providers.items() if p.config.enabled}


def list_providers() -> list[dict]:
    """List all enabled providers with display info."""
    return [
        {
            "name": p.provider_name,
            "display_name": p.display_name,
            "icon": p.icon,
        }
        for p in _providers.values()
        if p.config.enabled
    ]


def _get_env(key: str, default: str = "") -> str:
    """Get environment variable."""
    return os.getenv(key, default)


def _get_env_list(key: str, default: str = "") -> list[str]:
    """Get environment variable as list."""
    value = os.getenv(key, default)
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def initialize_providers() -> None:
    """Initialize all configured providers from environment variables.

    Environment variable naming convention:
    - OAUTH_{PROVIDER}_CLIENT_ID
    - OAUTH_{PROVIDER}_CLIENT_SECRET
    - OAUTH_{PROVIDER}_SCOPES (optional, comma-separated)
    - Provider-specific settings (e.g., OAUTH_AZURE_AD_TENANT_ID)
    """
    # Import provider classes
    from app.auth.providers.github_provider import GitHubProvider
    from app.auth.providers.oidc_provider import OIDCProvider
    from app.auth.providers.azure_ad_provider import AzureADProvider
    from app.auth.providers.okta_provider import OktaProvider
    from app.auth.providers.google_provider import GoogleProvider

    # Register provider classes
    register_provider_class("github", GitHubProvider)
    register_provider_class("oidc", OIDCProvider)
    register_provider_class("azure_ad", AzureADProvider)
    register_provider_class("okta", OktaProvider)
    register_provider_class("google", GoogleProvider)

    # GitHub (also support legacy GITHUB_CLIENT_ID for backwards compatibility)
    github_client_id = _get_env("OAUTH_GITHUB_CLIENT_ID") or _get_env("GITHUB_CLIENT_ID")
    github_client_secret = _get_env("OAUTH_GITHUB_CLIENT_SECRET") or _get_env("GITHUB_CLIENT_SECRET")
    if github_client_id and github_client_secret:
        config = OAuthConfig(
            client_id=github_client_id,
            client_secret=github_client_secret,
            scopes=_get_env_list("OAUTH_GITHUB_SCOPES"),
            display_name=_get_env("OAUTH_GITHUB_DISPLAY_NAME") or "GitHub",
            icon="github",
        )
        register_provider("github", GitHubProvider(config))
        logger.info("Registered GitHub OAuth provider")

    # Google
    google_client_id = _get_env("OAUTH_GOOGLE_CLIENT_ID")
    google_client_secret = _get_env("OAUTH_GOOGLE_CLIENT_SECRET")
    if google_client_id and google_client_secret:
        config = OAuthConfig(
            client_id=google_client_id,
            client_secret=google_client_secret,
            scopes=_get_env_list("OAUTH_GOOGLE_SCOPES"),
            domain=_get_env("OAUTH_GOOGLE_DOMAIN"),  # Restrict to Google Workspace domain
            display_name=_get_env("OAUTH_GOOGLE_DISPLAY_NAME") or "Google",
            icon="google",
        )
        register_provider("google", GoogleProvider(config))
        logger.info("Registered Google OAuth provider")

    # Azure AD
    azure_client_id = _get_env("OAUTH_AZURE_AD_CLIENT_ID")
    azure_client_secret = _get_env("OAUTH_AZURE_AD_CLIENT_SECRET")
    if azure_client_id and azure_client_secret:
        config = OAuthConfig(
            client_id=azure_client_id,
            client_secret=azure_client_secret,
            tenant_id=_get_env("OAUTH_AZURE_AD_TENANT_ID"),  # 'common' for multi-tenant
            scopes=_get_env_list("OAUTH_AZURE_AD_SCOPES"),
            display_name=_get_env("OAUTH_AZURE_AD_DISPLAY_NAME") or "Microsoft",
            icon="microsoft",
        )
        register_provider("azure_ad", AzureADProvider(config))
        logger.info("Registered Azure AD OAuth provider")

    # Okta
    okta_client_id = _get_env("OAUTH_OKTA_CLIENT_ID")
    okta_client_secret = _get_env("OAUTH_OKTA_CLIENT_SECRET")
    okta_domain = _get_env("OAUTH_OKTA_DOMAIN")
    if okta_client_id and okta_client_secret and okta_domain:
        config = OAuthConfig(
            client_id=okta_client_id,
            client_secret=okta_client_secret,
            domain=okta_domain,
            scopes=_get_env_list("OAUTH_OKTA_SCOPES"),
            display_name=_get_env("OAUTH_OKTA_DISPLAY_NAME") or "Okta",
            icon="okta",
        )
        register_provider("okta", OktaProvider(config))
        logger.info("Registered Okta OAuth provider")

    # Generic OIDC (Keycloak, Auth0, etc.)
    oidc_client_id = _get_env("OAUTH_OIDC_CLIENT_ID")
    oidc_client_secret = _get_env("OAUTH_OIDC_CLIENT_SECRET")
    oidc_discovery_url = _get_env("OAUTH_OIDC_DISCOVERY_URL")
    if oidc_client_id and oidc_client_secret and oidc_discovery_url:
        config = OAuthConfig(
            client_id=oidc_client_id,
            client_secret=oidc_client_secret,
            discovery_url=oidc_discovery_url,
            authorize_url=_get_env("OAUTH_OIDC_AUTHORIZE_URL"),
            token_url=_get_env("OAUTH_OIDC_TOKEN_URL"),
            userinfo_url=_get_env("OAUTH_OIDC_USERINFO_URL"),
            scopes=_get_env_list("OAUTH_OIDC_SCOPES"),
            display_name=_get_env("OAUTH_OIDC_DISPLAY_NAME") or "Single Sign-On",
            icon=_get_env("OAUTH_OIDC_ICON") or "key",
        )
        register_provider("oidc", OIDCProvider(config))
        logger.info("Registered OIDC OAuth provider")

    logger.info(f"Initialized {len(_providers)} OAuth providers: {list(_providers.keys())}")
