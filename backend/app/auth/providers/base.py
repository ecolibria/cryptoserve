"""Base OAuth Provider Interface.

Defines the contract that all OAuth providers must implement.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class OAuthUserInfo:
    """Normalized user information from OAuth provider.

    All providers return data in this format regardless of their
    native user info structure.
    """

    # Required fields (must be provided by all providers)
    provider_id: str  # Unique ID from the provider (e.g., GitHub ID, Azure OID)
    provider_name: str  # Provider identifier (e.g., "github", "azure_ad")
    username: str  # Display username

    # Optional fields
    email: str | None = None
    email_verified: bool = False
    name: str | None = None  # Full name if available
    avatar_url: str | None = None

    # Provider-specific metadata
    raw_data: dict[str, Any] = field(default_factory=dict)

    # All verified emails from provider (for domain matching)
    verified_emails: list[str] = field(default_factory=list)

    # Groups/roles from provider (for group-based access)
    groups: list[str] = field(default_factory=list)


@dataclass
class OAuthConfig:
    """OAuth provider configuration.

    Each provider has its own configuration settings loaded
    from environment variables.
    """

    client_id: str
    client_secret: str

    # URLs (some providers have fixed URLs, others are configurable)
    authorize_url: str | None = None
    token_url: str | None = None
    userinfo_url: str | None = None

    # OIDC discovery endpoint (auto-configures URLs)
    discovery_url: str | None = None

    # Scopes to request
    scopes: list[str] = field(default_factory=list)

    # Additional provider-specific settings
    tenant_id: str | None = None  # Azure AD tenant
    domain: str | None = None  # Okta domain

    # Provider metadata
    enabled: bool = True
    display_name: str | None = None
    icon: str | None = None  # Icon name for UI


class OAuthProvider(ABC):
    """Abstract base class for OAuth providers.

    Each provider must implement:
    - get_authorization_url(): Generate the OAuth authorization URL
    - exchange_code(): Exchange authorization code for tokens
    - get_user_info(): Fetch user information from provider

    Optional overrides:
    - refresh_token(): Refresh an expired access token
    - revoke_token(): Revoke a token
    """

    def __init__(self, config: OAuthConfig):
        self.config = config

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Unique identifier for this provider (e.g., 'github', 'azure_ad')."""
        pass

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable name for UI display."""
        pass

    @property
    def icon(self) -> str:
        """Icon identifier for UI (defaults to provider name)."""
        return self.config.icon or self.provider_name

    @abstractmethod
    async def get_authorization_url(
        self,
        redirect_uri: str,
        state: str,
        **kwargs,
    ) -> str:
        """Generate the OAuth authorization URL.

        Args:
            redirect_uri: Callback URL after authorization
            state: CSRF protection state token
            **kwargs: Provider-specific parameters

        Returns:
            Full authorization URL to redirect user to
        """
        pass

    @abstractmethod
    async def exchange_code(
        self,
        code: str,
        redirect_uri: str,
    ) -> dict[str, Any]:
        """Exchange authorization code for access token.

        Args:
            code: Authorization code from callback
            redirect_uri: Must match the redirect_uri used in authorization

        Returns:
            Token response containing at least 'access_token'
            May also contain 'refresh_token', 'id_token', 'expires_in'
        """
        pass

    @abstractmethod
    async def get_user_info(
        self,
        access_token: str,
        id_token: str | None = None,
    ) -> OAuthUserInfo:
        """Fetch user information from the provider.

        Args:
            access_token: OAuth access token
            id_token: Optional OIDC ID token (contains user info)

        Returns:
            Normalized user information
        """
        pass

    async def refresh_token(
        self,
        refresh_token: str,
    ) -> dict[str, Any] | None:
        """Refresh an expired access token.

        Args:
            refresh_token: Refresh token from original authorization

        Returns:
            New token response or None if not supported/failed
        """
        return None

    async def revoke_token(
        self,
        token: str,
        token_type: str = "access_token",
    ) -> bool:
        """Revoke a token.

        Args:
            token: Token to revoke
            token_type: Type of token ('access_token' or 'refresh_token')

        Returns:
            True if revocation succeeded
        """
        return False

    def get_scopes(self) -> list[str]:
        """Get OAuth scopes to request.

        Returns configured scopes or provider defaults.
        """
        return self.config.scopes or self._default_scopes()

    @abstractmethod
    def _default_scopes(self) -> list[str]:
        """Default scopes for this provider."""
        pass
