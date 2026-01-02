"""OAuth Provider Abstraction Layer.

Supports multiple identity providers for enterprise SSO:
- GitHub (default)
- OIDC (OpenID Connect) - Keycloak, Auth0, generic OIDC
- Azure AD (Microsoft Entra ID)
- Okta
- Google Workspace
"""

from app.auth.providers.base import OAuthProvider, OAuthUserInfo
from app.auth.providers.registry import (
    get_provider,
    get_enabled_providers,
    register_provider,
)

__all__ = [
    "OAuthProvider",
    "OAuthUserInfo",
    "get_provider",
    "get_enabled_providers",
    "register_provider",
]
