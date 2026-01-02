"""Generic OpenID Connect (OIDC) Provider.

Supports any OIDC-compliant identity provider:
- Keycloak
- Auth0
- Okta (also has dedicated provider)
- Any other OIDC provider

Uses OIDC Discovery to auto-configure endpoints.
"""

import base64
import json
from typing import Any
import httpx

from app.auth.providers.base import OAuthProvider, OAuthConfig, OAuthUserInfo


class OIDCProvider(OAuthProvider):
    """Generic OIDC provider implementation.

    Supports any OpenID Connect compliant identity provider.
    Uses OIDC Discovery (.well-known/openid-configuration) for configuration.
    """

    def __init__(self, config: OAuthConfig):
        super().__init__(config)
        self._discovery_cache: dict[str, Any] | None = None

    @property
    def provider_name(self) -> str:
        return "oidc"

    @property
    def display_name(self) -> str:
        return self.config.display_name or "Single Sign-On"

    def _default_scopes(self) -> list[str]:
        return ["openid", "profile", "email"]

    async def _get_discovery(self) -> dict[str, Any]:
        """Fetch OIDC discovery document."""
        if self._discovery_cache:
            return self._discovery_cache

        if not self.config.discovery_url:
            raise ValueError("OIDC discovery URL not configured")

        async with httpx.AsyncClient() as client:
            response = await client.get(self.config.discovery_url)
            if response.status_code != 200:
                raise ValueError(f"Failed to fetch OIDC discovery: {response.text}")

            self._discovery_cache = response.json()
            return self._discovery_cache

    async def _get_authorize_url(self) -> str:
        """Get authorization endpoint from config or discovery."""
        if self.config.authorize_url:
            return self.config.authorize_url
        discovery = await self._get_discovery()
        return discovery["authorization_endpoint"]

    async def _get_token_url(self) -> str:
        """Get token endpoint from config or discovery."""
        if self.config.token_url:
            return self.config.token_url
        discovery = await self._get_discovery()
        return discovery["token_endpoint"]

    async def _get_userinfo_url(self) -> str:
        """Get userinfo endpoint from config or discovery."""
        if self.config.userinfo_url:
            return self.config.userinfo_url
        discovery = await self._get_discovery()
        return discovery["userinfo_endpoint"]

    async def get_authorization_url(
        self,
        redirect_uri: str,
        state: str,
        **kwargs,
    ) -> str:
        """Generate OIDC authorization URL."""
        authorize_url = await self._get_authorize_url()

        params = {
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(self.get_scopes()),
            "state": state,
            "response_type": "code",
        }

        # Add nonce for ID token validation
        if "nonce" in kwargs:
            params["nonce"] = kwargs["nonce"]

        # Optional: prompt parameter
        if "prompt" in kwargs:
            params["prompt"] = kwargs["prompt"]

        # Optional: login_hint
        if "login_hint" in kwargs:
            params["login_hint"] = kwargs["login_hint"]

        query = "&".join(f"{k}={v}" for k, v in params.items())
        return f"{authorize_url}?{query}"

    async def exchange_code(
        self,
        code: str,
        redirect_uri: str,
    ) -> dict[str, Any]:
        """Exchange code for OIDC tokens."""
        token_url = await self._get_token_url()

        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_url,
                data={
                    "grant_type": "authorization_code",
                    "client_id": self.config.client_id,
                    "client_secret": self.config.client_secret,
                    "code": code,
                    "redirect_uri": redirect_uri,
                },
                headers={"Accept": "application/json"},
            )

            if response.status_code != 200:
                raise ValueError(f"Token exchange failed: {response.text}")

            return response.json()

    def _decode_id_token(self, id_token: str) -> dict[str, Any]:
        """Decode ID token claims (without signature verification).

        Note: In production, you should verify the signature using
        the provider's JWKS endpoint.
        """
        parts = id_token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid ID token format")

        # Decode payload (part 1)
        payload = parts[1]
        # Add padding if needed
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding

        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)

    async def get_user_info(
        self,
        access_token: str,
        id_token: str | None = None,
    ) -> OAuthUserInfo:
        """Fetch user info from OIDC provider."""
        # First, try to extract info from ID token if available
        claims: dict[str, Any] = {}
        if id_token:
            claims = self._decode_id_token(id_token)

        # If we don't have enough info from ID token, call userinfo endpoint
        if not claims.get("sub"):
            userinfo_url = await self._get_userinfo_url()

            async with httpx.AsyncClient() as client:
                response = await client.get(
                    userinfo_url,
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/json",
                    },
                )

                if response.status_code != 200:
                    raise ValueError(f"Failed to get user info: {response.text}")

                claims = response.json()

        # Extract groups if present (common OIDC claim)
        groups: list[str] = []
        if "groups" in claims:
            groups = claims["groups"]
        elif "roles" in claims:
            groups = claims["roles"]

        # Build verified emails list
        verified_emails: list[str] = []
        email = claims.get("email")
        email_verified = claims.get("email_verified", False)
        if email and email_verified:
            verified_emails.append(email)

        # Username: prefer username, fall back to email or sub
        username = (
            claims.get("preferred_username")
            or claims.get("username")
            or claims.get("email")
            or claims.get("sub")
        )

        return OAuthUserInfo(
            provider_id=claims["sub"],
            provider_name=self.provider_name,
            username=username,
            email=email,
            email_verified=email_verified,
            name=claims.get("name"),
            avatar_url=claims.get("picture"),
            raw_data=claims,
            verified_emails=verified_emails,
            groups=groups,
        )

    async def refresh_token(
        self,
        refresh_token: str,
    ) -> dict[str, Any] | None:
        """Refresh an expired access token."""
        token_url = await self._get_token_url()

        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_url,
                data={
                    "grant_type": "refresh_token",
                    "client_id": self.config.client_id,
                    "client_secret": self.config.client_secret,
                    "refresh_token": refresh_token,
                },
                headers={"Accept": "application/json"},
            )

            if response.status_code != 200:
                return None

            return response.json()
