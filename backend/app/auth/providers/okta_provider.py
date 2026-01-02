"""Okta OAuth Provider.

Implements OAuth 2.0 / OIDC flow for Okta authentication.
"""

from typing import Any
import httpx

from app.auth.providers.base import OAuthProvider, OAuthConfig, OAuthUserInfo


class OktaProvider(OAuthProvider):
    """Okta OAuth provider implementation.

    Requires the Okta domain to be configured (e.g., 'yourcompany.okta.com').
    """

    @property
    def provider_name(self) -> str:
        return "okta"

    @property
    def display_name(self) -> str:
        return self.config.display_name or "Okta"

    @property
    def _base_url(self) -> str:
        """Get Okta base URL from domain."""
        if not self.config.domain:
            raise ValueError("Okta domain not configured")
        domain = self.config.domain.rstrip("/")
        if not domain.startswith("https://"):
            domain = f"https://{domain}"
        return domain

    def _default_scopes(self) -> list[str]:
        return ["openid", "profile", "email", "groups"]

    async def get_authorization_url(
        self,
        redirect_uri: str,
        state: str,
        **kwargs,
    ) -> str:
        """Generate Okta authorization URL."""
        params = {
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(self.get_scopes()),
            "state": state,
            "response_type": "code",
        }

        # Optional: nonce for ID token validation
        if "nonce" in kwargs:
            params["nonce"] = kwargs["nonce"]

        # Optional: login_hint for pre-filled email
        if "login_hint" in kwargs:
            params["login_hint"] = kwargs["login_hint"]

        # Optional: idp for routing to specific identity provider
        if "idp" in kwargs:
            params["idp"] = kwargs["idp"]

        query = "&".join(f"{k}={v}" for k, v in params.items())
        return f"{self._base_url}/oauth2/default/v1/authorize?{query}"

    async def exchange_code(
        self,
        code: str,
        redirect_uri: str,
    ) -> dict[str, Any]:
        """Exchange code for Okta tokens."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self._base_url}/oauth2/default/v1/token",
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

    async def get_user_info(
        self,
        access_token: str,
        id_token: str | None = None,
    ) -> OAuthUserInfo:
        """Fetch user info from Okta."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self._base_url}/oauth2/default/v1/userinfo",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )

            if response.status_code != 200:
                raise ValueError(f"Failed to get user info: {response.text}")

            user_data = response.json()

            # Extract groups (if included in token claims)
            groups: list[str] = user_data.get("groups", [])

            # Build verified emails list
            verified_emails: list[str] = []
            email = user_data.get("email")
            email_verified = user_data.get("email_verified", False)
            if email and email_verified:
                verified_emails.append(email)

            # Username: prefer preferred_username, fallback to email
            username = (
                user_data.get("preferred_username")
                or user_data.get("email")
                or user_data.get("sub")
            )

            return OAuthUserInfo(
                provider_id=user_data["sub"],
                provider_name=self.provider_name,
                username=username,
                email=email,
                email_verified=email_verified,
                name=user_data.get("name"),
                avatar_url=user_data.get("picture"),
                raw_data=user_data,
                verified_emails=verified_emails,
                groups=groups,
            )

    async def refresh_token(
        self,
        refresh_token: str,
    ) -> dict[str, Any] | None:
        """Refresh an expired access token."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self._base_url}/oauth2/default/v1/token",
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

    async def revoke_token(
        self,
        token: str,
        token_type: str = "access_token",
    ) -> bool:
        """Revoke a token."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self._base_url}/oauth2/default/v1/revoke",
                data={
                    "client_id": self.config.client_id,
                    "client_secret": self.config.client_secret,
                    "token": token,
                    "token_type_hint": token_type,
                },
            )
            return response.status_code == 200
