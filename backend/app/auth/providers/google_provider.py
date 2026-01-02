"""Google OAuth Provider.

Implements OAuth 2.0 / OIDC flow for Google Workspace authentication.
"""

from typing import Any
import httpx

from app.auth.providers.base import OAuthProvider, OAuthConfig, OAuthUserInfo


class GoogleProvider(OAuthProvider):
    """Google OAuth provider implementation.

    Supports:
    - Google Workspace accounts
    - Personal Google accounts
    - Hosted domain restriction (hd parameter)
    """

    AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
    REVOKE_URL = "https://oauth2.googleapis.com/revoke"

    @property
    def provider_name(self) -> str:
        return "google"

    @property
    def display_name(self) -> str:
        return self.config.display_name or "Google"

    def _default_scopes(self) -> list[str]:
        return [
            "openid",
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email",
        ]

    async def get_authorization_url(
        self,
        redirect_uri: str,
        state: str,
        **kwargs,
    ) -> str:
        """Generate Google authorization URL."""
        params = {
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(self.get_scopes()),
            "state": state,
            "response_type": "code",
            "access_type": "offline",  # Request refresh token
            "prompt": kwargs.get("prompt", "consent"),  # Force consent for refresh token
        }

        # Optional: restrict to specific Google Workspace domain
        if self.config.domain:
            params["hd"] = self.config.domain

        # Optional: login_hint for pre-filled email
        if "login_hint" in kwargs:
            params["login_hint"] = kwargs["login_hint"]

        query = "&".join(f"{k}={v}" for k, v in params.items())
        return f"{self.AUTHORIZE_URL}?{query}"

    async def exchange_code(
        self,
        code: str,
        redirect_uri: str,
    ) -> dict[str, Any]:
        """Exchange code for Google tokens."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.TOKEN_URL,
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
        """Fetch user info from Google."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                self.USERINFO_URL,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )

            if response.status_code != 200:
                raise ValueError(f"Failed to get user info: {response.text}")

            user_data = response.json()

            # Build verified emails list
            verified_emails: list[str] = []
            email = user_data.get("email")
            email_verified = user_data.get("email_verified", False)
            if email and email_verified:
                verified_emails.append(email)

            # Username: prefer email, fallback to sub
            username = user_data.get("email") or user_data.get("sub")

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
            )

    async def refresh_token(
        self,
        refresh_token: str,
    ) -> dict[str, Any] | None:
        """Refresh an expired access token."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.TOKEN_URL,
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
                self.REVOKE_URL,
                data={"token": token},
            )
            return response.status_code == 200
