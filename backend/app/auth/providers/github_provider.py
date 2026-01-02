"""GitHub OAuth Provider.

Implements OAuth 2.0 flow for GitHub authentication.
"""

from typing import Any
import httpx

from app.auth.providers.base import OAuthProvider, OAuthConfig, OAuthUserInfo


class GitHubProvider(OAuthProvider):
    """GitHub OAuth provider implementation."""

    AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
    TOKEN_URL = "https://github.com/login/oauth/access_token"
    USER_URL = "https://api.github.com/user"
    EMAILS_URL = "https://api.github.com/user/emails"

    @property
    def provider_name(self) -> str:
        return "github"

    @property
    def display_name(self) -> str:
        return self.config.display_name or "GitHub"

    def _default_scopes(self) -> list[str]:
        return ["read:user", "user:email"]

    async def get_authorization_url(
        self,
        redirect_uri: str,
        state: str,
        **kwargs,
    ) -> str:
        """Generate GitHub authorization URL."""
        params = {
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(self.get_scopes()),
            "state": state,
        }

        # Optional: allow_signup parameter
        if "allow_signup" in kwargs:
            params["allow_signup"] = str(kwargs["allow_signup"]).lower()

        query = "&".join(f"{k}={v}" for k, v in params.items())
        return f"{self.AUTHORIZE_URL}?{query}"

    async def exchange_code(
        self,
        code: str,
        redirect_uri: str,
    ) -> dict[str, Any]:
        """Exchange code for GitHub access token."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.TOKEN_URL,
                data={
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
        """Fetch user info from GitHub API."""
        async with httpx.AsyncClient() as client:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            }

            # Get user profile
            user_response = await client.get(self.USER_URL, headers=headers)
            if user_response.status_code != 200:
                raise ValueError(f"Failed to get user info: {user_response.text}")

            user_data = user_response.json()

            # Get user emails
            emails_response = await client.get(self.EMAILS_URL, headers=headers)

            verified_emails: list[str] = []
            primary_email: str | None = None
            email_verified = False

            if emails_response.status_code == 200:
                emails = emails_response.json()
                verified_emails = [
                    e["email"] for e in emails if e.get("verified", False)
                ]
                primary_email_obj = next(
                    (e for e in emails if e.get("primary")), None
                )
                if primary_email_obj:
                    primary_email = primary_email_obj.get("email")
                    email_verified = primary_email_obj.get("verified", False)

            # Fall back to profile email
            if not primary_email and user_data.get("email"):
                primary_email = user_data["email"]
                if primary_email not in verified_emails:
                    verified_emails.append(primary_email)

            return OAuthUserInfo(
                provider_id=str(user_data["id"]),
                provider_name=self.provider_name,
                username=user_data["login"],
                email=primary_email,
                email_verified=email_verified,
                name=user_data.get("name"),
                avatar_url=user_data.get("avatar_url"),
                raw_data=user_data,
                verified_emails=verified_emails,
            )
