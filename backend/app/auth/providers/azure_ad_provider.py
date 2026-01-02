"""Azure Active Directory (Microsoft Entra ID) OAuth Provider.

Implements OAuth 2.0 / OIDC flow for Microsoft Azure AD authentication.
Supports both single-tenant and multi-tenant applications.
"""

from typing import Any
import httpx

from app.auth.providers.base import OAuthProvider, OAuthConfig, OAuthUserInfo


class AzureADProvider(OAuthProvider):
    """Azure Active Directory OAuth provider implementation.

    Supports:
    - Single-tenant apps (specific organization)
    - Multi-tenant apps (any Azure AD organization)
    - Personal Microsoft accounts (optional)
    """

    BASE_URL = "https://login.microsoftonline.com"
    GRAPH_URL = "https://graph.microsoft.com/v1.0"

    @property
    def provider_name(self) -> str:
        return "azure_ad"

    @property
    def display_name(self) -> str:
        return self.config.display_name or "Microsoft"

    @property
    def _tenant(self) -> str:
        """Get tenant ID (defaults to 'common' for multi-tenant)."""
        return self.config.tenant_id or "common"

    def _default_scopes(self) -> list[str]:
        return ["openid", "profile", "email", "User.Read"]

    async def get_authorization_url(
        self,
        redirect_uri: str,
        state: str,
        **kwargs,
    ) -> str:
        """Generate Azure AD authorization URL."""
        params = {
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(self.get_scopes()),
            "state": state,
            "response_type": "code",
            "response_mode": "query",
        }

        # Optional: domain_hint for faster login
        if "domain_hint" in kwargs:
            params["domain_hint"] = kwargs["domain_hint"]

        # Optional: login_hint for pre-filled email
        if "login_hint" in kwargs:
            params["login_hint"] = kwargs["login_hint"]

        # Optional: prompt parameter
        if "prompt" in kwargs:
            params["prompt"] = kwargs["prompt"]

        query = "&".join(f"{k}={v}" for k, v in params.items())
        return f"{self.BASE_URL}/{self._tenant}/oauth2/v2.0/authorize?{query}"

    async def exchange_code(
        self,
        code: str,
        redirect_uri: str,
    ) -> dict[str, Any]:
        """Exchange code for Azure AD tokens."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.BASE_URL}/{self._tenant}/oauth2/v2.0/token",
                data={
                    "grant_type": "authorization_code",
                    "client_id": self.config.client_id,
                    "client_secret": self.config.client_secret,
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "scope": " ".join(self.get_scopes()),
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
        """Fetch user info from Microsoft Graph API."""
        async with httpx.AsyncClient() as client:
            # Get user profile from Graph API
            response = await client.get(
                f"{self.GRAPH_URL}/me",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )

            if response.status_code != 200:
                raise ValueError(f"Failed to get user info: {response.text}")

            user_data = response.json()

            # Azure AD uses 'id' for the unique object ID
            provider_id = user_data.get("id")

            # Get email (mail or userPrincipalName)
            email = user_data.get("mail") or user_data.get("userPrincipalName")

            # userPrincipalName might be in format user_domain#EXT#@tenant.onmicrosoft.com
            # for external users - extract the real email
            if email and "#EXT#" in email:
                email = email.split("#EXT#")[0].replace("_", "@")

            # Try to get photo URL (requires additional permission)
            avatar_url = None
            try:
                photo_response = await client.get(
                    f"{self.GRAPH_URL}/me/photo/$value",
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                if photo_response.status_code == 200:
                    # Photo is available but we'd need to convert to data URI
                    # For now, just note it's available
                    avatar_url = f"{self.GRAPH_URL}/me/photo/$value"
            except Exception:
                pass

            # Get group memberships (requires Group.Read.All scope)
            groups: list[str] = []
            try:
                groups_response = await client.get(
                    f"{self.GRAPH_URL}/me/memberOf",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/json",
                    },
                )
                if groups_response.status_code == 200:
                    groups_data = groups_response.json()
                    groups = [
                        g.get("displayName")
                        for g in groups_data.get("value", [])
                        if g.get("displayName")
                    ]
            except Exception:
                pass

            # Username: prefer userPrincipalName, fallback to mail
            username = (
                user_data.get("userPrincipalName")
                or user_data.get("mail")
                or user_data.get("displayName")
                or provider_id
            )

            # Build verified emails list
            verified_emails: list[str] = []
            if email:
                # Azure AD emails are verified by the organization
                verified_emails.append(email)

            return OAuthUserInfo(
                provider_id=provider_id,
                provider_name=self.provider_name,
                username=username,
                email=email,
                email_verified=True,  # Azure AD emails are org-verified
                name=user_data.get("displayName"),
                avatar_url=avatar_url,
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
                f"{self.BASE_URL}/{self._tenant}/oauth2/v2.0/token",
                data={
                    "grant_type": "refresh_token",
                    "client_id": self.config.client_id,
                    "client_secret": self.config.client_secret,
                    "refresh_token": refresh_token,
                    "scope": " ".join(self.get_scopes()),
                },
                headers={"Accept": "application/json"},
            )

            if response.status_code != 200:
                return None

            return response.json()
