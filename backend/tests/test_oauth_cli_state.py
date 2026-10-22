"""CLI login: the server returns the CLI-issued state on the loopback callback.

The CLI sends `state` alongside `cli_callback`. The dev-login and provider
login paths return that value unchanged on the redirect to the loopback
callback, so the CLI can refuse a callback that does not carry it. A CLI login
that sends no `state` is redirected as before, and the callback host check is
kept.
"""

import secrets
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.auth import oauth
from app.auth.providers.base import OAuthUserInfo
from app.core.onboarding_service import onboarding_service
from app.core.slowapi_limiter import limiter
from app.database import get_db

CALLBACK = "http://127.0.0.1:9876/callback"


class _FakeProvider:
    """Stands in for an OAuth provider; nothing leaves the process."""

    def __init__(self):
        self.issued_states = []

    async def get_authorization_url(self, redirect_uri, state, **kwargs):
        self.issued_states.append(state)
        return "https://provider.invalid/authorize?" + "state=" + state

    async def exchange_code(self, code, redirect_uri):
        # Built at run time: an opaque value standing in for the provider's reply.
        return {"access_token": "-".join(["provider", "access", secrets.token_hex(4)])}

    async def get_user_info(self, access_token, id_token=None):
        return OAuthUserInfo(
            provider_id="4242",
            provider_name="github",
            username="cliuser",
            email="cliuser@example.com",
            email_verified=True,
        )


@pytest.fixture
async def client(db_session):
    app = FastAPI()
    app.state.limiter = limiter
    app.include_router(oauth.router)

    async def _db():
        yield db_session

    app.dependency_overrides[get_db] = _db
    limiter.reset()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        yield c
    limiter.reset()


@pytest.fixture
def provider(monkeypatch):
    fake = _FakeProvider()
    monkeypatch.setattr(oauth, "get_provider", lambda name: fake if name == "github" else None)
    return fake


def _provision(monkeypatch, allowed):
    async def check(db, email, github_orgs=None):
        return (True, "admin", "first_user") if allowed else (False, "viewer", None)

    monkeypatch.setattr(onboarding_service, "check_auto_provisioning", check)


def _callback_redirect(resp):
    """The loopback address and query of a redirect to the CLI callback."""
    assert resp.status_code == 302, resp.text
    location = urlsplit(resp.headers["location"])
    return f"{location.scheme}://{location.netloc}{location.path}", parse_qs(location.query)


async def _provider_login(client, provider, login_path="/auth/login/github", **params):
    resp = await client.get(login_path, params={"cli_callback": CALLBACK, **params})
    assert resp.status_code in (302, 307), resp.text
    return await client.get(
        "/auth/callback/github",
        params={"code": "c" + secrets.token_hex(4), "state": provider.issued_states[-1]},
    )


async def test_dev_login_returns_the_cli_state_on_the_callback_redirect(client):
    cli_state = secrets.token_urlsafe(32)

    resp = await client.get("/auth/dev-login", params={"cli_callback": CALLBACK, "state": cli_state})

    target, query = _callback_redirect(resp)
    assert target == CALLBACK
    assert query["state"] == [cli_state]
    assert query["session"][0]
    assert query["user"] == ["devuser"]


@pytest.mark.parametrize("login_path", ["/auth/login/github", "/auth/github"])
async def test_provider_login_returns_the_cli_state_on_the_callback_redirect(client, provider, monkeypatch, login_path):
    _provision(monkeypatch, allowed=True)
    cli_state = secrets.token_urlsafe(32)

    resp = await _provider_login(client, provider, login_path, state=cli_state)

    target, query = _callback_redirect(resp)
    assert target == CALLBACK
    assert query["state"] == [cli_state]
    assert query["session"][0]
    assert query["user"] == ["cliuser"]


async def test_provider_login_refusal_returns_the_cli_state(client, provider, monkeypatch):
    _provision(monkeypatch, allowed=False)
    cli_state = secrets.token_urlsafe(32)

    resp = await _provider_login(client, provider, state=cli_state)

    target, query = _callback_redirect(resp)
    assert target == CALLBACK
    assert query["state"] == [cli_state]
    assert query["error"] == ["not_authorized"]
    assert "session" not in query


async def test_dev_login_without_state_redirects_as_before(client):
    resp = await client.get("/auth/dev-login", params={"cli_callback": CALLBACK})

    target, query = _callback_redirect(resp)
    assert target == CALLBACK
    assert query["session"][0]
    assert "state" not in query


async def test_provider_login_without_state_returns_no_earlier_state(client, provider, monkeypatch):
    _provision(monkeypatch, allowed=True)
    # A CLI login that was started with a state and never finished...
    await client.get("/auth/login/github", params={"cli_callback": CALLBACK, "state": secrets.token_urlsafe(32)})

    # ...is followed by one that sends none.
    resp = await _provider_login(client, provider)

    target, query = _callback_redirect(resp)
    assert target == CALLBACK
    assert query["session"][0]
    assert "state" not in query


@pytest.mark.parametrize(
    "cli_state",
    ["has space", "semi;colon", 'quote"', "a" * 129, "short"],
    ids=["space", "semicolon", "quote", "longer-than-128", "shorter-than-16"],
)
async def test_malformed_cli_state_is_refused(client, provider, cli_state):
    dev = await client.get("/auth/dev-login", params={"cli_callback": CALLBACK, "state": cli_state})
    login = await client.get("/auth/login/github", params={"cli_callback": CALLBACK, "state": cli_state})

    assert dev.status_code == 400
    assert login.status_code == 400


@pytest.mark.parametrize("callback", ["http://example.invalid/callback", "http://127.0.0.1.example.invalid/callback"])
async def test_callback_host_check_is_kept(client, provider, callback):
    cli_state = secrets.token_urlsafe(32)

    dev = await client.get("/auth/dev-login", params={"cli_callback": callback, "state": cli_state})
    login = await client.get("/auth/login/github", params={"cli_callback": callback, "state": cli_state})

    assert dev.status_code == 400
    assert login.status_code == 400
