"""The request log describes a query string by its parameter names, never its values.

Every request passes the logging middleware, which writes a "Request started"
record. The record keeps which query parameters arrived, in order, the length
of each value and how many there were. No value is written, whatever the
parameter is called.

Every value planted in a query below is built at run time. A planted value
counts as present in a log or a response when it appears whole, URL-encoded,
or as any eight-character run of its hexadecimal parts. Failure messages
replace a planted value with its length.
"""

import base64
import io
import json
import logging
import re
import secrets
from contextlib import contextmanager, redirect_stdout
from types import SimpleNamespace
from typing import NamedTuple
from urllib.parse import quote, quote_plus

import httpx
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from starlette.datastructures import QueryParams

from app.api import admin as admin_api
from app.api import users as users_api
from app.auth import oauth
from app.auth.providers import github_provider
from app.auth.providers.base import OAuthConfig
from app.core import logging as request_logging
from app.core.slowapi_limiter import limiter
from app.database import get_db


@pytest.fixture
async def client(db_session):
    """The sign-in, admin and user routes behind the request logging middleware."""
    app = FastAPI()
    app.state.limiter = limiter
    app.add_middleware(request_logging.RequestLoggingMiddleware)
    app.include_router(oauth.router)
    app.include_router(admin_api.router)
    app.include_router(users_api.router)

    async def _db():
        yield db_session

    app.dependency_overrides[get_db] = _db
    limiter.reset()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        yield c
    limiter.reset()


@contextmanager
def _stdout_log(json_output: bool):
    """Logging set up as the application does it, with stdout captured. The previous setup is restored."""
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    library_levels = {name: logging.getLogger(name).level for name in ("uvicorn.access", "httpx", "httpcore")}
    out = io.StringIO()
    try:
        with redirect_stdout(out):
            request_logging.setup_logging(json_output=json_output)
            yield out
    finally:
        for handler in root.handlers[:]:
            root.removeHandler(handler)
        for handler in handlers:
            root.addHandler(handler)
        root.setLevel(level)
        for name, library_level in library_levels.items():
            logging.getLogger(name).setLevel(library_level)


def _started_line(text: str) -> str:
    """The one "Request started" line in captured stdout."""
    lines = [line for line in text.splitlines() if "Request started" in line]
    assert len(lines) == 1, f"{len(lines)} request-started lines in the captured log"
    return lines[0]


def _forms(value: str) -> set[str]:
    """The value as sent, and as a query string encodes it."""
    return {value, quote(value, safe=""), quote_plus(value)}


def _leaks(text: str, *values: str) -> int:
    """How many forms, or eight-character runs of hexadecimal parts, of the values appear in the text."""
    found = 0
    for value in values:
        fragments = _forms(value)
        for run in re.findall(r"[0-9a-f]{8,}", value):
            fragments.update(run[i : i + 8] for i in range(len(run) - 7))
        found += sum(fragment in text for fragment in fragments)
    return found


def _redacted(text: str, *values: str) -> str:
    """The text with each form of each value replaced by the value's length."""
    for value in values:
        for form in sorted(_forms(value), key=len, reverse=True):
            text = text.replace(form, f"<{len(value)} chars>")
    return text


def _session_shaped() -> str:
    """A value with the shape of a signed session token, built at run time."""

    def segment(claims: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()

    header = segment({"alg": "HS256", "typ": "JWT"})
    claims = segment({"sub": secrets.token_hex(4)})
    return ".".join([header, claims, secrets.token_urlsafe(32)])


# (a) The sign-in callback's record names `code` and `state` and holds neither value.
@pytest.mark.parametrize("json_output", [True, False], ids=["json", "human"])
async def test_sign_in_callback_record_names_code_and_state_without_their_values(client, json_output):
    code = secrets.token_hex(10)
    state = oauth.generate_oauth_state("github")

    with _stdout_log(json_output) as out:
        await client.get("/auth/callback/github", params={"code": code, "state": state})

    text = out.getvalue()
    started = _started_line(text)
    leaked, shown = _leaks(text, code, state), _redacted(started, code, state)
    assert leaked == 0, f"{leaked} fragments of the code and state in the log; record: {shown}"
    if json_output:
        record = json.loads(started)
        assert record["query_keys"] == ["code", "state"]
        assert record["query_value_lengths"] == [len(code), len(state)]
        assert record["query_count"] == 2
    else:
        assert "query_keys=['code', 'state']" in started


# (b) The backup route's record names `password` and holds no value.
@pytest.mark.parametrize("json_output", [True, False], ids=["json", "human"])
async def test_backup_record_names_password_without_its_value(client, json_output):
    password = "".join(["pw", secrets.token_hex(12)])

    with _stdout_log(json_output) as out:
        await client.get("/api/admin/backups/x", params={"password": password})

    text = out.getvalue()
    started = _started_line(text)
    leaked, shown = _leaks(text, password), _redacted(started, password)
    assert leaked == 0, f"{leaked} fragments of the password in the log; record: {shown}"
    if json_output:
        record = json.loads(started)
        assert record["query_keys"] == ["password"]
        assert record["query_value_lengths"] == [len(password)]
        assert record["query_count"] == 1
    else:
        assert "query_keys=['password']" in started


# (c) Positive control: the record keeps parameter names and value lengths.
@pytest.mark.parametrize("json_output", [True, False], ids=["json", "human"])
async def test_record_keeps_parameter_names_and_value_lengths(client, json_output):
    with _stdout_log(json_output) as out:
        await client.get("/api/users/me", params={"limit": "5"})

    started = _started_line(out.getvalue())
    if json_output:
        record = json.loads(started)
        assert record["query_keys"] == ["limit"]
        assert record["query_value_lengths"] == [1]
        assert record["query_count"] == 1
    else:
        assert "query_keys=['limit'] query_value_lengths=[1] query_count=1" in started


# (d) The boundary returns a plain parameter name unchanged and drops a secret-shaped value
# under it. Asserted on the boundary's own output: removal does not depend on the name.
def test_boundary_keeps_a_plain_name_and_drops_a_secret_shaped_value():
    name = "view"
    value = _session_shaped()

    fields = request_logging.query_log_fields(QueryParams([(name, value)]))

    rendered = json.dumps(fields)
    assert _leaks(rendered, value) == 0, f"the boundary's output holds the value: {_redacted(rendered, value)}"
    assert fields["query_keys"] == [name]
    assert fields["query_value_lengths"] == [len(value)]
    assert fields["query_count"] == 1
    # The formatters mask extra fields by field name; the parameter names pass through unchanged.
    assert request_logging.mask_sensitive(fields)["query_keys"] == [name]


@pytest.mark.parametrize(
    "query, names, lengths",
    [
        ("", [], []),
        ("tag=a&tag=bb&empty=", ["tag", "tag", "empty"], [1, 2, 0]),
    ],
    ids=["no-query", "repeated-and-blank"],
)
def test_boundary_lists_every_parameter_in_order(query, names, lengths):
    fields = request_logging.query_log_fields(QueryParams(query))

    assert fields == {"query_keys": names, "query_value_lengths": lengths, "query_count": len(names)}


# (e) setup_logging keeps the server's access log, which prints the request line, at WARNING.
def test_setup_logging_keeps_the_access_log_at_warning():
    access = logging.getLogger("uvicorn.access")
    before = access.level
    access.setLevel(logging.NOTSET)
    try:
        with _stdout_log(json_output=True):
            assert access.level == logging.WARNING
    finally:
        access.setLevel(before)


def _github(monkeypatch, replies: str | None):
    """The GitHub provider, with its token and user endpoints answered in process."""
    token_path, user_path = "/login/oauth/access_token", "/user"
    access = "-".join(["provider", "access", secrets.token_hex(4)])
    invalid_grant = {"error": "invalid_grant", "error_description": "The authorization code is invalid or expired."}
    bad_code = {"error": "bad_verification_code", "error_description": "The code passed is incorrect or expired."}
    answers = {
        None: {},
        "token-refused": {token_path: httpx.Response(400, json=invalid_grant)},
        "token-without-access": {token_path: httpx.Response(200, json=bad_code)},
        "user-refused": {
            token_path: httpx.Response(200, json={"access_token": access, "token_type": "bearer"}),
            user_path: httpx.Response(401, json={"message": "Bad credentials"}),
        },
    }[replies]

    def answer(request: httpx.Request) -> httpx.Response:
        if request.url.path not in answers:
            raise AssertionError(f"unexpected provider request: {request.url.path}")
        return answers[request.url.path]

    transport = httpx.MockTransport(answer)
    in_process = SimpleNamespace(AsyncClient=lambda *args, **kwargs: httpx.AsyncClient(transport=transport))
    monkeypatch.setattr(github_provider, "httpx", in_process)
    config = OAuthConfig(client_id="log-test-client", client_secret="-".join(["log", "test", secrets.token_hex(4)]))
    provider = github_provider.GitHubProvider(config)
    monkeypatch.setattr(oauth, "get_provider", lambda name: provider if name == "github" else None)


class SignInErrorCase(NamedTuple):
    """A sign-in error branch reached through a query string; every one answers 400."""

    path: str
    query: str  # "cli_callback", "blank-code" or "code-and-state"
    detail: str  # how the branch's detail starts
    signed_for: str | None = None  # the provider the state is signed for; None sends an unsigned value
    state_cookie: bool = False  # the request carries the state in the oauth_state cookie
    replies: str | None = None  # what the provider answers; None: the branch asks the provider nothing


SIGN_IN_ERRORS = {
    "login-provider-not-configured": SignInErrorCase(
        "/auth/login/unregistered", "cli_callback", "Unknown or unconfigured provider: unregistered."
    ),
    "login-callback-not-loopback": SignInErrorCase(
        "/auth/login/github", "cli_callback", "CLI callback must be localhost"
    ),
    "github-login-callback-not-loopback": SignInErrorCase(
        "/auth/github", "cli_callback", "CLI callback must be localhost"
    ),
    "dev-login-callback-not-loopback": SignInErrorCase(
        "/auth/dev-login", "cli_callback", "CLI callback must be localhost"
    ),
    "callback-without-code": SignInErrorCase("/auth/callback/github", "blank-code", "Missing authorization code"),
    "callback-state-not-in-cookie": SignInErrorCase(
        "/auth/callback/github", "code-and-state", "Invalid state parameter"
    ),
    "github-callback-state-not-in-cookie": SignInErrorCase(
        "/auth/github/callback", "code-and-state", "Invalid state parameter"
    ),
    "callback-state-not-signed": SignInErrorCase(
        "/auth/callback/github", "code-and-state", "Invalid or expired state parameter", state_cookie=True
    ),
    "callback-provider-not-configured": SignInErrorCase(
        "/auth/callback/unregistered", "code-and-state", "Unknown provider: unregistered", "unregistered", True
    ),
    "callback-token-exchange-refused": SignInErrorCase(
        "/auth/callback/github", "code-and-state", "Token exchange failed: ", "github", True, "token-refused"
    ),
    "callback-token-reply-without-access-token": SignInErrorCase(
        "/auth/callback/github", "code-and-state", "No access token in response", "github", True, "token-without-access"
    ),
    "callback-user-info-refused": SignInErrorCase(
        "/auth/callback/github", "code-and-state", "Failed to get user info: ", "github", True, "user-refused"
    ),
}
SIGN_IN_ERROR_PARAMS = [pytest.param(case, id=name) for name, case in SIGN_IN_ERRORS.items()]


async def _send_sign_in_error(client, monkeypatch, case: SignInErrorCase):
    """Send one request that ends in a sign-in error; return the response and the planted query values."""
    _github(monkeypatch, case.replies)
    code = secrets.token_hex(10)
    state = secrets.token_hex(16) if case.signed_for is None else oauth.generate_oauth_state(case.signed_for)
    callback = f"http://{secrets.token_hex(6)}.invalid:9876/callback"
    params, planted = {
        "cli_callback": ({"cli_callback": callback}, (callback,)),
        "blank-code": ({"code": "", "state": state}, (state,)),
        "code-and-state": ({"code": code, "state": state}, (code, state)),
    }[case.query]
    headers = {"Cookie": f"oauth_state={state}"} if case.state_cookie else {}
    response = await client.get(case.path, params=params, headers=headers)
    return response, planted


# The request-failed record keeps the error text, so no sign-in error detail may carry a query value.
@pytest.mark.parametrize("case", SIGN_IN_ERROR_PARAMS)
async def test_sign_in_error_detail_holds_no_query_value(client, monkeypatch, case):
    response, planted = await _send_sign_in_error(client, monkeypatch, case)

    assert response.status_code == 400
    answered = response.json()["detail"]
    assert answered.startswith(case.detail)
    leaked, shown = _leaks(answered, *planted), _redacted(answered, *planted)
    assert leaked == 0, f"{leaked} fragments of a query value in the detail: {shown}"


@pytest.mark.parametrize("case", SIGN_IN_ERROR_PARAMS)
async def test_sign_in_error_log_holds_no_query_value(client, monkeypatch, case):
    with _stdout_log(json_output=True) as out:
        response, planted = await _send_sign_in_error(client, monkeypatch, case)

    assert response.status_code == 400
    text = out.getvalue()
    leaked, shown = _leaks(text, *planted), _redacted(_started_line(text), *planted)
    assert leaked == 0, f"{leaked} fragments of a query value in the log; record: {shown}"
