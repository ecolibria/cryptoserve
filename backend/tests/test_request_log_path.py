"""The request log describes a request path by lengths and, for an API route, its template, never by the path.

Every request passes the logging middleware. Its "Request started" record carries no
path field. The "Request completed" and "Request failed" records are written after
routing: a path an API route matched is recorded as that route's template with the
length of each path parameter value, and any other path as the length of each of its
segments. Other paths include those of FastAPI's documentation routes, which set no
route in the request scope. No path field holds a path value, whatever its parameter
is called.

Every value planted in a path below is built at run time. A planted value counts as
present in a log when it appears whole, URL-encoded, or as any eight-character run of
its signature part, the text after its last dot. Failure messages give a planted
value's length, never the value, and never print a captured record.
"""

import io
import json
import logging
import secrets
import time
from contextlib import contextmanager, redirect_stdout
from typing import NamedTuple
from urllib.parse import quote, quote_plus

import jwt
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from starlette.routing import Mount, compile_path

from app.api import sdk as sdk_api
from app.core import logging as request_logging

MESSAGES = ("Request started", "Request completed", "Request failed")
PATH_FIELDS = ("path", "route", "path_param_lengths", "path_segment_lengths")


class Probe(NamedTuple):
    """A request with a planted value in its path, and what its record should say about the path."""

    method: str
    path: str  # "<v>" marks the planted value
    route: str | None  # the template of the API route that matched; None when no API route matched
    lengths: tuple  # path_param_lengths when an API route matched, else path_segment_lengths; "v" is the value's length
    status: int | None  # the completed record's status code; None when the handler raised


PROBES = {
    "sdk-info": Probe("GET", "/sdk/info/<v>", "/sdk/info/{token}", ("v",), 404),
    "sdk-download": Probe("GET", "/sdk/download/<v>/python", "/sdk/download/{token}/python", ("v",), 404),
    "no-route": Probe("GET", "/api/sdk/info/<v>", None, (3, 3, 4, "v"), 404),
    "slash-redirect": Probe("GET", "/sdk/info/<v>/", None, (3, 4, "v", 0), 307),
    "method-not-allowed": Probe("POST", "/sdk/info/<v>", "/sdk/info/{token}", ("v",), 405),
    "handler-raises": Probe("GET", "/probe-raise/<v>", "/probe-raise/{token}", ("v",), None),
}

# Every path parameter name the application's routes use. `credential`: the value grants access
# by itself. `identifier`: the value names a record or a setting. A route that takes a name not
# listed here fails the census test until the name is labelled.
PATH_PARAMETER_CENSUS = {
    "app_id": "identifier",
    "backup_id": "identifier",
    "cert_id": "identifier",
    "classification": "identifier",
    "context_name": "identifier",
    "domain": "identifier",
    "finding_id": "identifier",
    "framework": "identifier",
    "identity_id": "identifier",
    "invitation_id": "identifier",
    "key_id": "identifier",
    "key_type": "identifier",
    "lease_id": "identifier",
    "name": "identifier",
    "org": "identifier",
    "provider": "identifier",
    "report_id": "identifier",
    "report_id_or_ref": "identifier",
    "role": "identifier",
    "team_name": "identifier",
    "tenant_id": "identifier",
    "token": "credential",
    "user_id": "identifier",
    "username": "identifier",
}


@pytest.fixture
async def client(monkeypatch):
    """The SDK routes and one route whose handler raises, behind the request logging middleware.

    No identity resolves, so the SDK token routes answer 404 as they do for an invalid token.
    Their sessions come from an in-memory database that no query reaches.
    """
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def no_identity(db, token):
        return None

    monkeypatch.setattr(sdk_api, "get_session_maker", lambda: sessions)
    monkeypatch.setattr(sdk_api.identity_manager, "get_identity_by_token", no_identity)

    app = FastAPI()
    app.add_middleware(request_logging.RequestLoggingMiddleware)
    app.include_router(sdk_api.router)

    @app.get("/probe-raise/{token}")
    async def probe_raise(token: str):
        raise RuntimeError("probe")

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c
    await engine.dispose()


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


def _identity_token() -> str:
    """A value with the shape of an SDK identity token: the identity claims, signed under a random key."""
    now = int(time.time())
    claims = {
        "iss": f"https://{secrets.token_hex(4)}.invalid",
        "sub": "_".join(["dev", secrets.token_hex(4), secrets.token_hex(4)]),
        "aud": "cryptoserve-sdk",
        "iat": now,
        "exp": now + 3600,
        "type": "developer",
        "name": secrets.token_hex(6),
        "team": secrets.token_hex(4),
        "env": "development",
        "contexts": [secrets.token_hex(4), secrets.token_hex(4)],
    }
    return jwt.encode(claims, secrets.token_bytes(32), algorithm="HS256")


def _forms(value: str) -> set[str]:
    """The value as sent, and as a URL encodes it."""
    return {value, quote(value, safe=""), quote_plus(value)}


def _found(text: str, value: str) -> int:
    """How many forms of the value, or eight-character runs of its signature part, appear in the text."""
    signature = value.rsplit(".", 1)[-1]
    fragments = _forms(value) | {signature[i : i + 8] for i in range(len(signature) - 7)}
    return sum(fragment in text for fragment in fragments)


def _where(text: str, value: str) -> list[str]:
    """The kind of each captured line the value is present in. The line itself is never shown."""
    return [
        next((message for message in MESSAGES if message in line), "another line")
        for line in text.splitlines()
        if _found(line, value)
    ]


def _lines(text: str, message: str) -> list[str]:
    """The captured lines that carry the message."""
    return [line for line in text.splitlines() if message in line]


def _fields(line: str, json_output: bool) -> set[str]:
    """The field names a captured record carries."""
    if json_output:
        return set(json.loads(line))
    return {name for name in PATH_FIELDS + ("method",) if f" {name}=" in line}


def _expected_lengths(probe: Probe, value: str) -> list[int]:
    return [len(value) if part == "v" else part for part in probe.lengths]


async def _send_all(client, json_output: bool):
    """In one captured run, the control request and then every probe, each with a fresh planted value.

    The control is GET /sdk/contexts with no Authorization header: routed, answered 422, and
    carrying a planted correlation ID, which the JSON record writes.
    """
    correlation_id = secrets.token_urlsafe(24)
    accepted = request_logging.CORRELATION_ID_PATTERN.fullmatch(correlation_id) is not None
    assert accepted, "the planted correlation ID is outside the accepted form"
    values = {name: _identity_token() for name in PROBES}
    statuses = {}
    with _stdout_log(json_output) as out:
        control = await client.get("/sdk/contexts", headers={"X-Correlation-ID": correlation_id})
        statuses["control"] = control.status_code
        for name, probe in PROBES.items():
            response = await client.request(probe.method, probe.path.replace("<v>", values[name]))
            statuses[name] = response.status_code
    return out.getvalue(), values, statuses, correlation_id


# (b) No captured line holds a path value: not the start record, and not the completed or failed
# record, whether the path was routed, redirected, refused a method, matched nothing or raised.
@pytest.mark.parametrize("json_output", [True, False], ids=["json", "human"])
async def test_no_record_holds_a_path_value(client, json_output):
    text, values, statuses, _ = await _send_all(client, json_output)

    expected_statuses = {"control": 422} | {name: probe.status or 500 for name, probe in PROBES.items()}
    assert statuses == expected_statuses, "each request reached the routing branch it probes"
    started, expected_started = len(_lines(text, "Request started")), len(PROBES) + 1
    assert started == expected_started, "every request writes one start record"
    present = {
        name: f"a {len(value)}-character value in {_where(text, value)}"
        for name, value in values.items()
        if _found(text, value)
    }
    assert present == {}, "path values present in the log"


# (c) After routing, the completed or failed record names the matched API route's template and the
# length of each path value; a path no API route matched is written as the length of each segment.
@pytest.mark.parametrize("json_output", [True, False], ids=["json", "human"])
@pytest.mark.parametrize("name", list(PROBES))
async def test_record_names_the_route_template_and_value_lengths(client, name, json_output):
    probe = PROBES[name]
    value = _identity_token()

    with _stdout_log(json_output) as out:
        response = await client.request(probe.method, probe.path.replace("<v>", value))

    text = out.getvalue()
    status, expected_status = response.status_code, probe.status or 500
    assert status == expected_status
    message = "Request completed" if probe.status is not None else "Request failed"
    ended = _lines(text, message)
    count = len(ended)
    assert count == 1, f"{count} {message!r} lines in the captured log"
    lengths = _expected_lengths(probe, value)
    field = "path_param_lengths" if probe.route is not None else "path_segment_lengths"
    fields, expected_fields = sorted(_fields(ended[0], json_output) & set(PATH_FIELDS)), sorted(["route", field])
    assert fields == expected_fields, "the record's path fields"
    if json_output:
        record = json.loads(ended[0])
        route, found_lengths, error = record.get("route"), record.get(field), record.get("error")
        assert route == probe.route
        assert found_lengths == lengths
        if probe.status is None:
            assert error == "probe"
    else:
        expected = f"route={probe.route} {field}={lengths}"
        shown = expected in ended[0]
        assert shown, f"the record does not read {expected!r}"


# (d) Control, in the same run as (b): the parameter-free route's completed record keeps its
# template unchanged, and both that record and the planted correlation ID are found by the same
# presence rule that finds none of the path values.
async def test_control_record_and_correlation_id_are_found_in_the_same_run(client):
    text, values, statuses, correlation_id = await _send_all(client, json_output=True)

    control_lines = [line for line in _lines(text, "Request completed") if _found(line, "/sdk/contexts")]
    count = len(control_lines)
    assert count == 1, f"{count} completed records found for /sdk/contexts"
    record = json.loads(control_lines[0])
    route, status, lengths = record.get("route"), record.get("status_code"), record.get("path_param_lengths")
    assert (statuses["control"], status) == (422, 422)
    assert route == "/sdk/contexts"
    assert lengths == []
    correlation_found = _found(control_lines[0], correlation_id)
    assert correlation_found > 0, "the planted correlation ID is not found in the control record"
    present = sorted(name for name, value in values.items() if _found(text, value))
    assert present == [], "path values present in the same run"


# (e) The start record is written before routing and carries no path field at all.
@pytest.mark.parametrize("json_output", [True, False], ids=["json", "human"])
async def test_start_record_carries_no_path_field(client, json_output):
    text, _, _, _ = await _send_all(client, json_output)

    started = _lines(text, "Request started")
    count, expected_count = len(started), len(PROBES) + 1
    assert count == expected_count, "every request writes one start record"
    carried = sorted(set().union(*(_fields(line, json_output) for line in started)) & set(PATH_FIELDS))
    has_method = all("method" in _fields(line, json_output) for line in started)
    assert has_method, "the start records are read field by field"
    assert carried == [], "path fields on the start record"


def _route_paths(routes, prefix: str = ""):
    """The path template of every route, walking through included routers and mounts."""
    from fastapi.routing import iter_route_contexts

    for context in iter_route_contexts(routes):
        path = context.path
        if path is None:
            continue
        yield prefix + path
        if isinstance(context.original_route, Mount):
            yield from _route_paths(context.original_route.routes, prefix + path)


# (f) Census: every path parameter name the application's routes use is labelled, and every
# labelled name is still in use. An import failure fails this test; it never skips.
def test_path_parameter_census_matches_the_application_routes():
    # The application configures logging when imported; the capture restores the previous setup.
    with _stdout_log(json_output=True):
        from app.main import app as application

    used: dict[str, set[str]] = {}
    for path in _route_paths(application.routes):
        for name in compile_path(path)[2]:
            used.setdefault(name, set()).add(path)

    assert used, "the walk found no route path parameters"
    unlisted = sorted(set(used) - set(PATH_PARAMETER_CENSUS))
    unused = sorted(set(PATH_PARAMETER_CENSUS) - set(used))
    labels = sorted(set(PATH_PARAMETER_CENSUS.values()) - {"identifier", "credential"})
    assert unlisted == [], "route path parameters the census does not label identifier or credential"
    assert unused == [], "census names no route uses"
    assert labels == [], "census labels other than identifier and credential"
