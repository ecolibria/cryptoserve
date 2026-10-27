"""The backend accepts an incoming request or correlation ID only within a fixed bound.

The request ID is the X-Request-ID value when the request carries exactly one
such header line of 16 to 128 letters, digits, `_` or `-`; otherwise the
backend assigns its own UUID4. X-Correlation-ID is never read for the request
ID. The correlation ID is the X-Correlation-ID value when the request carries
exactly one such line of 1 to 128 of the same characters; otherwise it is the
request ID. Every response carries both IDs, and the request's log records
carry the same two values.
"""

import io
import json
import logging
import uuid
from contextlib import contextmanager, redirect_stdout

import httpx
import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from app.core import logging as request_logging


@pytest.fixture
async def client():
    """One route behind the request logging middleware."""
    app = FastAPI()
    app.add_middleware(request_logging.RequestLoggingMiddleware)

    @app.get("/ids")
    async def ids(request: Request):
        """How many lines of each ID header reached the route."""
        return {
            "requestIdLines": len(request.headers.getlist("X-Request-ID")),
            "correlationIdLines": len(request.headers.getlist("X-Correlation-ID")),
        }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        yield c


@contextmanager
def _json_log():
    """JSON logging set up as the application does it, with stdout captured. The previous setup is restored."""
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    library_levels = {name: logging.getLogger(name).level for name in ("uvicorn.access", "httpx", "httpcore")}
    out = io.StringIO()
    try:
        with redirect_stdout(out):
            request_logging.setup_logging(json_output=True)
            yield out
    finally:
        for handler in root.handlers[:]:
            root.removeHandler(handler)
        for handler in handlers:
            root.addHandler(handler)
        root.setLevel(level)
        for name, library_level in library_levels.items():
            logging.getLogger(name).setLevel(library_level)


def _response_ids(response: httpx.Response) -> tuple[str, str]:
    """The response's X-Request-ID and X-Correlation-ID, each sent once."""
    request_ids = response.headers.get_list("X-Request-ID")
    correlation_ids = response.headers.get_list("X-Correlation-ID")
    assert len(request_ids) == 1, f"{len(request_ids)} X-Request-ID headers on the response"
    assert len(correlation_ids) == 1, f"{len(correlation_ids)} X-Correlation-ID headers on the response"
    return request_ids[0], correlation_ids[0]


def _assigned(value: str) -> bool:
    """True when the value is a UUID4 in its 36-character string form."""
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return False
    return len(value) == 36 and parsed.version == 4 and str(parsed) == value


# (a) No ID header: the backend assigns a UUID4, and the correlation ID is the request ID.
async def test_request_without_ids_is_assigned_a_uuid4(client):
    response = await client.get("/ids")

    request_id, correlation_id = _response_ids(response)
    assert _assigned(request_id), f"X-Request-ID {request_id!r} is not an assigned UUID4"
    assert correlation_id == request_id


# (b) One X-Request-ID within the bound, in the form the scale proxy sets, is kept.
async def test_request_id_within_the_bound_is_kept(client):
    sent = "f8fb57bc39dd9e25720878c78d4fd128"

    response = await client.get("/ids", headers={"X-Request-ID": sent})

    assert _response_ids(response) == (sent, sent)


# (c) An X-Request-ID shorter than 16, longer than 128, or holding another character is replaced.
@pytest.mark.parametrize(
    "sent",
    ["short-id", "a" * 129, "abcdefgh ijklmnop", "req.1234567890abcdef"],
    ids=["shorter-than-16", "longer-than-128", "space", "dot"],
)
async def test_request_id_outside_the_bound_is_replaced(client, sent):
    response = await client.get("/ids", headers={"X-Request-ID": sent})

    request_id, correlation_id = _response_ids(response)
    assert _assigned(request_id), f"X-Request-ID {request_id!r} is not an assigned UUID4"
    assert sent not in (request_id, correlation_id)


# (d) Two X-Request-ID lines are replaced, even when each value is within the bound.
async def test_two_request_id_lines_are_replaced(client):
    sent = "0123456789abcdef0123456789abcdef"

    response = await client.get("/ids", headers=[("X-Request-ID", sent), ("X-Request-ID", sent)])

    assert response.json()["requestIdLines"] == 2
    request_id, correlation_id = _response_ids(response)
    assert _assigned(request_id), f"X-Request-ID {request_id!r} is not an assigned UUID4"
    assert sent not in (request_id, correlation_id)


# (e) An X-Correlation-ID within its bound is kept and is never taken as the request ID.
async def test_correlation_id_is_kept_and_not_used_as_the_request_id(client):
    response = await client.get("/ids", headers={"X-Correlation-ID": "corr-a"})

    request_id, correlation_id = _response_ids(response)
    assert correlation_id == "corr-a"
    assert request_id != "corr-a"
    assert _assigned(request_id), f"X-Request-ID {request_id!r} is not an assigned UUID4"


# (f) An X-Correlation-ID longer than 128, holding another character, or sent on two lines
# gives way to the request ID, which the backend assigns when no X-Request-ID is sent.
@pytest.mark.parametrize(
    "sent",
    [
        [("X-Correlation-ID", "a" * 129)],
        [("X-Correlation-ID", "corr-a, corr-b")],
        [("X-Correlation-ID", "corr-a"), ("X-Correlation-ID", "corr-b")],
    ],
    ids=["longer-than-128", "comma-list", "two-lines"],
)
async def test_correlation_id_outside_the_bound_gives_way_to_the_request_id(client, sent):
    response = await client.get("/ids", headers=sent)

    assert response.json()["correlationIdLines"] == len(sent)
    request_id, correlation_id = _response_ids(response)
    assert correlation_id == request_id
    assert _assigned(request_id), f"X-Request-ID {request_id!r}, X-Correlation-ID {correlation_id!r}"


# (g) With JSON output, the "Request started" record of case (e) carries the two response IDs.
async def test_started_record_carries_the_response_ids(client):
    with _json_log() as out:
        response = await client.get("/ids", headers={"X-Correlation-ID": "corr-a"})

    started = [line for line in out.getvalue().splitlines() if "Request started" in line]
    assert len(started) == 1, f"{len(started)} request-started lines in the captured log"
    record = json.loads(started[0])
    request_id, correlation_id = _response_ids(response)
    assert record["request_id"] == request_id
    assert record["correlation_id"] == correlation_id
