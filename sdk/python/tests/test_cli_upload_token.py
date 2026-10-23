"""`push` and `cbom` upload with an SDK token and never send the session that
`login` stored.

The server's `/api/v1/cbom` route takes only an SDK identity or application
token, from an `Authorization: Bearer` header (`get_sdk_identity` in
backend/app/api/crypto.py). It reads no cookie, so a login session sent to it
only gets the upload refused. Each cell stores a login session under a
temporary HOME, runs one command with `requests.get` and `requests.post`
replaced by a recorder that answers as that route does, and checks what the
command sent and printed. No request leaves the process.
"""

import json
import sys

import pytest
import requests

import cryptoserve
import cryptoserve.__main__ as cli
import cryptoserve._identity as identity

SERVER = "http://cryptoserve.invalid"
UPLOAD_URL = f"{SERVER}/api/v1/cbom"
SESSION = "not-a-real-session"
SDK_TOKEN = "not-a-real-sdk-token"


class _Response:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


@pytest.fixture
def stored_login(monkeypatch, tmp_path):
    """A login session stored under a temporary HOME, and a CBOM file to push."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    cli._save_credentials({"server_url": SERVER, "session_cookie": SESSION})
    (tmp_path / "cbom.json").write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}))
    monkeypatch.setattr(
        cryptoserve,
        "export_cbom",
        lambda format="json": cryptoserve.CBOMResult(
            cbom={"components": []}, format=format, quantum_readiness={"score": 100.0, "risk_level": "low"}
        ),
    )


@pytest.fixture
def sent(monkeypatch):
    """The requests the command made, as (method, url, headers, cookies)."""
    requests_sent = []

    def recorder(method):
        def send(url, *args, **kwargs):
            headers = kwargs.get("headers") or {}
            requests_sent.append((method, url, headers, kwargs.get("cookies")))
            # As /api/v1/cbom answers: only the SDK token it knows is accepted.
            authorization = headers.get("Authorization", "")
            if method == "POST" and authorization == f"Bearer {SDK_TOKEN}":
                return _Response(201, {"id": "scan-1"})
            if authorization.startswith("Bearer "):
                return _Response(401, {"detail": "Invalid or expired identity token"})
            return _Response(401, {"detail": "Not authenticated"})

        return send

    monkeypatch.setattr(requests, "get", recorder("GET"))
    monkeypatch.setattr(requests, "post", recorder("POST"))
    return requests_sent


def _configure_sdk_token(monkeypatch, token):
    monkeypatch.setattr(identity, "IDENTITY", {**identity.IDENTITY, "server_url": SERVER, "token": token})


# Each upload command line and its exit code when no SDK token is configured:
# `push` fails, `cbom` still prints the CBOM and skips only the upload.
UPLOADS = [
    pytest.param(["push", "cbom.json"], 1, id="push"),
    pytest.param(["cbom", "."], 0, id="cbom"),
]


@pytest.mark.parametrize("argv, exit_code", UPLOADS)
def test_without_an_sdk_token_sends_nothing_and_names_configure_token(
    monkeypatch, capsys, stored_login, sent, argv, exit_code
):
    _configure_sdk_token(monkeypatch, None)
    monkeypatch.setattr(sys, "argv", ["cryptoserve", *argv])

    code = cli.main()

    assert sent == [], f"sent {[f'{method} {url}' for method, url, _, _ in sent]}"
    out = capsys.readouterr().out
    assert "configure --token" in out
    assert f"{cli.CLI} login" not in out
    assert code == exit_code


@pytest.mark.parametrize("argv", [param.values[0] for param in UPLOADS], ids=[param.id for param in UPLOADS])
def test_with_an_sdk_token_uploads_with_it_and_without_the_session(monkeypatch, stored_login, sent, argv):
    _configure_sdk_token(monkeypatch, SDK_TOKEN)
    monkeypatch.setattr(sys, "argv", ["cryptoserve", *argv])

    assert cli.main() == 0
    assert sent == [("POST", UPLOAD_URL, {"Authorization": f"Bearer {SDK_TOKEN}"}, None)]


def test_cbom_does_not_suggest_login_when_the_server_refuses_the_sdk_token(monkeypatch, capsys, stored_login, sent):
    _configure_sdk_token(monkeypatch, "not-a-known-sdk-token")
    monkeypatch.setattr(sys, "argv", ["cryptoserve", "cbom", "."])

    assert cli.main() == 0
    assert [(method, url, cookies) for method, url, _, cookies in sent] == [("POST", UPLOAD_URL, None)]
    out = capsys.readouterr().out
    assert "Upload skipped" in out
    assert f"{cli.CLI} login" not in out
