"""CLI commands that call the server send the session `login` stored in the
cookie the server reads it from.

The server takes the session from an `Authorization: Bearer` header or from
the one cookie that `get_current_user` in backend/app/auth/jwt.py reads. Each
cell stores a session under a temporary HOME, runs one command with
`requests.get` and `requests.post` replaced by a recorder, and checks the
cookies of every request the command made. No request leaves the process.
"""

import ast
import getpass
import json
import pathlib
import secrets
import sys

import pytest
import requests

import cryptoserve.__main__ as cli

SERVER = "http://cryptoserve.invalid"
JWT_SOURCE = pathlib.Path(__file__).resolve().parents[3] / "backend" / "app" / "auth" / "jwt.py"
BACKUP_ID = "backup-1"

# Replies that let `backup` and `restore` go on to their second request. Any
# other request gets the server's reply to a request without a session.
REPLIES = {
    ("POST", "/api/admin/backups"): {
        "success": True,
        "backup_id": BACKUP_ID,
        "size_bytes": 1,
        "duration_seconds": 0.5,
        "tenant_count": 1,
        "context_count": 1,
        "key_count": 1,
        "pqc_key_count": 0,
        "checksum": "checksum-for-tests",
    },
    ("GET", f"/api/admin/backups/{BACKUP_ID}/download"): {},
    ("GET", f"/api/admin/backups/{BACKUP_ID}"): {
        "version": "1",
        "created_at": "2026-10-22T00:00:00Z",
        "database_type": "sqlite",
        "tenant_count": 1,
        "context_count": 1,
        "key_count": 1,
        "pqc_key_count": 0,
        "includes_audit_logs": False,
    },
    ("POST", f"/api/admin/backups/{BACKUP_ID}/restore"): {
        "success": True,
        "duration_seconds": 0.5,
        "records_restored": {"tenants": 1},
        "warnings": [],
    },
}


def _cookie_the_server_reads():
    """The name of the cookie `get_current_user` reads the session from."""
    tree = ast.parse(JWT_SOURCE.read_text(encoding="utf-8"))
    [func] = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "get_current_user"
    ]
    names = {
        node.args[0].value
        for node in ast.walk(func)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and isinstance(node.func.value, ast.Attribute)
        and node.func.value.attr == "cookies"
        and node.args
        and isinstance(node.args[0], ast.Constant)
    }
    assert len(names) == 1, f"get_current_user reads these cookies: {sorted(names)}"
    return names.pop()


def _session_value():
    # Built at run time: an opaque value standing in for what the server issues.
    return "-".join(["session", secrets.token_hex(8)])


class _Response:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self.ok = status_code < 400
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self):
        return self._payload

    def iter_content(self, chunk_size=1):
        yield b"backup bytes"

    def raise_for_status(self):
        if not self.ok:
            raise requests.HTTPError(f"{self.status_code} Client Error")


# Each command line, the answer it is given at its confirmation prompt, and
# the requests it makes, in order.
COMMANDS = [
    pytest.param(["info"], None, [("GET", "/api/v1/identity")], id="info"),
    pytest.param(
        ["backup", "--output", "{tmp}/backup.tar.gz.enc"],
        None,
        [("POST", "/api/admin/backups"), ("GET", f"/api/admin/backups/{BACKUP_ID}/download")],
        id="backup",
    ),
    pytest.param(
        ["restore", "--backup", f"{BACKUP_ID}.tar.gz.enc"],
        None,
        [("GET", f"/api/admin/backups/{BACKUP_ID}"), ("POST", f"/api/admin/backups/{BACKUP_ID}/restore")],
        id="restore",
    ),
    pytest.param(["backups"], None, [("GET", "/api/admin/backups")], id="backups"),
    pytest.param(["ceremony", "status"], None, [("GET", "/api/admin/ceremony/status")], id="ceremony-status"),
    pytest.param(
        ["ceremony", "initialize"],
        "INITIALIZE",
        [("POST", "/api/admin/ceremony/initialize")],
        id="ceremony-initialize",
    ),
    pytest.param(["ceremony", "seal"], "SEAL", [("POST", "/api/admin/ceremony/seal")], id="ceremony-seal"),
    pytest.param(
        ["ceremony", "unseal", "--share", "share-for-tests"],
        None,
        [("POST", "/api/admin/ceremony/unseal")],
        id="ceremony-unseal",
    ),
    pytest.param(
        ["ceremony", "verify", "--share", "share-for-tests"],
        None,
        [("POST", "/api/admin/ceremony/verify-share")],
        id="ceremony-verify",
    ),
    pytest.param(["ceremony", "audit"], None, [("GET", "/api/admin/ceremony/audit")], id="ceremony-audit"),
]


@pytest.mark.parametrize("argv, confirm, expected", COMMANDS)
def test_sends_the_session_in_the_cookie_the_server_reads(monkeypatch, tmp_path, argv, confirm, expected):
    monkeypatch.setenv("HOME", str(tmp_path))
    session = _session_value()
    cli._save_credentials({"server_url": SERVER, "session_cookie": session})

    sent = []

    def recorder(method):
        def send(url, *args, **kwargs):
            assert url.startswith(SERVER + "/"), url
            path = url[len(SERVER) :]
            sent.append((method, path, kwargs.get("cookies")))
            if (method, path) in REPLIES:
                return _Response(200, REPLIES[(method, path)])
            return _Response(401, {"detail": "Not authenticated"})

        return send

    monkeypatch.setattr(requests, "get", recorder("GET"))
    monkeypatch.setattr(requests, "post", recorder("POST"))
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "not-a-real-passphrase")
    monkeypatch.setattr("builtins.input", lambda prompt="": confirm)
    monkeypatch.setattr(sys, "argv", ["cryptoserve", *(arg.format(tmp=tmp_path) for arg in argv)])

    cli.main()

    assert [(method, path) for method, path, _ in sent] == expected
    cookie = _cookie_the_server_reads()
    for method, path, cookies in sent:
        assert cookies == {cookie: session}, f"{method} {path} sent cookies {sorted(cookies or {})}"
