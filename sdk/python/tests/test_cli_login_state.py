"""`cryptoserve login` stores a session only from the callback that returns the
state this login issued.

Each cell runs `cmd_login` in a thread against a stubbed `/auth/status` and a
stubbed browser launch, then plays the browser against the loopback listener,
whose address it reads from the authorization URL. Credentials are written
under a temporary HOME. The listener binds 127.0.0.1, and the cells connect to
127.0.0.1 only.
"""

import http.client
import json
import os
import queue
import secrets
import socket
import sys
import threading
import urllib.parse
import webbrowser

import pytest
import requests

import cryptoserve.__main__ as cli

SERVER = "http://cryptoserve.invalid"
LOOPBACK = "127.0.0.1"


class _StatusResponse:
    ok = True

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


def _session_value():
    # Built at run time: an opaque value standing in for what the server issues.
    return "-".join(["session", secrets.token_hex(8)])


class LoginRun:
    """One `cryptoserve login` running in a thread."""

    def __init__(self, home, url, thread, outcome):
        self.home = home
        self.url = url
        self.thread = thread
        self.outcome = outcome
        parts = urllib.parse.urlsplit(url)
        self.path = parts.path
        self.query = urllib.parse.parse_qs(parts.query)
        self.callback = urllib.parse.urlsplit(self.query["cli_callback"][0])
        # The cells only ever connect to the loopback address.
        assert self.callback.hostname == LOOPBACK, self.query["cli_callback"]

    @property
    def state(self):
        """The state the authorization URL carries ("" when it carries none)."""
        return self.query.get("state", [""])[0]

    def target(self, path=None, **params):
        """A request target on the callback path (or `path`) with `params`."""
        path = path if path is not None else (self.callback.path or "/")
        return path + ("?" + urllib.parse.urlencode(params) if params else "")

    def send(self, target, method="GET"):
        conn = http.client.HTTPConnection(LOOPBACK, self.callback.port, timeout=5)
        try:
            conn.request(method, target)
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def complete(self, session, user="someone"):
        """Send the callback the server sends: the issued state and a session."""
        return self.send(self.target(session=session, user=user, state=self.state))

    def stored(self):
        path = os.path.join(self.home, ".cryptoserve", "credentials.json")
        if not os.path.exists(path):
            return {}
        with open(path) as f:
            return json.load(f)

    def finished(self, timeout=10):
        self.thread.join(timeout)
        return not self.thread.is_alive()

    def assert_still_waiting(self):
        # Give a login that has wrongly ended the time to finish.
        self.thread.join(0.5)
        assert self.thread.is_alive(), "the login ended on a request it should refuse"
        assert "code" not in self.outcome


def _free_loopback_port():
    with socket.socket() as s:
        s.bind((LOOPBACK, 0))
        return s.getsockname()[1]


@pytest.fixture
def start_login(monkeypatch, tmp_path):
    """Start `cryptoserve login` in a thread; return a `LoginRun` once the
    authorization URL has been handed to the browser."""
    monkeypatch.setenv("HOME", str(tmp_path))
    # A free loopback port, so a cell does not depend on 9876 being free on
    # this machine; the URL cells check that the listener used it.
    monkeypatch.setattr(cli, "_LOGIN_CALLBACK_PORT", _free_loopback_port(), raising=False)
    runs = []

    def start(dev_mode=True, providers=()):
        def status(url, *args, **kwargs):
            assert url == SERVER + "/auth/status", url
            return _StatusResponse({"dev_mode": dev_mode, "providers": list(providers)})

        opened = queue.Queue()
        monkeypatch.setattr(sys, "argv", ["cryptoserve", "login", "--server", SERVER])
        monkeypatch.setattr(requests, "get", status)
        monkeypatch.setattr(webbrowser, "open", lambda url, *a, **k: opened.put(url) or True)

        outcome = {}

        def run():
            outcome["code"] = cli.cmd_login()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        try:
            url = opened.get(timeout=10)
        except queue.Empty:
            thread.join(5)
            pytest.fail(f"login did not open the authorization URL (exit {outcome.get('code')})")
        login = LoginRun(str(tmp_path), url, thread, outcome)
        runs.append(login)
        return login

    yield start

    # A login a cell left waiting is completed, so no listener outlives the cell.
    for login in runs:
        if login.thread.is_alive():
            try:
                login.complete(_session_value())
            except (OSError, http.client.HTTPException):
                pass
            login.thread.join(10)


def test_listener_is_the_loopback_callback_on_port_9876():
    callback = f"http://{cli._LOGIN_CALLBACK_HOST}:{cli._LOGIN_CALLBACK_PORT}{cli._LOGIN_CALLBACK_PATH}"
    assert callback == "http://127.0.0.1:9876/callback"


def test_authorization_url_carries_the_issued_state_and_the_loopback_callback(start_login):
    login = start_login()
    assert len(login.query.get("state", [])) == 1, login.url
    # 32 random bytes, URL-safe base64 without padding.
    assert len(login.state) >= 43
    assert set(login.state) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    assert login.path == "/auth/dev-login"
    assert login.query["cli_callback"] == [f"http://127.0.0.1:{cli._LOGIN_CALLBACK_PORT}/callback"]


def test_provider_authorization_url_carries_the_issued_state(start_login):
    login = start_login(dev_mode=False, providers=["github"])
    assert len(login.query.get("state", [])) == 1, login.url
    assert len(login.state) >= 43
    assert login.path == "/auth/login/github"
    assert login.query["cli_callback"] == [f"http://127.0.0.1:{cli._LOGIN_CALLBACK_PORT}/callback"]


def test_callback_with_the_issued_state_stores_the_session(start_login):
    login = start_login()
    session = _session_value()

    status, body = login.complete(session, user="devuser")

    assert status == 200
    assert login.finished()
    assert login.outcome["code"] == 0
    stored = login.stored()
    assert stored["session_cookie"] == session
    assert stored["user"] == "devuser"
    assert stored["server_url"] == SERVER


def test_callback_without_state_is_refused_and_the_login_keeps_waiting(start_login):
    login = start_login()

    status, _ = login.send(login.target(session=_session_value(), user="other"))

    assert status == 400
    assert "session_cookie" not in login.stored()
    login.assert_still_waiting()

    session = _session_value()
    assert login.complete(session)[0] == 200
    assert login.finished()
    assert login.outcome["code"] == 0
    assert login.stored()["session_cookie"] == session


@pytest.mark.parametrize(
    "state",
    [
        "different",
        "",
        "flip-last",
        "prefix",
    ],
)
def test_callback_with_another_state_is_refused_and_the_login_keeps_waiting(start_login, state):
    login = start_login()
    issued = login.state
    if state == "different":
        state = secrets.token_urlsafe(32)
    elif state == "flip-last":
        state = issued[:-1] + ("A" if issued[-1:] != "A" else "B")
    elif state == "prefix":
        state = issued[:-1]

    status, _ = login.send(login.target(session=_session_value(), state=state))

    assert status == 400
    assert "session_cookie" not in login.stored()
    login.assert_still_waiting()

    session = _session_value()
    assert login.complete(session)[0] == 200
    assert login.finished()
    assert login.stored()["session_cookie"] == session


def test_callback_carrying_the_state_twice_is_refused(start_login):
    login = start_login()
    target = login.target(session=_session_value()) + "&" + urllib.parse.urlencode(
        [("state", login.state), ("state", secrets.token_urlsafe(32))]
    )

    status, _ = login.send(target)

    assert status == 400
    assert "session_cookie" not in login.stored()
    login.assert_still_waiting()


@pytest.mark.parametrize("path", ["/", "/elsewhere", "/callback/extra", "/favicon.ico"])
def test_callback_on_another_path_is_refused_and_the_login_keeps_waiting(start_login, path):
    login = start_login()

    status, _ = login.send(login.target(path=path, session=_session_value(), state=login.state))

    assert status == 400
    assert "session_cookie" not in login.stored()
    login.assert_still_waiting()

    session = _session_value()
    assert login.complete(session)[0] == 200
    assert login.finished()
    assert login.stored()["session_cookie"] == session


def test_each_login_issues_its_own_state(start_login):
    first = start_login()
    first_session = _session_value()
    assert first.complete(first_session)[0] == 200
    assert first.finished()
    assert first.stored()["session_cookie"] == first_session

    second = start_login()

    # The first login's state does not complete the second login.
    status, _ = second.send(second.target(session=_session_value(), state=first.state))
    assert status == 400
    assert second.stored()["session_cookie"] == first_session
    second.assert_still_waiting()

    assert second.state and first.state
    assert second.state != first.state

    second_session = _session_value()
    assert second.complete(second_session)[0] == 200
    assert second.finished()
    assert second.stored()["session_cookie"] == second_session


def test_callback_with_a_session_longer_than_8192_characters_is_refused(start_login):
    login = start_login()

    status, _ = login.send(login.target(session="s" * 8193, state=login.state))

    assert status == 400
    assert "session_cookie" not in login.stored()
    login.assert_still_waiting()

    session = "s" * 8192
    assert login.complete(session)[0] == 200
    assert login.finished()
    assert login.stored()["session_cookie"] == session


@pytest.mark.parametrize("method", ["POST", "HEAD"])
def test_another_method_does_not_end_the_login(start_login, method):
    login = start_login()

    status, _ = login.send(login.target(session=_session_value(), state=login.state), method=method)

    assert status == 501
    assert "session_cookie" not in login.stored()
    login.assert_still_waiting()

    session = _session_value()
    assert login.complete(session)[0] == 200
    assert login.finished()
    assert login.stored()["session_cookie"] == session


def test_callback_without_a_session_is_refused_and_the_login_keeps_waiting(start_login):
    login = start_login()

    status, _ = login.send(login.target(state=login.state, user="someone"))

    assert status == 400
    assert "session_cookie" not in login.stored()
    login.assert_still_waiting()


def test_server_error_with_the_issued_state_ends_the_login_and_stores_nothing(start_login, capsys):
    login = start_login()
    message = "Ask an administrator for an invitation."

    status, _ = login.send(login.target(error="not_authorized", message=message, state=login.state))

    assert status == 200
    assert login.finished()
    assert login.outcome["code"] == 1
    assert "session_cookie" not in login.stored()
    assert message in capsys.readouterr().out


def test_server_error_without_the_issued_state_does_not_end_the_login(start_login):
    login = start_login()

    status, _ = login.send(login.target(error="not_authorized", message="no"))

    assert status == 400
    login.assert_still_waiting()


def test_login_gives_up_at_the_timeout_and_closes_the_listener(start_login, monkeypatch):
    monkeypatch.setattr(cli, "_LOGIN_TIMEOUT_SECONDS", 1, raising=False)
    login = start_login()

    assert login.finished(timeout=15), "the login did not give up at its timeout"
    assert login.outcome["code"] == 1
    assert "session_cookie" not in login.stored()
    with pytest.raises(OSError):
        socket.create_connection((LOOPBACK, login.callback.port), timeout=2).close()
