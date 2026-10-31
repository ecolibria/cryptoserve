"""`push` and `cbom` post `git_repo` without the userinfo of the origin remote URL.

`_get_git_info()` reads `remote.origin.url` for the `git_repo` field, and the
two upload paths, `_push_results_file` and `_upload_cbom`, spread what it
returns into the body they post to `/api/v1/cbom`. Each cell makes its own git
repository under a temporary directory, with HOME set to a temporary
directory, and sets its origin to a URL assembled at runtime from neutral
fragments. `requests.post` is replaced by a recorder that keeps the posted
body, so no request leaves the process. Cells (b) and (c) are the controls: a
value without userinfo comes back byte for byte, with no notice.
"""

import copy
import json
import re
import subprocess

import pytest
import requests

import cryptoserve
import cryptoserve.__main__ as cli
import cryptoserve._identity as identity

# The upload test's fixture form: a server that never resolves, a token no server knows.
SERVER = "http://cryptoserve.invalid"
UPLOAD_URL = f"{SERVER}/api/v1/cbom"
SDK_TOKEN = "not-a-real-sdk-token"

NOTICE = "Origin remote sent without its userinfo"

# Every URL below is assembled at runtime from these neutral fragments.
SCHEME = "https"
HOST = "example.invalid"
PATH = "/".join(["", "team", "project.git"])
USER_PART = "-".join(["qz", "user", "part"])
PASSWORD_PART = "-".join(["qz", "pass", "part"])
NAME_PART = "-".join(["qz", "lone", "part"])
LEFT_OF_AT = "-".join(["qz", "left", "part"])
RIGHT_OF_AT = "-".join(["qz", "right", "part"])

PLAIN = f"{SCHEME}://{HOST}{PATH}"
WITH_USER_AND_PASSWORD = f"{SCHEME}://{USER_PART}:{PASSWORD_PART}@{HOST}{PATH}"
WITH_USER_ONLY = f"{SCHEME}://{NAME_PART}@{HOST}{PATH}"
WITH_AT_IN_PASSWORD = f"{SCHEME}://{USER_PART}:{LEFT_OF_AT}@{RIGHT_OF_AT}@{HOST}{PATH}"
SCP_LIKE = f"git@{HOST}:{PATH.lstrip('/')}"

USERINFO_IN_AUTHORITY = re.compile(r"//[^/]*@")

# The body keys each upload path sends from a repository with a commit, a
# branch and an origin remote: its own keys and the three from _get_git_info.
PUSH_KEYS = {"format", "content", "scan_path", "scan_name", "git_commit", "git_branch", "git_repo"}
CBOM_KEYS = PUSH_KEYS | {"score", "risk_level"}


class _Response:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True, timeout=30)


@pytest.fixture
def origin(monkeypatch, tmp_path):
    """Make the working directory a new git repository whose origin is the given URL.

    HOME is a temporary directory and the system git configuration is not
    read, so only the repository's own configuration applies.
    """
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_CONFIG_GLOBAL", "XDG_CONFIG_HOME"):
        monkeypatch.delenv(name, raising=False)

    def make(url):
        work = tmp_path / "work"
        work.mkdir()
        _git(work, "-c", "init.defaultBranch=main", "init", "-q")
        _git(
            work,
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "init",
        )
        _git(work, "remote", "add", "origin", url)
        monkeypatch.chdir(work)
        return work

    return make


@pytest.fixture
def sent(monkeypatch):
    """The requests the upload made, each with the body passed as `json=`."""
    requests_sent = []

    def recorder(method):
        def send(url, *args, **kwargs):
            headers = kwargs.get("headers") or {}
            requests_sent.append(
                {
                    "method": method,
                    "url": url,
                    "headers": headers,
                    "cookies": kwargs.get("cookies"),
                    "json": copy.deepcopy(kwargs.get("json")),
                }
            )
            # As /api/v1/cbom answers: only the SDK token it knows is accepted.
            if method == "POST" and headers.get("Authorization") == f"Bearer {SDK_TOKEN}":
                return _Response(201, {"id": "scan-1"})
            return _Response(401, {"detail": "Not authenticated"})

        return send

    monkeypatch.setattr(requests, "get", recorder("GET"))
    monkeypatch.setattr(requests, "post", recorder("POST"))
    return requests_sent


def _configure_sdk_token(monkeypatch, token):
    monkeypatch.setattr(identity, "IDENTITY", {**identity.IDENTITY, "server_url": SERVER, "token": token})


def _git_repo_and_output(capfd):
    """Run _get_git_info() and return its git_repo with what it wrote to stdout and stderr."""
    capfd.readouterr()
    git_repo = cli._get_git_info()["git_repo"]
    out, err = capfd.readouterr()
    return git_repo, out, err


def test_a_git_repo_is_the_origin_url_without_user_and_password(origin, capfd):
    origin(WITH_USER_AND_PASSWORD)

    git_repo, out, err = _git_repo_and_output(capfd)

    assert git_repo == PLAIN
    assert not USERINFO_IN_AUTHORITY.search(git_repo)
    for fragment in (USER_PART, PASSWORD_PART):
        assert fragment not in out + err
    assert out == ""
    assert err.splitlines().count(NOTICE) == 1


def test_b_get_git_info_returns_an_origin_url_without_userinfo_byte_equal(origin, capfd):
    origin(PLAIN)

    git_repo, out, err = _git_repo_and_output(capfd)

    assert git_repo.encode() == PLAIN.encode()
    assert out == ""
    assert NOTICE not in err


def test_b_without_userinfo_returns_a_url_without_userinfo_byte_equal_and_false():
    value, removed = cli._without_userinfo(PLAIN)

    assert value.encode() == PLAIN.encode()
    assert removed is False


def test_c_an_scp_like_origin_is_returned_unchanged(origin, capfd):
    origin(SCP_LIKE)

    git_repo, out, err = _git_repo_and_output(capfd)

    assert git_repo.encode() == SCP_LIKE.encode()
    assert out == ""
    assert NOTICE not in err


def test_d_a_user_part_alone_is_removed_from_git_repo(origin, capfd):
    origin(WITH_USER_ONLY)

    git_repo, out, err = _git_repo_and_output(capfd)

    assert git_repo == PLAIN
    assert NAME_PART not in git_repo + out + err
    assert err.splitlines().count(NOTICE) == 1


def test_e_a_password_holding_an_at_sign_is_removed_whole_with_host_and_path_intact(origin, capfd):
    origin(WITH_AT_IN_PASSWORD)

    git_repo, out, err = _git_repo_and_output(capfd)

    assert git_repo == PLAIN
    assert "@" not in git_repo
    for fragment in (USER_PART, LEFT_OF_AT, RIGHT_OF_AT):
        assert fragment not in git_repo + out + err
    assert err.splitlines().count(NOTICE) == 1


def _push(results_dir):
    results = results_dir / "cbom.json"
    results.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}))
    return cli._push_results_file(str(results)) == 0


def _cbom(results_dir):
    result = cryptoserve.CBOMResult(
        cbom={"components": []}, format="json", quantum_readiness={"score": 100.0, "risk_level": "low"}
    )
    return cli._upload_cbom(result) is True


UPLOADS = [
    pytest.param(_push, PUSH_KEYS, id="push"),
    pytest.param(_cbom, CBOM_KEYS, id="cbom"),
]

# The origin of cell (a), whose upload carries the notice, and of cell (b), whose does not.
ORIGINS = [
    pytest.param(WITH_USER_AND_PASSWORD, 1, id="userinfo"),
    pytest.param(PLAIN, 0, id="plain"),
]


@pytest.mark.parametrize("url, notices", ORIGINS)
@pytest.mark.parametrize("upload, keys", UPLOADS)
def test_f_uploads_post_git_repo_without_userinfo(
    monkeypatch, capfd, tmp_path, origin, sent, upload, keys, url, notices
):
    _configure_sdk_token(monkeypatch, SDK_TOKEN)
    origin(url)
    capfd.readouterr()

    assert upload(tmp_path)

    out, err = capfd.readouterr()
    assert [(request["method"], request["url"]) for request in sent] == [("POST", UPLOAD_URL)]
    payload = sent[0]["json"]
    assert payload["git_repo"] == PLAIN
    assert not USERINFO_IN_AUTHORITY.search(payload["git_repo"])
    body = json.dumps(payload)
    for fragment in (USER_PART, PASSWORD_PART):
        assert fragment not in body
        assert fragment not in out
        assert fragment not in err
    assert set(payload) == keys
    assert err.splitlines().count(NOTICE) == notices
