"""Scale proxy access log and request ID.

``nginx.scale.conf`` writes request lines and Referer values to the access log
without their query strings, sends each request's ID to the backend in
``X-Request-ID``, and returns it on every response. These checks read the file
as text, so they run without nginx or Docker.
"""

import re
from pathlib import Path

CONF = Path(__file__).resolve().parents[2] / "nginx.scale.conf"

# Variables that put a query string, or a whole URI or Referer, into a log line.
RAW_FIELDS = re.compile(r"\$(?:request|request_uri|args|query_string|is_args|uri|http_referer)(?![A-Za-z0-9_])|\$arg_")
LOCATION = r"\blocation\b[^{]*\{"


def _body() -> str:
    """The configuration without comments; map regex rows keep their ``#``."""
    return "\n".join(
        line if line.lstrip().startswith('"~') else line.split("#", 1)[0] for line in CONF.read_text().splitlines()
    )


def _statement(src: str, head: str) -> str:
    """The statement that starts with ``head``, through its closing ``;``."""
    i = src.find(head)
    return "" if i < 0 else src[i : src.index(";", i) + 1]


def _blocks(src: str, opener: str) -> list[str]:
    """Every brace-balanced block whose opening matches ``opener``."""
    found = []
    for m in re.finditer(opener, src):
        depth = 0
        for j in range(src.index("{", m.start()), len(src)):
            depth += {"{": 1, "}": -1}.get(src[j], 0)
            if depth == 0:
                found.append(src[m.start() : j + 1])
                break
    return found


class TestAccessLog:
    def test_log_format_names_no_raw_request_line_uri_args_or_referer(self):
        fmt = _statement(_body(), "log_format main")
        assert fmt, "log_format main is missing"
        assert RAW_FIELDS.findall(fmt) == []

    def test_log_format_names_the_query_free_fields_and_the_request_id(self):
        fmt = _statement(_body(), "log_format main")
        for field in ("$request_noquery", "$http_referer_noquery", "req=$request_id"):
            assert field in fmt, field

    def test_both_maps_write_a_dash_for_an_absent_value(self):
        body = _body()
        for opener in (r"map \$request \$request_noquery\s*\{", r"map \$http_referer \$http_referer_noquery\s*\{"):
            maps = _blocks(body, opener)
            assert maps, opener
            assert re.search(r'^\s*""\s+"-";', maps[0], re.M), opener


class TestRequestId:
    def test_every_proxying_location_sends_the_request_id(self):
        locations = [b for b in _blocks(_body(), LOCATION) if "proxy_pass" in b]
        sending = [b for b in locations if re.search(r"proxy_set_header\s+X-Request-ID\s+\$request_id;", b)]
        assert locations
        assert len(sending) == len(locations), f"{len(sending)} of {len(locations)} proxying locations send it"

    def test_server_returns_the_request_id_and_hides_the_upstream_copy(self):
        body = _body()
        servers = [b for b in _blocks(body, r"\bserver\s*\{") if "listen 80;" in b]
        assert len(servers) == 1
        assert re.search(r"^\s*add_header\s+X-Request-ID\s+\$request_id\s+always;", servers[0], re.M)
        assert re.search(r"^\s*proxy_hide_header\s+X-Request-ID;", servers[0], re.M)
        # A location that declares its own add_header inherits none from the
        # server, so it would have to return the request ID itself.
        own_headers = [
            b
            for b in _blocks(body, LOCATION)
            if "add_header" in b and not re.search(r"add_header\s+X-Request-ID\s+\$request_id\s+always;", b)
        ]
        assert own_headers == []


class TestErrorLog:
    def test_log_not_found_is_off_and_the_level_stays_warn(self):
        body = _body()
        assert re.search(r"^\s*log_not_found\s+off;", body, re.M)
        assert re.search(r"^\s*error_log\s+/var/log/nginx/error\.log\s+warn;", body, re.M)
