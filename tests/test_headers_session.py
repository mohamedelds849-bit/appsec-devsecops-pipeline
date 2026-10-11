"""A05 Security Misconfiguration / A07: HTTP security headers and session cookie flags."""
import secrets

import pytest

from portal import create_app
from tests.conftest import csrf_from, login

EXPECTED = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
}


@pytest.mark.parametrize("path", ["/login", "/orders", "/does-not-exist", "/static/style.css"])
def test_security_headers_on_every_response(client, path):
    resp = client.get(path)
    for name, value in EXPECTED.items():
        assert resp.headers.get(name) == value, name
    csp = resp.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert "Permissions-Policy" in resp.headers


def test_server_header_does_not_leak_stack(client):
    server = client.get("/login").headers.get("Server", "")
    assert "werkzeug" not in server.lower() and "waitress" not in server.lower()
    assert "python" not in server.lower()


def test_pages_are_not_cacheable(as_user):
    assert as_user("client.a").get("/orders").headers["Cache-Control"] == "no-store"


def test_hsts_off_by_default_and_on_when_enabled(client, tmp_path):
    assert "Strict-Transport-Security" not in client.get("/login").headers
    app = create_app({"SECRET_KEY": secrets.token_hex(32), "DATABASE": str(tmp_path / "h.db"),
                      "HSTS_ENABLED": True})
    hsts = app.test_client().get("/login").headers["Strict-Transport-Security"]
    assert "max-age=31536000" in hsts


def _session_cookie_header(resp):
    cookies = [v for k, v in resp.headers.items()
               if k == "Set-Cookie" and v.startswith("__Host-session=")]
    assert cookies, "no session cookie set"
    return cookies[-1]


def test_session_cookie_flags(client):
    lowered = _session_cookie_header(client.get("/login")).lower()
    assert "; secure" in lowered
    assert "; httponly" in lowered
    assert "samesite=lax" in lowered
    assert "path=/" in lowered
    assert "domain=" not in lowered  # required by the __Host- prefix


def test_session_is_renewed_at_login(app, client):
    """Session fixation (CWE-384): the pre-login CSRF token must not survive login."""
    before = csrf_from(client)
    assert login(client, app, "client.a").status_code == 302
    after = csrf_from(client, "/orders")
    assert before != after


def test_errors_do_not_show_stack_traces(as_user):
    body = as_user("client.a").get("/orders/not-a-number").get_data(as_text=True)
    assert "Traceback" not in body and "werkzeug" not in body.lower()
