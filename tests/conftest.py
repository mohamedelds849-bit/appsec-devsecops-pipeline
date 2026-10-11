"""Shared fixtures. Every secret and password here is generated at random per test run."""
import re
import secrets

import pytest

from portal import create_app, db
from portal.auth import hash_password

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


@pytest.fixture
def app(tmp_path):
    app = create_app({
        "SECRET_KEY": secrets.token_hex(32),
        "DATABASE": str(tmp_path / "test.db"),
        "TESTING": True,
    })
    users = {}
    with app.app_context():
        for username, role in [("staff.agadir", "staff"), ("client.a", "customer"),
                               ("client.b", "customer")]:
            pw = secrets.token_urlsafe(16)
            uid = db.create_user(username, hash_password(pw), role)
            users[username] = {"id": uid, "password": pw, "role": role}
        users["client.a"]["order"] = db.create_order(users["client.a"]["id"], "Argan oil 1L", 20, 4200)
        users["client.b"]["order"] = db.create_order(users["client.b"]["id"], "Amlou 500g", 40, 3600)
    app.test_users = users
    return app


def make_client(app, ip="127.0.0.1"):
    """Test client that speaks HTTPS: the session cookie is Secure (+ __Host- prefix)."""
    c = app.test_client()
    c.environ_base["wsgi.url_scheme"] = "https"
    c.environ_base["REMOTE_ADDR"] = ip
    return c


@pytest.fixture
def client(app):
    return make_client(app)


def csrf_from(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    m = CSRF_RE.search(html)
    assert m, f"no CSRF token in {path}"
    return m.group(1)


def login(client, app, username, password=None, next_url=None):
    token = csrf_from(client)
    pw = password if password is not None else app.test_users[username]["password"]
    url = "/login" + (f"?next={next_url}" if next_url else "")
    return client.post(url, data={"username": username, "password": pw, "csrf_token": token})


@pytest.fixture
def as_user(app, client):
    """as_user('client.a') -> logged-in client."""
    def _login(username):
        resp = login(client, app, username)
        assert resp.status_code == 302, resp.status_code
        return client
    return _login
