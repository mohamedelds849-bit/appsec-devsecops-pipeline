"""A07 Identification and Authentication Failures: hashing, generic errors, throttling,
open redirect."""
import pytest

from portal import db
from portal.auth import hash_password
from portal.security import LoginThrottle, safe_next_url
from tests.conftest import login, make_client

WRONG = "wrong-password-123"


def test_passwords_are_stored_as_scrypt_hashes(app):
    with app.app_context():
        row = db.find_user_by_username("client.a")
    assert row["password_hash"].startswith("scrypt:")
    assert app.test_users["client.a"]["password"] not in row["password_hash"]


def test_too_short_password_is_refused_at_creation():
    with pytest.raises(ValueError):
        hash_password("short")


def test_wrong_password_and_unknown_user_give_same_message(app, client):
    r1 = login(client, app, "client.a", password=WRONG)
    r2 = login(client, app, "nobody.here", password=WRONG)
    assert r1.status_code == r2.status_code == 200
    msg = "Invalid username or password."
    assert msg in r1.get_data(as_text=True) and msg in r2.get_data(as_text=True)


def test_login_is_throttled_after_five_failures(app, client):
    for _ in range(app.config["LOGIN_MAX_FAILURES"]):
        assert login(client, app, "client.a", password=WRONG).status_code == 200
    assert login(client, app, "client.a", password=WRONG).status_code == 429
    # Even the right password is refused while blocked (otherwise brute force continues).
    assert login(client, app, "client.a").status_code == 429


def test_throttle_is_per_username_too(app):
    """Failures on one account from many IPs are still blocked ('user:<name>' key)."""
    for i in range(app.config["LOGIN_MAX_FAILURES"]):
        login(make_client(app, ip=f"192.0.2.{i + 1}"), app, "client.b", password=WRONG)
    assert login(make_client(app, ip="198.51.100.7"), app, "client.b").status_code == 429
    # Another account from a fresh IP is not affected.
    assert login(make_client(app, ip="198.51.100.8"), app, "client.a").status_code == 302


def test_throttle_window_expires():
    now = [1000.0]
    t = LoginThrottle(max_failures=2, window_seconds=60, clock=lambda: now[0])
    t.record_failure("ip:x")
    t.record_failure("ip:x")
    assert t.is_blocked("ip:x")
    now[0] += 61
    assert not t.is_blocked("ip:x")


def test_successful_login_resets_counter(app, client):
    for _ in range(app.config["LOGIN_MAX_FAILURES"] - 1):
        login(client, app, "client.a", password=WRONG)
    assert login(client, app, "client.a").status_code == 302


@pytest.mark.parametrize("target,expected", [
    ("/orders/1", "/orders/1"),
    (None, "/orders"),
    ("https://evil.example/", "/orders"),
    ("//evil.example/", "/orders"),
    ("/\\evil.example", "/orders"),
    ("javascript:alert(1)", "/orders"),
    ("orders", "/orders"),
])
def test_safe_next_url(target, expected):
    assert safe_next_url(target) == expected


def test_login_does_not_redirect_offsite(app, client):
    resp = login(client, app, "client.a", next_url="https://evil.example/")
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/orders")
