"""A03 Injection (XSS, SQL, CSV formula) and server-side input validation."""
import csv
import io

import pytest

from portal import db
from portal.security import neutralize_csv_cell
from tests.conftest import csrf_from, login

XSS = '<script>alert(1)</script><img src=x onerror=alert(2)>'


def _post_note(c, order, note):
    token = csrf_from(c, f"/orders/{order}")
    return c.post(f"/orders/{order}/note", data={"note": note, "csrf_token": token})


def test_note_is_html_escaped(app, as_user):
    c = as_user("client.a")
    order = app.test_users["client.a"]["order"]
    assert _post_note(c, order, XSS).status_code == 302
    html = c.get(f"/orders/{order}").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img src=x" not in html


def test_product_name_from_db_is_escaped(app, as_user):
    with app.app_context():
        db.create_order(app.test_users["client.a"]["id"], XSS, 1, 10)
    html = as_user("client.a").get("/orders").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html


def test_sql_metacharacters_in_username_are_just_data(app, client):
    """With ? placeholders, a classic payload is only a username that does not exist."""
    resp = login(client, app, "' OR '1'='1' --", password="anything-long-enough")
    assert resp.status_code == 200
    assert "Invalid username or password." in resp.get_data(as_text=True)
    with app.app_context():
        assert db.find_user_by_username("x' OR '1'='1") is None


def test_note_with_quotes_is_stored_verbatim(app, as_user):
    c = as_user("client.a")
    order = app.test_users["client.a"]["order"]
    note = "Robert'); DROP TABLE orders;--"
    _post_note(c, order, note)
    with app.app_context():
        row = db.get_order_for({"id": app.test_users["client.a"]["id"], "role": "customer"}, order)
    assert row["note"] == note  # stored as data; the table is still there


@pytest.mark.parametrize("value,expected", [
    ('=HYPERLINK("http://x")', '\'=HYPERLINK("http://x")'),
    ("+1", "'+1"), ("-1", "'-1"), ("@SUM(A1)", "'@SUM(A1)"),
    ("Argan oil", "Argan oil"), (42, "42"), (None, ""),
])
def test_csv_cells_are_neutralized(value, expected):
    assert neutralize_csv_cell(value) == expected


def test_csv_export_neutralizes_formula_in_note(app, as_user):
    c = as_user("client.a")
    order = app.test_users["client.a"]["order"]
    _post_note(c, order, "=1+2")
    rows = list(csv.reader(io.StringIO(c.get("/orders/export.csv").get_data(as_text=True))))
    assert rows[1][-1] == "'=1+2"


def test_note_too_long_is_rejected(app, as_user):
    c = as_user("client.a")
    order = app.test_users["client.a"]["order"]
    assert _post_note(c, order, "a" * 501).status_code == 400


def test_status_outside_allow_list_is_rejected(app, as_user):
    c = as_user("staff.agadir")
    order = app.test_users["client.a"]["order"]
    token = csrf_from(c, "/orders")
    resp = c.post(f"/orders/{order}/status", data={"status": "refunded", "csrf_token": token})
    assert resp.status_code == 400
    with app.app_context(), pytest.raises(ValueError):
        db.update_status(order, "refunded")


def test_non_integer_order_id_is_404(as_user):
    assert as_user("client.a").get("/orders/1%20OR%201=1").status_code == 404


def test_oversized_body_is_rejected(client):
    client.get("/login")
    resp = client.post("/login", data={"username": "a" * 20000, "password": "x"})
    assert resp.status_code == 413


def test_overlong_password_is_rejected(app, client):
    resp = login(client, app, "client.a", password="p" * 5000)
    assert resp.status_code == 200
    assert "Invalid username or password." in resp.get_data(as_text=True)
