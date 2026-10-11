"""A01 Broken Access Control: object-level and function-level authorization.

SAST tools cannot know that order 2 belongs to client.b: only these tests can prove it.
"""
import pytest

from tests.conftest import csrf_from


def test_anonymous_is_redirected_to_login(client):
    for path in ("/", "/orders", "/orders/1", "/orders/export.csv"):
        resp = client.get(path)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


def test_customer_list_shows_only_own_orders(app, as_user):
    c = as_user("client.a")
    html = c.get("/orders").get_data(as_text=True)
    assert "Argan oil" in html
    assert "Amlou" not in html


def test_customer_can_open_own_order(app, as_user):
    c = as_user("client.a")
    assert c.get(f"/orders/{app.test_users['client.a']['order']}").status_code == 200


def test_customer_gets_404_on_other_customers_order(app, as_user):
    """IDOR check: same answer as a non-existent id, so ids cannot be enumerated."""
    c = as_user("client.a")
    other = app.test_users["client.b"]["order"]
    assert c.get(f"/orders/{other}").status_code == 404
    assert c.get("/orders/999999").status_code == 404


def test_customer_cannot_write_note_on_other_customers_order(app, as_user):
    c = as_user("client.a")
    other = app.test_users["client.b"]["order"]
    token = csrf_from(c, "/orders")
    resp = c.post(f"/orders/{other}/note", data={"note": "hijack", "csrf_token": token})
    assert resp.status_code == 404
    c.post("/logout", data={"csrf_token": token})
    b = as_user("client.b")
    assert "hijack" not in b.get(f"/orders/{other}").get_data(as_text=True)


def test_customer_cannot_change_status(app, as_user):
    """Function-level authz: status change is staff-only (403)."""
    c = as_user("client.a")
    own = app.test_users["client.a"]["order"]
    token = csrf_from(c, "/orders")
    resp = c.post(f"/orders/{own}/status", data={"status": "delivered", "csrf_token": token})
    assert resp.status_code == 403


def test_staff_sees_all_orders_and_can_change_status(app, as_user):
    c = as_user("staff.agadir")
    html = c.get("/orders").get_data(as_text=True)
    assert "Argan oil" in html and "Amlou" in html
    order = app.test_users["client.b"]["order"]
    token = csrf_from(c, "/orders")
    resp = c.post(f"/orders/{order}/status", data={"status": "shipped", "csrf_token": token})
    assert resp.status_code == 302
    assert "shipped" in c.get(f"/orders/{order}").get_data(as_text=True)


def test_staff_cannot_write_customer_note(app, as_user):
    c = as_user("staff.agadir")
    order = app.test_users["client.a"]["order"]
    token = csrf_from(c, "/orders")
    assert c.post(f"/orders/{order}/note", data={"note": "x", "csrf_token": token}).status_code == 403


@pytest.mark.parametrize("user,visible,hidden", [
    ("client.a", "Argan oil", "Amlou"),
    ("client.b", "Amlou", "Argan oil"),
])
def test_csv_export_is_scoped_to_the_user(as_user, user, visible, hidden):
    body = as_user(user).get("/orders/export.csv").get_data(as_text=True)
    assert visible in body and hidden not in body


def test_logout_requires_post_and_ends_session(app, as_user):
    c = as_user("client.a")
    assert c.get("/logout").status_code == 405
    token = csrf_from(c, "/orders")
    assert c.post("/logout", data={"csrf_token": token}).status_code == 302
    assert c.get("/orders").status_code == 302
