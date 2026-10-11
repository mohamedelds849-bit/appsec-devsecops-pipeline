"""A01/CWE-352: every state-changing request needs the session's CSRF token."""
from tests.conftest import csrf_from, make_client


def test_login_post_without_token_is_rejected(app, client):
    client.get("/login")
    pw = app.test_users["client.a"]["password"]
    resp = client.post("/login", data={"username": "client.a", "password": pw})
    assert resp.status_code == 400


def test_login_post_with_wrong_token_is_rejected(app, client):
    client.get("/login")
    pw = app.test_users["client.a"]["password"]
    resp = client.post("/login", data={"username": "client.a", "password": pw, "csrf_token": "forged"})
    assert resp.status_code == 400


def test_note_post_without_token_is_rejected(app, as_user):
    c = as_user("client.a")
    own = app.test_users["client.a"]["order"]
    assert c.post(f"/orders/{own}/note", data={"note": "x"}).status_code == 400


def test_note_post_with_token_is_accepted(app, as_user):
    c = as_user("client.a")
    own = app.test_users["client.a"]["order"]
    token = csrf_from(c, f"/orders/{own}")
    assert c.post(f"/orders/{own}/note", data={"note": "Leave at gate", "csrf_token": token}).status_code == 302


def test_token_from_another_session_is_rejected(app):
    attacker = make_client(app)
    victim = make_client(app)
    stolen = csrf_from(attacker)
    victim.get("/login")
    pw = app.test_users["client.a"]["password"]
    resp = victim.post("/login", data={"username": "client.a", "password": pw, "csrf_token": stolen})
    assert resp.status_code == 400


def test_every_form_in_templates_carries_the_token():
    import pathlib
    import re
    tpl = pathlib.Path(__file__).resolve().parents[1] / "portal" / "templates"
    for f in tpl.glob("*.html"):
        text = f.read_text(encoding="utf-8")
        forms = re.findall(r"<form[^>]*method=\"post\"[^>]*>(.*?)</form>", text, re.S | re.I)
        for body in forms:
            assert 'name="csrf_token"' in body, f"form without CSRF token in {f.name}"
