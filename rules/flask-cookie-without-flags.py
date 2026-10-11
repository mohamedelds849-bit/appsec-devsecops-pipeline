# Semgrep test fixture (lint patterns only, not a runnable app).
from flask import Flask, make_response

app = Flask(__name__)
# ruleid: flask-cookie-without-flags
app.config["SESSION_COOKIE_SECURE"] = False
# ok: flask-cookie-without-flags
app.config["SESSION_COOKIE_SECURE"] = True


def view(value):
    resp = make_response("ok")
    # ruleid: flask-cookie-without-flags
    resp.set_cookie("pref", value)
    # ruleid: flask-cookie-without-flags
    resp.set_cookie("pref", value, secure=True)
    # ok: flask-cookie-without-flags
    resp.set_cookie("pref", value, secure=True, httponly=True, samesite="Lax")
    # ok: flask-cookie-without-flags
    resp.set_cookie("pref", value, samesite="Strict", httponly=True, secure=True)
    return resp
