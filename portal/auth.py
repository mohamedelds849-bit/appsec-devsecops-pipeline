"""Authentication: password hashing, login with throttling, session handling, decorators."""
import functools
import re
import secrets

from flask import (Blueprint, abort, current_app, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from . import db
from .security import safe_next_url

bp = Blueprint("auth", __name__)

USERNAME_RE = re.compile(r"^[a-z0-9_.-]{3,32}$")
MAX_PASSWORD_LEN = 128   # long enough for passphrases, bounded to limit hashing cost
MIN_PASSWORD_LEN = 12    # ASVS V2.1.1
# Hash of a random value, used when the user does not exist so that a wrong username
# costs the same time as a wrong password (no user enumeration by timing, CWE-204).
_DUMMY_HASH = None


def hash_password(password):
    """scrypt (Werkzeug 3 default): salted, memory-hard (ASVS V2.4, CWE-916)."""
    if not (MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN):
        raise ValueError(f"password length must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN}")
    return generate_password_hash(password, method="scrypt")


def _dummy_hash():
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = generate_password_hash(secrets.token_urlsafe(16), method="scrypt")
    return _DUMMY_HASH


def login_required(view):
    """Deny by default: every route that shows data must carry this decorator.
    The custom Semgrep rule rules/flask-route-missing-auth.yaml enforces it."""
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if g.get("user") is None:
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def role_required(role):
    def decorator(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            if g.get("user") is None:
                return redirect(url_for("auth.login", next=request.path))
            if g.user["role"] != role:
                current_app.logger.warning("authz_denied user=%s path=%s", g.user["id"], request.path)
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def load_logged_in_user():
    """before_request hook: g.user is the current user row or None."""
    user_id = session.get("user_id")
    g.user = db.find_user_by_id(user_id) if user_id is not None else None


@bp.route("/login", methods=["GET", "POST"])
def login():  # public by design: the login page itself
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        throttle = current_app.extensions["login_throttle"]
        keys = ("ip:" + (request.remote_addr or "?"), "user:" + username)
        if throttle.is_blocked(*keys):
            current_app.logger.warning("login_throttled ip=%s", request.remote_addr)
            return render_template("login.html", error="Too many attempts. Try again later."), 429

        user = None
        if USERNAME_RE.match(username) and len(password) <= MAX_PASSWORD_LEN:
            user = db.find_user_by_username(username)
        stored = user["password_hash"] if user else _dummy_hash()
        password_ok = check_password_hash(stored, password[:MAX_PASSWORD_LEN])
        if user and password_ok:
            throttle.reset(*keys)
            session.clear()              # new session on login: no session fixation (CWE-384)
            session.permanent = True     # PERMANENT_SESSION_LIFETIME = idle timeout
            session["user_id"] = user["id"]
            current_app.logger.info("login_ok user=%s", user["id"])
            return redirect(safe_next_url(request.args.get("next")))
        throttle.record_failure(*keys)
        # Never log the password, and the same message for "no such user" and "bad password".
        current_app.logger.warning("login_failed ip=%s", request.remote_addr)
        error = "Invalid username or password."
    return render_template("login.html", error=error)


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
