"""AgriSouss order portal — a small, secure-by-default Flask lab app.

Lab only: synthetic data, run on 127.0.0.1 or inside CI. Never deployed.
"""
import logging

from flask import Flask, render_template

from . import auth, db, orders
from .config import load_config
from .security import LoginThrottle, csrf_protect, get_csrf_token, set_security_headers


def create_app(overrides=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.update(load_config(overrides))
    # Jinja autoescaping is on by default for .html templates; we never disable it and
    # never use the "safe" filter or Markup on user data (Semgrep + Bandit B701/B704 watch this).
    app.jinja_env.autoescape = True
    app.logger.setLevel(logging.INFO)

    app.extensions["login_throttle"] = LoginThrottle(
        app.config["LOGIN_MAX_FAILURES"], app.config["LOGIN_WINDOW_SECONDS"]
    )

    app.before_request(csrf_protect)
    app.before_request(auth.load_logged_in_user)
    app.after_request(set_security_headers)
    app.teardown_appcontext(db.close_db)
    app.jinja_env.globals["csrf_token"] = get_csrf_token

    app.register_blueprint(auth.bp)
    app.register_blueprint(orders.bp)

    # Generic error pages: no stack trace, no framework version (ASVS V7.4.1).
    for code in (400, 403, 404, 405, 413, 429, 500):
        app.register_error_handler(code, _error_handler(code))

    with app.app_context():
        db.init_db()
    return app


def _error_handler(code):
    def handler(_err):
        return render_template("error.html", code=code), code
    return handler
