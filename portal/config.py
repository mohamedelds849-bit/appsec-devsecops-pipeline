"""Configuration: every secret comes from the environment, never from the code.

ASVS V14.1 / CWE-798: the code must not contain credentials. If PORTAL_SECRET_KEY is
missing or too short, the app refuses to start instead of falling back to a default.
"""
import os
from datetime import timedelta

MIN_SECRET_LEN = 32


class ConfigError(RuntimeError):
    """Raised when the environment does not provide a safe configuration."""


def load_config(overrides=None):
    """Build the Flask config dict from environment variables (+ optional test overrides)."""
    overrides = overrides or {}
    secret = overrides.get("SECRET_KEY") or os.environ.get("PORTAL_SECRET_KEY", "")
    if len(secret) < MIN_SECRET_LEN:
        raise ConfigError(
            "PORTAL_SECRET_KEY must be set to a random value of at least "
            f"{MIN_SECRET_LEN} characters (python -c \"import secrets; print(secrets.token_hex(32))\")"
        )
    cfg = {
        "SECRET_KEY": secret,
        "DATABASE": os.environ.get("PORTAL_DB", os.path.join("instance", "portal.db")),
        # Session cookie hardening (ASVS V3.4). The __Host- prefix forces Secure, Path=/
        # and no Domain attribute in the browser.
        "SESSION_COOKIE_NAME": "__Host-session",
        "SESSION_COOKIE_SECURE": True,
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Lax",
        "PERMANENT_SESSION_LIFETIME": timedelta(minutes=30),
        # HSTS is only meaningful behind HTTPS: enable it when a TLS reverse proxy exists.
        "HSTS_ENABLED": os.environ.get("PORTAL_HSTS", "0") == "1",
        # Login throttling (ASVS V2.2.1): max failures per window, per IP and per username.
        "LOGIN_MAX_FAILURES": 5,
        "LOGIN_WINDOW_SECONDS": 15 * 60,
        "MAX_CONTENT_LENGTH": 16 * 1024,
        "DEBUG": False,
        "TESTING": False,
    }
    cfg.update(overrides)
    return cfg
