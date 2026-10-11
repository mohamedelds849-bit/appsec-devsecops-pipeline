"""Cross-cutting security controls: CSRF, HTTP headers, login throttling, safe redirects,
CSV formula neutralisation. Each control is tested in tests/ and mapped in docs/CONTROLS.md.
"""
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque
from urllib.parse import urlsplit

from flask import abort, current_app, request, session

# --------------------------------------------------------------------------- CSRF
# Synchronizer token pattern (OWASP CSRF cheat sheet, ASVS V4.2.2, CWE-352):
# a random token lives in the server-signed session and must come back in every
# state-changing request. SameSite=Lax on the cookie is a second layer, not the only one.

CSRF_FIELD = "csrf_token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def get_csrf_token():
    token = session.get(CSRF_FIELD)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_FIELD] = token
    return token


def csrf_protect():
    """before_request hook: reject any unsafe method without a valid token (HTTP 400)."""
    if request.method in SAFE_METHODS:
        return
    expected = session.get(CSRF_FIELD)
    sent = request.form.get(CSRF_FIELD, "")
    # compare_digest: constant-time comparison, no timing side channel on the token.
    if not expected or not hmac.compare_digest(expected, sent):
        current_app.logger.warning("csrf_rejected path=%s ip=%s", request.path, request.remote_addr)
        abort(400)


# ----------------------------------------------------------------- security headers
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


def set_security_headers(response):
    """after_request hook (ASVS V14.4, OWASP Secure Headers project)."""
    h = response.headers
    h["Content-Security-Policy"] = CSP
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"  # legacy browsers; CSP frame-ancestors is the modern control
    h["Referrer-Policy"] = "no-referrer"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    h["Cross-Origin-Resource-Policy"] = "same-origin"
    h["Server"] = "portal"  # do not advertise the WSGI server and its version
    if current_app.config.get("HSTS_ENABLED"):
        h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if not request.path.startswith("/static/"):
        # Order data is personal data (law 09-08): never let a shared cache keep it.
        h["Cache-Control"] = "no-store"
    return response


# ------------------------------------------------------------------ login throttling
class LoginThrottle:
    """Sliding-window counter of failed logins, keyed by IP and by username.

    In-memory and per-process: enough for this single-process lab, NOT for a multi-worker
    deployment (there you would use Redis or the reverse proxy). Documented in REVIEW.md.
    """

    def __init__(self, max_failures, window_seconds, clock=time.monotonic):
        self.max_failures = max_failures
        self.window = window_seconds
        self.clock = clock
        self._fails = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key, now):
        q = self._fails[key]
        while q and now - q[0] > self.window:
            q.popleft()
        return q

    def is_blocked(self, *keys):
        now = self.clock()
        with self._lock:
            return any(len(self._prune(k, now)) >= self.max_failures for k in keys)

    def record_failure(self, *keys):
        now = self.clock()
        with self._lock:
            for k in keys:
                self._prune(k, now).append(now)

    def reset(self, *keys):
        with self._lock:
            for k in keys:
                self._fails.pop(k, None)


# --------------------------------------------------------------------- redirects
def safe_next_url(target, default="/orders"):
    """Only allow a local path as post-login redirect (CWE-601 open redirect)."""
    if not target:
        return default
    parts = urlsplit(target)
    if parts.scheme or parts.netloc or not target.startswith("/") or target.startswith("//"):
        return default
    if "\\" in target:  # some browsers treat /\evil.com as //evil.com
        return default
    return target


# ------------------------------------------------------------------- CSV export
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def neutralize_csv_cell(value):
    """Prefix cells that a spreadsheet would run as a formula (CWE-1236, CSV injection)."""
    text = "" if value is None else str(value)
    if text.startswith(FORMULA_PREFIXES):
        return "'" + text
    return text
