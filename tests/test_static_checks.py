"""Source-level guard rails, run with pytest (no Semgrep needed locally).

They duplicate on purpose part of what Semgrep checks in CI: if one tool is broken or
skipped, the other still catches the regression (defence in depth for the pipeline).
"""
import ast
import pathlib
import re

import pytest

from portal import create_app
from portal.config import ConfigError, load_config

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP_FILES = sorted((ROOT / "portal").glob("*.py")) + [ROOT / "run.py"]
TEMPLATES = sorted((ROOT / "portal" / "templates").glob("*.html"))
PUBLIC_VIEWS = {"login"}  # views reachable without authentication, on purpose
AUTH_DECORATORS = {"login_required", "role_required"}


def _trees():
    for path in APP_FILES:
        yield path, ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _name(node):
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def test_every_sql_statement_is_a_constant_string():
    """execute()/executemany() must receive a literal: no f-string, +, % or .format()."""
    found = 0
    for path, tree in _trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _name(node) in ("execute", "executemany"):
                found += 1
                first = node.args[0]
                assert isinstance(first, ast.Constant) and isinstance(first.value, str), (
                    f"{path.name}:{node.lineno}: SQL built dynamically")
    assert found >= 8  # sanity: the scan really looked at the queries


def test_every_route_requires_authentication_unless_whitelisted():
    checked = 0
    for path, tree in _trees():
        for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            decos = [_name(d) for d in fn.decorator_list]
            if "route" not in decos:
                continue
            checked += 1
            if fn.name in PUBLIC_VIEWS:
                continue
            assert AUTH_DECORATORS & set(decos), f"{path.name}: route {fn.name} has no auth decorator"
            # The auth decorator must sit BELOW @route, otherwise Flask registers the
            # unprotected function.
            assert decos.index("route") < max(decos.index(d) for d in AUTH_DECORATORS & set(decos))
    assert checked >= 7


@pytest.mark.parametrize("banned", ["render_template_string", "Markup(", "mark_safe", "eval(",
                                    "exec(", "pickle", "yaml.load(", "shell=True", "verify=False"])
def test_dangerous_apis_are_not_used(banned):
    for path in APP_FILES:
        assert banned not in path.read_text(encoding="utf-8"), f"{banned} in {path.name}"


def test_templates_never_disable_escaping():
    for tpl in TEMPLATES:
        text = tpl.read_text(encoding="utf-8")
        assert "|safe" not in text.replace(" ", ""), tpl.name
        assert "autoescape false" not in text.lower(), tpl.name
        assert "<script" not in text.lower(), f"inline script in {tpl.name} (CSP has no unsafe-inline)"
        assert "style=" not in text.lower(), f"inline style in {tpl.name}"


SECRET_PATTERNS = [
    re.compile(r"(SECRET_KEY|password|passwd|token|api_key)\s*[:=]\s*['\"][^'\"\s]{8,}['\"]", re.I),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]


def test_no_hardcoded_secrets_in_app_code():
    for path in APP_FILES:
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for pat in SECRET_PATTERNS:
                assert not pat.search(line), f"{path.name}:{i} looks like a hardcoded secret"


def test_debug_is_off():
    for path in APP_FILES:
        assert "debug=True" not in path.read_text(encoding="utf-8").replace(" ", "")


def test_server_binds_loopback_only():
    tree = ast.parse((ROOT / "run.py").read_text(encoding="utf-8"))
    hosts = [n.value.value for n in ast.walk(tree)
             if isinstance(n, ast.Assign) and any(_name(t) == "HOST" for t in n.targets)]
    assert hosts == ["127.0.0.1"]


def test_app_refuses_to_start_without_secret(monkeypatch):
    monkeypatch.delenv("PORTAL_SECRET_KEY", raising=False)
    with pytest.raises(ConfigError):
        load_config()


def test_app_refuses_short_secret(monkeypatch):
    monkeypatch.setenv("PORTAL_SECRET_KEY", "too-short")
    with pytest.raises(ConfigError):
        create_app()


def test_production_flags(app):
    assert app.config["DEBUG"] is False
    assert app.jinja_env.autoescape is True
    assert app.config["SESSION_COOKIE_SECURE"] is True
