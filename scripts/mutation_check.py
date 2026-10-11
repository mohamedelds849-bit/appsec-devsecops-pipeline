"""Mutation check: do the defense tests really catch a regression?

Each mutant removes or weakens ONE security control in a temporary copy of the repo,
then runs pytest. A mutant is "killed" when at least one test fails. A surviving
mutant means a control has no test that proves it.

    python scripts/mutation_check.py
"""
import pathlib
import shutil
import subprocess
import sys
import tempfile

SRC = pathlib.Path(__file__).resolve().parents[1]

# (name, file, original code, weakened code)
MUTANTS = [
    ("IDOR: drop owner filter", "portal/db.py",
     'FROM orders WHERE id = ? AND customer_id = ?",\n        (order_id, user["id"]),',
     'FROM orders WHERE id = ?",\n        (order_id,),'),
    ("list not scoped to the customer", "portal/db.py",
     'if user["role"] == "staff":\n        return db.execute(\n            "SELECT id, customer_id, product, quantity_kg, total_mad, status, note "\n            "FROM orders ORDER BY id"',
     'if True:\n        return db.execute(\n            "SELECT id, customer_id, product, quantity_kg, total_mad, status, note "\n            "FROM orders ORDER BY id"'),
    ("CSRF check disabled", "portal/security.py",
     "    if request.method in SAFE_METHODS:\n        return", "    return"),
    ("CSP header removed", "portal/security.py", '    h["Content-Security-Policy"] = CSP\n', ""),
    ("session cookie not Secure", "portal/config.py",
     '"SESSION_COOKIE_SECURE": True', '"SESSION_COOKIE_SECURE": False'),
    ("no session renewal at login", "portal/auth.py",
     "            session.clear()              #", "            pass  #"),
    ("login throttling off", "portal/security.py",
     "            return any(len(self._prune(k, now)) >= self.max_failures for k in keys)",
     "            return False"),
    ("CSV formula not neutralized", "portal/security.py", "        return \"'\" + text", "        return text"),
    ("note length not checked", "portal/orders.py", "    if len(note) > MAX_NOTE_LEN:", "    if False:"),
    ("status allow-list removed", "portal/orders.py",
     "    if status not in db.ALLOWED_STATUSES:  # allow-list, not a deny-list\n        abort(400)", "    pass"),
    ("customer can change status", "portal/orders.py", '@role_required("staff")', "@login_required"),
    ("open redirect via backslash", "portal/security.py", '    if "\\\\" in target:', "    if False:"),
    ("Jinja autoescape off", "portal/__init__.py",
     "app.jinja_env.autoescape = True", "app.jinja_env.autoescape = False"),
    ("SQL built with an f-string", "portal/db.py",
     '"SELECT id, username, role FROM users WHERE id = ?", (user_id,)',
     'f"SELECT id, username, role FROM users WHERE id = {int(user_id)}"'),
    ("route without auth decorator", "portal/orders.py",
     '@bp.route("/orders/export.csv")\n@login_required', '@bp.route("/orders/export.csv")'),
    ("server binds all interfaces", "run.py", 'HOST = "127.0.0.1"', 'HOST = "0.0.0.0"'),
]


def main():
    killed = 0
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="mutation-"))
    work = tmp / "repo"
    for name, rel, old, new in MUTANTS:
        if work.exists():
            shutil.rmtree(work)
        shutil.copytree(SRC, work, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", "instance"))
        path = work / rel
        text = path.read_text(encoding="utf-8")
        assert old in text, f"mutant '{name}': original code not found (code changed?)"
        path.write_text(text.replace(old, new, 1), encoding="utf-8")
        result = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider"],
                                cwd=work, capture_output=True, text=True)
        dead = result.returncode != 0
        killed += dead
        print("KILLED  " if dead else "SURVIVED", name)
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"{killed}/{len(MUTANTS)} mutants killed")
    return 0 if killed == len(MUTANTS) else 1


if __name__ == "__main__":
    sys.exit(main())
