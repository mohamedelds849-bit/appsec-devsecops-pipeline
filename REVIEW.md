# Self-review — AppSec DevSecOps Pipeline

Reviewer: the author, with an AI coding assistant, 2026-10-11. This is a self-review, not
an independent audit.

## Verdict

The application and its tests are solid **for a lab**: every control listed in
`docs/CONTROLS.md` has at least one test, and the mutation check shows the tests fail when a
control is removed (16/16). The pipeline is written with good supply-chain hygiene, but **it
has not run on GitHub yet**: until the first green run, the CI-only parts (Docker build,
Trivy, ZAP, SARIF upload) are unverified and must not be claimed as working.

## 1. How it was verified (locally, Windows 11, Python 3.11.9)

| What | Result |
|---|---|
| `python -m pytest -q` | 78 passed |
| `python scripts/mutation_check.py` | 16/16 mutants killed |
| `semgrep --test rules/` (Semgrep 1.180.0, installed with pip on Windows) | 7/7 rules, 22 `ruleid` + 17 `ok` cases |
| `semgrep scan` with `rules/` + `p/owasp-top-ten` + `p/python` | 194 rules, 0 findings after fixing 3 MEDIUM findings (Dependabot without cooldown) |
| `bandit -r portal run.py` (1.9.4) | 0 issues, 0 `# nosec` |
| `pip-audit -r requirements.txt` (2.10.1) | 1 real advisory on Werkzeug 3.1.8 → fixed by 3.1.9 → 0 |
| `gitleaks git` + `gitleaks dir` (8.30.1) | no leaks |
| `python run.py` + curl | headers and cookie flags as expected on the real Waitress server |
| Docker build, Trivy, ZAP | **not run** (no Docker on this PC) |

Pins were resolved on 2026-10-11: action commit SHAs with `git ls-remote`, image digests from
Docker Hub / GHCR, the Gitleaks SHA-256 from the release checksums file.

## 2. Problems found during the build (and fixed)

1. **Werkzeug CVE (real).** pip-audit flagged CVE-2026-102598 / GHSA-g6x2-hccm-hh4m in the
   first pinned version. Relevant because `/static` uses `send_from_directory` and the app
   runs on Windows locally. Bumped in a separate commit.
2. **Dependabot cooldown.** The Semgrep registry flagged 3 MEDIUM findings: no `cooldown` on
   Dependabot updates. Added a 7-day cooldown.
3. **SQL f-strings.** A first version of `db.py` built the column list with an f-string (a
   constant, not user input). It was safe, but every SAST tool would flag it and it would
   need suppressions. Rewritten as literal strings: zero suppressions in the code.
4. **`Via: waitress` header.** Seen in the live curl, not in the Flask test client (Waitress
   adds it). Fixed with `serve(..., ident="portal")`.
5. **Throttle test that proved nothing.** The first "per-username" test used the same IP for
   every attempt, so the per-IP key blocked it. Rewritten with distinct IPs, plus a check that
   another account is not affected.
6. **Logging control without a test.** Added `test_security_events_are_logged_without_the_password`.
7. **Semgrep on Windows** crashed with `UnicodeEncodeError` when its output was redirected;
   `PYTHONUTF8=1` fixes it (not an issue on the Linux CI runner).

## 3. Known limits (honest)

### Application
- Client-side signed sessions: logout cannot revoke a copied cookie before expiry (30 min).
- Login throttle in memory, per process; restart resets it. No global rate limit, no MFA.
- No TLS in the lab; HSTS only when `PORTAL_HSTS=1` behind a TLS proxy.
- CSV neutralisation follows OWASP advice; spreadsheet behaviour varies.
- Timing equalisation for unknown users (dummy hash) is implemented, not measured.
- SQLite, single process: fine for a lab, not for concurrency.

### Tests
- They prove the controls on the **current** routes. A new route without its own authz test
  would not be caught by pytest (the static check only verifies the decorator is present,
  not that the right ownership filter exists).
- The mutation check covers 16 hand-picked mutants, not automatic mutation of every line.
- `test_static_checks.py` uses AST/regex heuristics; it can be bypassed by unusual code
  (for example SQL built in a helper function and passed as a variable).

### Pipeline
- **Never executed on GitHub yet.** Possible first-run issues: ZAP container writing to the
  mounted folder (handled with `chmod`), Trivy DB download rate limits, a newly published
  HIGH CVE in the Debian base image (would make `container` red until the base is rebuilt —
  that is the gate working, not a bug).
- ZAP baseline is passive and unauthenticated: it sees `/login` and static files only.
- SARIF upload requires a public repo or GitHub Advanced Security; it is `continue-on-error`.
- pip-audit blocks on any advisory (stricter than high/critical) because PyPI advisories
  often have no CVSS score.
- The mutation check in CI re-runs the suite 16 times (several minutes).
- No SBOM artifact yet.

### Rules
- `flask-route-missing-auth` relies on decorator names (`login_required`, `role_required`)
  and an allow-list regex of public view names; a renamed decorator or a route registered
  with `add_url_rule` would not be seen.
- `sqlite-formatted-sql` follows a formatted string through one assignment in the same
  function, not across functions.
- `requests-verify-disabled` does not track `verify` passed through a variable.

## 4. Before claiming this project (to do by Mohamed)

1. Push the repo to GitHub (public, so code scanning works for free).
2. Watch the `security` workflow until **all six jobs are green**; if one is red, read the
   log, fix, and write what happened in this file (as in soc-detection-lab's CI history).
3. Open the Security tab → Code scanning and look at what each tool uploaded.
4. Download the `zap-report` artifact and read `zap.html`: be able to explain each WARN.
5. Break one control on purpose in a branch (for example remove `AND customer_id = ?`), push,
   and see the `tests` job fail. Then delete the branch. That is your interview story.
6. Read LEARN.md aloud, then answer the 21 questions without looking.

## 5. CI history

| Run | Date | Result | What happened |
|---|---|---|---|
| 1 (`38193848449`) | 2026-10-12 | 5/6 green, `container` red | The Trivy image gate failed on 2 HIGH CVEs with a fix available, both in packaging tools shipped by the `python:3.11-slim-trixie` base image, not in the app: `wheel` 0.45.1 (CVE-2026-24049) and `jaraco.context` 5.3.0 vendored inside setuptools (CVE-2026-23949). The gate did its job. Fix: `pip uninstall -y setuptools wheel` after installing the requirements, since the app never needs them at run time (smaller attack surface rather than a version bump). |
| 2 (`38194315086`) | 2026-10-12 | **6/6 green** | Same pipeline after the Dockerfile fix; the image gate now passes with no HIGH/CRITICAL fixable CVE. |
