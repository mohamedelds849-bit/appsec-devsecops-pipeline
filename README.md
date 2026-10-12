# AppSec DevSecOps Pipeline — secure-by-default portal + security CI

A **defensive** application-security portfolio project: a small Flask order portal for a
fictitious Moroccan SME (AgriSouss SARL), **built secure by default**, with tests that prove
each security control holds, and a **GitHub Actions pipeline** that runs real open-source
security tools (Semgrep, Bandit, Gitleaks, pip-audit, Trivy, OWASP ZAP) and fails the build
on high/critical findings.

> **Lab only.** Synthetic data, never deployed, never exposed: the app listens on
> `127.0.0.1` (your PC) or inside the CI runner. There is **no deliberately vulnerable code
> and no exploit** in this repo. The only "insecure" code is in `rules/*.py`: minimal
> lint fixtures that the custom Semgrep rules must flag (they are not an application and
> are excluded from scans).

**Author:** Mohamed Elansari — cybersecurity engineering student
**Status (2026-10-11):** app, 78 tests, 7 tested Semgrep rules and the pipeline are built.
Everything except Docker, Trivy and ZAP was run locally (see the table below).
**The GitHub Actions run has not happened yet**: the CI-only parts (Trivy, ZAP, SARIF upload)
are unverified until the repo is pushed and the workflow is green.

---

## What is in it

```
portal/                 Flask app (blueprints auth + orders, SQLite, Jinja templates)
  security.py           CSRF, security headers, login throttle, safe redirect, CSV neutralisation
  auth.py / orders.py   login, decorators, object-level authorization
  db.py                 parameterized SQL only, authorization inside the query
tests/                  78 pytest defense tests (authz, CSRF, headers, cookies, login, injection, static checks)
rules/                  7 custom Semgrep rules + their ruleid/ok fixtures (semgrep --test)
scripts/semgrep_gate.py quality gate on Semgrep JSON (fail on ERROR/HIGH/CRITICAL)
scripts/mutation_check.py removes each control in a temp copy -> a test must fail (16/16)
.github/workflows/security.yml  the pipeline (6 jobs)
.zap/rules.tsv          ZAP baseline rules promoted to FAIL
Dockerfile              non-root image used by Trivy and ZAP in CI
docs/THREAT-MODEL.md    STRIDE + data flow diagram
docs/CONTROLS.md        control -> OWASP Top 10 / ASVS 4.0.3 / CWE -> test -> tool, and honest gaps
LEARN.md                (FR) how each tool works, SAST vs DAST vs SCA, interview Q&A, CV line
REVIEW.md               self-review and known limits
```

## Security controls (summary)

| Area | Control | Proof |
|---|---|---|
| Access control (A01) | Every route `@login_required` / `@role_required`; order lookups scoped by `customer_id = ?` in SQL; 404 for "not yours"; CSRF token on every POST | `tests/test_authz.py`, `tests/test_csrf.py` |
| Injection (A03) | `?` placeholders only; Jinja autoescape; strict CSP without `unsafe-inline`; CSV formula neutralisation; allow-list validation | `tests/test_injection_validation.py`, `tests/test_static_checks.py` |
| Authentication (A07) | scrypt hashes; 12-128 chars; throttling per IP **and** per username (429); same message for unknown user / wrong password; new session at login | `tests/test_login.py`, `tests/test_headers_session.py` |
| Misconfiguration (A05) | `__Host-` cookie Secure/HttpOnly/SameSite; CSP, frame-ancestors, nosniff, Referrer/Permissions-Policy; HSTS behind TLS; no debug; no version in headers; `127.0.0.1` only; non-root image | `tests/test_headers_session.py`, `tests/test_static_checks.py` |
| Secrets | Only from `PORTAL_SECRET_KEY` (refuses to start without it); demo passwords random, printed once | `tests/test_static_checks.py`, Gitleaks |
| Supply chain (A06/A08) | Pinned deps + pip-audit; Trivy fs/image; actions pinned by SHA, images by digest; Dependabot with cooldown | CI jobs `sca`, `container` |

Full mapping with ASVS ids, CWE and gaps: [docs/CONTROLS.md](docs/CONTROLS.md).

## The pipeline

| Job | Tool (version) | Type | Fails the build when |
|---|---|---|---|
| `tests` | pytest + `scripts/mutation_check.py` | unit / defense tests | any test fails, or a mutant survives |
| `sast` | Semgrep 1.180.0 (`rules/` + `p/owasp-top-ten` + `p/python`) | SAST | a custom rule fixture breaks (`semgrep --test`), or a finding is ERROR/HIGH/CRITICAL |
| `sast` | Bandit 1.9.4 | SAST (Python AST) | a HIGH severity issue with MEDIUM+ confidence |
| `secrets` | Gitleaks 8.30.1 (checksum verified) | secret scanning, full git history | any finding |
| `sca` | pip-audit 2.10.1 | SCA (Python deps) | any known advisory (stricter than high/critical: PyPI advisories often have no score) |
| `container` | Trivy 0.75.0 (official image, by digest) | SCA + misconfig + secrets, repo and image | HIGH/CRITICAL with a fix available |
| `dast` | OWASP ZAP 2.17.0 baseline (by digest) | DAST (passive) | a rule set to FAIL in `.zap/rules.tsv` |

SARIF from Semgrep, Bandit, Gitleaks and Trivy is uploaded to GitHub code scanning
(`continue-on-error`: code scanning needs a public repo or GitHub Advanced Security).
Reports are also kept as workflow artifacts. A weekly scheduled run catches new CVEs in
unchanged code.

**Why Trivy is run from its Docker image and not `aquasecurity/trivy-action`:** in March 2026
the Trivy release process was compromised (CVE-2026-33634): malicious Trivy 0.69.4 binaries
and images, and hijacked `trivy-action` / `setup-trivy` tags. A security tool is also supply
chain. Here every third-party piece is pinned (SHA, digest, checksum) and updated by
Dependabot with a 7-day cooldown.

## Local results (2026-10-11, Windows 11, Python 3.11.9)

| Check | Command | Result |
|---|---|---|
| Defense tests | `python -m pytest -q` | **78 passed** |
| Mutation check | `python scripts/mutation_check.py` | **16/16 mutants killed** |
| Custom rules | `semgrep --test rules/` | **7/7 rules pass** (22 `ruleid` + 17 `ok` cases) |
| Semgrep scan | `semgrep scan --metrics=off --config rules/ --config p/owasp-top-ten --config p/python` | **194 rules, 0 findings** (after fixing the 3 MEDIUM Dependabot-cooldown findings it raised) |
| Bandit | `bandit -r portal run.py` | **0 issues** at all severities, 440 lines, 0 `# nosec` |
| pip-audit | `pip-audit -r requirements.txt` | first run: **1 real advisory** (Werkzeug 3.1.8, CVE-2026-102598) → bumped to 3.1.9 → **0** |
| Gitleaks | `gitleaks git --redact .` and `gitleaks dir .` | **no leaks** |
| Live headers | `python run.py` + `curl -D -` | all headers present, `Server: portal`, cookie `__Host-session; Secure; HttpOnly; SameSite=Lax` |
| Docker, Trivy, ZAP | — | **CI-only, not run locally** (Docker not installed) |

## Run it yourself (Windows)

```powershell
cd C:\Users\VIET\cyber-portfolio\appsec-devsecops-pipeline
pip install -r requirements-dev.txt
python -m pytest -q
python scripts/mutation_check.py          # ~10 min: 16 runs of the test suite

$env:PORTAL_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
python -m portal.seed                     # creates demo users, prints random passwords ONCE
python run.py                             # http://127.0.0.1:8080
```

Browsers accept `Secure` cookies on `http://127.0.0.1` / `localhost`, so login works without
TLS in the lab. A real deployment would put a TLS reverse proxy in front and set
`PORTAL_HSTS=1`.

Security tools locally:

```powershell
semgrep --test rules/
$env:PYTHONUTF8 = "1"; semgrep scan --metrics=off --config rules/ --config p/owasp-top-ten --config p/python --json-output=semgrep.json
python scripts/semgrep_gate.py semgrep.json
bandit -r portal run.py
pip-audit -r requirements.txt
C:\Users\VIET\tools\gitleaks\gitleaks.exe git --redact .
```

## Limits (short version — details in REVIEW.md and docs/CONTROLS.md §3)

- Lab app: no TLS, single process, in-memory login throttle, client-side signed sessions
  (a copied cookie stays valid until expiry).
- ZAP baseline is passive and **unauthenticated**: it only sees the login page.
- SAST/SCA only know known patterns and published CVEs; **business-logic** authorization is
  covered by hand-written tests, not by any scanner.
- First CI run (2026-10-12) was red: the Trivy image gate blocked 2 HIGH
  CVEs in base-image packaging tools; fixed by removing them (REVIEW.md §5). Run 2 is 6/6 green.

## License

MIT — see [LICENSE](LICENSE).
