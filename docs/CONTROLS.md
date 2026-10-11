# Controls matrix — what protects the portal, what proves it, what watches it

Each control is mapped to **OWASP Top 10 2021**, **OWASP ASVS 4.0.3** requirement ids and
**CWE**, then to the **test** that proves it holds today and the **pipeline tool** that would
notice if it regressed. Threat ids (T1...) come from [THREAT-MODEL.md](THREAT-MODEL.md).

How to read "Watched by":
- **pytest** = the defense tests (job `tests`), plus `scripts/mutation_check.py` which removes
  the control in a copy of the code and checks that a test fails (16 controls covered).
- **Semgrep (custom)** = one of the 7 rules in `rules/`; **Semgrep (registry)** = `p/owasp-top-ten`
  or `p/python`; **ZAP** = a FAIL rule in `.zap/rules.tsv`.
- "—" means no tool watches it: only the test does. That is a deliberate finding, not a typo.

ASVS ids are given for version 4.0.3 (the version most job offers and audits still cite).
Where no 4.0.3 requirement fits exactly, the cell says so.

## 1. Application controls

| Id | Control (where in the code) | Threat | OWASP 2021 | ASVS 4.0.3 | CWE | Proven by (tests/) | Watched by |
|---|---|---|---|---|---|---|---|
| C1 | Object-level authorization in the SQL query (`customer_id = ?`), 404 for "not yours" and "missing" — `db.get_order_for`, `orders._order_or_404` | T6 | A01 | V4.2.1, V4.1.1 | CWE-639 | `test_authz.py::test_customer_gets_404_on_other_customers_order`, `::test_customer_cannot_write_note_on_other_customers_order`, `::test_csv_export_is_scoped_to_the_user` | pytest only (no scanner understands ownership) |
| C2 | Function-level authorization: `@role_required("staff")` on status change, customer-only note | T7 | A01 | V4.1.3, V4.1.5 | CWE-285 | `test_authz.py::test_customer_cannot_change_status`, `::test_staff_cannot_write_customer_note` | pytest |
| C3 | Deny by default: every route has `@login_required` / `@role_required` (public allow-list: `login`) | T6, T7 | A01 | V4.1.3 | CWE-862 | `test_authz.py::test_anonymous_is_redirected_to_login`, `test_static_checks.py::test_every_route_requires_authentication_unless_whitelisted` | Semgrep (custom) `flask-route-missing-auth` |
| C4 | CSRF synchronizer token, constant-time compare — `security.csrf_protect` | T8 | A01 | V4.2.2 | CWE-352 | `test_csrf.py` (6 tests, incl. token from another session) | pytest; ZAP 10202 (forms without token) |
| C5 | Session cookie `__Host-session`, Secure, HttpOnly, SameSite=Lax, Path=/ — `config.load_config` | T4, T8 | A07, A05 | V3.4.1, V3.4.2, V3.4.3, V3.4.4, V3.4.5 | CWE-614, CWE-1004, CWE-1275 | `test_headers_session.py::test_session_cookie_flags` | Semgrep (custom) `flask-cookie-without-flags`; ZAP 10010, 10011, 10054 |
| C6 | New session at login (`session.clear()`), logout by POST, 30 min lifetime | T3 | A07 | V3.2.1, V3.3.1 (partial, see G2) | CWE-384, CWE-613 | `test_headers_session.py::test_session_is_renewed_at_login`, `test_authz.py::test_logout_requires_post_and_ends_session` | pytest |
| C7 | Password hashing with scrypt (salted, memory-hard), min 12 / max 128 chars — `auth.hash_password` | T1 | A02, A07 | V2.4.1, V2.1.1, V2.1.2 | CWE-916, CWE-521 | `test_login.py::test_passwords_are_stored_as_scrypt_hashes`, `::test_too_short_password_is_refused_at_creation`, `test_injection_validation.py::test_overlong_password_is_rejected` | Semgrep (registry) weak-hash rules; Bandit B303/B324 |
| C8 | Login throttling per IP **and** per username (5 failures / 15 min, 429), generic error, dummy hash for unknown users — `security.LoginThrottle`, `auth.login` | T1, T2, T15 | A07 | V2.2.1 | CWE-307, CWE-204 | `test_login.py::test_login_is_throttled_after_five_failures`, `::test_throttle_is_per_username_too`, `::test_throttle_window_expires`, `::test_wrong_password_and_unknown_user_give_same_message` | pytest |
| C9 | Parameterized SQL only (`?` placeholders, constant SQL text) — `db.py` | T10 | A03 | V5.3.4 | CWE-89 | `test_injection_validation.py::test_sql_metacharacters_in_username_are_just_data`, `::test_note_with_quotes_is_stored_verbatim`, `test_static_checks.py::test_every_sql_statement_is_a_constant_string` | Semgrep (custom) `sqlite-formatted-sql`; Semgrep (registry); Bandit B608 |
| C10 | CSV formula neutralization (prefix `'` before `= + - @ TAB CR`) — `security.neutralize_csv_cell` | T11 | A03 | no exact 4.0.3 item | CWE-1236 | `test_injection_validation.py::test_csv_cells_are_neutralized`, `::test_csv_export_neutralizes_formula_in_note` | pytest only |
| C11 | Jinja autoescape on, no `safe` filter / `Markup`, no `render_template_string` | T9 | A03 | V5.3.3, V5.2.5 | CWE-79, CWE-1336 | `test_injection_validation.py::test_note_is_html_escaped`, `::test_product_name_from_db_is_escaped`, `test_static_checks.py::test_templates_never_disable_escaping` | Semgrep (custom) `flask-render-template-string-user-input`; Bandit B701/B704 |
| C12 | Strict CSP (`script-src 'self'`, no `unsafe-inline`, `object-src 'none'`, `base-uri 'none'`, `form-action 'self'`, `frame-ancestors 'none'`), no inline script/style in templates | T4, T9 | A05 | V14.4.3, V14.4.7 | CWE-1021, CWE-79 | `test_headers_session.py::test_security_headers_on_every_response`, `test_static_checks.py::test_templates_never_disable_escaping` | ZAP 10038, 10020 |
| C13 | Secrets only from the environment; refuse to start if `PORTAL_SECRET_KEY` is missing or < 32 chars; demo passwords random, printed once | T5, T16 | A02, A05 | V2.10.4, V6.4.1 (partial, see G6) | CWE-798 | `test_static_checks.py::test_app_refuses_to_start_without_secret`, `::test_app_refuses_short_secret`, `::test_no_hardcoded_secrets_in_app_code` | Gitleaks; Trivy secret scanner; Bandit B105/B106 |
| C14 | Post-login redirect limited to local paths — `security.safe_next_url` | T12 | A01 | V5.1.5 | CWE-601 | `test_login.py::test_safe_next_url` (7 cases), `::test_login_does_not_redirect_offsite` | pytest; Semgrep (registry) open-redirect rules |
| C15 | Debug off, generic error pages, no stack traces | T13, T19 | A05 | V14.3.2, V7.4.1 | CWE-489, CWE-209 | `test_static_checks.py::test_debug_is_off`, `::test_production_flags`, `test_headers_session.py::test_errors_do_not_show_stack_traces` | Semgrep (custom) `flask-debug-enabled`; Bandit B201; ZAP 90022, 10023 |
| C16 | No product/version in `Server` / `Via` (app header + Waitress `ident`) | T13 | A05 | V14.3.3 | CWE-200 | `test_headers_session.py::test_server_header_does_not_leak_stack` | ZAP 10036, 10037 |
| C17 | `Cache-Control: no-store` on every non-static page | T14 | A04 / A05 | V8.2.1 | CWE-525 | `test_headers_session.py::test_pages_are_not_cacheable` | — |
| C18 | Server-side input validation: int route converter, note <= 500 chars, status allow-list, body <= 16 KB | T15, T10 | A03, A04 | V5.1.3, V5.1.4 | CWE-20, CWE-770 | `test_injection_validation.py::test_note_too_long_is_rejected`, `::test_status_outside_allow_list_is_rejected`, `::test_non_integer_order_id_is_404`, `::test_oversized_body_is_rejected` | pytest |
| C19 | Other security headers: `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP; HSTS behind TLS (`PORTAL_HSTS=1`) | T4, T13 | A05 | V14.4.4, V14.4.5, V14.4.6 | CWE-693, CWE-319 | `test_headers_session.py::test_security_headers_on_every_response`, `::test_hsts_off_by_default_and_on_when_enabled` | ZAP 10021, 10063 |
| C23 | Bind 127.0.0.1 only (`run.py`), non-root container | T19 | A05 | no exact 4.0.3 item | CWE-1327, CWE-250 | `test_static_checks.py::test_server_binds_loopback_only` | Semgrep (custom) `bind-all-interfaces`; Bandit B104; Trivy misconfig (root user) |
| C24 | Security events logged (login ok/failed/throttled, CSRF rejection, authz denial, status change), never the password | T20 | A09 | V7.1.1, V7.1.3 | CWE-778, CWE-532 | `test_login.py::test_security_events_are_logged_without_the_password` | pytest |

## 2. Supply-chain and pipeline controls

| Id | Control | Threat | OWASP 2021 | ASVS 4.0.3 | CWE | Evidence | Tool |
|---|---|---|---|---|---|---|---|
| C20 | Pinned Python dependencies, audited against PyPI/OSV advisories; weekly scheduled run | T17 | A06 | V14.2.1 | CWE-1104, CWE-1395 | Commit `deps: bump Werkzeug 3.1.8 -> 3.1.9` (real pip-audit finding) | pip-audit; Trivy fs; Dependabot |
| C21 | Container image scanned (OS packages + Python packages), HIGH/CRITICAL with a fix fail the build | T17 | A06 | V14.2.1 | CWE-1104 | CI job `container` | Trivy image |
| C22 | Actions pinned to commit SHA, tools to versions, images to digests, Gitleaks checksum; Dependabot 7-day cooldown; Trivy run at a post-incident version | T18 | A08 | V10.3.2 (integrity), V14.2.4 | CWE-494, CWE-829 | `.github/workflows/security.yml`, `.github/dependabot.yml` | Semgrep (registry) found the missing cooldown |
| C25 | Custom detection rules tested like code: every rule has `# ruleid:` (must match) and `# ok:` (must not match) fixtures | — | — | — | — | `semgrep --test rules/`: 7/7 rules, 22 `ruleid` + 17 `ok` cases | Semgrep |

## 3. Honest gaps — what neither the tools nor the tests cover

| Id | Gap | Why it matters | What would close it |
|---|---|---|---|
| G1 | No TLS in the lab (HTTP on localhost); HSTS only "ready" | Cookies are `Secure`; browsers accept that on localhost, but a real deployment needs TLS | TLS reverse proxy + `PORTAL_HSTS=1` |
| G2 | Flask sessions are signed client-side cookies: logout deletes the cookie, but a **copied** cookie stays valid until it expires (30 min) | ASVS V3.3.1 is only partly met | Server-side sessions (Redis / DB) with a revocation list |
| G3 | ZAP baseline is **passive and unauthenticated**: it never logs in, so it only sees `/login` and public pages | Most of the app is behind login | Authenticated ZAP context or a full active scan in a lab |
| G4 | No MFA, no password-breach check (HIBP k-anonymity) | Credential stuffing beyond the throttle | TOTP / WebAuthn; breached-password check at creation |
| G5 | Throttle is in memory and per process; no global rate limit | Several workers = several counters; restart resets them | Rate limiting at the proxy or in Redis |
| G6 | Secret in an environment variable, no vault, no rotation | Anyone reading the process environment gets it | Secret manager, rotation procedure |
| G7 | CSV neutralization follows the OWASP advice, but spreadsheet behaviour differs (LibreOffice, Excel, Google Sheets) | A new formula prefix could appear | Export to XLSX with typed text cells |
| G8 | Gitleaks and Trivy secret scanning are pattern/entropy based | A custom-format secret is missed (false negative) | Pre-commit hook + code review + short-lived credentials |
| G9 | SCA only knows **published** advisories; SAST rules only know **known** patterns | Zero-days and new bug classes pass | Defense in depth; this is why tests and threat model exist |
| G10 | Logs are plain local text, not centralised or tamper-evident | Repudiation (T20) only partly covered | Ship logs to a SIEM (see soc-detection-lab) |
| G11 | Business-logic flaws in **new** endpoints are not caught automatically | The IDOR test exists only for the endpoints written so far | Rule: every new route needs an authz test (enforced in code review) |
| G12 | No SBOM is published | Harder to answer "are we affected by CVE-X?" later | `trivy image --format cyclonedx` as a CI artifact |
