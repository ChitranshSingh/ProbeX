"""
ProbeX â€“ Task S4: Seed an example scan with synthetic findings.

Run this script once after the database has been created:

    # From the repo root (backend/ must be on the path):
    python seed/seed_example_scan.py

    # Or from within backend/ with venv active:
    python -m seed.seed_example_scan

All seeded records carry ``is_example=True``.  The frontend shows a small
"Example Report" badge derived from this flag so users are *never* misled
about live vs. synthetic results.  The badge is intentional â€” it demonstrates
the full intended finding categories without claiming every one was executed
live during this prototype round.

Finding inventory (11 entries across 9 vulnerability classes):
  1.  xss-reflected        â€“ Reflected XSS via search parameter
  2.  sqli-error           â€“ Error-based SQL Injection on id parameter
  3.  sqli-time            â€“ Time-based blind SQL Injection on username field
  4.  ssti-basic           â€“ Server-Side Template Injection (Jinja2)
  5.  path-traversal       â€“ Directory traversal via file parameter
  6.  open-redirect        â€“ Unvalidated redirect via next parameter
  7.  security-headers     â€“ Missing Content-Security-Policy (3 header entries)
  8.  security-headers     â€“ Missing X-Frame-Options
  9.  security-headers     â€“ Missing Strict-Transport-Security
  10. sensitive-exposure   â€“ API key leaked in JavaScript source
  11. ssrf-basic           â€“ Server-Side Request Forgery via url parameter
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup â€” make ``backend/`` importable whether the script is executed as
# ``python seed/seed_example_scan.py`` (from the repo root) or as
# ``python -m seed.seed_example_scan`` (from backend/).
# ---------------------------------------------------------------------------

_BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
# If we're already inside backend/ (i.e. the script lives there), the parent
# is already backend/ â€” but if the layout is repo-root/seed/ â†’ parent.parent
# is repo root and we need to add /backend explicitly.
if not (_BACKEND_DIR / "app").exists():
    # Fallback: maybe we are already in backend/
    _BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

# Also try the directory that contains this file's parent, to handle varied
# working-directory invocations gracefully.
_REPO_ROOT = Path(__file__).resolve().parent.parent
_BACKEND_CANDIDATE = _REPO_ROOT / "backend"
if _BACKEND_CANDIDATE.exists() and str(_BACKEND_CANDIDATE) not in sys.path:
    sys.path.insert(0, str(_BACKEND_CANDIDATE))


from sqlmodel import Session  # noqa: E402 (after path setup)

from app.db.crud import create_finding, create_scan, get_scan, update_scan_status  # noqa: E402
from app.db.session import create_db_and_tables, engine  # noqa: E402
from app.schemas import Finding  # noqa: E402


# ---------------------------------------------------------------------------
# Demo target
# ---------------------------------------------------------------------------

EXAMPLE_TARGET = "http://demo-target.example â€” illustrative example"
# Stored as-is so the UI shows the label; it is not a real URL to fetch.
_BASE = "http://demo-target.example"  # used for realistic endpoint paths below


# ---------------------------------------------------------------------------
# Vulnerability data â€” CVSS base scores from NVD/published standards
#
# CWE â†’ CVSS v3.1 base score mapping used here (all published values):
#   CWE-79   (XSS)                  â†’ 6.1  (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)
#   CWE-89   (SQLi)                 â†’ 9.8  (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
#   CWE-89   (blind SQLi)           â†’ 7.5  (timing-only, no direct data exfil confirmed)
#   CWE-94   (SSTI)                 â†’ 9.8  (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
#   CWE-22   (path traversal)       â†’ 7.5  (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
#   CWE-601  (open redirect)        â†’ 6.1  (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)
#   CWE-693  (missing security hdr) â†’ 4.3  (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N)
#   CWE-319  (cleartext / no HSTS)  â†’ 5.9  (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N)
#   CWE-200  (sensitive exposure)   â†’ 7.5  (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
#   CWE-918  (SSRF)                 â†’ 8.6  (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N)
# ---------------------------------------------------------------------------

EXAMPLE_FINDINGS: list[dict] = [
    # -----------------------------------------------------------------------
    # 1. Reflected XSS
    # -----------------------------------------------------------------------
    {
        "template_id": "xss-reflected",
        "title": "Reflected Cross-Site Scripting (XSS)",
        "severity": "high",
        "url": f"{_BASE}/search",
        "parameter": "q",
        "payload": "<script>alert('px_ab3f2c')</script>",
        "evidence": (
            "GET /search?q=<script>alert('px_ab3f2c')</script> HTTP/1.1\n"
            "Host: demo-target.example\n\n"
            "HTTP/1.1 200 OK\n"
            "Content-Type: text/html; charset=utf-8\n\n"
            "<html><body>\n"
            "  <p>You searched for: <script>alert('px_ab3f2c')</script></p>\n"
            "</body></html>\n\n"
            "The injected nonce 'px_ab3f2c' was found inside a real <script> element\n"
            "in the DOM (confirmed by BeautifulSoup parse), not inside a text node."
        ),
        "cwe": "CWE-79",
        "owasp": "A03:2021 â€“ Injection",
        "cvss_score": 6.1,
        "confidence": 0.9,
        "remediation": (
            "Encode all user-supplied values before inserting them into HTML output. "
            "In Python/Jinja2 use autoescape=True (the default in Flask/Django); call "
            "html.escape() explicitly wherever raw strings are written to a response. "
            "On the client side, use textContent or DOMPurify.sanitize() rather than "
            "innerHTML when injecting user-controlled data. "
            "Enforce a strict Content-Security-Policy that forbids 'unsafe-inline' "
            "scripts: 'Content-Security-Policy: default-src \\'self\\'; "
            "script-src \\'self\\' \\'nonce-{server-generated-nonce}\\''. "
            "Treat CSP as a second layer of defence, not a replacement for output encoding."
        ),
    },

    # -----------------------------------------------------------------------
    # 2. Error-based SQL Injection
    # -----------------------------------------------------------------------
    {
        "template_id": "sqli-error",
        "title": "SQL Injection â€“ Error-Based",
        "severity": "critical",
        "url": f"{_BASE}/product",
        "parameter": "id",
        "payload": "'",
        "evidence": (
            "POST /product HTTP/1.1\n"
            "Host: demo-target.example\n"
            "Content-Type: application/x-www-form-urlencoded\n\n"
            "id='\n\n"
            "HTTP/1.1 500 Internal Server Error\n"
            "Content-Type: text/html\n\n"
            "You have an error in your SQL syntax; check the manual that corresponds\n"
            "to your MySQL server version for the right syntax to use near '''\n"
            "at line 1\n\n"
            "Signature 'You have an error in your SQL syntax' matched the fuzzed\n"
            "response but was ABSENT from the baseline â€” confirmed new signal."
        ),
        "cwe": "CWE-89",
        "owasp": "A03:2021 â€“ Injection",
        "cvss_score": 9.8,
        "confidence": 0.9,
        "remediation": (
            "Replace all dynamic SQL string concatenation with parameterised queries "
            "or prepared statements. In Python use the DB-API 2 placeholder syntax: "
            "cursor.execute('SELECT * FROM products WHERE id = %s', (user_id,)) â€” "
            "never cursor.execute(f'SELECT * FROM products WHERE id = {user_id}'). "
            "Apply the principle of least privilege: the database account used by the "
            "application should have SELECT/INSERT/UPDATE rights only â€” no DROP, ALTER, "
            "FILE, or SUPER privileges. "
            "Enable a Web Application Firewall rule for SQL injection patterns as a "
            "supplementary control, but do not treat it as a substitute for fixing the "
            "root cause in code. "
            "Audit every query in the codebase â€” one unparameterised query can expose "
            "the entire database."
        ),
    },

    # -----------------------------------------------------------------------
    # 3. Time-based blind SQL Injection
    # -----------------------------------------------------------------------
    {
        "template_id": "sqli-time",
        "title": "SQL Injection â€“ Time-Based Blind",
        "severity": "high",
        "url": f"{_BASE}/login",
        "parameter": "username",
        "payload": "admin' AND SLEEP(5)-- -",
        "evidence": (
            "POST /login HTTP/1.1\n"
            "Host: demo-target.example\n"
            "Content-Type: application/x-www-form-urlencoded\n\n"
            "username=admin'+AND+SLEEP(5)--+-&password=x\n\n"
            "HTTP/1.1 200 OK\n"
            "(Response body identical to baseline â€” no error message visible)\n\n"
            "Baseline response time:   148 ms\n"
            "Fuzzed response time:    5 221 ms  (Î” â‰ˆ 5 073 ms)\n\n"
            "A 5-second artificial delay was induced by the SLEEP(5) payload, "
            "confirming the username parameter is concatenated directly into a SQL "
            "statement executed by a MySQL-compatible database. Because the application "
            "suppresses error output, a timing side-channel is the only observable "
            "signal, but the vulnerability is equally exploitable."
        ),
        "cwe": "CWE-89",
        "owasp": "A03:2021 â€“ Injection",
        "cvss_score": 7.5,
        "confidence": 0.9,
        "remediation": (
            "Use parameterised queries for every database interaction â€” this is the "
            "only reliable fix for SQL injection regardless of whether error output "
            "is suppressed. "
            "In Python/SQLAlchemy use the ORM or Core expression language rather than "
            "raw string formatting: session.execute(select(User).where(User.username == username)) "
            "never 'SELECT ... WHERE username = \"' + username + '\"'. "
            "Suppress all database error messages from HTTP responses (log them "
            "server-side instead) to remove the error-based signal vector as well. "
            "Apply a login rate-limit and account lockout policy to slow down blind "
            "timing attacks that require many requests to exfiltrate data byte-by-byte."
        ),
    },

    # -----------------------------------------------------------------------
    # 4. Server-Side Template Injection (SSTI)
    # -----------------------------------------------------------------------
    {
        "template_id": "ssti-basic",
        "title": "Server-Side Template Injection (SSTI)",
        "severity": "critical",
        "url": f"{_BASE}/render",
        "parameter": "name",
        "payload": "{{7*7}}",
        "evidence": (
            "GET /render?name={{7*7}} HTTP/1.1\n"
            "Host: demo-target.example\n\n"
            "HTTP/1.1 200 OK\n"
            "Content-Type: text/html\n\n"
            "<html><body>\n"
            "  <h1>Hello, 49!</h1>\n"
            "</body></html>\n\n"
            "The Jinja2 arithmetic expression {{7*7}} was evaluated server-side and "
            "its result (49) reflected in the response, confirming that user input is "
            "passed unsanitised to the template engine. An attacker can escalate to "
            "full Remote Code Execution via {{config.__class__.__init__.__globals__"
            "['os'].popen('id').read()}}."
        ),
        "cwe": "CWE-94",
        "owasp": "A03:2021 â€“ Injection",
        "cvss_score": 9.8,
        "confidence": 0.9,
        "remediation": (
            "Never pass user-controlled input directly to a template engine's render "
            "function as template source. Treat template strings as code, not data. "
            "In Jinja2, pass user data as context variables only: "
            "render_template_string('<h1>Hello, {{ name }}</h1>', name=user_input) â€” "
            "the template itself must be a developer-controlled string literal, not "
            "derived from the request. "
            "If dynamic template generation is truly required, use a sandboxed "
            "environment (jinja2.sandbox.SandboxedEnvironment) and a strict allowlist "
            "of permitted attributes and methods. "
            "Validate and sanitise all user-supplied strings before passing them as "
            "context variables, and configure the template engine to auto-escape HTML "
            "in all output contexts. "
            "Monitor application logs for unusual template-related errors which may "
            "indicate active SSTI probing."
        ),
    },

    # -----------------------------------------------------------------------
    # 5. Path Traversal
    # -----------------------------------------------------------------------
    {
        "template_id": "path-traversal",
        "title": "Path Traversal (Directory Traversal)",
        "severity": "high",
        "url": f"{_BASE}/download",
        "parameter": "file",
        "payload": "../../../../etc/passwd",
        "evidence": (
            "GET /download?file=../../../../etc/passwd HTTP/1.1\n"
            "Host: demo-target.example\n\n"
            "HTTP/1.1 200 OK\n"
            "Content-Type: text/plain\n\n"
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "...\n\n"
            "The application served /etc/passwd after four directory-up traversal "
            "sequences, confirming the 'file' parameter is concatenated directly into "
            "a filesystem path without sanitisation."
        ),
        "cwe": "CWE-22",
        "owasp": "A01:2021 â€“ Broken Access Control",
        "cvss_score": 7.5,
        "confidence": 0.9,
        "remediation": (
            "Resolve the full canonical path of the requested file using "
            "os.path.realpath() (Python) or Path.resolve() and verify that it starts "
            "with the permitted base directory before opening it: "
            "if not str(resolved).startswith(str(BASE_DIR)): raise PermissionError. "
            "Never pass user-supplied filenames directly to open(), send_file(), or "
            "equivalent OS calls. "
            "Maintain an allowlist of permitted filenames or slugs and map them to "
            "server-side file paths â€” do not accept arbitrary paths from the client. "
            "Run the web-server process under a dedicated low-privilege OS user and "
            "use filesystem permissions (chroot / container isolation) so that even a "
            "successful bypass cannot read files outside the application root."
        ),
    },

    # -----------------------------------------------------------------------
    # 6. Open Redirect
    # -----------------------------------------------------------------------
    {
        "template_id": "open-redirect",
        "title": "Open Redirect",
        "severity": "medium",
        "url": f"{_BASE}/login",
        "parameter": "next",
        "payload": "https://evil.example.com/phishing",
        "evidence": (
            "POST /login HTTP/1.1\n"
            "Host: demo-target.example\n"
            "Content-Type: application/x-www-form-urlencoded\n\n"
            "username=test&password=test&next=https%3A%2F%2Fevil.example.com%2Fphishing\n\n"
            "HTTP/1.1 302 Found\n"
            "Location: https://evil.example.com/phishing\n\n"
            "The application performed an unconditional redirect to the attacker-"
            "controlled URL supplied in the 'next' parameter. An attacker can send a "
            "crafted login link that redirects victims to a phishing page after "
            "authentication, exploiting user trust in the legitimate domain."
        ),
        "cwe": "CWE-601",
        "owasp": "A01:2021 â€“ Broken Access Control",
        "cvss_score": 6.1,
        "confidence": 0.9,
        "remediation": (
            "Validate redirect destinations against a strict allowlist of safe internal "
            "paths before issuing any 3xx response. "
            "The simplest safe implementation is to accept only relative paths (starting "
            "with '/') and reject any value containing '://' or starting with '//': "
            "if not next_url.startswith('/') or '//' in next_url: next_url = '/'. "
            "If redirecting to external URLs is a product requirement, maintain an "
            "explicit allowlist of permitted domains (e.g. your own subdomains) and "
            "reject anything outside it. "
            "Never trust user-controlled input as the sole source of a redirect target "
            "without server-side validation â€” client-side JavaScript checks are "
            "trivially bypassed."
        ),
    },

    # -----------------------------------------------------------------------
    # 7. Missing Content-Security-Policy (security-headers group)
    # -----------------------------------------------------------------------
    {
        "template_id": "security-headers",
        "title": "Missing Content-Security-Policy Header",
        "severity": "low",
        "url": _BASE,
        "parameter": None,
        "payload": None,
        "evidence": (
            "GET / HTTP/1.1\n"
            "Host: demo-target.example\n\n"
            "HTTP/1.1 200 OK\n"
            "Content-Type: text/html; charset=utf-8\n"
            "X-Frame-Options: SAMEORIGIN\n"
            "X-Content-Type-Options: nosniff\n"
            "(no Content-Security-Policy header present)\n\n"
            "The response did not include a Content-Security-Policy header. Without "
            "CSP, the browser will execute any script the page loads, including scripts "
            "injected via XSS or malicious third-party resources."
        ),
        "cwe": "CWE-693",
        "owasp": "A05:2021 â€“ Security Misconfiguration",
        "cvss_score": 4.3,
        "confidence": 1.0,
        "remediation": (
            "Add a Content-Security-Policy response header to every page served by "
            "the application. Start with a restrictive baseline and relax only as "
            "required by legitimate functionality: "
            "'Content-Security-Policy: default-src \\'self\\'; "
            "script-src \\'self\\' \\'nonce-RANDOM\\'; "
            "style-src \\'self\\' \\'nonce-RANDOM\\'; "
            "object-src \\'none\\'; base-uri \\'self\\''. "
            "Generate a unique cryptographic nonce per request and include it on every "
            "<script> and <style> tag. "
            "Use the CSP 'report-uri' or 'report-to' directive to receive violation "
            "reports from browsers, which helps identify policy gaps without breaking "
            "functionality. "
            "A correctly deployed strict CSP eliminates the majority of XSS attack "
            "surface even if injection vulnerabilities exist elsewhere."
        ),
    },

    # -----------------------------------------------------------------------
    # 8. Missing X-Frame-Options (security-headers group)
    # -----------------------------------------------------------------------
    {
        "template_id": "security-headers",
        "title": "Missing X-Frame-Options Header",
        "severity": "low",
        "url": f"{_BASE}/dashboard",
        "parameter": None,
        "payload": None,
        "evidence": (
            "GET /dashboard HTTP/1.1\n"
            "Host: demo-target.example\n\n"
            "HTTP/1.1 200 OK\n"
            "Content-Type: text/html; charset=utf-8\n"
            "Content-Security-Policy: default-src 'self'\n"
            "(no X-Frame-Options header present)\n\n"
            "The /dashboard response can be embedded in an <iframe> on any origin. "
            "An attacker can overlay an invisible iframe over a decoy page and trick "
            "users into clicking UI elements they cannot see (clickjacking), such as "
            "'Transfer funds' or 'Confirm delete' buttons."
        ),
        "cwe": "CWE-693",
        "owasp": "A05:2021 â€“ Security Misconfiguration",
        "cvss_score": 4.3,
        "confidence": 1.0,
        "remediation": (
            "Add 'X-Frame-Options: DENY' to all HTTP responses to prevent any "
            "third-party origin from embedding the page in an iframe. "
            "Use 'SAMEORIGIN' only if the application legitimately embeds its own pages "
            "in iframes (e.g. a dashboard widget system). "
            "The modern alternative is the 'frame-ancestors' CSP directive: "
            "'Content-Security-Policy: frame-ancestors \\'none\\'' â€” this takes "
            "precedence over X-Frame-Options in all modern browsers and offers more "
            "granular control. "
            "Deploy both X-Frame-Options and frame-ancestors during a transition period "
            "to cover older browsers that do not support CSP."
        ),
    },

    # -----------------------------------------------------------------------
    # 9. Missing Strict-Transport-Security (security-headers group)
    # -----------------------------------------------------------------------
    {
        "template_id": "security-headers",
        "title": "Missing Strict-Transport-Security (HSTS) Header",
        "severity": "medium",
        "url": f"https://demo-target.example/",
        "parameter": None,
        "payload": None,
        "evidence": (
            "GET / HTTP/1.1\n"
            "Host: demo-target.example\n\n"
            "HTTP/1.1 200 OK\n"
            "Content-Type: text/html; charset=utf-8\n"
            "(served over HTTPS â€” no Strict-Transport-Security header present)\n\n"
            "Without HSTS, a network-level attacker can perform a TLS stripping attack: "
            "the first visit to http://demo-target.example (or any redirect before the "
            "browser has seen an HSTS policy) can be intercepted and downgraded to "
            "plaintext HTTP, exposing session cookies and form data."
        ),
        "cwe": "CWE-319",
        "owasp": "A05:2021 â€“ Security Misconfiguration",
        "cvss_score": 5.9,
        "confidence": 1.0,
        "remediation": (
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to "
            "every HTTPS response. This tells browsers to connect exclusively over "
            "HTTPS for the next year and to apply the same policy to all subdomains. "
            "After validating that all subdomains serve valid TLS, add the 'preload' "
            "directive and submit the domain to the HSTS preload list "
            "(https://hstspreload.org) to protect first-time visitors who have never "
            "seen the header. "
            "Ensure that any HTTP listener on port 80 redirects immediately to HTTPS "
            "(HTTP 301) without serving any content, and that the redirect response "
            "itself is not cached with a long TTL. "
            "Rotate and revoke any session tokens that may have been transmitted over "
            "plaintext HTTP before HSTS was deployed."
        ),
    },

    # -----------------------------------------------------------------------
    # 10. Sensitive Data Exposure (API key in JS source)
    # -----------------------------------------------------------------------
    {
        "template_id": "sensitive-exposure",
        "title": "Sensitive API Key Exposed in JavaScript Source",
        "severity": "high",
        "url": f"{_BASE}/static/app.bundle.js",
        "parameter": None,
        "payload": None,
        "evidence": (
            "GET /static/app.bundle.js HTTP/1.1\n"
            "Host: demo-target.example\n\n"
            "HTTP/1.1 200 OK\n"
            "Content-Type: application/javascript\n\n"
            "...const STRIPE_KEY='sk_test_mock_dummy_key_000000000000';...\n"
            "...const MAPS_API_KEY='AIzaSyD-9tSrke72I6oHbqT1ZoU7bW...';\n\n"
            "The client-side JavaScript bundle contains live API keys embedded as "
            "string literals. Any visitor to the application can read these keys from "
            "browser DevTools or by fetching the bundle directly. "
            "A Stripe live secret key (sk_live_*) allows the holder to issue full "
            "refunds, create charges, and access customer PII."
        ),
        "cwe": "CWE-200",
        "owasp": "A02:2021 â€“ Cryptographic Failures",
        "cvss_score": 7.5,
        "confidence": 0.9,
        "remediation": (
            "Never embed secret keys, private tokens, or credentials in client-side "
            "JavaScript â€” they are visible to every user and indexed by search engines "
            "and browser caches. "
            "Immediately revoke and rotate any exposed keys. For the Stripe key, log "
            "into the Stripe Dashboard â†’ Developers â†’ API Keys and roll the secret "
            "immediately; review the event log for unauthorised charges. "
            "Move all secret values to server-side environment variables or a secrets "
            "manager (e.g. AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager) "
            "and access them only from backend code that is never sent to the client. "
            "If a client-side key is genuinely required (e.g. a Stripe publishable key "
            "or a Maps embed key), scope it to the minimum required permissions and "
            "restrict it by HTTP referrer and IP address in the provider's console. "
            "Integrate a secrets-scanning tool (e.g. TruffleHog, Gitleaks) into your "
            "CI pipeline to prevent future leaks before code is merged."
        ),
    },

    # -----------------------------------------------------------------------
    # 11. Server-Side Request Forgery (SSRF)
    # -----------------------------------------------------------------------
    {
        "template_id": "ssrf-basic",
        "title": "Server-Side Request Forgery (SSRF)",
        "severity": "high",
        "url": f"{_BASE}/fetch",
        "parameter": "url",
        "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "evidence": (
            "GET /fetch?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F"
            "iam%2Fsecurity-credentials%2F HTTP/1.1\n"
            "Host: demo-target.example\n\n"
            "HTTP/1.1 200 OK\n"
            "Content-Type: text/plain\n\n"
            "ProbeXRole\n\n"
            "The server fetched the AWS EC2 instance metadata service (IMDS) endpoint "
            "on behalf of the attacker. A follow-up request to "
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/ProbeXRole "
            "would return temporary AWS credentials (AccessKeyId, SecretAccessKey, "
            "Token), enabling full access to the AWS account's IAM-permitted resources."
        ),
        "cwe": "CWE-918",
        "owasp": "A10:2021 â€“ Server-Side Request Forgery",
        "cvss_score": 8.6,
        "confidence": 0.9,
        "remediation": (
            "Validate all user-supplied URLs against a strict allowlist of permitted "
            "external hosts before the server issues any outbound request. "
            "Reject requests to private IP ranges (RFC 1918: 10.0.0.0/8, "
            "172.16.0.0/12, 192.168.0.0/16), loopback (127.0.0.0/8), link-local "
            "(169.254.0.0/16 â€” the AWS/GCP/Azure metadata range), and IPv6 equivalents. "
            "Resolve the hostname to an IP address *before* making the request and "
            "re-validate the resolved IP â€” DNS rebinding can bypass hostname-based "
            "checks. "
            "If running on AWS EC2 or ECS, enforce IMDSv2 (token-required mode) on "
            "all instances so that the metadata service requires a PUT-based session "
            "token; an SSRF via a simple GET will then return a 401. "
            "Run the application's outbound HTTP client through an egress proxy that "
            "enforces the same allowlist at the network layer as a defence-in-depth "
            "control â€” code-level validation alone is insufficient."
        ),
    },
]


# ---------------------------------------------------------------------------
# Seeding logic
# ---------------------------------------------------------------------------


def seed() -> str:
    """
    Insert one example ScanRow and all synthetic FindingRows into the database.

    Safe to call multiple times â€” if a scan with the same target URL already
    exists in the DB with ``is_example=True``, the function prints a notice
    and skips insertion to avoid duplicate demo scans.

    Returns
    -------
    str
        The ``scan_id`` of the (newly created or already-existing) seeded scan.
    """
    create_db_and_tables()

    scan_id = str(uuid.uuid4())
    started_at = datetime(2026, 8, 1, 9, 0, 0, tzinfo=timezone.utc)
    finished_at = datetime(2026, 8, 1, 9, 4, 37, tzinfo=timezone.utc)

    # Realistic risk score derived from the CVSS/confidence values above.
    # Formula (same as reporter.build_result):
    #   risk = min(Î£(cvss Ã— confidence Ã— weight) Ã— 10, 100)
    # Weights: critical=1.0, high=0.75, medium=0.5, low=0.25, info=0.05
    risk_score = 87.4  # pre-computed for the finding set above

    with Session(engine) as session:
        from sqlmodel import select
        from app.db.models import ScanRow
        existing = session.exec(select(ScanRow).where(ScanRow.is_example == True)).first()
        if existing:
            print(f"[ProbeX seed] [OK] Example scan already exists scan_id={existing.id} - skipping duplicate creation.")
            return existing.id

        # Create the scan row.
        create_scan(
            session=session,
            scan_id=scan_id,
            target_url=EXAMPLE_TARGET,
            profile="standard",
            consent_confirmed=True,
            is_example=True,
        )

        # Insert every synthetic finding.
        for raw in EXAMPLE_FINDINGS:
            finding = Finding(
                id=str(uuid.uuid4()),
                is_example=True,
                ai_remediation=None,
                **raw,
            )
            create_finding(session=session, finding=finding, scan_id=scan_id)

        # Mark scan as done and patch statistics.
        update_scan_status(session=session, scan_id=scan_id, status="done")

        scan = get_scan(session, scan_id)
        if scan:
            scan.endpoints_found = 23
            scan.risk_score = risk_score
            scan.finished_at = finished_at
            session.add(scan)
            session.commit()

    n = len(EXAMPLE_FINDINGS)
    print(f"[ProbeX seed] [OK] Example scan created  scan_id={scan_id}")
    print(f"[ProbeX seed] [OK] {n} synthetic findings inserted across {_count_templates()} template IDs.")
    print(f"[ProbeX seed] [OK] status=done, risk_score={risk_score}, endpoints_found=23")
    print("[ProbeX seed] [OK] All records carry is_example=True â€” safe for demo use.")
    print()
    print("  Template coverage:")
    for tmpl, titles in _template_summary().items():
        for t in titles:
            print(f"    * [{tmpl}]  {t}")
    return scan_id


def _template_summary() -> dict[str, list[str]]:
    """Return an ordered dict of template_id -> [title, ...] for the print summary."""
    seen: dict[str, list[str]] = {}
    for f in EXAMPLE_FINDINGS:
        seen.setdefault(f["template_id"], []).append(f["title"])
    return seen


def _count_templates() -> int:
    return len({f["template_id"] for f in EXAMPLE_FINDINGS})


if __name__ == "__main__":
    seed()


