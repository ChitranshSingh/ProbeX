"""Additional low-impact, baseline-aware DAST checks."""

from __future__ import annotations

import re
import uuid
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from engine.confidence import is_match, score
from engine.http_client import HttpClient
from engine.models import Endpoint, Finding

_URL_PARAM = re.compile(r"(?:url|uri|redirect|return|next|dest|continue)", re.I)
_PATH_PARAM = re.compile(r"(?:file|path|page|template|folder|dir|document|name)", re.I)
_SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub personal access token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("Stripe live secret key", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("JWT token", re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b")),
]
_DEBUG_PATTERNS = [
    ("Python traceback", re.compile(r"Traceback \(most recent call last\):", re.I)),
    ("Java stack trace", re.compile(r"\bat [\w.$]+\([\w.]+:\d+\)")),
    ("ASP.NET exception detail", re.compile(r"(?:Server Error in ['\"]?/['\"]? Application|System\.[\w.]+Exception)", re.I)),
]


def _url_with_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    values = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = [(key, value if key == name else existing) for key, existing in values]
    if not any(key == name for key, _ in replaced):
        replaced.append((name, value))
    return urlunparse(parsed._replace(query=urlencode(replaced)))


def _finding(*, template: str, title: str, severity: str, url: str, parameter: str | None, payload: str | None, evidence: str, cwe: str, cvss: float, remediation: str, confidence: float) -> Finding:
    return Finding(id=str(uuid.uuid4()), template_id=template, title=title, severity=severity, url=url, parameter=parameter, payload=payload, evidence=evidence[:500], cwe=cwe, owasp="A03:2021 – Injection", cvss_score=cvss, confidence=confidence, remediation=remediation)


async def detect_open_redirect(client: HttpClient, endpoint: Endpoint) -> Finding | None:
    """Confirm an external 3xx Location header; do not follow the redirect."""
    candidates = [p for p in endpoint.params if _URL_PARAM.search(p)]
    candidates += [f.name for f in endpoint.form_fields if f.input_type == "url_field"]
    if not candidates:
        return None
    nonce = uuid.uuid4().hex[:10]
    payload = f"https://probe.invalid/{nonce}"
    for parameter in candidates:
        try:
            if parameter in endpoint.params:
                response = await client.get(_url_with_param(endpoint.url, parameter, payload), follow_redirects=False)
            else:
                data = {field.name: field.default_value for field in endpoint.form_fields}
                data[parameter] = payload
                response = await (client.get(endpoint.url, params=data, follow_redirects=False) if endpoint.method == "GET" else client.request(endpoint.method, endpoint.url, data=data, follow_redirects=False))
        except Exception:
            continue
        location = response.headers.get("location", "")
        if response.is_redirect and location.startswith(payload):
            return _finding(template="open-redirect", title="Open Redirect", severity="medium", url=endpoint.url, parameter=parameter, payload=payload, evidence=f"{response.status_code} Location: {location}", cwe="CWE-601", cvss=6.1, confidence=0.9, remediation="Validate redirect destinations against a server-side allow-list of trusted relative paths or domains. Never redirect directly to a user-supplied URL.")
    return None


async def detect_path_traversal(client: HttpClient, endpoint: Endpoint) -> Finding | None:
    candidates = [p for p in endpoint.params if _PATH_PARAM.search(p)]
    candidates += [f.name for f in endpoint.form_fields if _PATH_PARAM.search(f.name)]
    if not candidates:
        return None
    try:
        baseline = await client.record_baseline(endpoint.url)
    except Exception:
        return None
    payload = "../../../../etc/passwd"
    for parameter in candidates:
        try:
            if parameter in endpoint.params:
                response = await client.get(_url_with_param(endpoint.url, parameter, payload))
            else:
                data = {field.name: field.default_value for field in endpoint.form_fields}
                data[parameter] = payload
                response = await (client.get(endpoint.url, params=data) if endpoint.method == "GET" else client.request(endpoint.method, endpoint.url, data=data))
        except Exception:
            continue
        matched = is_match(baseline, response.text, response.status_code, "regex", r"root:x:0:0:")
        if matched:
            return _finding(template="path-traversal", title="Path Traversal / Local File Inclusion", severity="high", url=endpoint.url, parameter=parameter, payload=payload, evidence=response.text, cwe="CWE-22", cvss=8.1, confidence=score(2), remediation="Treat user input as a file identifier, not a filesystem path. Resolve it against a fixed base directory and reject values that escape that directory after canonicalisation.")
    return None


async def detect_ssti(client: HttpClient, endpoint: Endpoint) -> Finding | None:
    candidates = [f.name for f in endpoint.form_fields if f.input_type in {"generic_text", "search_field"}] + endpoint.params
    if not candidates:
        return None
    try:
        baseline = await client.record_baseline(endpoint.url)
    except Exception:
        return None
    for parameter in candidates:
        signals = 0
        for expression, expected in (("{{7*7}}", "49"), ("{{8*8}}", "64")):
            try:
                if parameter in endpoint.params:
                    response = await client.get(_url_with_param(endpoint.url, parameter, expression))
                else:
                    data = {field.name: field.default_value for field in endpoint.form_fields}
                    data[parameter] = expression
                    response = await (client.get(endpoint.url, params=data) if endpoint.method == "GET" else client.request(endpoint.method, endpoint.url, data=data))
            except Exception:
                continue
            # A help page can legitimately contain 49/64 (including the
            # literal math example), so compare occurrences rather than only
            # asking whether the number exists. Two independent calculations
            # must each add a new response signal.
            if response.text.count(expected) > baseline.text.count(expected):
                signals += 1
        if signals >= 2:
            return _finding(template="ssti-math-probe", title="Server-Side Template Injection", severity="high", url=endpoint.url, parameter=parameter, payload="{{7*7}} / {{8*8}}", evidence="Two independent template math probes evaluated in the response.", cwe="CWE-1336", cvss=8.2, confidence=score(signals), remediation="Do not compile or evaluate templates constructed from user input. Keep template source server-controlled and pass user values only through the template engine's data-binding API.")
    return None


async def detect_sensitive_data(client: HttpClient, url: str) -> list[Finding]:
    """Passive check: never injects a payload or follows a new scope."""
    try:
        response = await client.get(url)
    except Exception:
        return []
    findings: list[Finding] = []
    for label, pattern in _SECRET_PATTERNS:
        match = pattern.search(response.text)
        if match:
            findings.append(_finding(template="sensitive-data-exposure", title=f"Exposed {label}", severity="high", url=url, parameter=None, payload=None, evidence=f"Detected {label}; value redacted.", cwe="CWE-200", cvss=7.5, confidence=0.9, remediation="Remove secrets from responses and source control, rotate the exposed credential immediately, and load secrets from a managed secret store at runtime."))
    return findings


async def detect_debug_disclosure(client: HttpClient, url: str) -> list[Finding]:
    """Passively report server diagnostics or directory indexes in responses."""
    try:
        response = await client.get(url)
    except Exception:
        return []
    findings: list[Finding] = []
    for label, pattern in _DEBUG_PATTERNS:
        if pattern.search(response.text):
            findings.append(_finding(template="debug-error-disclosure", title=f"Exposed {label}", severity="medium", url=url, parameter=None, payload=None, evidence=f"Detected {label} in the HTTP response.", cwe="CWE-209", cvss=5.3, confidence=0.9, remediation="Return a generic error page to clients and log detailed exceptions only on the server. Disable debug mode in deployed environments."))
    if re.search(r"<(?:title|h1)>\s*Index of /", response.text, re.I):
        findings.append(_finding(template="directory-listing", title="Directory Listing Enabled", severity="medium", url=url, parameter=None, payload=None, evidence="The response appears to be an automatically generated directory index.", cwe="CWE-548", cvss=5.3, confidence=0.9, remediation="Disable automatic directory listing in the web server and explicitly define index resources for served directories."))
    return findings


async def detect_cors_misconfiguration(client: HttpClient, url: str) -> Finding | None:
    """Check whether a target reflects an arbitrary Origin with credentials."""
    probe_origin = "https://probe.invalid"
    try:
        response = await client.get(url, headers={"Origin": probe_origin})
    except Exception:
        return None
    allow_origin = response.headers.get("access-control-allow-origin", "")
    allow_credentials = response.headers.get("access-control-allow-credentials", "")
    if allow_origin == probe_origin and allow_credentials.lower() == "true":
        return _finding(template="cors-origin-reflection", title="CORS Allows Arbitrary Credentialed Origin", severity="high", url=url, parameter=None, payload=probe_origin, evidence="The response reflected the supplied Origin and enabled credentialed cross-origin requests.", cwe="CWE-942", cvss=8.1, confidence=0.9, remediation="Use a fixed allow-list of trusted origins. Do not reflect the Origin header, and only enable Access-Control-Allow-Credentials where it is strictly required.")
    return None


async def detect_cookie_security(client: HttpClient, url: str) -> list[Finding]:
    """Check session-like cookies for HTTPS, HttpOnly, and SameSite attributes."""
    try:
        response = await client.get(url)
    except Exception:
        return []
    cookies = response.headers.get_list("set-cookie")
    findings: list[Finding] = []
    is_https = urlparse(url).scheme == "https"
    for cookie in cookies:
        name = cookie.split("=", 1)[0].strip()
        lower = cookie.lower()
        session_like = bool(re.search(r"(?:session|sess|auth|token|jwt|sid)", name, re.I))
        if not session_like:
            continue
        if is_https and "secure" not in lower:
            findings.append(_finding(template="insecure-cookie", title="Session Cookie Missing Secure Flag", severity="medium", url=url, parameter=name, payload=None, evidence=f"Cookie '{name}' is set without the Secure attribute.", cwe="CWE-614", cvss=5.3, confidence=1.0, remediation="Set the Secure attribute on every session cookie so browsers send it only over HTTPS."))
        if "httponly" not in lower:
            findings.append(_finding(template="insecure-cookie", title="Session Cookie Missing HttpOnly Flag", severity="medium", url=url, parameter=name, payload=None, evidence=f"Cookie '{name}' is set without the HttpOnly attribute.", cwe="CWE-1004", cvss=5.3, confidence=1.0, remediation="Set HttpOnly on session cookies so client-side scripts cannot read them if an XSS issue occurs."))
        if "samesite" not in lower:
            findings.append(_finding(template="insecure-cookie", title="Session Cookie Missing SameSite Attribute", severity="low", url=url, parameter=name, payload=None, evidence=f"Cookie '{name}' does not declare a SameSite policy.", cwe="CWE-1275", cvss=4.3, confidence=1.0, remediation="Set SameSite=Lax or SameSite=Strict on session cookies, using SameSite=None; Secure only when a cross-site flow is necessary."))
    return findings


async def detect_dangerous_http_methods(client: HttpClient, url: str) -> Finding | None:
    """Use a safe OPTIONS request to identify exposed TRACE support."""
    try:
        response = await client.request("OPTIONS", url)
    except Exception:
        return None
    allowed = response.headers.get("allow", "")
    if "TRACE" in {method.strip().upper() for method in allowed.split(",")}:
        return _finding(template="dangerous-http-method", title="TRACE HTTP Method Enabled", severity="medium", url=url, parameter=None, payload=None, evidence=f"Allow: {allowed}", cwe="CWE-749", cvss=5.3, confidence=1.0, remediation="Disable TRACE at the reverse proxy and application server unless it is explicitly required for controlled diagnostics.")
    return None
