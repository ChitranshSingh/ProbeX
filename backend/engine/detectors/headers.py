"""
ProbeX Engine â€“ security-headers detector.

Makes one clean GET request per page (no payload injection) and inspects the
response headers for the presence of mandatory security headers.  Missing
headers are reported as findings with appropriate severity.

Checks performed
----------------
- Content-Security-Policy            â†’ low severity
- X-Frame-Options                    â†’ low severity
- X-Content-Type-Options             â†’ info severity
- Strict-Transport-Security          â†’ medium severity (HTTPS targets only)

Zero FastAPI / SQLModel imports â€” this module must stay standalone.
"""

from __future__ import annotations

import uuid
from urllib.parse import urlparse

from engine.http_client import HttpClient
from engine.models import Finding

# ---------------------------------------------------------------------------
# Header check specifications
# ---------------------------------------------------------------------------

# Each entry: (header_name, severity, cwe, cvss, title, remediation)
_HEADER_CHECKS: list[tuple[str, str, str, float, str, str]] = [
    (
        "content-security-policy",
        "low",
        "CWE-693",
        4.3,
        "Missing Content-Security-Policy Header",
        (
            "Add a Content-Security-Policy response header to all pages. "
            "Start with 'Content-Security-Policy: default-src \\'self\\';' and "
            "progressively tighten it. A strict CSP dramatically reduces the "
            "blast radius of XSS vulnerabilities."
        ),
    ),
    (
        "x-frame-options",
        "low",
        "CWE-693",
        4.3,
        "Missing X-Frame-Options Header",
        (
            "Add 'X-Frame-Options: DENY' (or 'SAMEORIGIN') to all HTTP responses "
            "to prevent clickjacking attacks. Alternatively, use the "
            "'frame-ancestors' CSP directive for more granular control."
        ),
    ),
    (
        "x-content-type-options",
        "info",
        "CWE-693",
        3.1,
        "Missing X-Content-Type-Options Header",
        (
            "Add 'X-Content-Type-Options: nosniff' to all HTTP responses. "
            "This prevents browsers from MIME-sniffing a response away from the "
            "declared content-type, which can lead to script injection."
        ),
    ),
]

_HSTS_CHECK: tuple[str, str, str, float, str, str] = (
    "strict-transport-security",
    "medium",
    "CWE-319",
    5.9,
    "Missing Strict-Transport-Security Header",
    (
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
        "to all HTTPS responses. This tells browsers to always use HTTPS for "
        "this domain and prevents protocol-downgrade attacks."
    ),
)

_OWASP_A05 = "A05:2021 â€“ Security Misconfiguration"
_TEMPLATE_ID = "missing-security-header"


# ---------------------------------------------------------------------------
# Async detector
# ---------------------------------------------------------------------------


async def check_headers(
    client: HttpClient,
    url: str,
) -> list[Finding]:
    """
    Inspect the security headers of a single GET response for ``url``.

    Makes exactly one HTTP request (no payload injection).

    Parameters
    ----------
    client:
        Shared ``HttpClient`` instance (caller owns lifecycle).
    url:
        Absolute URL of the page to inspect.

    Returns
    -------
    list[Finding]
        One ``Finding`` per missing security header.  Empty list if all
        expected headers are present.
    """
    try:
        resp = await client.get(url)
    except Exception:
        return []

    response_headers = {k.lower(): v for k, v in resp.headers.items()}
    findings: list[Finding] = []
    is_https = urlparse(url).scheme.lower() == "https"

    # ---- Standard header checks ----
    for header_name, severity, cwe, cvss, title, remediation in _HEADER_CHECKS:
        if header_name not in response_headers:
            findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    template_id=_TEMPLATE_ID,
                    title=title,
                    severity=severity,
                    url=url,
                    parameter=None,
                    payload=None,
                    evidence=(
                        f"HTTP response did not include a '{header_name}' header.\n"
                        f"Response headers present: {', '.join(sorted(response_headers.keys()))}"
                    ),
                    cwe=cwe,
                    owasp=_OWASP_A05,
                    cvss_score=cvss,
                    confidence=0.97,  # header absence is deterministic but policy-dependent
                    remediation=remediation,
                )
            )

    # ---- HSTS check (HTTPS only) ----
    if is_https:
        header_name, severity, cwe, cvss, title, remediation = _HSTS_CHECK
        if header_name not in response_headers:
            findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    template_id=_TEMPLATE_ID,
                    title=title,
                    severity=severity,
                    url=url,
                    parameter=None,
                    payload=None,
                    evidence=(
                        f"HTTPS response did not include a '{header_name}' header. "
                        "Browsers may be vulnerable to protocol-downgrade attacks."
                    ),
                    cwe=cwe,
                    owasp=_OWASP_A05,
                    cvss_score=cvss,
                    confidence=0.95,
                    remediation=remediation,
                )
            )

    return findings

