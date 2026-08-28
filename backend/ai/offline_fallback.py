"""
ProbeX AI – offline fallback remediation library.

When the Gemini API is unavailable (no key, quota exhausted, network error)
this module provides curated, static remediation snippets keyed by CWE
identifier so the UI always shows *something* useful.

Extend this dict as new detector templates are added.
"""

from __future__ import annotations

# Map CWE ID (e.g. "CWE-79") → remediation text.
OFFLINE_REMEDIATION: dict[str, str] = {
    "CWE-79": (
        "Encode all user-supplied data before inserting it into HTML contexts. "
        "Use a context-aware output-encoding library (e.g. DOMPurify for JS, "
        "html.escape() for Python templates). Set the Content-Security-Policy "
        "header to restrict inline script execution."
    ),
    "CWE-89": (
        "Use parameterised queries or prepared statements for all database "
        "interactions. Never concatenate user input into SQL strings. "
        "Apply the principle of least privilege to database accounts."
    ),
    "CWE-601": (
        "Validate redirect targets against an allowlist of known-safe URLs. "
        "Reject any redirect that leads to an external origin not explicitly "
        "permitted by your application."
    ),
    "CWE-918": (
        "Validate and restrict URLs that the server fetches on behalf of the "
        "client. Block requests to loopback addresses, link-local ranges, and "
        "internal cloud metadata endpoints (169.254.169.254)."
    ),
    "CWE-693": (
        "Add the following HTTP security headers to all responses: "
        "Content-Security-Policy, X-Content-Type-Options: nosniff, "
        "X-Frame-Options: DENY, Strict-Transport-Security (HTTPS only), "
        "Referrer-Policy: no-referrer."
    ),
}

DEFAULT_REMEDIATION = (
    "Review the OWASP Top 10 guidance and CWE entry for this vulnerability "
    "class. Apply defence-in-depth: validate all inputs, encode all outputs, "
    "enforce least privilege, and add relevant security headers."
)


def get_offline_remediation(cwe: str) -> str:
    """
    Return a static remediation string for the given CWE identifier.

    Falls back to ``DEFAULT_REMEDIATION`` for unknown CWE IDs.
    """
    return OFFLINE_REMEDIATION.get(cwe, DEFAULT_REMEDIATION)
