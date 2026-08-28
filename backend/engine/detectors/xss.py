"""
ProbeX Engine – XSS detector.

Two-stage detection
-------------------
1. **Inject** a payload containing a unique nonce into each eligible parameter.
2. **Verify via DOM parsing** that the nonce sits inside a real ``<script>``
   tag or unescaped event-handler attribute — NOT inside a text node (meaning
   it was safely HTML-escaped) and NOT inside an HTML comment.

This DOM-based verification is what separates ProbeX from naive scanners that
simply check ``if "<script>" in response.text``.  A properly escaped response
will contain ``&lt;script&gt;`` in the body text, but BeautifulSoup will
correctly report it as a text node, not an executable script element.

Zero FastAPI / SQLModel imports — this module must stay standalone.
"""

from __future__ import annotations

import random
import string
import uuid
from typing import Optional

from bs4 import BeautifulSoup, Comment

from engine.confidence import MINIMUM_CONFIDENCE, is_match, score
from engine.http_client import HttpClient
from engine.models import Baseline, Endpoint, Finding

# ---------------------------------------------------------------------------
# Event-handler attributes that can execute JavaScript when unescaped.
# ---------------------------------------------------------------------------
_EVENT_HANDLER_ATTRS: frozenset[str] = frozenset(
    {
        "onload", "onerror", "onclick", "onmouseover", "onfocus", "onblur",
        "onchange", "onsubmit", "onkeydown", "onkeyup", "onkeypress",
        "onmouseenter", "onmouseleave", "ondblclick", "oncontextmenu",
        "onabort", "oninput", "oninvalid", "onreset", "onresize",
        "onscroll", "ontoggle",
    }
)

# ---------------------------------------------------------------------------
# Input types the XSS detector targets.
# ---------------------------------------------------------------------------
_TARGET_INPUT_TYPES: frozenset[str] = frozenset({"generic_text", "search_field"})

# Finding metadata constants.
_SEVERITY = "high"
_CWE = "CWE-79"
_OWASP = "A03:2021 – Injection"
_CVSS = 6.1
_TEMPLATE_ID = "xss-reflected"
_REMEDIATION = (
    "Encode all user-supplied data before inserting it into HTML contexts. "
    "Use a context-aware output-encoding library (e.g. DOMPurify client-side, "
    "html.escape() / Jinja2 autoescape server-side). "
    "Enforce a strict Content-Security-Policy that prohibits unsafe-inline scripts."
)


# ---------------------------------------------------------------------------
# DOM-based XSS verification
# ---------------------------------------------------------------------------


def verify_unescaped(html: str, nonce: str) -> bool:
    """
    Return ``True`` iff ``nonce`` appears in a **browser-executable context**
    in the rendered DOM — i.e., inside a real ``<script>`` tag or as the value
    of an event-handler attribute.

    Return ``False`` (safely escaped / not present) when:

    - The nonce only appears inside a plain text node — meaning the ``<`` and
      ``>`` characters were HTML-encoded (``&lt;``, ``&gt;``) by the server.
    - The nonce appears only inside an HTML comment (``<!-- ... -->``).
    - The nonce is absent entirely from the page.

    Parameters
    ----------
    html:
        Raw HTML response body from the fuzzed request.
    nonce:
        Unique string injected as part of the XSS payload.  The nonce is
        generated per-request so it can never appear in the baseline.

    Returns
    -------
    bool
        ``True`` → confirmed XSS (nonce in executable DOM context).
        ``False`` → safely escaped or absent (not a true positive).
    """
    soup = BeautifulSoup(html, "html.parser")

    # ---- Check 1: nonce inside a <script> tag body ----
    for script_tag in soup.find_all("script"):
        # script_tag.string gives the raw text content of the script element.
        if script_tag.string and nonce in script_tag.string:
            return True
        # Also check concatenated strings (multiple NavigableString children).
        if nonce in (script_tag.get_text() or ""):
            return True

    # ---- Check 2: nonce inside an event-handler attribute ----
    for tag in soup.find_all(True):  # True → all tags
        for attr, value in tag.attrs.items():
            if attr.lower() in _EVENT_HANDLER_ATTRS:
                attr_text = value if isinstance(value, str) else " ".join(value)
                if nonce in attr_text:
                    return True

    # ---- Explicitly exclude: HTML comments ----
    # BeautifulSoup represents comments as Comment objects (subclass of str),
    # so we would have caught them in text nodes.  Nothing more to check.

    return False


def _make_nonce() -> str:
    """Generate a short unique alphanumeric nonce for a single XSS probe."""
    return "px_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=6))


# ---------------------------------------------------------------------------
# Async detector
# ---------------------------------------------------------------------------


async def detect_xss(
    client: HttpClient,
    endpoint: Endpoint,
) -> Optional[Finding]:
    """
    Probe ``endpoint`` for reflected XSS by injecting a nonce payload into
    each eligible parameter and verifying unescaped reflection in the DOM.

    Parameters
    ----------
    client:
        Shared ``HttpClient`` instance (caller owns lifecycle).
    endpoint:
        Crawled endpoint with ``form_fields`` populated by the crawler.
        Only fields with ``input_type`` in ``{"generic_text", "search_field"}``
        are targeted.

    Returns
    -------
    Finding | None
        A confirmed ``Finding`` on the first verified XSS, or ``None`` if no
        vulnerability is detected.
    """
    target_fields = [
        ff for ff in endpoint.form_fields
        if ff.input_type in _TARGET_INPUT_TYPES
    ]

    # Also check URL query parameters when there are no form fields.
    if not target_fields and not endpoint.params:
        return None

    # --- Record baseline once per endpoint ---
    try:
        baseline: Baseline = await client.record_baseline(endpoint.url)
    except Exception:
        return None

    nonce = _make_nonce()
    payload = f"<script>alert('{nonce}')</script>"

    # --- Probe form fields ---
    for field in target_fields:
        try:
            fuzzed_resp = await client.request(
                endpoint.method,
                endpoint.url,
                data={field.name: payload},
            )
        except Exception:
            continue

        fuzzed_text = fuzzed_resp.text

        # Differential check: nonce must be NEW (not in baseline).
        if not is_match(baseline, fuzzed_text, fuzzed_resp.status_code, "word", nonce):
            continue  # not reflected, or already present (impossible with a nonce, but be safe)

        # DOM check: nonce must be in an executable context, not a text node.
        if not verify_unescaped(fuzzed_text, nonce):
            continue  # reflected but safely HTML-escaped

        matcher_count = 2  # both is_match and verify_unescaped passed
        confidence = score(matcher_count)
        if confidence < MINIMUM_CONFIDENCE:
            continue

        return Finding(
            id=str(uuid.uuid4()),
            template_id=_TEMPLATE_ID,
            title="Reflected Cross-Site Scripting",
            severity=_SEVERITY,
            url=endpoint.url,
            parameter=field.name,
            payload=payload,
            evidence=fuzzed_text[:500],
            cwe=_CWE,
            owasp=_OWASP,
            cvss_score=_CVSS,
            confidence=confidence,
            remediation=_REMEDIATION,
        )

    # --- Probe URL query parameters (GET endpoints) ---
    for param in endpoint.params:
        try:
            fuzzed_resp = await client.get(
                endpoint.url,
                params={param: payload},
            )
        except Exception:
            continue

        fuzzed_text = fuzzed_resp.text

        if not is_match(baseline, fuzzed_text, fuzzed_resp.status_code, "word", nonce):
            continue

        if not verify_unescaped(fuzzed_text, nonce):
            continue

        confidence = score(2)
        if confidence < MINIMUM_CONFIDENCE:
            continue

        return Finding(
            id=str(uuid.uuid4()),
            template_id=_TEMPLATE_ID,
            title="Reflected Cross-Site Scripting",
            severity=_SEVERITY,
            url=endpoint.url,
            parameter=param,
            payload=payload,
            evidence=fuzzed_text[:500],
            cwe=_CWE,
            owasp=_OWASP,
            cvss_score=_CVSS,
            confidence=confidence,
            remediation=_REMEDIATION,
        )

    return None
