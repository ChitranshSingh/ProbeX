"""
ProbeX AI – prompt builder for Gemini remediation calls.

Design goals
------------
- Pass all the context a senior engineer needs: vuln type, exact URL,
  parameter, payload, and a clipped evidence excerpt.
- Instruct the model to respond in exactly four labelled sections so the
  dashboard can display structured output.
- Hard-cap the response to ~150 words so it fits cleanly in the UI card
  without scrolling.
- Keep the prompt stable enough that unit tests can assert on its structure
  without making live API calls.
"""

from __future__ import annotations

from typing import Any


def build_remediation_prompt(finding: Any) -> str:
    """
    Build a Gemini prompt for a single security finding.

    The prompt instructs the model to return **exactly four short sections**:

    1. What this means
    2. How an attacker could use this
    3. How to fix it  (numbered steps)
    4. One code example

    Output is capped at ~150 words so it renders cleanly in the dashboard
    card without a scrollbar.

    Parameters
    ----------
    finding:
        Any object (engine dataclass or Pydantic schema) that exposes the
        standard Finding fields: ``template_id``, ``title``, ``url``,
        ``parameter``, ``payload``, ``evidence``, ``cwe``, ``owasp``,
        ``cvss_score``, ``remediation``.

    Returns
    -------
    str
        A formatted prompt string ready to send to the Gemini API.
    """
    # --- Extract fields defensively ----------------------------------------
    title       = getattr(finding, "title",       "Unknown vulnerability")
    template_id = getattr(finding, "template_id", "unknown")
    url         = getattr(finding, "url",         "N/A")
    parameter   = getattr(finding, "parameter",   None) or "N/A"
    payload     = getattr(finding, "payload",     None) or "N/A"
    evidence    = getattr(finding, "evidence",    "") or ""
    cwe         = getattr(finding, "cwe",         "")
    owasp       = getattr(finding, "owasp",       "")
    cvss        = getattr(finding, "cvss_score",  0.0)
    static_fix  = getattr(finding, "remediation", "") or ""

    # Clip evidence to ~300 chars to keep the prompt token-light
    evidence_excerpt = evidence[:300].strip()
    if len(evidence) > 300:
        evidence_excerpt += " …[truncated]"

    return f"""You are a senior application-security engineer writing developer-facing remediation guidance. Be concise, practical, and code-focused.

## Finding context
- **Vulnerability type**: {title} (template: {template_id})
- **URL**: {url}
- **Parameter**: {parameter}
- **Payload used**: {payload}
- **CWE**: {cwe} | **OWASP**: {owasp} | **CVSS**: {cvss}

## Evidence excerpt (≤300 chars)
```
{evidence_excerpt}
```

## Existing static guidance (baseline — do not simply copy this)
{static_fix}

## Your task
Respond in **exactly four sections** with these exact headings, each kept to 2–4 sentences or steps:

**What this means**
(Plain-English explanation of what the scanner found.)

**How an attacker could use this**
(Concrete, realistic abuse scenario — no jargon.)

**How to fix it**
1. (First concrete step.)
2. (Second concrete step.)
3. (Third concrete step, if needed.)

**One code example**
(A short before/after snippet — pseudocode or the relevant language is fine.)

Keep the **total response under 150 words**. Do not repeat the vulnerability name as a top-level heading. Do not add any section not listed above."""
