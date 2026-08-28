"""
ProbeX AI – Gemini-powered remediation generator.

Sends a structured prompt to the Gemini API and returns context-aware
remediation advice for a given finding.  Falls back to the static template
remediation when the API key is absent or the call fails.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


async def generate_remediation(
    finding_title: str,
    finding_evidence: str,
    static_remediation: str,
    gemini_api_key: str = "",
) -> str:
    """
    Return AI-generated remediation text for a finding.

    Parameters
    ----------
    finding_title:
        Human-readable title of the vulnerability (e.g. 'Reflected XSS').
    finding_evidence:
        Raw HTTP response snippet demonstrating the issue.
    static_remediation:
        Fallback static guidance — returned as-is when AI is unavailable.
    gemini_api_key:
        Google Generative AI key.  If empty, ``static_remediation`` is returned.

    Returns
    -------
    str
        AI-generated remediation, or ``static_remediation`` on failure.
    """
    if not gemini_api_key:
        logger.debug("GEMINI_API_KEY not set — using static remediation.")
        return static_remediation

    try:
        import google.generativeai as genai  # type: ignore[import]
        from ai.prompts import build_remediation_prompt

        genai.configure(api_key=gemini_api_key)
        model = genai.GenerativeModel("gemini-1.5-flash")
        prompt = build_remediation_prompt(finding_title, finding_evidence, static_remediation)
        response = model.generate_content(prompt)
        return response.text.strip()

    except Exception as exc:  # noqa: BLE001
        logger.warning("AI remediation failed (%s) — falling back to static.", exc)
        return static_remediation
