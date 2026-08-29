"""
ProbeX AI – Gemini-powered remediation generator.

Public API
----------
``get_ai_remediation(finding)`` is the single entry point.  It:

1. Checks for a ``GEMINI_API_KEY`` in settings.
2. Builds a structured prompt via ``ai.prompts.build_remediation_prompt``.
3. Calls ``gemini-2.5-flash`` with a hard 5-second asyncio timeout.
4. On **any** failure (missing key, timeout, network error, rate-limit,
   API exception) falls through to ``ai.offline_fallback.get_offline_fallback``
   and returns a complete, readable static response.

This function is guaranteed never to raise — callers in the scan pipeline
can await it and discard the result on failure without any try/except.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)

_GEMINI_TIMEOUT_S = 5.0
_MODEL_NAME       = "gemini-2.5-flash"


async def get_ai_remediation(finding: Any) -> str:
    """
    Return AI-generated remediation advice for a finding.

    Guaranteed to return a non-empty string and to **never raise**.

    Parameters
    ----------
    finding:
        Any object exposing standard Finding fields (``template_id``,
        ``title``, ``url``, ``parameter``, ``payload``, ``evidence``,
        ``cwe``, ``owasp``, ``cvss_score``, ``remediation``).
        Both engine dataclasses and Pydantic schema objects are accepted.

    Returns
    -------
    str
        Gemini-generated text, or the offline fallback on any failure.
    """
    template_id = getattr(finding, "template_id", "") or ""
    cwe         = getattr(finding, "cwe",         "") or ""

    # Fast-path: skip the API call entirely if no key is configured.
    api_key = _get_api_key()
    if not api_key:
        logger.debug("GEMINI_API_KEY not set — using offline fallback for %s", template_id)
        return _offline(template_id, cwe)

    try:
        result = await asyncio.wait_for(
            _call_gemini(api_key, finding),
            timeout=_GEMINI_TIMEOUT_S,
        )
        logger.debug("AI remediation generated for %s (%d chars)", template_id, len(result))
        return result

    except asyncio.TimeoutError:
        logger.warning(
            "Gemini call timed out after %.1fs for %s — offline fallback",
            _GEMINI_TIMEOUT_S, template_id,
        )
        return _offline(template_id, cwe)

    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Gemini call failed for %s (%s: %s) — offline fallback",
            template_id, type(exc).__name__, exc,
        )
        return _offline(template_id, cwe)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_api_key() -> str:
    """Return the Gemini API key from settings, or '' if absent/blank."""
    try:
        from app.core.config import settings
        key = getattr(settings, "gemini_api_key", None) or ""
        return key.strip()
    except Exception:
        return ""


async def _call_gemini(api_key: str, finding: Any) -> str:
    """
    Make the actual Gemini API call.

    Runs in a thread-pool executor because ``google.generativeai`` is a
    synchronous library.  The outer ``wait_for`` enforces the 5-second wall-
    clock cap regardless of how long the executor waits.
    """
    from ai.prompts import build_remediation_prompt

    prompt = build_remediation_prompt(finding)

    loop = asyncio.get_running_loop()
    text = await loop.run_in_executor(None, _sync_gemini_call, api_key, prompt)
    return text


def _sync_gemini_call(api_key: str, prompt: str) -> str:
    """Synchronous Gemini call — runs inside a thread-pool executor."""
    import google.generativeai as genai  # type: ignore[import]

    genai.configure(api_key=api_key)
    model    = genai.GenerativeModel(_MODEL_NAME)
    response = model.generate_content(prompt)
    return response.text.strip()


def _offline(template_id: str, cwe: str) -> str:
    """Return the best available offline fallback — never empty."""
    from ai.offline_fallback import get_offline_fallback
    return get_offline_fallback(template_id, cwe)
