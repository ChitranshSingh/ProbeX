"""
Tests for the AI remediation layer.

Coverage
--------
- build_remediation_prompt: structure, required sections, evidence clipping.
- get_offline_fallback: template_id resolution, CWE fallback, default fallback.
- get_ai_remediation: offline path (no key), timeout path, API-error path.

Design
------
All tests that exercise get_ai_remediation() use monkeypatching to avoid
any real network call.  The key property being tested is that NO exception
ever surfaces from get_ai_remediation() — it must always return a non-empty
string.
"""

from __future__ import annotations

import asyncio
import dataclasses
from typing import Optional
from unittest.mock import AsyncMock, patch, MagicMock

import pytest


# ---------------------------------------------------------------------------
# Minimal Finding stub
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class _Finding:
    id: str = "test-finding-uuid"
    template_id: str = "xss-reflected"
    title: str = "Reflected Cross-Site Scripting"
    url: str = "http://target.example/search?q=test"
    parameter: Optional[str] = "q"
    payload: Optional[str] = "<script>alert(1)</script>"
    evidence: str = (
        "GET /search?q=<script>alert(1)</script> HTTP/1.1\r\n"
        "...\r\n"
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n\r\n"
        "<html>Results for: <script>alert(1)</script></html>"
    )
    cwe: str = "CWE-79"
    owasp: str = "A03:2021 – Injection"
    cvss_score: float = 6.1
    confidence: float = 0.9
    remediation: str = "Apply context-aware output encoding."
    ai_remediation: Optional[str] = None
    is_example: bool = False


# ===========================================================================
# prompts.py
# ===========================================================================

class TestBuildRemediationPrompt:
    def test_returns_string(self):
        from ai.prompts import build_remediation_prompt
        result = build_remediation_prompt(_Finding())
        assert isinstance(result, str) and len(result) > 0

    def test_contains_four_section_headings(self):
        from ai.prompts import build_remediation_prompt
        result = build_remediation_prompt(_Finding())
        assert "What this means" in result
        assert "How an attacker could use this" in result
        assert "How to fix it" in result
        assert "One code example" in result

    def test_contains_url_and_parameter(self):
        from ai.prompts import build_remediation_prompt
        result = build_remediation_prompt(_Finding())
        assert "http://target.example/search?q=test" in result
        assert "q" in result

    def test_contains_payload(self):
        from ai.prompts import build_remediation_prompt
        result = build_remediation_prompt(_Finding())
        assert "<script>alert(1)</script>" in result

    def test_evidence_clipped_to_300_chars(self):
        from ai.prompts import build_remediation_prompt
        f = _Finding(evidence="A" * 1000)
        result = build_remediation_prompt(f)
        # Only the first 300 chars of evidence should appear
        assert "A" * 300 in result
        # The 301st+ chars must not appear as-is (they are clipped)
        assert "A" * 301 not in result

    def test_contains_cwe_and_owasp(self):
        from ai.prompts import build_remediation_prompt
        result = build_remediation_prompt(_Finding())
        assert "CWE-79" in result
        assert "A03:2021" in result

    def test_graceful_with_missing_fields(self):
        """Prompt builder must not raise when optional fields are None."""
        from ai.prompts import build_remediation_prompt
        f = _Finding(parameter=None, payload=None, evidence="")
        result = build_remediation_prompt(f)
        assert "What this means" in result


# ===========================================================================
# offline_fallback.py
# ===========================================================================

class TestOfflineFallback:
    def test_template_id_hit(self):
        from ai.offline_fallback import get_offline_fallback
        result = get_offline_fallback("xss-reflected", "CWE-79")
        assert "What this means" in result
        assert "How an attacker could use this" in result
        assert "How to fix it" in result
        assert "One code example" in result

    def test_sqli_error_fallback(self):
        from ai.offline_fallback import get_offline_fallback
        result = get_offline_fallback("sqli-error", "CWE-89")
        assert "parameterised" in result.lower() or "parameterized" in result.lower()

    def test_security_headers_fallback(self):
        from ai.offline_fallback import get_offline_fallback
        result = get_offline_fallback("security-headers", "CWE-693")
        assert "Content-Security-Policy" in result

    def test_cwe_fallback_when_no_template_hit(self):
        """Unknown template_id should fall back to CWE lookup."""
        from ai.offline_fallback import get_offline_fallback
        result = get_offline_fallback("unknown-template", "CWE-79")
        assert "What this means" in result

    def test_default_fallback_when_both_unknown(self):
        """Completely unknown template + CWE should still return useful text."""
        from ai.offline_fallback import get_offline_fallback
        result = get_offline_fallback("novel-detector", "CWE-99999")
        assert len(result) > 50
        assert "What this means" in result

    def test_all_template_ids_have_four_sections(self):
        from ai.offline_fallback import OFFLINE_BY_TEMPLATE
        for tid, text in OFFLINE_BY_TEMPLATE.items():
            for section in ("What this means", "How an attacker could use this", "How to fix it", "One code example"):
                assert section in text, f"Template '{tid}' missing section: {section}"

    def test_never_returns_empty_string(self):
        from ai.offline_fallback import get_offline_fallback
        assert get_offline_fallback("", "") != ""


# ===========================================================================
# remediation.py — get_ai_remediation()
# This is the critical "no-exception" test.
# ===========================================================================

class TestGetAiRemediation:

    def test_offline_when_no_api_key(self):
        """
        KEY SCENARIO: GEMINI_API_KEY is unset (empty string from settings).

        The function must:
          - Return a non-empty string.
          - Return a complete 4-section offline fallback.
          - Never raise.
        """
        with patch("ai.remediation._get_api_key", return_value=""):
            from ai.remediation import get_ai_remediation
            result = asyncio.get_event_loop().run_until_complete(
                get_ai_remediation(_Finding())
            )

        assert isinstance(result, str)
        assert len(result) > 50
        assert "What this means" in result, (
            "Offline fallback must contain 'What this means' section"
        )
        assert "How to fix it" in result

    def test_offline_fallback_text_is_human_readable(self):
        """The offline fallback for xss-reflected must read like real guidance."""
        with patch("ai.remediation._get_api_key", return_value=""):
            from ai.remediation import get_ai_remediation
            result = asyncio.get_event_loop().run_until_complete(
                get_ai_remediation(_Finding(template_id="xss-reflected"))
            )
        # Should mention encoding or escaping
        assert any(w in result.lower() for w in ("encod", "escap", "csp", "content-security")), \
            "XSS offline fallback must mention encoding/CSP"

    def test_offline_fallback_for_sqli(self):
        """sqli-error offline fallback must mention parameterised queries."""
        with patch("ai.remediation._get_api_key", return_value=""):
            from ai.remediation import get_ai_remediation
            result = asyncio.get_event_loop().run_until_complete(
                get_ai_remediation(_Finding(template_id="sqli-error", cwe="CWE-89"))
            )
        assert any(w in result.lower() for w in ("parameteris", "parameterize", "prepared")), \
            "SQLi offline fallback must mention parameterised queries"

    def test_falls_back_on_timeout(self):
        """When the Gemini call times out, offline fallback is returned, no exception."""
        async def _slow(*_args, **_kwargs):
            await asyncio.sleep(99)

        with patch("ai.remediation._get_api_key", return_value="fake-key"), \
             patch("ai.remediation._call_gemini", side_effect=asyncio.TimeoutError()):
            from ai.remediation import get_ai_remediation
            result = asyncio.get_event_loop().run_until_complete(
                get_ai_remediation(_Finding())
            )

        assert isinstance(result, str) and len(result) > 50

    def test_falls_back_on_api_exception(self):
        """On any API exception, offline fallback is returned, no exception propagated."""
        with patch("ai.remediation._get_api_key", return_value="fake-key"), \
             patch("ai.remediation._call_gemini", side_effect=Exception("rate limited")):
            from ai.remediation import get_ai_remediation
            result = asyncio.get_event_loop().run_until_complete(
                get_ai_remediation(_Finding())
            )

        assert isinstance(result, str) and len(result) > 50

    def test_returns_gemini_text_on_success(self):
        """When Gemini succeeds, its text is returned verbatim."""
        expected = "**What this means**\nTest AI output."

        async def _mock_call(_api_key, _finding):
            return expected

        with patch("ai.remediation._get_api_key", return_value="fake-key"), \
             patch("ai.remediation._call_gemini", new=_mock_call):
            from ai.remediation import get_ai_remediation
            result = asyncio.get_event_loop().run_until_complete(
                get_ai_remediation(_Finding())
            )

        assert result == expected

    def test_never_raises_with_malformed_finding(self):
        """Even a completely empty object must not cause get_ai_remediation to raise."""
        class Empty:
            pass

        with patch("ai.remediation._get_api_key", return_value=""):
            from ai.remediation import get_ai_remediation
            result = asyncio.get_event_loop().run_until_complete(
                get_ai_remediation(Empty())
            )

        assert isinstance(result, str) and len(result) > 0
