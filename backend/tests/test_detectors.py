"""
ProbeX – detector regression tests.

The two most important tests in this file are marked with a docstring that
begins "DEMO REGRESSION" — these are the proof that the false-positive layer
actually works and should be narrated out loud during any technical demo.

Run from the ``backend/`` directory::

    python -m pytest tests/test_detectors.py -v
"""

from __future__ import annotations

import asyncio
import html as html_module
import sys
import os
from datetime import datetime, timezone
from typing import Optional

# ---------------------------------------------------------------------------
# Path setup: ensure ``backend/`` is on sys.path.
# ---------------------------------------------------------------------------
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import httpx
import pytest
import respx

from engine.confidence import MINIMUM_CONFIDENCE, is_match, score
from engine.detectors.headers import check_headers
from engine.detectors.sqli import ERROR_SIGNATURES, detect_sqli_error
from engine.detectors.xss import detect_xss, verify_unescaped
from engine.http_client import HttpClient
from engine.models import Baseline, Endpoint, FormField, Finding, ScanResult
from engine.reporter import build_html, build_json, build_result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def run(coro):
    """Run an async coroutine synchronously."""
    return asyncio.get_event_loop().run_until_complete(coro)


def _endpoint(
    url: str = "http://target.local/form",
    method: str = "POST",
    fields: Optional[list[FormField]] = None,
    params: Optional[list[str]] = None,
) -> Endpoint:
    """Build a minimal Endpoint for testing."""
    fields = fields or [FormField(name="q", input_type="generic_text")]
    return Endpoint(
        url=url,
        method=method,
        form_fields=fields,
        input_types=list({f.input_type for f in fields}),
        params=params or [],
    )


def _baseline(text: str = "", status: int = 200) -> Baseline:
    return Baseline(status=status, text=text, elapsed_ms=50.0)


# ===========================================================================
#  DEMO REGRESSION #1 – SQLi false-positive defence
# ===========================================================================


class TestSQLiFalsePositiveDefence:
    """
    DEMO REGRESSION — narrate this in the demo:

    "Pages that already contain SQL error phrases in their normal response —
    for example, a developer blog that talks about SQL syntax — must NEVER be
    flagged as SQL Injection.  ProbeX's baseline confidence layer makes this
    impossible: is_match() returns False whenever the pattern was already
    present in the clean baseline response."
    """

    def test_page_always_contains_syntax_error_is_not_flagged(self):
        """
        DEMO REGRESSION #1 (SQLi false-positive).

        A mock page whose body ALWAYS contains "You have an error in your SQL
        syntax" — e.g. a blog post about debugging SQL — must produce
        detect_sqli_error() → None.
        """
        # The page content before ANY injection.
        page_body = (
            "<html><body>"
            "<h1>Debugging SQL: You have an error in your SQL syntax</h1>"
            "<p>Today I'll explain how MySQL error messages work...</p>"
            "</body></html>"
        )
        baseline = _baseline(text=page_body)

        # After injecting a single quote, the page body is identical.
        fuzzed_text = page_body  # server ignores the payload, returns same content

        # The signature that matches the static content.
        sig = "You have an error in your SQL syntax"

        result = is_match(baseline, fuzzed_text, 200, "regex", sig)

        assert result is False, (
            "CRITICAL false-positive: is_match() returned True for a pattern "
            "that was already present in the baseline. "
            "The SQLi detector would have flagged this page incorrectly."
        )

    @respx.mock
    def test_detect_sqli_returns_none_for_static_error_page(self):
        """
        DEMO REGRESSION #1 — full integration path.

        detect_sqli_error() must return None even when every request
        (baseline + fuzzed) returns a body containing SQL error phrases.
        """
        # Both baseline GET and fuzzed POST return the same error-containing body.
        error_body = (
            "<html><body>You have an error in your SQL syntax near '1'</body></html>"
        )

        respx.get("http://target.local/form").mock(
            return_value=httpx.Response(
                200,
                text=error_body,
                headers={"content-type": "text/html"},
            )
        )
        respx.post("http://target.local/form").mock(
            return_value=httpx.Response(
                200,
                text=error_body,  # ← same body; no NEW signal
                headers={"content-type": "text/html"},
            )
        )

        async def _run():
            async with HttpClient(max_retries=0) as client:
                ep = _endpoint()
                return await detect_sqli_error(client, ep)

        result = run(_run())

        assert result is None, (
            f"CRITICAL false-positive: detect_sqli_error() returned a Finding "
            f"for a page that already contained the SQL error phrase in its "
            f"baseline. Finding: {result}"
        )

    def test_new_sql_error_in_fuzzed_response_is_flagged(self):
        """
        Positive control: a signature that is NOT in the baseline but IS in the
        fuzzed response should be detected by is_match().
        """
        clean_baseline = _baseline(text="<html><body>Welcome to the store</body></html>")
        fuzzed = (
            "<html><body>You have an error in your SQL syntax near '\\'' "
            "at line 1</body></html>"
        )

        result = is_match(clean_baseline, fuzzed, 500, "regex",
                          "You have an error in your SQL syntax")

        assert result is True, (
            "is_match() returned False for a genuine new SQLi signal. "
            "The detector would miss a real vulnerability."
        )


# ===========================================================================
#  DEMO REGRESSION #2 – XSS false-positive defence (DOM-based)
# ===========================================================================


class TestXSSFalsePositiveDefence:
    """
    DEMO REGRESSION — narrate this in the demo:

    "A scanner that simply checks 'if <script> in response.text' will fire a
    false positive when the server HTML-escapes the payload. ProbeX uses
    BeautifulSoup to parse the DOM: if the nonce appears only inside a text
    node (i.e., it was escaped to &lt;script&gt;...), verify_unescaped()
    returns False and the finding is dropped."
    """

    def test_html_escaped_payload_is_not_flagged(self):
        """
        DEMO REGRESSION #2 (XSS false-positive).

        When the server HTML-escapes the injected payload, the response body
        will contain ``&lt;script&gt;alert('px_abc123')&lt;/script&gt;``.
        This is SAFE — the nonce lives in a text node, not in an executable
        script context.  verify_unescaped() must return False.
        """
        nonce = "px_abc123"
        # The server safely escaped our payload — it's in a <p> text node.
        html_safe_response = (
            "<html><body>"
            f"<p>You searched for: &lt;script&gt;alert('{nonce}')&lt;/script&gt;</p>"
            "</body></html>"
        )
        result = verify_unescaped(html_safe_response, nonce)

        assert result is False, (
            "CRITICAL false-positive: verify_unescaped() returned True for a "
            "response where the payload was safely HTML-escaped. The XSS "
            "detector would have reported a false positive."
        )

    def test_html_escaped_payload_naive_check_would_fire(self):
        """
        Demonstrates WHY DOM-based verification matters.

        The naive ``nonce in response_text`` check would incorrectly fire on
        this escaped response.  BeautifulSoup-based verification does not.
        """
        nonce = "px_abc123"
        html_safe = (
            "<html><body>"
            f"<p>You searched for: &lt;script&gt;alert('{nonce}')&lt;/script&gt;</p>"
            "</body></html>"
        )
        # Prove the naive check would wrongly fire.
        assert nonce in html_safe, "Test setup error: nonce not in raw HTML text."

        # Prove the DOM check correctly rejects it.
        assert verify_unescaped(html_safe, nonce) is False

    def test_unescaped_script_tag_is_detected(self):
        """
        Positive control: nonce inside a real ``<script>`` tag IS a true positive.
        """
        nonce = "px_abc123"
        unsafe_html = (
            "<html><body>"
            f"<script>alert('{nonce}')</script>"
            "</body></html>"
        )
        assert verify_unescaped(unsafe_html, nonce) is True

    def test_event_handler_attribute_is_detected(self):
        """
        Positive control: nonce inside an event-handler attribute IS a true positive.
        """
        nonce = "px_abc123"
        unsafe_html = (
            "<html><body>"
            f"<img src=x onerror=\"alert('{nonce}')\">"
            "</body></html>"
        )
        assert verify_unescaped(unsafe_html, nonce) is True

    def test_nonce_in_html_comment_is_not_flagged(self):
        """
        A nonce inside an HTML comment is NOT executable.  Must not be flagged.
        """
        nonce = "px_abc123"
        comment_html = (
            "<html><body>"
            f"<!-- debug: payload={nonce} -->"
            "<p>Hello</p>"
            "</body></html>"
        )
        assert verify_unescaped(comment_html, nonce) is False

    @respx.mock
    def test_detect_xss_returns_none_for_html_escaped_response(self):
        """
        DEMO REGRESSION #2 — full integration path.

        detect_xss() must return None when the server always HTML-escapes
        all reflected input.
        """
        clean_html = "<html><body><p>Search page</p></body></html>"

        def escaped_response(request: httpx.Request) -> httpx.Response:
            """Return a response that HTML-escapes any reflected query value."""
            # Extract the injected value from either POST body or GET params.
            try:
                body = request.content.decode()
                val = body.split("=", 1)[-1] if "=" in body else ""
            except Exception:
                val = ""
            safe_val = html_module.escape(val)
            text = f"<html><body><p>You searched for: {safe_val}</p></body></html>"
            return httpx.Response(200, text=text, headers={"content-type": "text/html"})

        respx.get("http://target.local/form").mock(
            return_value=httpx.Response(
                200, text=clean_html, headers={"content-type": "text/html"}
            )
        )
        respx.post("http://target.local/form").mock(side_effect=escaped_response)

        async def _run():
            async with HttpClient(max_retries=0) as client:
                ep = _endpoint()
                return await detect_xss(client, ep)

        result = run(_run())

        assert result is None, (
            f"CRITICAL false-positive: detect_xss() returned a Finding for a "
            f"page that HTML-escapes all reflected input. Finding: {result}"
        )

    @respx.mock
    def test_detect_xss_returns_finding_for_unescaped_response(self):
        """
        Positive control: detect_xss() must return a Finding when the server
        reflects the payload inside a real <script> tag.
        """
        clean_html = "<html><body><p>Search page</p></body></html>"

        def unsafe_response(request: httpx.Request) -> httpx.Response:
            """Reflect the POST body value directly into a <script> tag."""
            try:
                body = request.content.decode()
                val = body.split("=", 1)[-1] if "=" in body else ""
            except Exception:
                val = ""
            # Server DOES NOT escape — reflected into script context.
            text = f"<html><body><script>var q='{val}';</script></body></html>"
            return httpx.Response(200, text=text, headers={"content-type": "text/html"})

        respx.get("http://target.local/form").mock(
            return_value=httpx.Response(
                200, text=clean_html, headers={"content-type": "text/html"}
            )
        )
        respx.post("http://target.local/form").mock(side_effect=unsafe_response)

        async def _run():
            async with HttpClient(max_retries=0) as client:
                ep = _endpoint()
                return await detect_xss(client, ep)

        finding = run(_run())

        assert finding is not None, "detect_xss() returned None for a real XSS vulnerability."
        assert finding.severity == "high"
        assert finding.cwe == "CWE-79"
        assert finding.confidence >= MINIMUM_CONFIDENCE


# ===========================================================================
#  confidence.is_match() unit tests
# ===========================================================================


class TestIsMatch:
    def test_word_not_in_fuzzed_returns_false(self):
        bl = _baseline("Welcome to our store")
        assert is_match(bl, "Welcome to our store", 200, "word", "SQL syntax") is False

    def test_word_in_both_returns_false(self):
        bl = _baseline("This page has a syntax error")
        fuzzed = "This page has a syntax error — and more content"
        assert is_match(bl, fuzzed, 200, "word", "syntax error") is False

    def test_word_only_in_fuzzed_returns_true(self):
        bl = _baseline("Normal page content")
        fuzzed = "Normal page content plus new SQL syntax error"
        assert is_match(bl, fuzzed, 200, "word", "SQL syntax error") is True

    def test_regex_only_in_fuzzed_returns_true(self):
        bl = _baseline("Normal page")
        fuzzed = "ORA-01234: table not found"
        assert is_match(bl, fuzzed, 200, "regex", r"ORA-\d{5}") is True

    def test_regex_in_baseline_returns_false(self):
        bl = _baseline("ORA-99999: existing error")
        fuzzed = "ORA-99999: existing error — same content"
        assert is_match(bl, fuzzed, 200, "regex", r"ORA-\d{5}") is False

    def test_status_match_different_from_baseline(self):
        bl = _baseline("ok", status=200)
        assert is_match(bl, "error", 500, "status", 500) is True

    def test_status_match_same_as_baseline(self):
        bl = _baseline("already 500", status=500)
        assert is_match(bl, "still error", 500, "status", 500) is False

    def test_word_case_insensitive(self):
        bl = _baseline("clean page")
        fuzzed = "You have an Error in your SQL Syntax"
        assert is_match(bl, fuzzed, 200, "word", "error in your SQL syntax") is True


# ===========================================================================
#  confidence.score() unit tests
# ===========================================================================


class TestScore:
    def test_zero_matchers(self):
        assert score(0) == 0.0

    def test_negative_matchers(self):
        assert score(-1) == 0.0

    def test_one_matcher(self):
        assert score(1) == 0.6

    def test_two_matchers(self):
        assert score(2) == 0.9

    def test_many_matchers(self):
        assert score(10) == 0.9

    def test_minimum_confidence_constant(self):
        assert MINIMUM_CONFIDENCE == 0.5

    def test_score_one_exceeds_minimum(self):
        assert score(1) >= MINIMUM_CONFIDENCE

    def test_score_zero_below_minimum(self):
        assert score(0) < MINIMUM_CONFIDENCE


# ===========================================================================
#  Headers detector
# ===========================================================================


class TestHeadersDetector:
    @respx.mock
    def test_all_headers_missing_produces_three_findings_for_http(self):
        """HTTP target should not include HSTS finding."""
        respx.get("http://target.local/").mock(
            return_value=httpx.Response(
                200,
                text="<html></html>",
                headers={"content-type": "text/html"},
            )
        )

        async def _run():
            async with HttpClient(max_retries=0) as client:
                return await check_headers(client, "http://target.local/")

        findings = run(_run())

        titles = {f.title for f in findings}
        assert "Missing Content-Security-Policy Header" in titles
        assert "Missing X-Frame-Options Header" in titles
        assert "Missing X-Content-Type-Options Header" in titles
        assert "Missing Strict-Transport-Security Header" not in titles, (
            "HSTS finding must not be reported for HTTP targets."
        )

    @respx.mock
    def test_https_target_includes_hsts_finding(self):
        """HTTPS target should include HSTS finding when header is absent."""
        respx.get("https://target.local/").mock(
            return_value=httpx.Response(
                200,
                text="<html></html>",
                headers={"content-type": "text/html"},
            )
        )

        async def _run():
            async with HttpClient(max_retries=0, verify_ssl=False) as client:
                return await check_headers(client, "https://target.local/")

        findings = run(_run())

        titles = {f.title for f in findings}
        assert "Missing Strict-Transport-Security Header" in titles

    @respx.mock
    def test_all_headers_present_returns_empty_list(self):
        respx.get("http://target.local/").mock(
            return_value=httpx.Response(
                200,
                text="<html></html>",
                headers={
                    "content-type": "text/html",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff",
                },
            )
        )

        async def _run():
            async with HttpClient(max_retries=0) as client:
                return await check_headers(client, "http://target.local/")

        findings = run(_run())
        assert findings == [], f"Expected no findings, got: {[f.title for f in findings]}"

    @respx.mock
    def test_finding_confidence_is_one(self):
        """Header checks are deterministic — confidence must always be 1.0."""
        respx.get("http://target.local/").mock(
            return_value=httpx.Response(
                200,
                text="<html></html>",
                headers={"content-type": "text/html"},
            )
        )

        async def _run():
            async with HttpClient(max_retries=0) as client:
                return await check_headers(client, "http://target.local/")

        findings = run(_run())
        for f in findings:
            assert f.confidence == 1.0, (
                f"Header finding '{f.title}' has confidence {f.confidence} ≠ 1.0"
            )


# ===========================================================================
#  verify_unescaped() additional edge cases
# ===========================================================================


class TestVerifyUnescaped:
    def test_nonce_absent_returns_false(self):
        assert verify_unescaped("<html><body>nothing here</body></html>", "px_xyz") is False

    def test_nonce_in_script_src_attribute_not_detected(self):
        """src attribute is not an event handler — should not be flagged."""
        html = '<html><body><script src="px_xyz.js"></script></body></html>'
        # The nonce isn't in the script *body*, only in src — verify this is safe.
        # (In a real XSS, the nonce would be in the script body or event handler.)
        assert verify_unescaped(html, "px_xyz") is False

    def test_nonce_in_nested_event_handler(self):
        nonce = "px_abc"
        html = f'<html><body><div onclick="doThing(\'{nonce}\')"></div></body></html>'
        assert verify_unescaped(html, nonce) is True

    def test_multiple_script_tags_any_match(self):
        nonce = "px_abc"
        html = (
            f"<html><head><script>var a=1;</script></head>"
            f"<body><script>alert('{nonce}')</script></body></html>"
        )
        assert verify_unescaped(html, nonce) is True


# ===========================================================================
#  Reporter tests
# ===========================================================================


class TestReporter:
    def _make_result(self, findings: Optional[list[Finding]] = None) -> ScanResult:
        return build_result(
            scan_id="test-scan-1234",
            target_url="http://target.local",
            started_at=datetime(2026, 8, 1, 9, 0, 0, tzinfo=timezone.utc),
            endpoints_found=5,
            findings=findings or [],
        )

    def _make_finding(self, severity: str = "high") -> Finding:
        from engine.models import Finding
        import uuid
        return Finding(
            id=str(uuid.uuid4()),
            template_id="test-tpl",
            title="Test Finding",
            severity=severity,
            url="http://target.local/vuln",
            evidence="test evidence",
            cwe="CWE-79",
            owasp="A03:2021",
            cvss_score=7.5,
            confidence=0.9,
            remediation="Fix it.",
        )

    def test_build_json_has_required_keys(self):
        result = self._make_result()
        j = build_json(result)
        for key in ("scan_id", "target_url", "status", "started_at",
                    "risk_score", "findings", "findings_by_severity"):
            assert key in j, f"Key '{key}' missing from build_json() output."

    def test_build_json_findings_serialised(self):
        f = self._make_finding()
        result = self._make_result([f])
        j = build_json(result)
        assert len(j["findings"]) == 1
        assert j["findings"][0]["severity"] == "high"
        assert j["findings"][0]["cwe"] == "CWE-79"

    def test_build_json_datetime_is_string(self):
        result = self._make_result()
        j = build_json(result)
        assert isinstance(j["started_at"], str), "started_at must be a string in JSON output."

    def test_build_html_returns_str(self):
        result = self._make_result()
        h = build_html(result)
        assert isinstance(h, str)
        assert h.strip().startswith("<!DOCTYPE html")

    def test_build_html_contains_scan_id(self):
        result = self._make_result()
        h = build_html(result)
        assert "test-scan-1234" in h

    def test_build_html_contains_finding_title(self):
        result = self._make_result([self._make_finding()])
        h = build_html(result)
        assert "Test Finding" in h

    def test_build_html_demo_banner_present_for_example(self):
        result = self._make_result()
        result.is_example = True
        h = build_html(result)
        assert "Demo Scan" in h

    def test_build_html_no_demo_banner_for_real_scan(self):
        result = self._make_result()
        result.is_example = False
        h = build_html(result)
        assert "Demo Scan" not in h

    def test_build_html_risk_score_displayed(self):
        result = self._make_result([self._make_finding("critical")])
        h = build_html(result)
        # risk score is shown in the summary table
        assert "/100" in h

    def test_build_result_risk_score_capped_at_100(self):
        """Even many critical findings must not exceed 100."""
        findings = [self._make_finding("critical") for _ in range(50)]
        result = self._make_result(findings)
        assert result.risk_score <= 100.0

    def test_build_result_empty_findings_zero_risk(self):
        result = self._make_result([])
        assert result.risk_score == 0.0
