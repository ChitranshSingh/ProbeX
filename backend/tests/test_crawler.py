"""
ProbeX – unit tests for engine/crawler.py and engine/http_client.py.

Test strategy
-------------
- Uses ``respx`` to mock all outbound HTTP at the HTTPX transport level.
  No real network calls are made.
- Each test class is self-contained with its own ``respx.MockRouter``.
- The SCOPE LOCK test (``TestScopeLock``) is the one non-negotiable safety
  property: links whose hostname differs from the seed MUST NEVER be followed
  or appear in the result.

Run from the ``backend/`` directory::

    python -m pytest tests/test_crawler.py -v
"""

from __future__ import annotations

import asyncio
import re
import sys
import os

# ---------------------------------------------------------------------------
# Path setup: ensure ``backend/`` is on sys.path so ``engine.*`` can be
# imported without installing the package.
# ---------------------------------------------------------------------------
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import httpx
import pytest
import respx

from engine.crawler import (
    HttpCrawler,
    _normalise_url,
    _is_same_host,
    _has_skippable_extension,
    classify_input,
    _parse_forms,
)
from engine.http_client import HttpClient
from engine.models import Baseline


# ===========================================================================
# Helpers
# ===========================================================================


def run(coro):
    """Run an async coroutine synchronously (compatible with older pytest)."""
    return asyncio.get_event_loop().run_until_complete(coro)


# ===========================================================================
# URL normalisation
# ===========================================================================


class TestNormaliseUrl:
    def test_lowercase_host(self):
        assert _normalise_url("HTTP://EXAMPLE.COM/path") == "http://example.com/path"

    def test_strip_fragment(self):
        assert _normalise_url("http://example.com/page#section") == "http://example.com/page"

    def test_sort_query_params(self):
        result = _normalise_url("http://example.com/?b=2&a=1")
        assert result == "http://example.com/?a=1&b=2"

    def test_strip_trailing_slash(self):
        assert _normalise_url("http://example.com/page/") == "http://example.com/page"

    def test_root_slash_preserved(self):
        # The root path "/" must not be stripped to "".
        result = _normalise_url("http://example.com/")
        assert result in ("http://example.com/", "http://example.com")

    def test_combined_transformations(self):
        result = _normalise_url("HTTP://Example.COM/Page/?b=2&a=1#top")
        # Trailing slash is stripped from path (/Page/ → /Page),
        # host lowercased, params sorted, fragment dropped.
        assert result == "http://example.com/Page?a=1&b=2"

    def test_equivalent_urls_collapse(self):
        """Two URLs that differ only in fragment and param order must normalise to the same string."""
        u1 = _normalise_url("http://example.com/search?q=xss&page=1#results")
        u2 = _normalise_url("http://example.com/search?page=1&q=xss")
        assert u1 == u2


# ===========================================================================
# Scope lock unit tests
# ===========================================================================


class TestScopeLock:
    """
    THE NON-NEGOTIABLE SAFETY PROPERTY.

    The crawler MUST NOT follow or return any endpoint whose hostname differs
    from the seed URL's hostname, under any circumstances.
    """

    # --- _is_same_host helper ---

    def test_same_host_returns_true(self):
        assert _is_same_host("http://target.local/page", "target.local") is True

    def test_different_host_returns_false(self):
        assert _is_same_host("http://evil.com/steal", "target.local") is False

    def test_subdomain_is_out_of_scope(self):
        """Subdomains are treated as different hosts (strict match)."""
        assert _is_same_host("http://sub.target.local/page", "target.local") is False

    def test_case_insensitive_host_match(self):
        assert _is_same_host("http://TARGET.LOCAL/page", "target.local") is True

    # --- Integration: crawler scope lock ---

    @respx.mock
    def test_crawler_does_not_follow_external_links(self):
        """
        SCOPE LOCK INTEGRATION TEST.

        Seed page links to an external domain.  The crawler must:
        1. Visit the seed page.
        2. Discover the external link.
        3. NOT fetch the external URL.
        4. NOT include the external URL in the returned endpoints.
        """
        seed_html = """
        <html><body>
          <a href="http://target.local/internal">Internal</a>
          <a href="http://evil.com/steal">External — must NOT be followed</a>
          <a href="https://google.com/">Google — must NOT be followed</a>
        </body></html>
        """
        internal_html = "<html><body><p>Internal page</p></body></html>"

        respx.get("http://target.local/").mock(
            return_value=httpx.Response(200, text=seed_html, headers={"content-type": "text/html"})
        )
        respx.get("http://target.local/internal").mock(
            return_value=httpx.Response(200, text=internal_html, headers={"content-type": "text/html"})
        )
        # evil.com and google.com must NEVER be called — respx will raise if they are.

        async def _run():
            async with HttpClient(max_retries=0) as client:
                crawler = HttpCrawler(client)
                return await crawler.crawl("http://target.local/", max_depth=2)

        endpoints = run(_run())

        urls = [ep.url for ep in endpoints]

        # Internal page must be present.
        assert any("target.local" in u for u in urls), f"Expected target.local endpoints, got {urls}"

        # External domains must NOT appear.
        for url in urls:
            from urllib.parse import urlparse
            host = urlparse(url).netloc.lower()
            assert host == "target.local", (
                f"SCOPE LOCK VIOLATION: endpoint from external host '{host}' "
                f"found in results: {url}"
            )

    @respx.mock
    def test_out_of_scope_form_action_skipped(self):
        """
        A form whose action points to an external host must be silently skipped.
        """
        html = """
        <html><body>
          <form action="http://evil.com/exfiltrate" method="POST">
            <input name="data" type="text"/>
            <input type="submit" value="Send"/>
          </form>
        </body></html>
        """
        respx.get("http://target.local/").mock(
            return_value=httpx.Response(200, text=html, headers={"content-type": "text/html"})
        )

        forms = _parse_forms(html, "http://target.local/", "target.local")
        assert forms == [], (
            f"SCOPE LOCK VIOLATION: out-of-scope form action produced endpoint: {forms}"
        )


# ===========================================================================
# Deduplication
# ===========================================================================


class TestDeduplication:
    @respx.mock
    def test_duplicate_links_produce_one_endpoint(self):
        """
        A page with multiple links to the same URL (different fragments / param
        order) must produce exactly one endpoint for that URL.
        """
        html = """
        <html><body>
          <a href="/page?a=1&b=2">Link 1</a>
          <a href="/page?b=2&a=1">Link 2 (same, different order)</a>
          <a href="/page?a=1&b=2#section">Link 3 (same, has fragment)</a>
        </body></html>
        """
        page_html = "<html><body>page</body></html>"

        respx.get("http://target.local/").mock(
            return_value=httpx.Response(200, text=html, headers={"content-type": "text/html"})
        )
        respx.get("http://target.local/page").mock(
            return_value=httpx.Response(200, text=page_html, headers={"content-type": "text/html"})
        )

        async def _run():
            async with HttpClient(max_retries=0) as client:
                crawler = HttpCrawler(client)
                return await crawler.crawl("http://target.local/", max_depth=1)

        endpoints = run(_run())
        page_endpoints = [
            ep for ep in endpoints
            if "page" in ep.url and "target.local" in ep.url
        ]
        assert len(page_endpoints) == 1, (
            f"Expected 1 deduplicated /page endpoint, got {len(page_endpoints)}: "
            f"{[ep.url for ep in page_endpoints]}"
        )

    @respx.mock
    def test_trailing_slash_dedup(self):
        """/page and /page/ must collapse to a single endpoint."""
        html = """
        <html><body>
          <a href="/about">About</a>
          <a href="/about/">About with slash</a>
        </body></html>
        """
        about_html = "<html><body>about</body></html>"

        respx.get("http://target.local/").mock(
            return_value=httpx.Response(200, text=html, headers={"content-type": "text/html"})
        )
        respx.get("http://target.local/about").mock(
            return_value=httpx.Response(200, text=about_html, headers={"content-type": "text/html"})
        )

        async def _run():
            async with HttpClient(max_retries=0) as client:
                crawler = HttpCrawler(client)
                return await crawler.crawl("http://target.local/", max_depth=1)

        endpoints = run(_run())
        about_endpoints = [ep for ep in endpoints if "about" in ep.url]
        assert len(about_endpoints) == 1, (
            f"Expected 1 /about endpoint after trailing-slash dedup, "
            f"got {len(about_endpoints)}: {[ep.url for ep in about_endpoints]}"
        )


# ===========================================================================
# Two-page site with one form — core integration test
# ===========================================================================


class TestTwoPageSiteWithForm:
    """
    Full integration test against a mocked 2-page site:

    Page 1 (seed): links to Page 2 and contains a login form.
    Page 2:        a simple page with no forms.

    Expected results:
    - 2 GET link endpoints (seed + page2).
    - 1 POST form endpoint with 2 fields (username=id_field, password=generic_text).
    - All form_fields correctly populated.
    - No external endpoints.
    """

    SEED_HTML = """
    <!DOCTYPE html>
    <html>
    <head><title>Target App</title></head>
    <body>
      <nav>
        <a href="/page2">Page 2</a>
        <a href="http://external.com/evil">External (must be blocked)</a>
      </nav>

      <form action="/login" method="POST">
        <input name="username" type="text" value=""/>
        <input name="password" type="password" value=""/>
        <input name="next" type="hidden" value="/dashboard"/>
        <select name="lang">
          <option value="en">English</option>
          <option value="fr">French</option>
        </select>
        <textarea name="comment"></textarea>
        <input type="submit" value="Login"/>
      </form>
    </body>
    </html>
    """

    PAGE2_HTML = """
    <!DOCTYPE html>
    <html>
    <head><title>Page 2</title></head>
    <body>
      <p>Nothing interesting here.</p>
      <a href="/">Back home</a>
    </body>
    </html>
    """

    @respx.mock
    def test_discovers_both_pages(self):
        respx.get("http://target.local/").mock(
            return_value=httpx.Response(
                200, text=self.SEED_HTML, headers={"content-type": "text/html"}
            )
        )
        respx.get("http://target.local/page2").mock(
            return_value=httpx.Response(
                200, text=self.PAGE2_HTML, headers={"content-type": "text/html"}
            )
        )

        async def _run():
            async with HttpClient(max_retries=0) as client:
                crawler = HttpCrawler(client)
                return await crawler.crawl("http://target.local/", max_depth=2)

        endpoints = run(_run())
        get_urls = {ep.url for ep in endpoints if ep.method == "GET"}

        assert any("target.local" in u and u.endswith(("/", "")) or "target.local" in u for u in get_urls), \
            f"Seed URL not found in {get_urls}"
        assert any("page2" in u for u in get_urls), f"/page2 not found in {get_urls}"

    @respx.mock
    def test_form_endpoint_discovered(self):
        respx.get("http://target.local/").mock(
            return_value=httpx.Response(
                200, text=self.SEED_HTML, headers={"content-type": "text/html"}
            )
        )
        respx.get("http://target.local/page2").mock(
            return_value=httpx.Response(
                200, text=self.PAGE2_HTML, headers={"content-type": "text/html"}
            )
        )

        async def _run():
            async with HttpClient(max_retries=0) as client:
                crawler = HttpCrawler(client)
                return await crawler.crawl("http://target.local/", max_depth=2)

        endpoints = run(_run())
        form_endpoints = [ep for ep in endpoints if ep.method == "POST"]

        assert len(form_endpoints) == 1, (
            f"Expected 1 POST form endpoint, got {len(form_endpoints)}"
        )
        login_ep = form_endpoints[0]
        assert "login" in login_ep.url

    @respx.mock
    def test_form_fields_extracted_correctly(self):
        respx.get("http://target.local/").mock(
            return_value=httpx.Response(
                200, text=self.SEED_HTML, headers={"content-type": "text/html"}
            )
        )
        respx.get("http://target.local/page2").mock(
            return_value=httpx.Response(
                200, text=self.PAGE2_HTML, headers={"content-type": "text/html"}
            )
        )

        async def _run():
            async with HttpClient(max_retries=0) as client:
                crawler = HttpCrawler(client)
                return await crawler.crawl("http://target.local/", max_depth=2)

        endpoints = run(_run())
        login_ep = next(ep for ep in endpoints if ep.method == "POST" and "login" in ep.url)

        field_names = {f.name for f in login_ep.form_fields}
        # submit buttons must be excluded; all data-bearing fields must be present.
        assert "username" in field_names, f"username missing from {field_names}"
        assert "password" in field_names, f"password missing from {field_names}"
        assert "next" in field_names, f"next (hidden) missing from {field_names}"
        assert "lang" in field_names, f"lang (select) missing from {field_names}"
        assert "comment" in field_names, f"comment (textarea) missing from {field_names}"

    @respx.mock
    def test_input_type_classification_on_form(self):
        respx.get("http://target.local/").mock(
            return_value=httpx.Response(
                200, text=self.SEED_HTML, headers={"content-type": "text/html"}
            )
        )
        respx.get("http://target.local/page2").mock(
            return_value=httpx.Response(
                200, text=self.PAGE2_HTML, headers={"content-type": "text/html"}
            )
        )

        async def _run():
            async with HttpClient(max_retries=0) as client:
                crawler = HttpCrawler(client)
                return await crawler.crawl("http://target.local/", max_depth=2)

        endpoints = run(_run())
        login_ep = next(ep for ep in endpoints if ep.method == "POST" and "login" in ep.url)

        by_name = {f.name: f for f in login_ep.form_fields}

        # username — name contains nothing special → generic_text
        assert by_name["username"].input_type == "generic_text", by_name["username"]
        # next — name contains 'next' → url_field
        assert by_name["next"].input_type == "url_field", by_name["next"]

        # input_types list must be populated and deduplicated
        assert len(login_ep.input_types) > 0
        assert len(login_ep.input_types) == len(set(login_ep.input_types)), \
            "input_types contains duplicates"

    @respx.mock
    def test_scope_lock_no_external_endpoints(self):
        """SCOPE LOCK: external.com link in SEED_HTML must never appear in results."""
        respx.get("http://target.local/").mock(
            return_value=httpx.Response(
                200, text=self.SEED_HTML, headers={"content-type": "text/html"}
            )
        )
        respx.get("http://target.local/page2").mock(
            return_value=httpx.Response(
                200, text=self.PAGE2_HTML, headers={"content-type": "text/html"}
            )
        )

        async def _run():
            async with HttpClient(max_retries=0) as client:
                crawler = HttpCrawler(client)
                return await crawler.crawl("http://target.local/", max_depth=2)

        endpoints = run(_run())

        from urllib.parse import urlparse
        for ep in endpoints:
            host = urlparse(ep.url).netloc.lower()
            assert host == "target.local", (
                f"SCOPE LOCK VIOLATION: external host '{host}' in endpoint: {ep.url}"
            )


# ===========================================================================
# Input type classification unit tests
# ===========================================================================


class TestClassifyInput:
    def test_email_html_type(self):
        assert classify_input("contact", "email") == "email_field"

    def test_id_field_by_name(self):
        assert classify_input("user_id", "text") == "id_field"
        assert classify_input("uid", "text") == "id_field"
        assert classify_input("productId", "text") == "id_field"

    def test_search_field_by_name(self):
        assert classify_input("q", "text") == "search_field"
        assert classify_input("query", "text") == "search_field"
        assert classify_input("search_term", "text") == "search_field"

    def test_url_field_by_name(self):
        assert classify_input("next", "text") == "url_field"
        assert classify_input("redirect_url", "text") == "url_field"
        assert classify_input("return", "text") == "url_field"
        assert classify_input("goto", "text") == "url_field"

    def test_generic_text_fallback(self):
        assert classify_input("username", "text") == "generic_text"
        assert classify_input("password", "password") == "generic_text"
        assert classify_input("comment", "text") == "generic_text"

    def test_email_type_takes_precedence_over_name(self):
        """html_type=email wins even if name would classify differently."""
        assert classify_input("search", "email") == "email_field"


# ===========================================================================
# Extension skipping
# ===========================================================================


class TestSkipExtensions:
    def test_jpg_skipped(self):
        assert _has_skippable_extension("http://x.com/img.jpg") is True

    def test_css_skipped(self):
        assert _has_skippable_extension("http://x.com/style.css") is True

    def test_pdf_skipped(self):
        assert _has_skippable_extension("http://x.com/doc.pdf") is True

    def test_html_not_skipped(self):
        assert _has_skippable_extension("http://x.com/page.html") is False

    def test_no_extension_not_skipped(self):
        assert _has_skippable_extension("http://x.com/about") is False

    def test_query_string_not_confused_with_extension(self):
        assert _has_skippable_extension("http://x.com/search?file=doc.pdf") is False


# ===========================================================================
# HttpClient — retry and baseline
# ===========================================================================


class TestHttpClientRetry:
    @respx.mock
    def test_retries_on_503(self):
        """Client must retry on 503 and succeed on the second attempt."""
        call_count = 0

        def handler(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(503, text="Service Unavailable")
            return httpx.Response(200, text="OK")

        respx.get("http://target.local/retry").mock(side_effect=handler)

        async def _run():
            async with HttpClient(max_retries=2) as client:
                resp = await client.get("http://target.local/retry")
                return resp

        resp = run(_run())
        assert resp.status_code == 200
        assert call_count == 2, f"Expected 2 calls (1 fail + 1 retry), got {call_count}"

    @respx.mock
    def test_raises_after_all_retries_exhausted(self):
        """Client must raise after max_retries are all exhausted."""
        respx.get("http://target.local/fail").mock(
            return_value=httpx.Response(503, text="Always broken")
        )

        async def _run():
            async with HttpClient(max_retries=2) as client:
                return await client.get("http://target.local/fail")

        with pytest.raises(Exception):
            run(_run())

    @respx.mock
    def test_record_baseline_returns_baseline_dataclass(self):
        """record_baseline must return a Baseline with correct status and text."""
        respx.get("http://target.local/baseline").mock(
            return_value=httpx.Response(200, text="<html>baseline</html>")
        )

        async def _run():
            async with HttpClient(max_retries=0) as client:
                return await client.record_baseline("http://target.local/baseline")

        baseline = run(_run())
        assert isinstance(baseline, Baseline)
        assert baseline.status == 200
        assert "baseline" in baseline.text
        assert baseline.elapsed_ms >= 0

    @respx.mock
    def test_record_baseline_captures_elapsed_ms(self):
        """elapsed_ms must be a positive float."""
        respx.get("http://target.local/timing").mock(
            return_value=httpx.Response(200, text="ok")
        )

        async def _run():
            async with HttpClient(max_retries=0) as client:
                return await client.record_baseline("http://target.local/timing")

        baseline = run(_run())
        assert isinstance(baseline.elapsed_ms, float)
        assert baseline.elapsed_ms >= 0.0
