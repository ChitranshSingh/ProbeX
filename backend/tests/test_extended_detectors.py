"""Positive controls for the live checks added beyond the prototype set."""

from __future__ import annotations

import asyncio

import httpx
import respx

from engine.detectors.extended import (
    detect_cookie_security,
    detect_cors_misconfiguration,
    detect_dangerous_http_methods,
    detect_debug_disclosure,
    detect_open_redirect,
    detect_path_traversal,
    detect_sensitive_data,
    detect_ssti,
)
from engine.http_client import HttpClient
from engine.models import Endpoint


def run(coro):
    return asyncio.run(coro)


@respx.mock
def test_open_redirect_requires_external_location_match():
    def handler(request: httpx.Request) -> httpx.Response:
        location = request.url.params.get("next", "")
        return httpx.Response(302, headers={"location": location})

    respx.get("http://target.local/go").mock(side_effect=handler)

    async def scan():
        async with HttpClient(max_retries=0) as client:
            return await detect_open_redirect(client, Endpoint("http://target.local/go?next=/", params=["next"]))

    finding = run(scan())
    assert finding is not None
    assert finding.template_id == "open-redirect"
    assert finding.confidence == 0.9


@respx.mock
def test_path_traversal_requires_new_passwd_signature():
    def handler(request: httpx.Request) -> httpx.Response:
        if "etc%2Fpasswd" in str(request.url) or "etc/passwd" in str(request.url):
            return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash")
        return httpx.Response(200, text="safe file listing")

    respx.get("http://target.local/download").mock(side_effect=handler)

    async def scan():
        async with HttpClient(max_retries=0) as client:
            return await detect_path_traversal(client, Endpoint("http://target.local/download?file=readme", params=["file"]))

    finding = run(scan())
    assert finding is not None
    assert finding.template_id == "path-traversal"


@respx.mock
def test_ssti_needs_two_math_probe_results():
    def handler(request: httpx.Request) -> httpx.Response:
        query = str(request.url)
        if "7%2A7" in query:
            return httpx.Response(200, text="calculated: 49")
        if "8%2A8" in query:
            return httpx.Response(200, text="calculated: 64")
        return httpx.Response(200, text="search results")

    respx.get("http://target.local/search").mock(side_effect=handler)

    async def scan():
        async with HttpClient(max_retries=0) as client:
            return await detect_ssti(client, Endpoint("http://target.local/search?q=hello", params=["q"]))

    finding = run(scan())
    assert finding is not None
    assert finding.template_id == "ssti-math-probe"
    assert finding.confidence == 0.9


@respx.mock
def test_sensitive_data_evidence_does_not_echo_the_secret():
    secret = "AKIA1234567890ABCDEF"
    respx.get("http://target.local/").mock(return_value=httpx.Response(200, text=secret))

    async def scan():
        async with HttpClient(max_retries=0) as client:
            return await detect_sensitive_data(client, "http://target.local/")

    findings = run(scan())
    assert len(findings) == 1
    assert secret not in findings[0].evidence


@respx.mock
def test_credentialed_cors_origin_reflection_is_confirmed():
    def handler(request: httpx.Request) -> httpx.Response:
        origin = request.headers["origin"]
        return httpx.Response(200, headers={"access-control-allow-origin": origin, "access-control-allow-credentials": "true"})

    respx.get("https://target.local/").mock(side_effect=handler)

    async def scan():
        async with HttpClient(max_retries=0) as client:
            return await detect_cors_misconfiguration(client, "https://target.local/")

    finding = run(scan())
    assert finding is not None
    assert finding.template_id == "cors-origin-reflection"


@respx.mock
def test_session_cookie_without_security_flags_is_reported():
    respx.get("https://target.local/").mock(return_value=httpx.Response(200, headers={"set-cookie": "sessionid=abc123; Path=/"}))

    async def scan():
        async with HttpClient(max_retries=0) as client:
            return await detect_cookie_security(client, "https://target.local/")

    titles = [finding.title for finding in run(scan())]
    assert "Session Cookie Missing Secure Flag" in titles
    assert "Session Cookie Missing HttpOnly Flag" in titles
    assert "Session Cookie Missing SameSite Attribute" in titles


@respx.mock
def test_debug_disclosure_and_directory_listing_are_passively_detected():
    response = "<title>Index of /</title> Traceback (most recent call last):"
    respx.get("http://target.local/").mock(return_value=httpx.Response(500, text=response))

    async def scan():
        async with HttpClient(max_retries=0) as client:
            return await detect_debug_disclosure(client, "http://target.local/")

    templates = {finding.template_id for finding in run(scan())}
    assert templates == {"debug-error-disclosure", "directory-listing"}


@respx.mock
def test_trace_method_in_allow_header_is_reported():
    respx.options("https://target.local/").mock(return_value=httpx.Response(204, headers={"allow": "GET, POST, TRACE"}))

    async def scan():
        async with HttpClient(max_retries=0) as client:
            return await detect_dangerous_http_methods(client, "https://target.local/")

    finding = run(scan())
    assert finding is not None
    assert finding.template_id == "dangerous-http-method"
