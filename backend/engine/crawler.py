"""
ProbeX Engine – async BFS web crawler with form extraction and scope lock.

Design principles
-----------------
- **Scope lock** (non-negotiable safety property): links whose hostname differs
  from the seed URL's hostname are NEVER followed, even on localhost.
- **URL normalisation** collapses equivalent URLs to a single canonical form
  before deduplication so ``/page`` and ``/page/`` don't generate two entries.
- **Concurrent BFS** uses ``asyncio.Semaphore`` to cap outbound connections.
- **Form extraction** records every ``<form>`` element with its action URL,
  HTTP method, and all ``<input>`` / ``<select>`` / ``<textarea>`` fields.
- **Input classification** maps each field name / HTML type to a semantic
  ``input_type`` understood by the fuzzer.

Zero FastAPI / SQLModel imports — this package must stay standalone.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections import deque
from urllib.parse import (
    urljoin,
    urlparse,
    urlunparse,
    parse_qs,
    urlencode,
)

from bs4 import BeautifulSoup

from engine.http_client import HttpClient
from engine.models import Endpoint, FormField

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# File-extension skip-list
# ---------------------------------------------------------------------------

_SKIP_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico",
        ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z",
        ".mp3", ".mp4", ".avi", ".mov", ".wmv",
        ".exe", ".dll", ".so", ".dmg", ".pkg",
        ".xml",  # sitemaps are useful, but avoid large XML documents
        ".json",  # API responses; the fuzzer targets these separately
    }
)


# ---------------------------------------------------------------------------
# URL normalisation
# ---------------------------------------------------------------------------


def _normalise_url(url: str) -> str:
    """
    Return a canonical form of ``url`` for deduplication.

    Transformations applied:
    1. Lowercase scheme and host.
    2. Strip URL fragment (``#section``).
    3. Sort query-string parameters alphabetically.
    4. Remove trailing slash from the path *unless* the path is ``/``.

    Examples
    --------
    >>> _normalise_url("HTTP://Example.COM/Page/?b=2&a=1#top")
    'http://example.com/Page/?a=1&b=2'
    >>> _normalise_url("http://example.com/page/")
    'http://example.com/page'
    """
    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    host = parsed.netloc.lower()

    path = parsed.path
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")

    # Sort query params for stable deduplication.
    qs_dict = parse_qs(parsed.query, keep_blank_values=True)
    sorted_query = urlencode(
        sorted((k, v[0]) for k, v in qs_dict.items() if v),
        doseq=False,
    )

    # Drop fragment entirely.
    return urlunparse((scheme, host, path, parsed.params, sorted_query, ""))


def _is_same_host(url: str, seed_host: str) -> bool:
    """
    Return ``True`` iff ``url``'s hostname (lowercased) equals ``seed_host``.

    This is the **scope lock** — the one non-negotiable safety property.
    ``seed_host`` should already be lowercased before calling this function.
    """
    return urlparse(url).netloc.lower() == seed_host


def _has_skippable_extension(url: str) -> bool:
    """Return ``True`` if the URL path ends with a non-HTML extension."""
    path = urlparse(url).path.lower()
    _, _, ext = path.rpartition(".")
    return f".{ext}" in _SKIP_EXTENSIONS if ext else False


# ---------------------------------------------------------------------------
# Input-type classification
# ---------------------------------------------------------------------------

# Compiled patterns for field-name based classification.
_ID_PATTERN = re.compile(r"\bid\b|uid|_id$|id_|Id$|ID$", re.IGNORECASE)
_SEARCH_PATTERN = re.compile(r"\bq\b|query|search", re.IGNORECASE)
_URL_PATTERN = re.compile(r"url|redirect|next|return|goto|dest", re.IGNORECASE)


def classify_input(name: str, html_type: str) -> str:
    """
    Map a form field's name and HTML type to a semantic ``input_type`` string.

    Classification rules (first match wins):

    1. ``html_type == "email"``              → ``"email_field"``
    2. name matches id/uid pattern           → ``"id_field"``
    3. name matches q/query/search pattern   → ``"search_field"``
    4. name matches url/redirect/next pattern→ ``"url_field"``
    5. everything else                       → ``"generic_text"``

    Parameters
    ----------
    name:
        The ``name`` attribute of the ``<input>`` element.
    html_type:
        The ``type`` attribute of the ``<input>`` element (e.g. ``"text"``,
        ``"email"``, ``"hidden"``).  Use ``"text"`` as the default.

    Returns
    -------
    str
        One of ``"email_field"``, ``"id_field"``, ``"search_field"``,
        ``"url_field"``, or ``"generic_text"``.
    """
    if html_type.lower() == "email":
        return "email_field"
    if _ID_PATTERN.search(name):
        return "id_field"
    if _SEARCH_PATTERN.search(name):
        return "search_field"
    if _URL_PATTERN.search(name):
        return "url_field"
    return "generic_text"


# ---------------------------------------------------------------------------
# Form parser
# ---------------------------------------------------------------------------


def _parse_forms(
    html: str,
    page_url: str,
    seed_host: str,
) -> list[Endpoint]:
    """
    Extract all ``<form>`` elements from ``html`` and return them as
    ``Endpoint`` objects.

    Each form action is resolved relative to ``page_url`` and scope-checked
    against ``seed_host``.  Out-of-scope form actions are skipped.

    Parameters
    ----------
    html:
        Raw HTML body of the page.
    page_url:
        Absolute URL of the page containing the forms (used for relative
        action resolution).
    seed_host:
        Lowercased hostname of the seed URL (scope lock reference).

    Returns
    -------
    list[Endpoint]
        One ``Endpoint`` per in-scope form, with ``form_fields`` and
        ``input_types`` populated.
    """
    soup = BeautifulSoup(html, "html.parser")
    endpoints: list[Endpoint] = []

    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = (form.get("method", "GET") or "GET").upper()

        # Resolve relative action → absolute URL.
        action_url = urljoin(page_url, action) if action else page_url
        action_norm = _normalise_url(action_url)

        # Scope check: skip forms that submit to external hosts.
        if not _is_same_host(action_norm, seed_host):
            logger.debug("Skipping out-of-scope form action: %s", action_norm)
            continue

        form_fields: list[FormField] = []

        # ---- <input> elements ----
        for inp in form.find_all("input"):
            name = inp.get("name", "").strip()
            if not name:
                continue  # unnamed inputs can't be fuzzed
            html_type = (inp.get("type", "text") or "text").strip().lower()
            if html_type in ("submit", "button", "reset", "image"):
                continue  # not a data-bearing field
            default_value = inp.get("value", "") or ""
            itype = classify_input(name, html_type)
            form_fields.append(
                FormField(
                    name=name,
                    input_type=itype,
                    html_type=html_type,
                    default_value=str(default_value),
                )
            )

        # ---- <select> elements ----
        for sel in form.find_all("select"):
            name = sel.get("name", "").strip()
            if not name:
                continue
            # Use the first <option> value as the default.
            first_option = sel.find("option")
            default_value = first_option.get("value", "") if first_option else ""
            itype = classify_input(name, "text")
            form_fields.append(
                FormField(
                    name=name,
                    input_type=itype,
                    html_type="select",
                    default_value=str(default_value),
                )
            )

        # ---- <textarea> elements ----
        for ta in form.find_all("textarea"):
            name = ta.get("name", "").strip()
            if not name:
                continue
            default_value = ta.string or ""
            itype = classify_input(name, "text")
            form_fields.append(
                FormField(
                    name=name,
                    input_type=itype,
                    html_type="textarea",
                    default_value=str(default_value).strip(),
                )
            )

        # Build de-duplicated input_types list (preserving order of first seen).
        seen_types: list[str] = []
        for ff in form_fields:
            if ff.input_type not in seen_types:
                seen_types.append(ff.input_type)

        endpoints.append(
            Endpoint(
                url=action_norm,
                method=method,
                form_fields=form_fields,
                input_types=seen_types,
            )
        )

    return endpoints


# ---------------------------------------------------------------------------
# Link extractor
# ---------------------------------------------------------------------------


def _extract_links(html: str, page_url: str) -> list[str]:
    """
    Return all absolute URLs found in ``<a href>`` tags in ``html``.

    Relative URLs are resolved against ``page_url``.
    """
    soup = BeautifulSoup(html, "html.parser")
    links: list[str] = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if not href or href.startswith(("javascript:", "mailto:", "tel:")):
            continue
        abs_url = urljoin(page_url, href)
        # Only keep http/https links.
        if urlparse(abs_url).scheme in ("http", "https"):
            links.append(abs_url)
    return links


# ---------------------------------------------------------------------------
# HttpCrawler
# ---------------------------------------------------------------------------


class HttpCrawler:
    """
    Async BFS crawler that discovers ``Endpoint`` objects reachable from a
    seed URL, respecting a strict same-host scope lock.

    Usage::

        async with HttpClient() as client:
            crawler = HttpCrawler(client)
            endpoints = await crawler.crawl("http://target.local/", max_depth=2)
    """

    def __init__(self, client: HttpClient) -> None:
        """
        Parameters
        ----------
        client:
            Shared ``HttpClient`` instance.  The caller is responsible for
            its lifecycle (``async with`` or explicit ``aclose()``).
        """
        self._client = client

    async def crawl(
        self,
        start_url: str,
        max_depth: int = 2,
        max_concurrency: int = 8,
        max_urls: int = 200,
    ) -> list[Endpoint]:
        """
        Discover all in-scope endpoints reachable from ``start_url``.

        Algorithm
        ---------
        Standard BFS: a queue of ``(url, depth)`` tuples is drained level by
        level.  Each URL is fetched once (tracked in ``visited``).  Discovered
        links are enqueued for the next level if:

        - The URL is not already visited.
        - The URL is within scope (same hostname as ``start_url``).
        - The URL's path does not end with a skippable extension.
        - The current depth is less than ``max_depth``.
        - The total number of fetched URLs has not exceeded ``max_urls``.

        Forms on each page are parsed and their action endpoints appended to
        the result list separately (they share the same scope and depth
        constraints).

        Parameters
        ----------
        start_url:
            Absolute seed URL to begin crawling from.
        max_depth:
            Maximum BFS depth.  0 = seed page only; 1 = seed + direct links;
            2 = seed + 2 levels deep; etc.
        max_concurrency:
            Maximum number of simultaneous HTTP requests.
        max_urls:
            Hard cap on total pages fetched (not counting form endpoints).

        Returns
        -------
        list[Endpoint]
            De-duplicated list of all endpoints found (link-based GET endpoints
            plus form-based endpoints with ``form_fields`` populated).
        """
        seed_parsed = urlparse(start_url)
        seed_host = seed_parsed.netloc.lower()

        # Normalise the seed URL itself.
        start_norm = _normalise_url(start_url)

        # visited tracks normalised URLs to prevent re-fetching.
        visited: set[str] = set()
        # endpoint_urls tracks all unique endpoint URLs (links + forms) to dedup.
        endpoint_urls: set[str] = set()

        endpoints: list[Endpoint] = []

        # BFS queue: (normalised_url, depth)
        queue: deque[tuple[str, int]] = deque()
        queue.append((start_norm, 0))
        visited.add(start_norm)

        semaphore = asyncio.Semaphore(max_concurrency)
        fetched_count = 0

        async def fetch_page(url: str, depth: int) -> None:
            nonlocal fetched_count

            async with semaphore:
                try:
                    resp = await self._client.get(url)
                except Exception as exc:
                    logger.warning("Failed to fetch %s: %s", url, exc)
                    return

                fetched_count += 1
                content_type = resp.headers.get("content-type", "")
                if "html" not in content_type.lower():
                    # Non-HTML response (JSON API, binary, etc.) — record as
                    # an endpoint but don't try to parse links from it.
                    _add_endpoint(
                        Endpoint(url=url, method="GET", depth=depth),
                        endpoint_urls,
                        endpoints,
                    )
                    return

                html = resp.text

                # ---- Record this page as a GET endpoint ----
                query_params = sorted(
                    parse_qs(urlparse(url).query, keep_blank_values=True).keys()
                )
                _add_endpoint(
                    Endpoint(url=url, method="GET", params=query_params, depth=depth),
                    endpoint_urls,
                    endpoints,
                )

                # ---- Extract and enqueue links ----
                if depth < max_depth:
                    for link in _extract_links(html, url):
                        norm = _normalise_url(link)

                        # SCOPE LOCK — enforce same-host constraint.
                        if not _is_same_host(norm, seed_host):
                            logger.debug("Out-of-scope link skipped: %s", norm)
                            continue

                        if norm in visited:
                            continue

                        if _has_skippable_extension(norm):
                            logger.debug("Skipping non-HTML extension: %s", norm)
                            continue

                        if fetched_count >= max_urls:
                            logger.info("max_urls (%d) reached — stopping crawl.", max_urls)
                            break

                        visited.add(norm)
                        queue.append((norm, depth + 1))

                # ---- Extract forms ----
                for form_ep in _parse_forms(html, url, seed_host):
                    _add_endpoint(form_ep, endpoint_urls, endpoints)

        # BFS loop — process queue level by level with concurrency.
        while queue:
            # Drain the current BFS level into a batch.
            batch: list[tuple[str, int]] = []
            while queue:
                batch.append(queue.popleft())

            if fetched_count >= max_urls:
                break

            await asyncio.gather(*(fetch_page(u, d) for u, d in batch))

        logger.info(
            "Crawl complete: %d pages fetched, %d endpoints found (seed=%s)",
            fetched_count,
            len(endpoints),
            start_url,
        )
        return endpoints


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _add_endpoint(
    ep: Endpoint,
    seen_urls: set[str],
    result: list[Endpoint],
) -> None:
    """
    Add ``ep`` to ``result`` if its normalised URL hasn't been seen before.

    Mutates ``seen_urls`` and ``result`` in-place.
    """
    norm = _normalise_url(ep.url)
    if norm not in seen_urls:
        seen_urls.add(norm)
        ep.url = norm  # store the canonical form
        result.append(ep)
