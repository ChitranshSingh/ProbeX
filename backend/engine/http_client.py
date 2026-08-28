"""
ProbeX Engine – async HTTP client with retry and baseline recording.

Responsibilities
----------------
- Wrap ``httpx.AsyncClient`` with a consistent User-Agent.
- Transparently retry transient errors (connection reset, 429, 503) up to
  ``max_retries`` times with exponential back-off (0.5 s, 1.0 s).
- Enforce a hard 10-second per-request timeout.
- Expose ``record_baseline(url)`` which issues one clean, unmodified GET and
  returns a ``Baseline`` dataclass consumed by the confidence scorer (Task S2).

Zero FastAPI / SQLModel imports — this module must stay standalone.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from engine.models import Baseline

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_USER_AGENT = (
    "Mozilla/5.0 (compatible; ProbeX-Scanner/0.1; "
    "+https://github.com/probex/probex; security-research)"
)
"""
Realistic User-Agent that:
  - Looks browser-like enough to avoid trivial bot-filters.
  - Identifies itself as a security scanner for ethical transparency.
  - Includes a public reference URL (placeholder) so site owners can verify.
"""

_DEFAULT_TIMEOUT = 10.0        # seconds per request
_MAX_RETRIES = 2               # total retry attempts after the first failure
_RETRY_BASE_DELAY = 0.5        # seconds — doubles on each retry (0.5 → 1.0)

# HTTP status codes that are safe to retry (server-side transient errors).
_RETRYABLE_STATUSES: frozenset[int] = frozenset({429, 503, 504})


# ---------------------------------------------------------------------------
# HttpClient
# ---------------------------------------------------------------------------


class HttpClient:
    """
    Async HTTP client used throughout the ProbeX engine pipeline.

    Usage::

        async with HttpClient() as client:
            resp = await client.get("http://target.local/page")
            baseline = await client.record_baseline("http://target.local/page")
    """

    def __init__(
        self,
        timeout: float = _DEFAULT_TIMEOUT,
        max_retries: int = _MAX_RETRIES,
        follow_redirects: bool = True,
        verify_ssl: bool = True,
    ) -> None:
        """
        Initialise the client.

        Parameters
        ----------
        timeout:
            Per-request timeout in seconds (connect + read combined).
        max_retries:
            Number of retry attempts after the first failure.  Set to 0 to
            disable retries entirely (useful in unit tests).
        follow_redirects:
            Whether to follow HTTP 3xx redirects automatically.
        verify_ssl:
            Set to ``False`` to skip TLS certificate verification — useful
            when scanning self-signed staging environments.
        """
        self._timeout = timeout
        self._max_retries = max_retries
        self._client = httpx.AsyncClient(
            headers={"User-Agent": _USER_AGENT},
            timeout=timeout,
            follow_redirects=follow_redirects,
            verify=verify_ssl,
        )

    # ------------------------------------------------------------------
    # Public request methods
    # ------------------------------------------------------------------

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """Send a GET request with automatic retry on transient failures."""
        return await self._request_with_retry("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        """Send a POST request with automatic retry on transient failures."""
        return await self._request_with_retry("POST", url, **kwargs)

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Send an arbitrary HTTP request with automatic retry."""
        return await self._request_with_retry(method, url, **kwargs)

    # ------------------------------------------------------------------
    # Baseline recording
    # ------------------------------------------------------------------

    async def record_baseline(self, url: str) -> Baseline:
        """
        Issue one clean, unmodified GET to ``url`` and return a ``Baseline``.

        The baseline captures the *pre-fuzzing* state of the endpoint so the
        confidence scorer can compute:
        - Response-body delta (did the response change significantly?).
        - Status-code variance (did a 200 become a 500?).
        - Timing anomalies (did response time spike — possible blind SQLi?).

        Parameters
        ----------
        url:
            Absolute URL to record the baseline for.  No payload is injected.

        Returns
        -------
        Baseline
            Dataclass with ``status``, ``text``, and ``elapsed_ms``.

        Raises
        ------
        httpx.HTTPError
            Propagated from the underlying HTTPX client after all retries are
            exhausted.
        """
        t0 = time.monotonic()
        resp = await self._request_with_retry("GET", url)
        elapsed_ms = (time.monotonic() - t0) * 1000.0
        return Baseline(
            status=resp.status_code,
            text=resp.text,
            elapsed_ms=elapsed_ms,
        )

    # ------------------------------------------------------------------
    # Internal retry logic
    # ------------------------------------------------------------------

    async def _request_with_retry(
        self, method: str, url: str, **kwargs: Any
    ) -> httpx.Response:
        """
        Execute an HTTP request, retrying up to ``self._max_retries`` times.

        Retry conditions:
        - ``httpx.TransportError`` (connection reset, network unreachable, …).
        - ``httpx.TimeoutException`` (connect or read timeout).
        - HTTP responses with a status code in ``_RETRYABLE_STATUSES``
          (429 Too Many Requests, 503/504 Service Unavailable).

        Back-off schedule: ``_RETRY_BASE_DELAY * 2^attempt`` seconds
        (0.5 s before attempt 1, 1.0 s before attempt 2).
        """
        last_exc: BaseException | None = None

        for attempt in range(self._max_retries + 1):
            if attempt > 0:
                delay = _RETRY_BASE_DELAY * (2 ** (attempt - 1))
                logger.debug(
                    "Retry %d/%d for %s %s — sleeping %.1fs",
                    attempt,
                    self._max_retries,
                    method,
                    url,
                    delay,
                )
                await asyncio.sleep(delay)

            try:
                resp = await self._client.request(method, url, **kwargs)
                if resp.status_code in _RETRYABLE_STATUSES:
                    logger.debug(
                        "Retryable status %d from %s %s",
                        resp.status_code,
                        method,
                        url,
                    )
                    last_exc = httpx.HTTPStatusError(
                        f"Retryable status {resp.status_code}",
                        request=resp.request,
                        response=resp,
                    )
                    continue  # retry
                return resp

            except (httpx.TransportError, httpx.TimeoutException) as exc:
                logger.debug(
                    "Transport error on attempt %d for %s %s: %s",
                    attempt,
                    method,
                    url,
                    exc,
                )
                last_exc = exc

        # All attempts exhausted — re-raise the last exception.
        raise last_exc  # type: ignore[misc]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def aclose(self) -> None:
        """Close the underlying HTTPX client and release all connections."""
        await self._client.aclose()

    async def __aenter__(self) -> "HttpClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()
