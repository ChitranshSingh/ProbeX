"""
ProbeX Engine – async HTTP client wrapper.

Thin wrapper around ``httpx.AsyncClient`` that adds:
  - Consistent User-Agent header so targets can identify scanner traffic.
  - Configurable timeout / retry behaviour.
  - Response normalisation (always returns an ``httpx.Response`` or raises).

Zero FastAPI / SQLModel imports — this module must stay standalone.
"""

from __future__ import annotations

import httpx

_USER_AGENT = "ProbeX-Scanner/0.1 (security research; contact: security@example.com)"
_DEFAULT_TIMEOUT = 10.0  # seconds


class HttpClient:
    """Async HTTP client used throughout the engine pipeline."""

    def __init__(
        self,
        timeout: float = _DEFAULT_TIMEOUT,
        follow_redirects: bool = True,
        verify_ssl: bool = True,
    ) -> None:
        """
        Initialise the client.

        Parameters
        ----------
        timeout:
            Per-request timeout in seconds.
        follow_redirects:
            Whether to follow HTTP 3xx redirects automatically.
        verify_ssl:
            Set to False to skip TLS certificate verification (useful when
            testing self-signed staging environments).
        """
        self._client = httpx.AsyncClient(
            headers={"User-Agent": _USER_AGENT},
            timeout=timeout,
            follow_redirects=follow_redirects,
            verify=verify_ssl,
        )

    async def get(self, url: str, **kwargs) -> httpx.Response:  # type: ignore[no-untyped-def]
        """Send a GET request and return the response."""
        return await self._client.get(url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:  # type: ignore[no-untyped-def]
        """Send a POST request and return the response."""
        return await self._client.post(url, **kwargs)

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:  # type: ignore[no-untyped-def]
        """Send an arbitrary HTTP request."""
        return await self._client.request(method, url, **kwargs)

    async def aclose(self) -> None:
        """Close the underlying HTTPX client and release connections."""
        await self._client.aclose()

    async def __aenter__(self) -> "HttpClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()
