"""
ProbeX Engine – web crawler (placeholder).

The crawler discovers endpoints starting from a seed URL using BFS.  It
extracts links from HTML responses and records the URLs + parameter names
it finds.

Zero FastAPI / SQLModel imports — this module must stay standalone.

TODO (Task E1): implement full BFS crawl using HttpClient + BeautifulSoup.
"""

from __future__ import annotations

from engine.http_client import HttpClient
from engine.models import Endpoint, ScanProfile


async def crawl(
    seed_url: str,
    profile: ScanProfile,
    client: HttpClient,
) -> list[Endpoint]:
    """
    Discover endpoints reachable from ``seed_url`` within the constraints set
    by ``profile``.

    Parameters
    ----------
    seed_url:
        Absolute URL to start crawling from.
    profile:
        Controls ``max_depth`` and ``max_urls``.
    client:
        Shared ``HttpClient`` instance (caller owns lifecycle).

    Returns
    -------
    list[Endpoint]
        All unique endpoints discovered, including query/form parameters.
    """
    # Placeholder: return the seed URL as a single endpoint.
    # TODO: BFS loop, link extraction, form parsing, deduplication.
    _ = await client.get(seed_url)
    return [Endpoint(url=seed_url)]
