"""
ProbeX Engine – payload fuzzer (placeholder).

Iterates over discovered endpoints, loads payloads from
``templates/payloads/``, sends them to each parameter, and yields raw
``httpx.Response`` objects for the detectors to analyse.

Zero FastAPI / SQLModel imports — this module must stay standalone.

TODO (Task E2): implement payload loading, parameter injection, response routing.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from engine.http_client import HttpClient
from engine.models import Endpoint, ScanProfile


async def fuzz(
    endpoints: list[Endpoint],
    profile: ScanProfile,
    client: HttpClient,
) -> AsyncIterator[tuple[Endpoint, str, str, object]]:
    """
    Fuzz each endpoint with payloads up to ``profile.max_payloads_per_param``.

    Yields
    ------
    tuple[Endpoint, param_name, payload, httpx.Response]
        One tuple per (endpoint, parameter, payload) combination that received
        a response.  The detector layer consumes these tuples.

    Parameters
    ----------
    endpoints:
        Endpoints returned by the crawler.
    profile:
        Controls how many payloads to send per parameter.
    client:
        Shared ``HttpClient`` instance (caller owns lifecycle).
    """
    # Placeholder: yield nothing — no endpoints have parameters yet.
    # TODO: load YAML payload templates, inject into params, yield responses.
    return
    yield  # make this an async generator without unreachable syntax
