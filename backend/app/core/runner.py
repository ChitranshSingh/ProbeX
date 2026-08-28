"""
ProbeX – scan runner (placeholder).

In the full implementation this module will:
  1. Accept a ScanRequest and a scan_id.
  2. Orchestrate the engine pipeline: crawler → fuzzer → confidence scorer → reporter.
  3. Push real-time progress over the WebSocket broadcast channel.
  4. Write findings and status updates to the database via db/crud.py.

For the scaffold, it exposes the function signature only so that the API
layer compiles without errors.
"""

from __future__ import annotations

import asyncio


async def run_scan(scan_id: str, target_url: str, profile: str) -> None:
    """
    Entry point called by the background task in api/scans.py.

    Parameters
    ----------
    scan_id:
        UUID-v4 string assigned to this scan at creation time.
    target_url:
        Validated target URL string (already serialised from ``HttpUrl``).
    profile:
        Either ``"quick"`` or ``"standard"`` — controls crawl depth and
        payload set size.
    """
    # TODO (Task E1): wire in crawler, fuzzer, confidence scorer, reporter.
    await asyncio.sleep(0)  # yield to event loop; replace with real pipeline
