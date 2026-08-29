"""
ProbeX – real scan pipeline with WebSocket broadcast.

Architecture
------------
``RUNNING_SCANS`` is an in-process registry that maps each live ``scan_id``
to an ``asyncio.Queue[WSMessage]``.  The WebSocket handler in ``api/ws.py``
reads from this queue; the runner puts into it.

    POST /api/scans  →  start_scan_task()  →  asyncio.create_task(run_scan())
                                                          ↓
                                              RUNNING_SCANS[scan_id] queue
                                                          ↓
                                              ws.py reads & streams to client

The queue is created before the task starts and deleted when the scan reaches
a terminal state, so late-connecting WS clients that find the scan already
done will see an empty / missing queue and can read the DB directly.

Event replay buffer
-------------------
``_EVENT_BUFFER[scan_id]`` stores every WSMessage that was ever put into the
queue for that scan.  A WS client that connects after events have already been
emitted will receive the full replay before switching to live mode.

Pipeline stages
---------------
queued → crawling → fuzzing → analyzing → done  (or failed / blocked on error)
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any

from app.core.config import settings
from app.db import crud
from app.db.session import engine
from app.schemas import ScanRequest, WSMessage
from engine.crawler import HttpCrawler
from engine.detectors.headers import check_headers
from engine.detectors.sqli import detect_sqli_error
from engine.detectors.xss import detect_xss
from engine.http_client import HttpClient
from engine.reporter import build_result

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-process registries
# ---------------------------------------------------------------------------

# scan_id → asyncio.Queue of WSMessage-compatible dicts
RUNNING_SCANS: dict[str, asyncio.Queue] = {}

# scan_id → list of all events ever broadcast (for WS replay on late connect)
_EVENT_BUFFER: dict[str, list[dict]] = {}

# Terminal statuses — queue is cleaned up after these.
_TERMINAL_STATUSES = frozenset({"done", "failed", "blocked"})


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def start_scan_task(scan_id: str, request: ScanRequest) -> None:
    """
    Register a queue for ``scan_id`` and schedule ``run_scan`` as an asyncio
    background task.

    Must be called from within an async context (i.e. inside a FastAPI route
    handler) so the running event loop is available.

    Parameters
    ----------
    scan_id:
        UUID assigned to this scan at creation time.
    request:
        The validated ``ScanRequest`` object (carries target_url, profile,
        consent_confirmed).
    """
    q: asyncio.Queue = asyncio.Queue()
    RUNNING_SCANS[scan_id] = q
    _EVENT_BUFFER[scan_id] = []
    asyncio.create_task(run_scan(scan_id, request))


def broadcast(scan_id: str, msg: dict) -> None:
    """
    Put a WSMessage-compatible dict onto the queue for ``scan_id``.

    Also appends to ``_EVENT_BUFFER`` so late WS connections can replay all
    events from the beginning.

    Safe to call even if ``scan_id`` is not in ``RUNNING_SCANS`` (the message
    is only buffered, not queued).
    """
    _EVENT_BUFFER.setdefault(scan_id, []).append(msg)
    q = RUNNING_SCANS.get(scan_id)
    if q is not None:
        q.put_nowait(msg)


def get_event_buffer(scan_id: str) -> list[dict]:
    """Return all buffered events for ``scan_id`` (empty list if none)."""
    return list(_EVENT_BUFFER.get(scan_id, []))


def _status_msg(status: str) -> dict:
    return {"type": "status", "data": {"status": status}}


def _log_msg(message: str) -> dict:
    return {"type": "log", "data": {"message": message}}


def _finding_msg(finding_dict: dict) -> dict:
    return {"type": "finding", "data": finding_dict}


def _progress_msg(pct: float, phase: str) -> dict:
    return {"type": "progress", "data": {"pct": pct, "phase": phase}}


def _finding_to_dict(finding: Any) -> dict:
    """Convert an engine Finding dataclass to a JSON-safe dict."""
    if dataclasses.is_dataclass(finding) and not isinstance(finding, type):
        return {
            "id": finding.id,
            "template_id": finding.template_id,
            "title": finding.title,
            "severity": finding.severity,
            "url": finding.url,
            "parameter": finding.parameter,
            "payload": finding.payload,
            "evidence": finding.evidence,
            "cwe": finding.cwe,
            "owasp": finding.owasp,
            "cvss_score": finding.cvss_score,
            "confidence": finding.confidence,
            "remediation": finding.remediation,
            "ai_remediation": finding.ai_remediation,
            "is_example": finding.is_example,
        }
    # Pydantic model
    return finding.model_dump()


# ---------------------------------------------------------------------------
# DB write helpers (synchronous SQLModel within async context)
# ---------------------------------------------------------------------------


def _db_update_status(
    scan_id: str,
    status: str,
    endpoints_found: int = 0,
    risk_score: float = 0.0,
    stats: dict | None = None,
) -> None:
    from sqlmodel import Session

    with Session(engine) as session:
        crud.update_scan_status(
            session,
            scan_id,
            status,
            endpoints_found=endpoints_found,
            risk_score=risk_score,
            stats=stats,
        )


def _db_add_finding(scan_id: str, finding: Any) -> None:
    """Persist an engine Finding to the DB, converting types as needed."""
    from sqlmodel import Session
    from app.schemas import Finding as SchemaFinding

    with Session(engine) as session:
        # Wrap engine dataclass in the Pydantic schema so crud.add_finding
        # can access attributes uniformly.
        if dataclasses.is_dataclass(finding) and not isinstance(finding, type):
            schema_finding = SchemaFinding(**_finding_to_dict(finding))
        else:
            schema_finding = finding
        crud.add_finding(session, schema_finding, scan_id)


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


async def run_scan(scan_id: str, request: ScanRequest) -> None:
    """
    Execute the full DAST pipeline for ``scan_id``.

    Stages
    ------
    1. **crawling**   – discover endpoints via BFS crawl.
    2. **fuzzing**    – run XSS, SQLi, and header detectors on each endpoint.
    3. **analyzing**  – compute final risk score; placeholder for AI remediation
                        (Task S7).
    4. **done**       – persist final stats; broadcast completion.

    All status transitions are both persisted to SQLite and broadcast over the
    WS queue.  On any unhandled exception, the scan is marked ``failed`` and
    the exception is logged.

    Parameters
    ----------
    scan_id:
        UUID assigned at scan creation time.
    request:
        The original ``ScanRequest`` (carries target_url, profile).
    """
    target_url = str(request.target_url)
    t_start = time.monotonic()
    all_findings: list[Any] = []

    try:
        # ------------------------------------------------------------------
        # Stage 1: crawling
        # ------------------------------------------------------------------
        _db_update_status(scan_id, "crawling")
        broadcast(scan_id, _status_msg("crawling"))
        broadcast(scan_id, _log_msg(f"Starting crawl of {target_url}"))

        max_depth = 2 if request.profile == "standard" else 1
        max_urls = 200 if request.profile == "standard" else 50

        async with HttpClient() as client:
            crawler = HttpCrawler(client)
            try:
                endpoints = await crawler.crawl(
                    target_url,
                    max_depth=max_depth,
                    max_urls=max_urls,
                )
            except Exception as crawl_exc:
                logger.warning("Crawl failed for %s: %s", target_url, crawl_exc)
                endpoints = []

        n_endpoints = len(endpoints)
        broadcast(scan_id, _log_msg(f"Crawl complete: {n_endpoints} endpoints discovered."))
        broadcast(scan_id, _progress_msg(25.0, "crawling"))

        # ------------------------------------------------------------------
        # Stage 2: fuzzing
        # ------------------------------------------------------------------
        _db_update_status(scan_id, "fuzzing", endpoints_found=n_endpoints)
        broadcast(scan_id, _status_msg("fuzzing"))

        async with HttpClient() as client:
            for idx, ep in enumerate(endpoints):
                pct = 25.0 + (idx / max(n_endpoints, 1)) * 50.0
                broadcast(scan_id, _progress_msg(pct, "fuzzing"))

                # XSS detector
                try:
                    xss_finding = await detect_xss(client, ep)
                    if xss_finding:
                        _db_add_finding(scan_id, xss_finding)
                        broadcast(scan_id, _finding_msg(_finding_to_dict(xss_finding)))
                        all_findings.append(xss_finding)
                        logger.info("XSS finding at %s", ep.url)
                except Exception as exc:
                    logger.warning("XSS detector error on %s: %s", ep.url, exc)

                # SQLi detector
                try:
                    sqli_finding = await detect_sqli_error(client, ep)
                    if sqli_finding:
                        _db_add_finding(scan_id, sqli_finding)
                        broadcast(scan_id, _finding_msg(_finding_to_dict(sqli_finding)))
                        all_findings.append(sqli_finding)
                        logger.info("SQLi finding at %s", ep.url)
                except Exception as exc:
                    logger.warning("SQLi detector error on %s: %s", ep.url, exc)

                # Headers detector (once per endpoint URL)
                try:
                    header_findings = await check_headers(client, ep.url)
                    for hf in header_findings:
                        _db_add_finding(scan_id, hf)
                        broadcast(scan_id, _finding_msg(_finding_to_dict(hf)))
                        all_findings.append(hf)
                except Exception as exc:
                    logger.warning("Headers detector error on %s: %s", ep.url, exc)

        broadcast(scan_id, _progress_msg(75.0, "fuzzing"))
        broadcast(
            scan_id,
            _log_msg(f"Fuzzing complete: {len(all_findings)} findings."),
        )

        # ------------------------------------------------------------------
        # Stage 3: analyzing
        # ------------------------------------------------------------------
        _db_update_status(scan_id, "analyzing")
        broadcast(scan_id, _status_msg("analyzing"))
        broadcast(scan_id, _log_msg("Computing risk score…"))
        # AI remediation loop deferred to Task S7.

        scan_result = build_result(
            scan_id=scan_id,
            target_url=target_url,
            started_at=datetime.now(timezone.utc),
            endpoints_found=n_endpoints,
            findings=all_findings,
        )
        broadcast(scan_id, _progress_msg(95.0, "analyzing"))

        # ------------------------------------------------------------------
        # Stage 4: done
        # ------------------------------------------------------------------
        elapsed = time.monotonic() - t_start
        _db_update_status(
            scan_id,
            "done",
            endpoints_found=n_endpoints,
            risk_score=scan_result.risk_score,
            stats={"duration_s": round(elapsed, 2), "findings_total": len(all_findings)},
        )
        broadcast(scan_id, _status_msg("done"))
        broadcast(scan_id, _progress_msg(100.0, "done"))
        broadcast(
            scan_id,
            _log_msg(
                f"Scan complete in {elapsed:.1f}s — "
                f"risk score {scan_result.risk_score:.1f}/100."
            ),
        )
        logger.info(
            "Scan %s done: %d endpoints, %d findings, risk=%.1f, elapsed=%.1fs",
            scan_id,
            n_endpoints,
            len(all_findings),
            scan_result.risk_score,
            elapsed,
        )

    except Exception as exc:
        logger.exception("Scan %s failed with unhandled exception", scan_id)
        _db_update_status(scan_id, "failed")
        broadcast(scan_id, _status_msg("failed"))
        broadcast(scan_id, {"type": "error", "data": {"message": str(exc)}})

    finally:
        # Remove the live queue; the event buffer stays for late WS connects.
        RUNNING_SCANS.pop(scan_id, None)
