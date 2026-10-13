"""
ProbeX – scan REST endpoints.

Routes
------
POST /api/scans                         – validate consent, create scan, start pipeline.
GET  /api/scans                         – list all scans, newest first.
GET  /api/scans/{scan_id}               – full ScanSummary with findings.
GET  /api/scans/{scan_id}/report        – download JSON or self-contained HTML report.

Design decisions
----------------
- Consent check returns HTTP 400 (Bad Request), not 422.  422 is the FastAPI
  default for schema-validation errors; a deliberate logical rejection like
  "you didn't tick the consent box" is semantically a 400.
- The POST handler calls ``start_scan_task()`` instead of adding to
  ``BackgroundTasks`` — the task needs to run in the main event loop so it can
  use ``asyncio.Queue`` for WS broadcast.
- The report endpoint streams the HTML as a ``StreamingResponse`` so very large
  reports don't buffer in memory.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from sqlmodel import Session

from app.core.runner import start_scan_task
from app.core.config import settings
from app.core.guardrails import TargetBlocked, check_scan_rate_limit, resolve_and_check_target
from app.db import crud
from app.db.session import get_session
from app.schemas import Finding, ScanRequest, ScanSummary

router = APIRouter(tags=["scans"])


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _row_to_finding(f) -> Finding:  # type: ignore[no-untyped-def]
    """Convert a ``FindingRow`` ORM object to a ``Finding`` Pydantic schema."""
    return Finding(
        id=f.id,
        template_id=f.template_id,
        title=f.title,
        severity=f.severity,  # type: ignore[arg-type]
        url=f.url,
        parameter=f.parameter,
        payload=f.payload,
        evidence=f.evidence,
        cwe=f.cwe,
        owasp=f.owasp,
        cvss_score=f.cvss_score,
        confidence=f.confidence,
        remediation=f.remediation,
        ai_remediation=f.ai_remediation,
        is_example=f.is_example,
    )


def _build_summary(scan, findings) -> ScanSummary:  # type: ignore[no-untyped-def]
    """Assemble a ``ScanSummary`` from ORM rows."""
    finding_objs = [_row_to_finding(f) for f in findings]

    severity_counts: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    for f in finding_objs:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    return ScanSummary(
        scan_id=scan.id,
        target_url=scan.target_url,
        status=scan.status,  # type: ignore[arg-type]
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        endpoints_found=scan.endpoints_found,
        findings_by_severity=severity_counts,
        risk_score=scan.risk_score,
        findings=finding_objs,
        is_example=scan.is_example,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "/scans",
    status_code=202,
    summary="Create and enqueue a new scan",
    response_description="Scan ID and initial status 'queued'.",
    responses={
        400: {"description": "Consent not confirmed."},
        202: {"description": "Scan accepted and queued."},
    },
)
async def create_scan(
    body: ScanRequest,
    request: Request,
    session: Session = Depends(get_session),
) -> dict:
    """
    Start a new DAST scan against ``target_url``.

    **Consent gate**: ``consent_confirmed`` must be ``true``.  Requests with
    ``false`` are rejected with HTTP **400 Bad Request** and the message
    ``"You must confirm you have permission to scan this target."``

    The scan is persisted immediately with status ``queued`` and the engine
    pipeline runs as an ``asyncio`` background task.  Poll
    ``GET /api/scans/{scan_id}`` or open ``/ws/scans/{scan_id}`` for live
    progress.
    """
    if not body.consent_confirmed:
        raise HTTPException(
            status_code=400,
            detail="You must confirm you have permission to scan this target.",
        )

    requester_ip = request.client.host if request.client else "unknown"
    try:
        # Local lab mode is explicitly enabled with ALLOW_PRIVATE_TARGETS=true.
        # Do not make a developer wait after a few localhost iterations; public
        # deployments retain the per-requester admission limit.
        if not settings.allow_private_targets:
            check_scan_rate_limit(requester_ip)
        await resolve_and_check_target(str(body.target_url))
    except TargetBlocked as exc:
        crud.add_audit_log(session, "scan_blocked", str(exc), requester_ip=requester_ip)
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    scan_id = str(uuid.uuid4())
    target_str = str(body.target_url)

    crud.create_scan(
        session=session,
        scan_id=scan_id,
        target_url=target_str,
        profile=body.profile,
        consent_confirmed=body.consent_confirmed,
    )
    crud.add_audit_log(session, "scan_accepted", f"profile={body.profile}", scan_id=scan_id, requester_ip=requester_ip)

    # Schedule the pipeline — creates an asyncio.Task in the running loop.
    start_scan_task(scan_id, body)

    return {"scan_id": scan_id, "status": "queued"}


@router.get(
    "/scans",
    summary="List all scans",
    response_model=list[ScanSummary],
)
def list_scans(session: Session = Depends(get_session)) -> list[ScanSummary]:
    """
    Return all scans, newest first (by ``started_at``).

    Includes the seeded example scan from Task S4 — those rows carry
    ``is_example=true`` so the frontend can render a "Demo" badge.
    """
    scans = crud.list_scans(session)
    summaries: list[ScanSummary] = []
    for scan in scans:
        findings = crud.get_findings_for_scan(session, scan.id)
        summaries.append(_build_summary(scan, findings))
    return summaries


@router.get(
    "/scans/{scan_id}",
    summary="Get a single scan with full findings",
    response_model=ScanSummary,
    responses={404: {"description": "Scan not found."}},
)
def get_scan(scan_id: str, session: Session = Depends(get_session)) -> ScanSummary:
    """Fetch the full ``ScanSummary`` including all ``Finding`` objects."""
    scan = crud.get_scan(session, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    findings = crud.get_findings_for_scan(session, scan_id)
    return _build_summary(scan, findings)


@router.get(
    "/scans/{scan_id}/report",
    summary="Download scan report as JSON or HTML",
    responses={
        200: {"description": "Report file (application/json or text/html)."},
        400: {"description": "Unsupported format."},
        404: {"description": "Scan not found."},
        409: {"description": "Scan not yet complete."},
    },
)
def get_report(
    scan_id: str,
    format: str = Query(default="json", pattern="^(json|html)$"),
    session: Session = Depends(get_session),
):
    """
    Download a complete scan report.

    ``format=json`` returns the ``ScanSummary`` serialised as JSON.
    ``format=html`` returns a self-contained dark-theme HTML file that can be
    opened offline — embeds all CSS inline, no external dependencies.

    The scan must be in status ``done`` (reports for in-progress scans are
    rejected with 409).
    """
    scan = crud.get_scan(session, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")

    if scan.status not in ("done", "failed", "blocked"):
        raise HTTPException(
            status_code=409,
            detail=f"Scan is not yet complete (status='{scan.status}'). Try again when done.",
        )

    findings_rows = crud.get_findings_for_scan(session, scan_id)

    # Build engine ScanResult for the reporter.
    from engine.models import (
        Finding as EngineFinding,
        ScanResult as EngineScanResult,
    )
    from engine.reporter import build_json, build_html

    engine_findings = [
        EngineFinding(
            id=f.id,
            template_id=f.template_id,
            title=f.title,
            severity=f.severity,
            url=f.url,
            evidence=f.evidence,
            cwe=f.cwe,
            owasp=f.owasp,
            cvss_score=f.cvss_score,
            confidence=f.confidence,
            remediation=f.remediation,
            parameter=f.parameter,
            payload=f.payload,
            ai_remediation=f.ai_remediation,
            is_example=f.is_example,
        )
        for f in findings_rows
    ]

    engine_result = EngineScanResult(
        scan_id=scan.id,
        target_url=scan.target_url,
        status=scan.status,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        endpoints_found=scan.endpoints_found,
        findings=engine_findings,
        risk_score=scan.risk_score,
        is_example=scan.is_example,
    )

    if format == "json":
        return JSONResponse(
            content=build_json(engine_result),
            headers={
                "Content-Disposition": f'attachment; filename="probex-{scan_id[:8]}.json"'
            },
        )

    # HTML
    html_content = build_html(engine_result)
    return StreamingResponse(
        iter([html_content]),
        media_type="text/html",
        headers={
            "Content-Disposition": f'attachment; filename="probex-{scan_id[:8]}.html"'
        },
    )


# ---------------------------------------------------------------------------
# Delete endpoints
# ---------------------------------------------------------------------------

@router.delete(
    "/scans/{scan_id}",
    summary="Delete a single scan and all its findings",
    status_code=200,
)
async def delete_scan(
    scan_id: str,
    session: Session = Depends(get_session),
) -> dict:
    """Permanently remove one scan record plus every finding attached to it."""
    found = crud.delete_scan(session, scan_id)
    if not found:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"deleted": scan_id}


@router.delete(
    "/scans",
    summary="Clear scan history (keeps example scans by default)",
    status_code=200,
)
async def clear_history(
    keep_examples: bool = True,
    session: Session = Depends(get_session),
) -> dict:
    """Delete all real scans (and optionally example scans too)."""
    count = crud.clear_scan_history(session, keep_examples=keep_examples)
    return {"deleted_count": count}
