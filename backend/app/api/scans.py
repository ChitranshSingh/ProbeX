"""
ProbeX – scan REST endpoints.

Routes
------
POST /api/scans        – create and enqueue a new scan.
GET  /api/scans        – list all scans (summary view).
GET  /api/scans/{id}   – fetch a single scan with full findings.

Background tasks run the engine pipeline asynchronously so the POST handler
returns immediately with HTTP 202 Accepted.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlmodel import Session

from app.core.runner import run_scan
from app.db import crud
from app.db.session import get_session
from app.schemas import ScanRequest, ScanSummary

router = APIRouter(tags=["scans"])


# ---------------------------------------------------------------------------
# Placeholder helper — builds a ScanSummary from DB rows
# ---------------------------------------------------------------------------


def _build_summary(scan, findings) -> ScanSummary:  # type: ignore[no-untyped-def]
    """Assemble a ScanSummary from ORM objects (used by GET endpoints)."""
    from app.schemas import Finding

    finding_objs = [
        Finding(
            id=f.id,
            template_id=f.template_id,
            title=f.title,
            severity=f.severity,
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
        for f in findings
    ]

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
)
async def create_scan(
    body: ScanRequest,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session),
) -> dict:
    """
    Start a new DAST scan against ``target_url``.

    The scan is persisted immediately with status ``queued`` and the engine
    pipeline runs as a background task.  Poll ``GET /api/scans/{scan_id}`` or
    open the WebSocket for live progress.

    Requires ``consent_confirmed=true`` — requests with false are rejected.
    """
    if not body.consent_confirmed:
        raise HTTPException(
            status_code=422,
            detail="consent_confirmed must be true — you must have authorisation to test the target.",
        )

    scan_id = str(uuid.uuid4())
    target_str = str(body.target_url)

    crud.create_scan(
        session=session,
        scan_id=scan_id,
        target_url=target_str,
        profile=body.profile,
    )

    background_tasks.add_task(run_scan, scan_id, target_str, body.profile)

    return {"scan_id": scan_id, "status": "queued"}


@router.get(
    "/scans",
    summary="List all scans",
    response_model=list[ScanSummary],
)
def list_scans(session: Session = Depends(get_session)) -> list[ScanSummary]:
    """Return all scans, newest first, with a lightweight summary (no findings list)."""
    scans = crud.list_scans(session)
    summaries = []
    for scan in scans:
        findings = crud.get_findings_for_scan(session, scan.id)
        summaries.append(_build_summary(scan, findings))
    return summaries


@router.get(
    "/scans/{scan_id}",
    summary="Get a single scan with full findings",
    response_model=ScanSummary,
)
def get_scan(scan_id: str, session: Session = Depends(get_session)) -> ScanSummary:
    """Fetch the full ScanSummary including all Finding objects."""
    scan = crud.get_scan(session, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    findings = crud.get_findings_for_scan(session, scan_id)
    return _build_summary(scan, findings)
