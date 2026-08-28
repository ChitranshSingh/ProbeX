"""
ProbeX – CRUD helpers for the database layer.

All database I/O goes through these thin functions so that:
  a) API route handlers stay lean.
  b) We have a single place to add caching or audit logging later.
  c) The engine package (engine/) never has to touch SQLModel directly.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlmodel import Session, select

from app.db.models import FindingRecord, Scan
from app.schemas import Finding, ScanSummary


# ---------------------------------------------------------------------------
# Scan CRUD
# ---------------------------------------------------------------------------


def create_scan(
    session: Session,
    scan_id: str,
    target_url: str,
    profile: str,
    is_example: bool = False,
) -> Scan:
    """Insert a new Scan row and return it."""
    scan = Scan(
        id=scan_id,
        target_url=target_url,
        profile=profile,
        status="queued",
        is_example=is_example,
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


def get_scan(session: Session, scan_id: str) -> Optional[Scan]:
    """Fetch a Scan by primary key.  Returns None if not found."""
    return session.get(Scan, scan_id)


def update_scan_status(session: Session, scan_id: str, status: str) -> Optional[Scan]:
    """Update the ``status`` field of a Scan row."""
    scan = session.get(Scan, scan_id)
    if scan is None:
        return None
    scan.status = status
    if status in ("done", "failed", "blocked"):
        scan.finished_at = datetime.utcnow()
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


def list_scans(session: Session) -> list[Scan]:
    """Return all scans, newest first."""
    statement = select(Scan).order_by(Scan.started_at.desc())  # type: ignore[arg-type]
    return list(session.exec(statement).all())


# ---------------------------------------------------------------------------
# Finding CRUD
# ---------------------------------------------------------------------------


def create_finding(session: Session, finding: Finding, scan_id: str) -> FindingRecord:
    """Persist a Finding (from the engine schema) as a FindingRecord row."""
    record = FindingRecord(
        id=finding.id,
        scan_id=scan_id,
        template_id=finding.template_id,
        title=finding.title,
        severity=finding.severity,
        url=finding.url,
        parameter=finding.parameter,
        payload=finding.payload,
        evidence=finding.evidence,
        cwe=finding.cwe,
        owasp=finding.owasp,
        cvss_score=finding.cvss_score,
        confidence=finding.confidence,
        remediation=finding.remediation,
        ai_remediation=finding.ai_remediation,
        is_example=finding.is_example,
    )
    session.add(record)
    session.commit()
    session.refresh(record)
    return record


def get_findings_for_scan(session: Session, scan_id: str) -> list[FindingRecord]:
    """Return all FindingRecord rows for a given scan."""
    statement = select(FindingRecord).where(FindingRecord.scan_id == scan_id)
    return list(session.exec(statement).all())
