"""
ProbeX – CRUD helpers for the database layer.

All database I/O goes through these thin functions so that:
  a) API route handlers stay lean.
  b) We have a single place to add caching or audit logging later.
  c) The engine package (engine/) never has to touch SQLModel directly.

Imported schemas come from ``app.schemas`` — nothing is redefined here.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Optional

from sqlmodel import Session, select

from app.db.models import FindingRow, ScanRow
from app.schemas import Finding


# ---------------------------------------------------------------------------
# Scan CRUD
# ---------------------------------------------------------------------------


def create_scan(
    session: Session,
    scan_id: str,
    target_url: str,
    profile: str,
    consent_confirmed: bool = False,
    is_example: bool = False,
) -> ScanRow:
    """
    Insert a new ScanRow and return it.

    Parameters
    ----------
    scan_id:
        UUID-v4 to use as the primary key.
    target_url:
        Serialised target URL string.
    profile:
        ``"quick"`` or ``"standard"``.
    consent_confirmed:
        Mirrors the caller's consent flag — stored for audit purposes.
    is_example:
        True for seed-script injected demo scans.
    """
    scan = ScanRow(
        id=scan_id,
        target_url=target_url,
        profile=profile,
        status="queued",
        consent_confirmed=consent_confirmed,
        is_example=is_example,
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


def get_scan(session: Session, scan_id: str) -> Optional[ScanRow]:
    """Fetch a ScanRow by primary key.  Returns None if not found."""
    return session.get(ScanRow, scan_id)


def update_scan_status(
    session: Session,
    scan_id: str,
    status: str,
    endpoints_found: int = 0,
    risk_score: float = 0.0,
    stats: Optional[dict] = None,
) -> Optional[ScanRow]:
    """
    Update the ``status`` (and optionally ``endpoints_found``, ``risk_score``,
    ``stats_json``, and ``finished_at``) of a ScanRow.

    Parameters
    ----------
    session:
        Active SQLModel session.
    scan_id:
        Target scan UUID.
    status:
        New lifecycle status string.
    endpoints_found:
        Number of unique endpoints discovered so far (cumulative).
    risk_score:
        Current composite risk score.
    stats:
        Optional dict of miscellaneous statistics to serialise into
        ``stats_json``.  Merged with any existing stats.
    """
    scan = session.get(ScanRow, scan_id)
    if scan is None:
        return None

    scan.status = status

    if endpoints_found:
        scan.endpoints_found = endpoints_found

    if risk_score:
        scan.risk_score = risk_score

    if stats:
        existing: dict = {}
        if scan.stats_json:
            try:
                existing = json.loads(scan.stats_json)
            except (json.JSONDecodeError, ValueError):
                existing = {}
        existing.update(stats)
        scan.stats_json = json.dumps(existing)

    if status in ("done", "failed", "blocked"):
        scan.finished_at = datetime.utcnow()

    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


def list_scans(session: Session) -> list[ScanRow]:
    """Return all scans, newest first (by started_at)."""
    statement = select(ScanRow).order_by(ScanRow.started_at.desc())  # type: ignore[arg-type]
    return list(session.exec(statement).all())


# ---------------------------------------------------------------------------
# Finding CRUD
# ---------------------------------------------------------------------------


def add_finding(session: Session, finding: Finding, scan_id: str) -> FindingRow:
    """
    Persist a ``Finding`` (engine dataclass or Pydantic schema) as a
    ``FindingRow`` row in the database.

    Parameters
    ----------
    session:
        Active SQLModel session.
    finding:
        The ``Finding`` object produced by a detector.  Must expose all fields
        listed in the mapping below.
    scan_id:
        UUID of the parent scan.
    """
    record = FindingRow(
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


# Backwards-compat alias used by seed script.
def create_finding(session: Session, finding: Finding, scan_id: str) -> FindingRow:
    """Alias for :func:`add_finding` — kept for backwards compatibility."""
    return add_finding(session, finding, scan_id)


def get_findings_for_scan(session: Session, scan_id: str) -> list[FindingRow]:
    """Return all FindingRow rows for a given scan, ordered by cvss_score desc."""
    statement = (
        select(FindingRow)
        .where(FindingRow.scan_id == scan_id)
        .order_by(FindingRow.cvss_score.desc())  # type: ignore[arg-type]
    )
    return list(session.exec(statement).all())
