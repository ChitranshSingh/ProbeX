"""
ProbeX Engine – report builder (placeholder).

Aggregates all findings from a scan run into a ``ScanResult`` dataclass,
computes the composite risk score, and optionally writes a JSON / HTML report
to disk.

Zero FastAPI / SQLModel imports — this module must stay standalone.

TODO (Task E3): implement risk score formula and HTML report template.
"""

from __future__ import annotations

from datetime import datetime

from engine.models import Finding, ScanResult


def build_result(
    scan_id: str,
    target_url: str,
    started_at: datetime,
    endpoints_found: int,
    findings: list[Finding],
    is_example: bool = False,
) -> ScanResult:
    """
    Assemble a :class:`~engine.models.ScanResult` from raw engine output.

    The composite risk score formula (placeholder — to be calibrated):

    .. code-block:: text

        risk_score = Σ (cvss_score × confidence × severity_weight) / normaliser

    Parameters
    ----------
    scan_id:
        UUID-v4 of the scan.
    target_url:
        Serialised target URL.
    started_at:
        UTC timestamp when the scan started.
    endpoints_found:
        Total endpoints discovered during crawling.
    findings:
        All findings produced by the detectors.
    is_example:
        True for seeded / demo scans.

    Returns
    -------
    ScanResult
        Fully assembled result with computed risk_score.
    """
    severity_weights = {
        "critical": 1.0,
        "high": 0.75,
        "medium": 0.5,
        "low": 0.25,
        "info": 0.05,
    }

    raw_score = sum(
        f.cvss_score * f.confidence * severity_weights.get(f.severity, 0.1)
        for f in findings
    )
    # Normalise to [0, 100] — cap so a single critical doesn't exceed 100.
    risk_score = min(raw_score * 10, 100.0)

    return ScanResult(
        scan_id=scan_id,
        target_url=target_url,
        status="done",
        started_at=started_at,
        finished_at=datetime.utcnow(),
        endpoints_found=endpoints_found,
        findings=findings,
        risk_score=risk_score,
        is_example=is_example,
    )
