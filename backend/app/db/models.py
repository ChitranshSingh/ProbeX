"""
ProbeX – SQLModel table definitions.

One table per domain concept.  SQLModel lets us use the same class as both
a Pydantic model (for validation) and a SQLAlchemy ORM model (for DB I/O),
keeping the two layers in sync automatically.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlmodel import JSON, Column, Field, SQLModel


def _new_uuid() -> str:
    return str(uuid.uuid4())


class Scan(SQLModel, table=True):
    """Persisted record for a single DAST scan run."""

    __tablename__ = "scans"

    id: str = Field(
        default_factory=_new_uuid,
        primary_key=True,
        description="UUID-v4 primary key.",
    )

    target_url: str = Field(
        ...,
        description="Serialised target URL exactly as submitted.",
    )

    profile: str = Field(
        default="quick",
        description="Scan intensity profile: 'quick' or 'standard'.",
    )

    status: str = Field(
        default="queued",
        description="Current lifecycle state (matches ScanStatus literal).",
    )

    started_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="UTC timestamp when the scan was created / queued.",
    )

    finished_at: Optional[datetime] = Field(
        default=None,
        description="UTC timestamp when the scan reached a terminal state.",
    )

    endpoints_found: int = Field(
        default=0,
        description="Number of unique endpoints discovered during crawling.",
    )

    risk_score: float = Field(
        default=0.0,
        description="Composite risk score [0, 100].",
    )

    is_example: bool = Field(
        default=False,
        description="True for scans seeded by seed/seed_example_scan.py.",
    )


class FindingRecord(SQLModel, table=True):
    """Persisted record for a single security finding."""

    __tablename__ = "findings"

    id: str = Field(
        default_factory=_new_uuid,
        primary_key=True,
        description="UUID-v4 primary key.",
    )

    scan_id: str = Field(
        ...,
        foreign_key="scans.id",
        index=True,
        description="FK → Scan.id.",
    )

    template_id: str = Field(
        ...,
        description="Detector template identifier.",
    )

    title: str = Field(
        ...,
        description="Short human-readable vulnerability title.",
    )

    severity: str = Field(
        ...,
        description="Severity band: critical | high | medium | low | info.",
    )

    url: str = Field(
        ...,
        description="URL where the vulnerability was detected.",
    )

    parameter: Optional[str] = Field(
        default=None,
        description="Vulnerable HTTP parameter name, if applicable.",
    )

    payload: Optional[str] = Field(
        default=None,
        description="Payload string that triggered the finding.",
    )

    evidence: str = Field(
        ...,
        description="Raw HTTP response snippet demonstrating the issue.",
    )

    cwe: str = Field(
        ...,
        description="CWE identifier, e.g. 'CWE-79'.",
    )

    owasp: str = Field(
        ...,
        description="OWASP Top 10 category reference.",
    )

    cvss_score: float = Field(
        default=0.0,
        description="CVSS v3.1 base score [0.0, 10.0].",
    )

    confidence: float = Field(
        default=0.0,
        description="Engine confidence [0.0, 1.0].",
    )

    remediation: str = Field(
        ...,
        description="Static template-driven remediation guidance.",
    )

    ai_remediation: Optional[str] = Field(
        default=None,
        description="Gemini-generated context-aware remediation advice.",
    )

    is_example: bool = Field(
        default=False,
        description="True for findings injected by the seed script.",
    )
