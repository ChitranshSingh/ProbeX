"""
ProbeX – Pydantic v2 schema definitions.

All API request/response shapes live here so that FastAPI can generate
accurate OpenAPI docs and the frontend TypeScript client can be auto-generated
from a single source of truth.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, HttpUrl


# ---------------------------------------------------------------------------
# Literals
# ---------------------------------------------------------------------------

ScanStatus = Literal[
    "queued",
    "crawling",
    "fuzzing",
    "analyzing",
    "done",
    "failed",
    "blocked",
]
"""Lifecycle states a scan passes through, in rough chronological order.

- ``queued``    – created, waiting for a worker slot.
- ``crawling``  – spider is discovering endpoints.
- ``fuzzing``   – payloads are being sent to discovered endpoints.
- ``analyzing`` – findings are being enriched / AI remediation is running.
- ``done``      – scan completed successfully.
- ``failed``    – scan aborted due to an unrecoverable error.
- ``blocked``   – target returned enough 4xx/WAF responses to abort early.
"""


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    """Payload sent by the client to kick off a new scan."""

    target_url: HttpUrl = Field(
        ...,
        description=(
            "Fully-qualified URL of the application under test. "
            "Must include scheme (http:// or https://)."
        ),
        examples=["http://localhost:3000"],
    )

    profile: Literal["quick", "standard"] = Field(
        default="quick",
        description=(
            "Scan intensity profile. "
            "'quick' runs a single-depth crawl with a reduced payload set (~30 s). "
            "'standard' runs a multi-depth crawl with the full payload library (~3 min)."
        ),
    )

    consent_confirmed: bool = Field(
        ...,
        description=(
            "The caller must explicitly set this to True, acknowledging they have "
            "authorisation to test the target URL. Requests with False are rejected "
            "with HTTP 422 to prevent accidental scanning of third-party systems."
        ),
    )


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    """A single security finding discovered during a scan."""

    id: str = Field(
        ...,
        description="UUID-v4 unique identifier for this finding.",
    )

    template_id: str = Field(
        ...,
        description=(
            "Identifier of the detector template that produced this finding "
            "(e.g. 'xss-reflected', 'sqli-error-based')."
        ),
    )

    title: str = Field(
        ...,
        description="Short human-readable title of the vulnerability.",
        examples=["Reflected Cross-Site Scripting"],
    )

    severity: Literal["critical", "high", "medium", "low", "info"] = Field(
        ...,
        description="CVSS-aligned severity band for prioritisation.",
    )

    url: str = Field(
        ...,
        description="Full URL where the vulnerability was detected.",
    )

    parameter: str | None = Field(
        default=None,
        description=(
            "Name of the HTTP parameter (query string, form field, header) "
            "that was found to be vulnerable. None for vulnerabilities not "
            "tied to a specific parameter (e.g. missing security headers)."
        ),
    )

    payload: str | None = Field(
        default=None,
        description=(
            "Exact payload string that triggered the finding. "
            "None when not applicable (e.g. information-disclosure checks)."
        ),
    )

    evidence: str = Field(
        ...,
        description=(
            "Raw HTTP response snippet or other evidence demonstrating the "
            "vulnerability exists. Kept short (<500 chars) for display purposes."
        ),
    )

    cwe: str = Field(
        ...,
        description="CWE identifier in 'CWE-NNN' format (e.g. 'CWE-79').",
        examples=["CWE-79"],
    )

    owasp: str = Field(
        ...,
        description=(
            "OWASP Top 10 category reference "
            "(e.g. 'A03:2021 – Injection')."
        ),
        examples=["A03:2021 – Injection"],
    )

    cvss_score: float = Field(
        ...,
        ge=0.0,
        le=10.0,
        description="CVSS v3.1 base score in the range [0.0, 10.0].",
    )

    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description=(
            "Engine confidence that this is a true positive, in [0.0, 1.0]. "
            "Computed by engine/confidence.py using signal strength and "
            "response variance."
        ),
    )

    remediation: str = Field(
        ...,
        description=(
            "Static, template-driven remediation guidance stored in the "
            "payload YAML. Always present even when AI is unavailable."
        ),
    )

    ai_remediation: str | None = Field(
        default=None,
        description=(
            "Gemini-generated context-aware remediation advice. "
            "Populated asynchronously after the scan completes; "
            "None when the GEMINI_API_KEY is absent or the AI call fails."
        ),
    )

    is_example: bool = Field(
        default=False,
        description=(
            "True for findings that were injected by the seed script "
            "(seed/seed_example_scan.py) rather than discovered by a live "
            "scan. The UI uses this flag to display a 'Demo' badge so users "
            "are never misled about real vs. synthetic results."
        ),
    )


# ---------------------------------------------------------------------------
# Scan summary model
# ---------------------------------------------------------------------------


class ScanSummary(BaseModel):
    """Aggregated result returned by GET /api/scans/{scan_id}."""

    scan_id: str = Field(
        ...,
        description="UUID-v4 identifier assigned when the scan was created.",
    )

    target_url: str = Field(
        ...,
        description="Serialised target URL exactly as submitted in ScanRequest.",
    )

    status: ScanStatus = Field(
        ...,
        description="Current lifecycle state of the scan.",
    )

    started_at: datetime = Field(
        ...,
        description="UTC timestamp when the scan transitioned from 'queued' to active.",
    )

    finished_at: datetime | None = Field(
        default=None,
        description=(
            "UTC timestamp when the scan reached a terminal state "
            "('done', 'failed', or 'blocked'). None while still running."
        ),
    )

    endpoints_found: int = Field(
        ...,
        ge=0,
        description="Total number of unique endpoints discovered during crawling.",
    )

    findings_by_severity: dict[str, int] = Field(
        ...,
        description=(
            "Mapping of severity label → count of findings at that severity. "
            "Keys are a subset of {'critical','high','medium','low','info'}."
        ),
        examples=[{"critical": 0, "high": 2, "medium": 5, "low": 1, "info": 3}],
    )

    risk_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description=(
            "Composite risk score in [0, 100] computed from CVSS scores and "
            "confidence values of all findings. Higher is worse."
        ),
    )

    findings: list[Finding] = Field(
        default=[],
        description="Full list of Finding objects for this scan.",
    )

    is_example: bool = Field(
        default=False,
        description=(
            "True when this entire ScanSummary was produced by the seed script "
            "rather than a live scan. Mirrors Finding.is_example at the scan level "
            "so the UI can render a prominent 'Demo scan' banner."
        ),
    )


# ---------------------------------------------------------------------------
# WebSocket message envelope
# ---------------------------------------------------------------------------


class WSMessage(BaseModel):
    """Envelope for all messages sent over the /ws/{scan_id} WebSocket stream."""

    type: Literal["status", "progress", "finding", "log", "error"] = Field(
        ...,
        description=(
            "Discriminant field. Consumers should switch on this value:\n"
            "  'status'   – scan lifecycle state changed (data has 'status' key).\n"
            "  'progress' – crawl/fuzz progress update (data has 'pct' key).\n"
            "  'finding'  – a new Finding was detected (data is a Finding dict).\n"
            "  'log'      – informational log line (data has 'message' key).\n"
            "  'error'    – non-fatal error during the scan (data has 'message' key)."
        ),
    )

    data: dict = Field(
        ...,
        description=(
            "Payload whose shape depends on 'type'. "
            "See WSMessage.type docstring for per-type keys."
        ),
    )
