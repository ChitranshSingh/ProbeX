"""
ProbeX Engine – plain dataclasses mirroring the API schemas.

This package is intentionally standalone: zero FastAPI, zero SQLModel, zero
pydantic imports.  It can be imported and tested in isolation, embedded in a
CLI tool, or reused in future team builds without pulling in the web stack.

All shapes here must stay in sync with ``backend/app/schemas.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# ---------------------------------------------------------------------------
# ScanProfile
# ---------------------------------------------------------------------------


@dataclass
class ScanProfile:
    """Controls crawl depth and payload set size for a scan run."""

    name: str
    """Profile identifier: 'quick' or 'standard'."""

    max_depth: int
    """Maximum BFS crawl depth from the seed URL."""

    max_urls: int
    """Hard cap on the number of URLs to crawl."""

    max_payloads_per_param: int
    """Maximum number of payloads to fuzz against each discovered parameter."""


QUICK_PROFILE = ScanProfile(
    name="quick",
    max_depth=1,
    max_urls=50,
    max_payloads_per_param=5,
)

STANDARD_PROFILE = ScanProfile(
    name="standard",
    max_depth=3,
    max_urls=200,
    max_payloads_per_param=20,
)

PROFILES: dict[str, ScanProfile] = {
    "quick": QUICK_PROFILE,
    "standard": STANDARD_PROFILE,
}


# ---------------------------------------------------------------------------
# Baseline (used by confidence scorer — produced by HttpClient.record_baseline)
# ---------------------------------------------------------------------------


@dataclass
class Baseline:
    """
    One clean, unmodified HTTP response recorded before fuzzing begins.

    The confidence scorer compares fuzzed responses against this baseline to
    distinguish deliberate changes (caused by a payload) from server noise.
    """

    status: int
    """HTTP status code of the baseline response."""

    text: str
    """Full response body text of the baseline response."""

    elapsed_ms: float
    """Round-trip time in milliseconds for the baseline request."""


# ---------------------------------------------------------------------------
# FormField
# ---------------------------------------------------------------------------


@dataclass
class FormField:
    """
    A single input discovered inside an HTML ``<form>``.

    Extracted by the crawler's form parser and stored on ``Endpoint`` so the
    fuzzer knows exactly which parameters to target and with what type hints.
    """

    name: str
    """``name`` attribute of the input element."""

    input_type: str
    """
    Normalised semantic type used by the fuzzer for payload selection.

    Values:
    - ``"id_field"``      – name contains 'id' or 'uid'.
    - ``"search_field"``  – name contains 'q', 'query', or 'search'.
    - ``"url_field"``     – name contains 'url', 'redirect', or 'next'.
    - ``"email_field"``   – HTML type attribute is 'email'.
    - ``"generic_text"``  – everything else.
    """

    html_type: str = "text"
    """Raw ``type`` attribute of the ``<input>`` element (e.g. 'text', 'email', 'hidden')."""

    default_value: str = ""
    """Default / placeholder value to use when fuzzing this field."""


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@dataclass
class Endpoint:
    """A URL + HTTP method pair discovered during crawling."""

    url: str
    """Absolute URL of the endpoint."""

    method: str = "GET"
    """HTTP method (GET, POST, PUT, DELETE, …)."""

    params: list[str] = field(default_factory=list)
    """Query-string parameter names present in the URL."""

    headers: dict[str, str] = field(default_factory=dict)
    """Additional headers observed or required for this endpoint."""

    form_fields: list[FormField] = field(default_factory=list)
    """
    Form inputs discovered at this endpoint.

    Populated when the crawler encounters an HTML ``<form>`` whose ``action``
    resolves to this endpoint's URL.  Empty for plain link endpoints.
    """

    input_types: list[str] = field(default_factory=list)
    """
    De-duplicated list of ``FormField.input_type`` values for quick filtering.

    Example: ``["id_field", "search_field", "generic_text"]``.
    The fuzzer uses this to decide which payload sets to apply without
    iterating over ``form_fields`` repeatedly.
    """

    depth: int = 0
    """BFS depth at which this endpoint was first discovered (0 = seed URL)."""


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """
    A single security finding produced by the engine.

    Mirrors ``app.schemas.Finding`` without the Pydantic machinery so the
    engine stays framework-agnostic.
    """

    id: str
    """UUID-v4 unique identifier assigned at creation time."""

    template_id: str
    """Identifier of the detector template that produced this finding."""

    title: str
    """Short human-readable vulnerability title."""

    severity: str
    """Severity band: 'critical' | 'high' | 'medium' | 'low' | 'info'."""

    url: str
    """Full URL where the vulnerability was detected."""

    evidence: str
    """HTTP response snippet or other evidence demonstrating the issue."""

    cwe: str
    """CWE identifier in 'CWE-NNN' format."""

    owasp: str
    """OWASP Top 10 category reference."""

    cvss_score: float
    """CVSS v3.1 base score in [0.0, 10.0]."""

    confidence: float
    """Engine confidence this is a true positive, in [0.0, 1.0]."""

    remediation: str
    """Static, template-driven remediation guidance."""

    parameter: Optional[str] = None
    """Vulnerable HTTP parameter name, if applicable."""

    payload: Optional[str] = None
    """Payload string that triggered the finding."""

    ai_remediation: Optional[str] = None
    """Gemini-generated context-aware remediation (populated post-scan)."""

    is_example: bool = False
    """True for findings injected by seed/seed_example_scan.py."""


# ---------------------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    """
    Aggregated result produced by the engine at the end of a scan run.

    Mirrors ``app.schemas.ScanSummary`` without Pydantic.
    """

    scan_id: str
    """UUID-v4 assigned at scan creation time."""

    target_url: str
    """Serialised target URL."""

    status: str
    """Terminal status: 'done' | 'failed' | 'blocked'."""

    started_at: datetime
    """UTC timestamp when the scan was created."""

    finished_at: Optional[datetime]
    """UTC timestamp when the scan reached terminal status."""

    endpoints_found: int
    """Number of unique endpoints discovered during crawling."""

    findings: list[Finding] = field(default_factory=list)
    """All findings from this scan."""

    risk_score: float = 0.0
    """Composite risk score in [0, 100]."""

    is_example: bool = False
    """True for scans seeded by the seed script."""

    @property
    def findings_by_severity(self) -> dict[str, int]:
        """Return a mapping of severity → count."""
        counts: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts
