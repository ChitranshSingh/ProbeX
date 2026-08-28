"""
ProbeX – Task S4: Seed an example scan with synthetic findings.

Run this script once after the database has been created to populate a
realistic-looking demo scan that the UI can display immediately — even before
a real scan has been executed.

Usage (from the backend/ directory with venv active):

    python -m seed.seed_example_scan

All seeded records carry ``is_example=True`` so the UI can display a
prominent "Demo" badge and users are never misled about live vs. synthetic
results.
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup — make sure 'backend/' is on sys.path when run as a script.
# ---------------------------------------------------------------------------

_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))


from app.db.crud import create_finding, create_scan, update_scan_status
from app.db.session import create_db_and_tables, engine
from app.schemas import Finding
from sqlmodel import Session


# ---------------------------------------------------------------------------
# Synthetic findings data
# ---------------------------------------------------------------------------

EXAMPLE_TARGET = "http://demo.probex.local"

EXAMPLE_FINDINGS: list[dict] = [
    {
        "template_id": "xss-reflected",
        "title": "Reflected Cross-Site Scripting",
        "severity": "high",
        "url": f"{EXAMPLE_TARGET}/search?q=test",
        "parameter": "q",
        "payload": '<script>alert(1)</script>',
        "evidence": (
            "Response body contained the injected payload verbatim:\n"
            "<p>Results for: <script>alert(1)</script></p>"
        ),
        "cwe": "CWE-79",
        "owasp": "A03:2021 – Injection",
        "cvss_score": 7.2,
        "confidence": 0.95,
        "remediation": (
            "Encode all user-supplied data before inserting it into HTML contexts. "
            "Use html.escape() server-side and DOMPurify client-side. "
            "Add a strict Content-Security-Policy header."
        ),
    },
    {
        "template_id": "sqli-error-based",
        "title": "SQL Injection (Error-Based)",
        "severity": "critical",
        "url": f"{EXAMPLE_TARGET}/product?id=1",
        "parameter": "id",
        "payload": "'",
        "evidence": (
            "Response status 500. Body contained:\n"
            "You have an error in your SQL syntax near ''' at line 1"
        ),
        "cwe": "CWE-89",
        "owasp": "A03:2021 – Injection",
        "cvss_score": 9.8,
        "confidence": 0.92,
        "remediation": (
            "Use parameterised queries or prepared statements. "
            "Never concatenate user input into SQL strings. "
            "Apply least privilege to the DB account."
        ),
    },
    {
        "template_id": "missing-csp",
        "title": "Missing Content-Security-Policy Header",
        "severity": "medium",
        "url": EXAMPLE_TARGET,
        "parameter": None,
        "payload": None,
        "evidence": "HTTP response did not include a Content-Security-Policy header.",
        "cwe": "CWE-693",
        "owasp": "A05:2021 – Security Misconfiguration",
        "cvss_score": 5.3,
        "confidence": 1.0,
        "remediation": (
            "Add 'Content-Security-Policy: default-src self;' to all HTTP responses. "
            "Tune the policy to allow only required sources."
        ),
    },
    {
        "template_id": "open-redirect",
        "title": "Open Redirect",
        "severity": "medium",
        "url": f"{EXAMPLE_TARGET}/login?next=http://evil.example.com",
        "parameter": "next",
        "payload": "http://evil.example.com",
        "evidence": (
            "Server returned HTTP 302 with Location: http://evil.example.com "
            "without validating the redirect destination."
        ),
        "cwe": "CWE-601",
        "owasp": "A01:2021 – Broken Access Control",
        "cvss_score": 6.1,
        "confidence": 0.88,
        "remediation": (
            "Validate redirect targets against an allowlist of known-safe internal paths. "
            "Reject any redirect to an external origin."
        ),
    },
    {
        "template_id": "x-frame-options-missing",
        "title": "Missing X-Frame-Options Header",
        "severity": "low",
        "url": EXAMPLE_TARGET,
        "parameter": None,
        "payload": None,
        "evidence": "HTTP response did not include an X-Frame-Options header.",
        "cwe": "CWE-693",
        "owasp": "A05:2021 – Security Misconfiguration",
        "cvss_score": 4.3,
        "confidence": 1.0,
        "remediation": (
            "Add 'X-Frame-Options: DENY' (or SAMEORIGIN) to all HTTP responses "
            "to prevent clickjacking attacks."
        ),
    },
]


# ---------------------------------------------------------------------------
# Seeding logic
# ---------------------------------------------------------------------------


def seed() -> str:
    """
    Insert one example scan with synthetic findings into the database.

    Returns
    -------
    str
        The ``scan_id`` of the seeded scan.
    """
    create_db_and_tables()

    scan_id = str(uuid.uuid4())
    started_at = datetime(2026, 8, 1, 9, 0, 0, tzinfo=timezone.utc)

    with Session(engine) as session:
        # 1. Create the scan record.
        create_scan(
            session=session,
            scan_id=scan_id,
            target_url=EXAMPLE_TARGET,
            profile="standard",
            is_example=True,
        )

        # 2. Insert each synthetic finding.
        for raw in EXAMPLE_FINDINGS:
            finding = Finding(
                id=str(uuid.uuid4()),
                is_example=True,
                ai_remediation=None,
                **raw,
            )
            create_finding(session=session, finding=finding, scan_id=scan_id)

        # 3. Mark scan as done with a plausible risk score.
        update_scan_status(session=session, scan_id=scan_id, status="done")

        # Manually patch endpoints_found and risk_score (crud helpers TBD).
        from app.db.crud import get_scan

        scan = get_scan(session, scan_id)
        if scan:
            scan.endpoints_found = 14
            scan.risk_score = 72.5
            scan.finished_at = datetime(2026, 8, 1, 9, 3, 12, tzinfo=timezone.utc)
            session.add(scan)
            session.commit()

    print(f"[ProbeX seed] Example scan created: scan_id={scan_id}")
    print(f"[ProbeX seed] {len(EXAMPLE_FINDINGS)} synthetic findings inserted.")
    print("[ProbeX seed] All records carry is_example=True — safe for demo use.")
    return scan_id


if __name__ == "__main__":
    seed()
