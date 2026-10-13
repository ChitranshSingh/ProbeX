"""
ProbeX Engine – SQL Injection detector (error-based).

Detection strategy
------------------
1. Inject a single quote ``'`` into each eligible parameter.
2. Compare the fuzzed response against the baseline via ``confidence.is_match()``
   using each known database error signature (regex matcher).
3. A signature that matches the fuzzed response **but not the baseline** is a
   confirmed new signal — the key false-positive defence.

The detector only reports when at least one signature passes ``is_match()``.
Pages that always contain "syntax error" in their content (e.g. a coding blog,
a debugging page) will never be flagged because the pattern is already present
in the baseline.

Zero FastAPI / SQLModel imports — this module must stay standalone.
"""

from __future__ import annotations

import uuid
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from engine.confidence import MINIMUM_CONFIDENCE, is_match, score
from engine.http_client import HttpClient
from engine.models import Baseline, Endpoint, Finding

# ---------------------------------------------------------------------------
# Error signatures — one regex per database / driver
# ---------------------------------------------------------------------------

ERROR_SIGNATURES: list[str] = [
    # MySQL / MariaDB
    r"You have an error in your SQL syntax",
    r"mysql_fetch_(array|row|object|assoc)",
    r"supplied argument is not a valid MySQL",
    r"MySqlException",
    # PostgreSQL
    r"ERROR:\s+unterminated",
    r"pg_query\(\):",
    r"PSQLException",
    r"PostgreSQL.*ERROR",
    # MSSQL / SQL Server
    r"Unclosed quotation mark after the character string",
    r"Incorrect syntax near",
    r"Microsoft OLE DB Provider for SQL Server",
    r"SqlException",
    # Oracle
    r"ORA-\d{5}",
    r"oracle\.jdbc",
    # SQLite
    r"SQLite3::query\(\)",
    r"sqlite3\.OperationalError",
    r"near\s+['\"].*['\"]:\s*syntax error",
    r"unrecognized token:",
    # Generic PHP database helpers
    r"Warning:\s+mysql_",
    r"Warning:\s+mysqli_",
    r"Warning:\s+pg_",
    # Generic JDBC / Java
    r"java\.sql\.SQLException",
    r"com\.mysql\.jdbc",
]

# ---------------------------------------------------------------------------
# Input types the SQLi detector targets.
# ---------------------------------------------------------------------------

_TARGET_INPUT_TYPES: frozenset[str] = frozenset({"id_field", "generic_text"})

# Injection payload — a bare single quote is the most universal SQLi probe.
_PAYLOAD = "'"

# Finding metadata constants.
_SEVERITY = "high"
_CWE = "CWE-89"
_OWASP = "A03:2021 – Injection"
_CVSS = 8.6
_TEMPLATE_ID = "sqli-error-based"
_REMEDIATION = (
    "Use parameterised queries or prepared statements for all database interactions. "
    "Never concatenate user-controlled input directly into SQL strings. "
    "Apply the principle of least privilege — the DB account should not have "
    "DROP / ALTER / FILE permissions."
)


def _replace_query_value(url: str, parameter: str, value: str) -> str:
    parsed = urlparse(url)
    query = [(key, value if key == parameter else current) for key, current in parse_qsl(parsed.query, keep_blank_values=True)]
    return urlunparse(parsed._replace(query=urlencode(query)))


# ---------------------------------------------------------------------------
# Async detector
# ---------------------------------------------------------------------------


async def detect_sqli_error(
    client: HttpClient,
    endpoint: Endpoint,
) -> Optional[Finding]:
    """
    Probe ``endpoint`` for error-based SQL injection.

    For each eligible parameter a single ``'`` is injected.  The fuzzed
    response is then compared against the baseline using every signature in
    ``ERROR_SIGNATURES`` via ``confidence.is_match(matcher_type="regex")``.

    A signature must appear **newly** in the fuzzed response (not already in
    the baseline) to count as a match.  The number of newly-matching signatures
    determines the confidence score.

    Parameters
    ----------
    client:
        Shared ``HttpClient`` instance (caller owns lifecycle).
    endpoint:
        Crawled endpoint with ``form_fields`` populated by the crawler.

    Returns
    -------
    Finding | None
        A confirmed ``Finding`` on the first parameter that triggers at least
        one new error signature, or ``None`` if no vulnerability is detected.
    """
    target_fields = [
        ff for ff in endpoint.form_fields
        if ff.input_type in _TARGET_INPUT_TYPES
    ]
    target_params = endpoint.params  # URL query params

    if not target_fields and not target_params:
        return None

    # --- Record baseline once per endpoint ---
    try:
        baseline: Baseline = await client.record_baseline(endpoint.url)
    except Exception:
        return None

    # --- Helper: check a fuzzed response against all signatures ---
    def _count_new_matches(fuzzed_text: str, fuzzed_status: int) -> tuple[int, str]:
        """
        Return (match_count, first_matching_evidence).

        ``match_count`` is the number of signatures that appear in ``fuzzed_text``
        but NOT in ``baseline.text``.
        """
        matched: list[str] = []
        for sig in ERROR_SIGNATURES:
            if is_match(baseline, fuzzed_text, fuzzed_status, "regex", sig):
                matched.append(sig)
        evidence_snippet = fuzzed_text[:500] if matched else ""
        return len(matched), evidence_snippet

    # --- Probe form fields ---
    for field in target_fields:
        # Build a form payload with the injection in the target field and
        # default values for all other fields (to avoid form-validation errors).
        form_data = {ff.name: ff.default_value for ff in endpoint.form_fields}
        form_data[field.name] = _PAYLOAD

        try:
            if endpoint.method == "GET":
                fuzzed_resp = await client.get(endpoint.url, params=form_data)
            else:
                fuzzed_resp = await client.request(endpoint.method, endpoint.url, data=form_data)
        except Exception:
            continue

        match_count, evidence = _count_new_matches(
            fuzzed_resp.text, fuzzed_resp.status_code
        )
        confidence = score(match_count)

        if confidence < MINIMUM_CONFIDENCE:
            continue

        return Finding(
            id=str(uuid.uuid4()),
            template_id=_TEMPLATE_ID,
            title="SQL Injection (Error-Based)",
            severity=_SEVERITY,
            url=endpoint.url,
            parameter=field.name,
            payload=_PAYLOAD,
            evidence=evidence,
            cwe=_CWE,
            owasp=_OWASP,
            cvss_score=_CVSS,
            confidence=confidence,
            remediation=_REMEDIATION,
        )

    # --- Probe URL query parameters ---
    for param in target_params:
        try:
            fuzzed_resp = await client.get(_replace_query_value(endpoint.url, param, _PAYLOAD))
        except Exception:
            continue

        match_count, evidence = _count_new_matches(
            fuzzed_resp.text, fuzzed_resp.status_code
        )
        confidence = score(match_count)

        if confidence < MINIMUM_CONFIDENCE:
            continue

        return Finding(
            id=str(uuid.uuid4()),
            template_id=_TEMPLATE_ID,
            title="SQL Injection (Error-Based)",
            severity=_SEVERITY,
            url=endpoint.url,
            parameter=param,
            payload=_PAYLOAD,
            evidence=evidence,
            cwe=_CWE,
            owasp=_OWASP,
            cvss_score=_CVSS,
            confidence=confidence,
            remediation=_REMEDIATION,
        )

    return None
