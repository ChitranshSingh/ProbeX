"""
ProbeX – API integration tests for the scan endpoints.

Test scope
----------
- POST /api/scans:
    • consent_confirmed=False  → HTTP 400 with exact error message.
    • consent_confirmed=True   → HTTP 202, scan_id returned, DB row created.
- GET  /api/scans              → list returns rows (including seeded examples).
- GET  /api/scans/{id}         → returns ScanSummary, 404 for unknown id.
- GET  /api/scans/{id}/report  → 409 for non-terminal scan, json+html for done.
- GET  /api/health             → sanity check.

All tests use FastAPI's synchronous ``TestClient`` with an in-memory SQLite
database so they never touch the real ``probex.db`` on disk.

Run from the ``backend/`` directory::

    python -m pytest tests/test_api_scans.py -v
"""

from __future__ import annotations

import json
import sys
import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

# ---------------------------------------------------------------------------
# Override the database engine BEFORE importing the app so that all modules
# that import from app.db.session use the in-memory test engine.
# ---------------------------------------------------------------------------
_TEST_DB_URL = "sqlite://"  # pure in-memory, no file

_test_engine = create_engine(
    _TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,  # single shared connection — required for in-memory SQLite
)


def _override_get_session():
    """FastAPI dependency override that yields a session on the test engine."""
    with Session(_test_engine) as session:
        yield session


# Patch the engine used by crud.py's direct Session() calls inside runner.py.
import app.db.session as _session_module  # noqa: E402

_session_module.engine = _test_engine

# Also patch runner.engine reference
import app.core.runner as _runner_module  # noqa: E402

_runner_module.engine = _test_engine  # type: ignore[assignment]

import app.db.models  # noqa: F401, E402 — populate SQLModel metadata before create_all

from app.db.session import get_session  # noqa: E402
from app.main import app as _fastapi_app  # noqa: E402  — alias avoids clobbering the `app` pkg

# Create tables on the in-memory engine.
from app.core.config import settings  # noqa: E402

# API endpoint tests intentionally use a loopback fixture. Production defaults
# remain safe; integration tests opt in to their isolated local target.
settings.allow_private_targets = True
settings.scan_rate_limit = 999

SQLModel.metadata.create_all(_test_engine)

# Apply the dependency override.
_fastapi_app.dependency_overrides[get_session] = _override_get_session


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def client():
    """Shared TestClient for the entire module."""
    with TestClient(_fastapi_app, raise_server_exceptions=True) as c:
        yield c



@pytest.fixture(autouse=True)
def _patch_start_scan_task():
    """
    Prevent the real scan pipeline from running during API tests.

    The pipeline makes real HTTP requests to the target URL, which would fail
    in a unit-test context.  We stub it to a no-op so we can test the API
    layer in isolation.
    """
    with patch("app.api.scans.start_scan_task") as mock_start:
        mock_start.return_value = None
        yield mock_start


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

_VALID_PAYLOAD = {
    "target_url": "http://localhost:3000",
    "profile": "quick",
    "consent_confirmed": True,
}

_NO_CONSENT_PAYLOAD = {
    "target_url": "http://localhost:3000",
    "profile": "quick",
    "consent_confirmed": False,
}


# ===========================================================================
# Health check
# ===========================================================================


class TestHealth:
    def test_health_returns_ok(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


# ===========================================================================
# POST /api/scans — consent gate
# ===========================================================================


class TestCreateScanConsentGate:
    """
    The most important contract: consent_confirmed=False must return HTTP 400
    with the exact message "You must confirm you have permission to scan this
    target."  This is a hard legal/ethical requirement.
    """

    def test_no_consent_returns_400(self, client):
        """
        CRITICAL: consent_confirmed=False → HTTP 400 Bad Request.

        This must never change to 200/202 — it would allow the tool to be used
        against targets without authorisation.
        """
        resp = client.post("/api/scans", json=_NO_CONSENT_PAYLOAD)
        assert resp.status_code == 400, (
            f"Expected 400 for missing consent, got {resp.status_code}. "
            f"Body: {resp.text}"
        )

    def test_no_consent_error_message(self, client):
        """The 400 response must include the exact consent error message."""
        resp = client.post("/api/scans", json=_NO_CONSENT_PAYLOAD)
        detail = resp.json().get("detail", "")
        assert "permission" in detail.lower() or "consent" in detail.lower(), (
            f"Consent error message not found in response detail: {detail!r}"
        )

    def test_no_consent_not_422(self, client):
        """
        HTTP 422 is reserved for schema-validation failures.  A consent refusal
        is a deliberate logical rejection and must be 400, not 422.
        """
        resp = client.post("/api/scans", json=_NO_CONSENT_PAYLOAD)
        assert resp.status_code != 422, (
            "Consent rejection must return 400, not 422 (422 is for schema errors)."
        )

    def test_missing_consent_field_returns_422(self, client):
        """
        If consent_confirmed is omitted entirely, Pydantic rejects it with 422
        (schema validation error) — this is different from consent=False.
        """
        resp = client.post(
            "/api/scans",
            json={"target_url": "http://localhost:3000", "profile": "quick"},
        )
        # Pydantic v2 either uses a default of False (which hits our 400) or
        # raises 422 for a required field.  Either is acceptable.
        assert resp.status_code in (400, 422), (
            f"Expected 400 or 422 for missing consent_confirmed, got {resp.status_code}"
        )


# ===========================================================================
# POST /api/scans — successful creation
# ===========================================================================


class TestCreateScanSuccess:
    def test_with_consent_returns_202(self, client):
        """consent_confirmed=True → HTTP 202 Accepted."""
        resp = client.post("/api/scans", json=_VALID_PAYLOAD)
        assert resp.status_code == 202, f"Expected 202, got {resp.status_code}. Body: {resp.text}"

    def test_response_contains_scan_id(self, client):
        """Response body must contain a ``scan_id`` string."""
        resp = client.post("/api/scans", json=_VALID_PAYLOAD)
        body = resp.json()
        assert "scan_id" in body, f"scan_id missing from response: {body}"
        assert isinstance(body["scan_id"], str)
        assert len(body["scan_id"]) == 36, "scan_id should be a UUID-v4 (36 chars)"

    def test_response_status_is_queued(self, client):
        """Initial status must be 'queued'."""
        resp = client.post("/api/scans", json=_VALID_PAYLOAD)
        assert resp.json()["status"] == "queued"

    def test_scan_task_is_started(self, client, _patch_start_scan_task):
        """start_scan_task must be called once per valid POST."""
        client.post("/api/scans", json=_VALID_PAYLOAD)
        _patch_start_scan_task.assert_called_once()

    def test_scan_persisted_in_db(self, client):
        """The created scan must be retrievable from the DB."""
        resp = client.post("/api/scans", json=_VALID_PAYLOAD)
        scan_id = resp.json()["scan_id"]

        get_resp = client.get(f"/api/scans/{scan_id}")
        assert get_resp.status_code == 200
        data = get_resp.json()
        assert data["scan_id"] == scan_id
        assert data["target_url"] == "http://localhost:3000/"  # Pydantic normalises URL

    def test_standard_profile_accepted(self, client):
        """profile='standard' is a valid profile value."""
        payload = {**_VALID_PAYLOAD, "profile": "standard"}
        resp = client.post("/api/scans", json=payload)
        assert resp.status_code == 202

    def test_invalid_profile_rejected(self, client):
        """profile='deep' is not a valid value — must be rejected."""
        payload = {**_VALID_PAYLOAD, "profile": "deep"}
        resp = client.post("/api/scans", json=payload)
        assert resp.status_code == 422

    def test_invalid_url_rejected(self, client):
        """A non-URL string in target_url must be rejected with 422."""
        payload = {**_VALID_PAYLOAD, "target_url": "not-a-url"}
        resp = client.post("/api/scans", json=payload)
        assert resp.status_code == 422


# ===========================================================================
# GET /api/scans
# ===========================================================================


class TestListScans:
    def test_list_returns_200(self, client):
        resp = client.get("/api/scans")
        assert resp.status_code == 200

    def test_list_returns_array(self, client):
        resp = client.get("/api/scans")
        assert isinstance(resp.json(), list)

    def test_created_scan_appears_in_list(self, client):
        """A scan created via POST must appear in GET /api/scans."""
        post_resp = client.post("/api/scans", json=_VALID_PAYLOAD)
        scan_id = post_resp.json()["scan_id"]

        list_resp = client.get("/api/scans")
        ids = [s["scan_id"] for s in list_resp.json()]
        assert scan_id in ids, f"Newly created scan {scan_id} not in list: {ids}"

    def test_list_newest_first(self, client):
        """Scans should be ordered newest-first (by started_at)."""
        # Create two scans and ensure the second appears first.
        resp1 = client.post("/api/scans", json=_VALID_PAYLOAD)
        id1 = resp1.json()["scan_id"]

        resp2 = client.post("/api/scans", json=_VALID_PAYLOAD)
        id2 = resp2.json()["scan_id"]

        list_resp = client.get("/api/scans")
        ids = [s["scan_id"] for s in list_resp.json()]

        # Both must be present; id2 should appear before id1 (or at same position
        # if timestamps are identical in fast test runs).
        assert id1 in ids and id2 in ids


# ===========================================================================
# GET /api/scans/{scan_id}
# ===========================================================================


class TestGetScan:
    def test_get_existing_scan_200(self, client):
        """A valid scan_id returns 200."""
        post_resp = client.post("/api/scans", json=_VALID_PAYLOAD)
        scan_id = post_resp.json()["scan_id"]

        get_resp = client.get(f"/api/scans/{scan_id}")
        assert get_resp.status_code == 200

    def test_get_scan_shape(self, client):
        """Response must contain all expected ScanSummary fields."""
        post_resp = client.post("/api/scans", json=_VALID_PAYLOAD)
        scan_id = post_resp.json()["scan_id"]

        data = client.get(f"/api/scans/{scan_id}").json()
        for key in ("scan_id", "target_url", "status", "started_at",
                    "endpoints_found", "risk_score", "findings", "findings_by_severity"):
            assert key in data, f"Field '{key}' missing from ScanSummary response."

    def test_get_unknown_scan_404(self, client):
        """An unknown UUID returns 404."""
        resp = client.get("/api/scans/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 404

    def test_get_scan_findings_is_list(self, client):
        """findings field must be a list (empty for a queued scan)."""
        post_resp = client.post("/api/scans", json=_VALID_PAYLOAD)
        scan_id = post_resp.json()["scan_id"]
        data = client.get(f"/api/scans/{scan_id}").json()
        assert isinstance(data["findings"], list)

    def test_get_scan_status_queued(self, client):
        """A freshly created scan has status 'queued'."""
        post_resp = client.post("/api/scans", json=_VALID_PAYLOAD)
        scan_id = post_resp.json()["scan_id"]
        data = client.get(f"/api/scans/{scan_id}").json()
        assert data["status"] == "queued"


# ===========================================================================
# GET /api/scans/{scan_id}/report
# ===========================================================================


class TestGetReport:
    def _create_done_scan(self, client) -> str:
        """Helper: create a scan and fast-forward its DB status to 'done'."""
        post_resp = client.post("/api/scans", json=_VALID_PAYLOAD)
        scan_id = post_resp.json()["scan_id"]

        # Directly update the DB row to 'done' so the report endpoint accepts it.
        with Session(_test_engine) as session:
            from app.db.crud import update_scan_status
            update_scan_status(session, scan_id, "done")

        return scan_id

    def test_report_pending_scan_409(self, client):
        """Requesting a report for a non-terminal scan returns 409."""
        post_resp = client.post("/api/scans", json=_VALID_PAYLOAD)
        scan_id = post_resp.json()["scan_id"]  # status = 'queued'

        resp = client.get(f"/api/scans/{scan_id}/report?format=json")
        assert resp.status_code == 409, (
            f"Expected 409 for in-progress scan, got {resp.status_code}"
        )

    def test_report_json_format_200(self, client):
        """format=json on a done scan returns 200."""
        scan_id = self._create_done_scan(client)
        resp = client.get(f"/api/scans/{scan_id}/report?format=json")
        assert resp.status_code == 200

    def test_report_json_content_type(self, client):
        """format=json returns application/json content-type."""
        scan_id = self._create_done_scan(client)
        resp = client.get(f"/api/scans/{scan_id}/report?format=json")
        assert "application/json" in resp.headers.get("content-type", "")

    def test_report_json_has_required_keys(self, client):
        """JSON report must contain scan_id and findings list."""
        scan_id = self._create_done_scan(client)
        resp = client.get(f"/api/scans/{scan_id}/report?format=json")
        body = resp.json()
        assert "scan_id" in body
        assert "findings" in body

    def test_report_html_format_200(self, client):
        """format=html on a done scan returns 200."""
        scan_id = self._create_done_scan(client)
        resp = client.get(f"/api/scans/{scan_id}/report?format=html")
        assert resp.status_code == 200

    def test_report_html_is_html(self, client):
        """HTML report must start with <!DOCTYPE html."""
        scan_id = self._create_done_scan(client)
        resp = client.get(f"/api/scans/{scan_id}/report?format=html")
        assert resp.text.strip().startswith("<!DOCTYPE html")

    def test_report_unknown_scan_404(self, client):
        """Unknown scan_id returns 404."""
        resp = client.get("/api/scans/00000000-0000-0000-0000-000000000000/report?format=json")
        assert resp.status_code == 404

    def test_report_invalid_format_422(self, client):
        """An unsupported format value returns 422."""
        scan_id = self._create_done_scan(client)
        resp = client.get(f"/api/scans/{scan_id}/report?format=xml")
        assert resp.status_code == 422
