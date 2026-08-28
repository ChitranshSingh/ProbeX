"""
ProbeX – FastAPI application entry point.

Startup sequence
----------------
1. Load settings from .env via core/config.py.
2. Create SQLite tables (SQLModel) if they don't exist.
3. Mount sub-routers for scan REST endpoints and WebSocket streams.
4. Expose /api/health for uptime checks and /docs for the OpenAPI UI.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.scans import router as scans_router
from app.api.ws import router as ws_router
from app.core.config import settings
from app.db.session import create_db_and_tables


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ANN001
    """Run startup/shutdown logic without the deprecated @app.on_event pattern."""
    # ---- startup ----
    create_db_and_tables()
    yield
    # ---- shutdown ---- (nothing to clean up yet)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


app = FastAPI(
    title="ProbeX",
    description=(
        "Dynamic Application Security Testing (DAST) scanner — solo prototype. "
        "Full team architecture documented in docs/."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

app.include_router(scans_router, prefix="/api")
app.include_router(ws_router)


# ---------------------------------------------------------------------------
# Core routes
# ---------------------------------------------------------------------------


@app.get(
    "/api/health",
    tags=["meta"],
    summary="Liveness check",
    response_description="Returns {'status': 'ok'} when the server is running.",
)
async def health() -> dict[str, str]:
    """Simple liveness probe — no DB query, intentionally cheap."""
    return {"status": "ok"}
