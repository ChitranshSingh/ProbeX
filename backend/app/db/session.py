"""
ProbeX – database session factory.

Provides:
  - ``engine``               – shared SQLModel / SQLAlchemy engine.
  - ``create_db_and_tables`` – called once at app startup.
  - ``get_session``          – FastAPI dependency that yields a session per request.
"""

from __future__ import annotations

from collections.abc import Generator

from sqlmodel import Session, SQLModel, create_engine

from app.core.config import settings

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

# check_same_thread=False is required for SQLite when used with async frameworks
# because FastAPI may call the dependency from different threads.
connect_args = (
    {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
)

engine = create_engine(
    settings.database_url,
    connect_args=connect_args,
    echo=False,  # set True for SQL debug logging
)


def create_db_and_tables() -> None:
    """
    Create all SQLModel tables that haven't been created yet.

    Safe to call multiple times (SQLModel uses ``CREATE TABLE IF NOT EXISTS``
    semantics under the hood).  Called from ``app.main`` lifespan.
    """
    # Import models here so SQLModel's metadata is populated before create_all.
    import app.db.models  # noqa: F401

    SQLModel.metadata.create_all(engine)


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------


def get_session() -> Generator[Session, None, None]:
    """
    Yield a database session for the duration of a single HTTP request.

    Usage::

        @router.get("/example")
        def example(session: Session = Depends(get_session)):
            ...
    """
    with Session(engine) as session:
        yield session
