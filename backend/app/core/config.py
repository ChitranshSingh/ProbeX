"""
ProbeX – application configuration.

All settings are loaded from environment variables (or a .env file in the
backend/ directory).  Using pydantic-settings means every field is type-checked
at startup and the app fails fast if a required variable is missing.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central settings object — import `settings` everywhere."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    database_url: str = "sqlite:///./probex.db"
    """SQLAlchemy / SQLModel connection string.  Defaults to a local SQLite file."""

    gemini_api_key: str = ""
    """Google Generative AI key.  Optional — AI remediation is skipped when absent."""

    frontend_origin: str = "http://localhost:5173"
    """Origin allowed through CORS middleware (Vite dev server by default)."""


settings = Settings()
