"""Regression tests for the server-side target admission controls."""

from __future__ import annotations

import asyncio

import pytest

from app.core.guardrails import TargetBlocked, check_scan_rate_limit, resolve_and_check_target


def run(coro):
    return asyncio.run(coro)


def test_loopback_is_blocked_by_default(monkeypatch):
    monkeypatch.setattr("app.core.guardrails.settings.allow_private_targets", False)
    with pytest.raises(TargetBlocked, match="private, loopback"):
        run(resolve_and_check_target("http://127.0.0.1:3000"))


def test_private_lab_requires_explicit_opt_in():
    addresses = run(resolve_and_check_target("http://127.0.0.1:3000", allow_private=True))
    assert "127.0.0.1" in addresses


def test_sensitive_domain_is_blocked_without_dns():
    with pytest.raises(TargetBlocked, match="protected domain"):
        run(resolve_and_check_target("https://example.gov.in"))


def test_rate_limit_rejects_excess(monkeypatch):
    monkeypatch.setattr("app.core.guardrails.settings.scan_rate_limit", 1)
    monkeypatch.setattr("app.core.guardrails.settings.scan_rate_window_seconds", 600)
    requester = "unit-test-rate-limit"
    check_scan_rate_limit(requester)
    with pytest.raises(TargetBlocked, match="limit"):
        check_scan_rate_limit(requester)
