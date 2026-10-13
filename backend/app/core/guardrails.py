"""Target validation and in-process abuse controls for server-side scans."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from collections import defaultdict, deque
from urllib.parse import urlparse

from app.core.config import settings

_SENSITIVE_SUFFIXES = (".gov", ".gov.in", ".nic.in", ".mil", ".bank", ".bank.in")
_SENSITIVE_HOSTS = {"localhost", "metadata.google.internal"}
_recent_scans: dict[str, deque[float]] = defaultdict(deque)


class TargetBlocked(ValueError):
    """Raised when a URL is not safe for the scanner service to request."""


def _is_non_public(address: str) -> bool:
    return not ipaddress.ip_address(address).is_global


async def resolve_and_check_target(url: str, *, allow_private: bool | None = None) -> list[str]:
    """Validate scheme/host and ensure every resolved address is public.

    This must be called for the initial target and every redirect hop. DNS is
    resolved at validation time so hostname tricks cannot reach internal
    services. Local labs are an explicit opt-in for development only.
    """
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise TargetBlocked("Target must be an absolute HTTP or HTTPS URL.")
    if parsed.username or parsed.password:
        raise TargetBlocked("Targets containing URL credentials are not supported.")

    host = parsed.hostname.rstrip(".").lower()
    permitted_private = settings.allow_private_targets if allow_private is None else allow_private
    if (host in _SENSITIVE_HOSTS and not permitted_private) or any(host.endswith(suffix) for suffix in _SENSITIVE_SUFFIXES):
        raise TargetBlocked("This target belongs to a protected domain category and cannot be scanned.")

    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetBlocked("Target hostname could not be resolved.") from exc

    addresses = sorted({info[4][0] for info in infos})
    if not permitted_private and any(_is_non_public(address) for address in addresses):
        raise TargetBlocked("Target resolves to a private, loopback, or reserved IP address and cannot be scanned.")
    return addresses


def check_scan_rate_limit(requester: str) -> None:
    """Allow a small bounded number of new scans per requester window."""
    now = time.monotonic()
    bucket = _recent_scans[requester]
    cutoff = now - settings.scan_rate_window_seconds
    while bucket and bucket[0] < cutoff:
        bucket.popleft()
    if len(bucket) >= settings.scan_rate_limit:
        raise TargetBlocked("Scan creation limit reached. Please wait before starting another scan.")
    bucket.append(now)
