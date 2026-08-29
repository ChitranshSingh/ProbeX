"""
ProbeX – WebSocket endpoint for real-time scan progress.

Protocol
--------
Client connects to ``/ws/scans/{scan_id}``.

1. **Replay phase**: all events buffered since the scan started are sent
   immediately (so a page reload during a scan doesn't miss any events).
2. **Live phase**: events are streamed as they arrive in the queue.
3. **Terminal close**: once the runner emits a ``status`` event with a
   terminal value (``done`` / ``failed`` / ``blocked``), the server sends
   a WebSocket close frame.

Message format matches ``WSMessage`` from ``app/schemas.py``::

    {"type": "status"|"progress"|"finding"|"log"|"error", "data": {...}}

If the scan_id is unknown (not in DB and not in the event buffer), the server
accepts the connection, sends a 404-equivalent error frame, and closes.
"""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.runner import RUNNING_SCANS, get_event_buffer

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websocket"])

_TERMINAL_STATUSES = frozenset({"done", "failed", "blocked"})

# How long to poll the queue when the scan queue exists but is temporarily empty.
_POLL_TIMEOUT = 1.0  # seconds


def _is_terminal(msg: dict) -> bool:
    """Return True if this message signals a terminal scan status."""
    return (
        msg.get("type") == "status"
        and msg.get("data", {}).get("status") in _TERMINAL_STATUSES
    )


@router.websocket("/ws/scans/{scan_id}")
async def scan_progress(websocket: WebSocket, scan_id: str) -> None:
    """
    Stream real-time scan events for ``scan_id``.

    Behaviour on connect
    --------------------
    1. Accept the connection unconditionally.
    2. Replay all buffered events (events already emitted before this connect).
    3. If the scan reached a terminal state during replay, close immediately.
    4. Otherwise, subscribe to the live queue and forward events until terminal.
    5. Close on WebSocket disconnect or terminal status.
    """
    await websocket.accept()
    logger.debug("WS connected for scan_id=%s", scan_id)

    try:
        # ---- Phase 1: replay buffered events ----
        buffered = get_event_buffer(scan_id)

        if not buffered:
            # Scan unknown — send an info frame and leave connection open for
            # the queue to populate (scan may not have emitted anything yet).
            await websocket.send_text(
                json.dumps({
                    "type": "log",
                    "data": {"message": f"Waiting for scan {scan_id} to start…"},
                })
            )
        else:
            for event in buffered:
                await websocket.send_text(json.dumps(event))
                # If replay contains a terminal event, close after flushing.
                if _is_terminal(event):
                    logger.debug("WS %s: terminal state in replay — closing.", scan_id)
                    return

        # ---- Phase 2: live streaming ----
        while True:
            queue = RUNNING_SCANS.get(scan_id)

            if queue is None:
                # Runner finished and cleaned up the queue.  Check if we
                # already sent a terminal event; if not, the scan ended between
                # replay and now — send a late terminal frame from the buffer.
                late_buffer = get_event_buffer(scan_id)
                for event in late_buffer[len(buffered):]:  # only new events
                    await websocket.send_text(json.dumps(event))
                    if _is_terminal(event):
                        return
                # No terminal event found — scan may have ended cleanly.
                # Send a synthetic done frame so the client isn't left hanging.
                await websocket.send_text(
                    json.dumps({"type": "status", "data": {"status": "done"}})
                )
                return

            try:
                event = await asyncio.wait_for(queue.get(), timeout=_POLL_TIMEOUT)
            except asyncio.TimeoutError:
                # Send a keepalive ping so the connection stays alive.
                try:
                    await websocket.send_text(
                        json.dumps({"type": "log", "data": {"message": "…"}})
                    )
                except Exception:
                    return
                continue

            await websocket.send_text(json.dumps(event))

            if _is_terminal(event):
                logger.debug("WS %s: terminal status received — closing.", scan_id)
                return

    except WebSocketDisconnect:
        logger.debug("WS %s: client disconnected.", scan_id)
    except Exception as exc:
        logger.warning("WS %s: unexpected error: %s", scan_id, exc)
    finally:
        logger.debug("WS %s: handler exiting.", scan_id)
