"""
ProbeX – WebSocket endpoint for real-time scan progress.

Clients connect to ``/ws/{scan_id}`` immediately after creating a scan and
receive WSMessage JSON frames as the engine progresses through crawl → fuzz →
analyse → done.

In the scaffold, the single placeholder route echoes a greeting so you can
verify the WebSocket infrastructure works end-to-end before the engine is wired.
"""

from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

import json

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/{scan_id}")
async def scan_progress(websocket: WebSocket, scan_id: str) -> None:
    """
    Stream real-time scan events for ``scan_id`` over a WebSocket connection.

    Message types sent to the client (WSMessage schema):

    * ``status``   – lifecycle state transitions.
    * ``progress`` – percentage through crawl or fuzz phase.
    * ``finding``  – new Finding discovered (pushed immediately on detection).
    * ``log``      – informational messages from the engine.
    * ``error``    – non-fatal errors encountered during the scan.

    The connection is closed by the server when the scan reaches a terminal
    state (done / failed / blocked).

    .. note::
        Full broadcast logic (using an in-memory or Redis pub/sub channel)
        will be implemented in Task E3.  This placeholder simply accepts the
        connection and sends a greeting so the WebSocket layer is verifiable.
    """
    await websocket.accept()
    try:
        # Placeholder: send a single greeting frame then wait for disconnect.
        greeting = {
            "type": "log",
            "data": {
                "message": (
                    f"[ProbeX] WebSocket connected for scan_id={scan_id}. "
                    "Live events will stream here once the engine is wired (Task E3)."
                )
            },
        }
        await websocket.send_text(json.dumps(greeting))

        # Keep connection open; real impl will await a broadcast queue here.
        while True:
            # Echo any client messages (useful for ping/keepalive testing).
            data = await websocket.receive_text()
            await websocket.send_text(
                json.dumps({"type": "log", "data": {"message": f"echo: {data}"}})
            )
    except WebSocketDisconnect:
        pass
