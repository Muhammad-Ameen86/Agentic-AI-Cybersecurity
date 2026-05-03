import json
import asyncio
import logging
from datetime import datetime, timezone
from typing import Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger("sentinel.websocket")
router = APIRouter()


class ConnectionManager:
    """
    Manages active WebSocket connections.
    Broadcasts real-time threat events to all connected frontend clients.
    """
    def __init__(self):
        self.active: Set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.add(ws)
        logger.info(f"[WS] Client connected. Active: {len(self.active)}")

    def disconnect(self, ws: WebSocket):
        self.active.discard(ws)
        logger.info(f"[WS] Client disconnected. Active: {len(self.active)}")

    async def broadcast(self, message: dict):
        """Send message to all connected clients."""
        if not self.active:
            return
        data    = json.dumps(message)
        dead    = set()
        for ws in self.active:
            try:
                await ws.send_text(data)
            except Exception:
                dead.add(ws)
        self.active -= dead


# Singleton manager used by prediction_service to broadcast
manager = ConnectionManager()


@router.websocket("/ws/feed")
async def websocket_feed(websocket: WebSocket):
    """
    WebSocket endpoint for real-time threat feed.

    Connect from frontend:
        const ws = new WebSocket('ws://localhost:8000/ws/feed');
        ws.onmessage = (e) => {
            const event = JSON.parse(e.data);
            // update terminal feed, threat map, confidence bars
        };

    Message format:
        {
            "type":       "threat_event" | "ping" | "connected",
            "timestamp":  "2025-...",
            "srcip":      "192.168.1.44",
            "prediction": "Attack" | "Normal",
            "decision":   "BLOCK" | "ALERT" | "MONITOR" | "ALLOW",
            "confidence": 0.984,
            "reason":     "Escalating attack pattern detected | ...",
            "model":      "random_forest"
        }
    """
    await manager.connect(websocket)

    try:
        # Send welcome message
        await websocket.send_text(json.dumps({
            "type":      "connected",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message":   "Sentinel live feed active",
        }))
    except Exception:
        return

    try:
        while True:
            # Keep connection alive with ping every 30s
            await asyncio.sleep(30)
            try:
                await websocket.send_text(json.dumps({
                    "type":      "ping",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))
            except Exception:
                # Client likely disconnected during sleep
                break
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"[WS] Feed error: {e}")
        manager.disconnect(websocket)


async def broadcast_threat_event(
    srcip:      str,
    prediction: str,
    decision:   str,
    confidence: float,
    reason:     str,
    model:      str,
):
    """
    Called by prediction_service after every prediction.
    Pushes live event to all connected frontend clients.
    """
    await manager.broadcast({
        "type":       "threat_event",
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "srcip":      srcip,
        "prediction": prediction,
        "decision":   decision,
        "confidence": round(confidence, 4),
        "reason":     reason,
        "model":      model,
    })