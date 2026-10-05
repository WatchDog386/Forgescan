"""Pushes live events to every connected dashboard over WebSocket (FR-39)."""
from fastapi import WebSocket


class EventHub:
    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.clients.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self.clients.discard(websocket)

    async def broadcast(self, event: dict) -> None:
        for client in list(self.clients):
            try:
                await client.send_json(event)
            except Exception:  # a dashboard that has gone away must not stop the others
                self.disconnect(client)


hub = EventHub()
