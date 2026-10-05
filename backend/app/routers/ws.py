from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

from .. import security
from ..database import SessionLocal
from ..events import hub

router = APIRouter()


@router.websocket("/ws/events")
async def events(websocket: WebSocket, token: str = ""):
    """Live alerts, incidents and responses. The dashboard passes its access token as ?token=..."""
    db = SessionLocal()
    try:
        security.user_from_token(db, token)
    except HTTPException:
        await websocket.close(code=4401)
        return
    finally:
        db.close()
    await hub.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # nothing is expected from the dashboard; this keeps the connection open
    except WebSocketDisconnect:
        hub.disconnect(websocket)
