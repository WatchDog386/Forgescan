import ipaddress

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from ..database import get_db
from ..events import hub
from ..models import Incident, User
from ..security import current_user, require_role
from .incidents import response_out

router = APIRouter(prefix="/responses", tags=["responses"])


class AddressIn(BaseModel):
    ip: str
    incident_id: int | None = None

    @field_validator("ip")
    @classmethod
    def must_be_an_address(cls, value: str) -> str:
        return str(ipaddress.ip_address(value.strip()))


@router.get("/active")
def active(request: Request, db: Session = Depends(get_db), _: User = Depends(current_user)):
    blocks = request.app.state.pipeline.responder.active_blocks(db)
    db.commit()
    return [response_out(r) for r in blocks]


@router.post("/block")
async def block(body: AddressIn, request: Request, db: Session = Depends(get_db), user: User = Depends(require_role("analyst"))):
    incident = db.get(Incident, body.incident_id) if body.incident_id else None
    response = request.app.state.pipeline.responder.block(db, body.ip, incident, automatic=False, user_id=user.user_id)
    db.commit()
    if response.status == "refused":
        raise HTTPException(status.HTTP_409_CONFLICT, f"This address cannot be blocked: it is {response.detail}." if response.detail != "already blocked" else "This address is already blocked.")
    await hub.broadcast({"type": "response", **response_out(response)})
    return response_out(response)


@router.post("/release")
async def release(body: AddressIn, request: Request, db: Session = Depends(get_db), user: User = Depends(require_role("analyst"))):
    incident = db.get(Incident, body.incident_id) if body.incident_id else None
    response = request.app.state.pipeline.responder.release(db, body.ip, user.user_id, incident)
    db.commit()
    await hub.broadcast({"type": "response", **response_out(response)})
    return response_out(response)
