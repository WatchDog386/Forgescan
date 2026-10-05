from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import audit
from ..database import get_db
from ..events import hub
from ..models import ATTACK_TYPES, INCIDENT_STATES, SEVERITIES, Alert, FlowWindow, Incident, IncidentNote, Response, User, utcnow
from ..security import current_user, require_role
from ..services.incidents import TRANSITIONS

router = APIRouter(tags=["incidents"])
iso = lambda d: d.isoformat() + "Z" if d else None  # noqa: E731


def alert_out(a: Alert) -> dict:
    return {"alert_id": a.alert_id, "incident_id": a.incident_id, "source_ip": a.source_ip, "target_ip": a.target_ip,
            "attack_type": a.attack_type, "confidence": a.confidence, "risk_score": a.risk_score, "severity": a.severity,
            "rule_match": a.rule_match, "created_at": iso(a.created_at)}


def response_out(r: Response) -> dict:
    return {"response_id": r.response_id, "incident_id": r.incident_id, "action": r.action, "target_ip": r.target_ip,
            "automatic": r.automatic, "status": r.status, "detail": r.detail, "created_at": iso(r.created_at), "expires_at": iso(r.expires_at)}


def incident_out(i: Incident, full: bool = False) -> dict:
    out = {"incident_id": i.incident_id, "source_ip": i.source_ip, "attack_type": i.attack_type, "severity": i.severity,
           "risk_score": i.risk_score, "status": i.status, "assigned_to": i.assigned_to, "opened_at": iso(i.opened_at),
           "last_alert_at": iso(i.last_alert_at), "closed_at": iso(i.closed_at), "alert_count": len(i.alerts)}
    if full:
        out["alerts"] = [alert_out(a) for a in i.alerts[-50:]]
        out["notes"] = [{"note_id": n.note_id, "user_id": n.user_id, "body": n.body, "created_at": iso(n.created_at)} for n in i.notes]
        out["responses"] = [response_out(r) for r in i.responses]
    return out


@router.get("/alerts")
def list_alerts(severity: str | None = None, attack_type: str | None = None, limit: int = 100,
                db: Session = Depends(get_db), _: User = Depends(current_user)):
    query = db.query(Alert)
    if severity in SEVERITIES:
        query = query.filter(Alert.severity == severity)
    if attack_type in ATTACK_TYPES:
        query = query.filter(Alert.attack_type == attack_type)
    return [alert_out(a) for a in query.order_by(Alert.alert_id.desc()).limit(min(max(limit, 1), 500))]


@router.get("/incidents")
def list_incidents(status_: str | None = None, severity: str | None = None, attack_type: str | None = None, source_ip: str | None = None,
                   limit: int = 100, db: Session = Depends(get_db), _: User = Depends(current_user)):
    query = db.query(Incident)
    if status_ in INCIDENT_STATES:
        query = query.filter(Incident.status == status_)
    if severity in SEVERITIES:
        query = query.filter(Incident.severity == severity)
    if attack_type in ATTACK_TYPES:
        query = query.filter(Incident.attack_type == attack_type)
    if source_ip:
        query = query.filter(Incident.source_ip == source_ip)
    return [incident_out(i) for i in query.order_by(Incident.incident_id.desc()).limit(min(max(limit, 1), 500))]


def _get(db: Session, incident_id: int) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "There is no incident with that number.")
    return incident


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: int, db: Session = Depends(get_db), _: User = Depends(current_user)):
    return incident_out(_get(db, incident_id), full=True)


class IncidentPatch(BaseModel):
    status: str | None = None
    take: bool = False


@router.patch("/incidents/{incident_id}")
async def change_incident(incident_id: int, body: IncidentPatch, request: Request, db: Session = Depends(get_db),
                          user: User = Depends(require_role("analyst"))):
    incident = _get(db, incident_id)
    if body.take:
        incident.assigned_to = user.user_id
        if incident.status == "new" and body.status is None:
            body.status = "investigating"
    if body.status and body.status != incident.status:
        if body.status not in TRANSITIONS[incident.status]:
            raise HTTPException(status.HTTP_409_CONFLICT, f"An incident that is {incident.status.replace('_', ' ')} cannot become {body.status.replace('_', ' ')}.")
        incident.status = body.status
        if body.status in ("resolved", "false_positive"):
            incident.closed_at = utcnow()
        if body.status == "false_positive":  # FR-38: undo the block and keep the traffic as a normal example
            responder = request.app.state.pipeline.responder
            if any(r.action == "block" and r.status == "applied" for r in incident.responses):
                responder.release(db, incident.source_ip, None, incident)
            for alert in incident.alerts:
                window = db.get(FlowWindow, alert.window_id)
                if window is not None:
                    window.label = "normal"
    audit.record(db, "incident.change", user.user_id, incident_id=incident_id, status=incident.status, taken=body.take)
    db.commit()
    await hub.broadcast({"type": "incident", "incident_id": incident_id, "status": incident.status, "assigned_to": incident.assigned_to})
    return incident_out(incident, full=True)


class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=2000)


@router.post("/incidents/{incident_id}/notes", status_code=status.HTTP_201_CREATED)
def add_note(incident_id: int, body: NoteIn, db: Session = Depends(get_db), user: User = Depends(require_role("analyst"))):
    incident = _get(db, incident_id)
    db.add(IncidentNote(incident_id=incident.incident_id, user_id=user.user_id, body=body.body.strip()))
    audit.record(db, "incident.note", user.user_id, incident_id=incident_id)
    db.commit()
    return incident_out(incident, full=True)
