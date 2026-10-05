import ipaddress
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import audit, runtime
from ..database import get_db
from ..models import Alert, AllowlistEntry, AuditEntry, Incident, Sensor, User, utcnow
from ..security import current_user, require_role

router = APIRouter(tags=["administration"])
admin = require_role("administrator")


@router.get("/settings")
def read_settings(db: Session = Depends(get_db), _: User = Depends(admin)):
    return runtime.get_all(db)


@router.put("/settings")
def change_settings(values: dict, db: Session = Depends(get_db), user: User = Depends(admin)):
    try:
        for key, value in values.items():
            runtime.put(db, key, value)
    except KeyError as error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"There is no setting called {error.args[0]}.") from None
    except (TypeError, ValueError) as error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from None
    audit.record(db, "settings.change", user.user_id, **values)
    db.commit()
    return runtime.get_all(db)


class AllowIn(BaseModel):
    ip_range: str
    reason: str = Field(min_length=3, max_length=200)

    @field_validator("ip_range")
    @classmethod
    def must_be_a_range(cls, value: str) -> str:
        return str(ipaddress.ip_network(value.strip(), strict=False))


@router.get("/allowlist")
def list_allowlist(db: Session = Depends(get_db), _: User = Depends(admin)):
    return [{"entry_id": e.entry_id, "ip_range": e.ip_range, "reason": e.reason} for e in db.query(AllowlistEntry).order_by(AllowlistEntry.entry_id)]


@router.post("/allowlist", status_code=status.HTTP_201_CREATED)
def add_allowlist(body: AllowIn, db: Session = Depends(get_db), user: User = Depends(admin)):
    if db.query(AllowlistEntry).filter(AllowlistEntry.ip_range == body.ip_range).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "That address or range is already trusted.")
    entry = AllowlistEntry(ip_range=body.ip_range, reason=body.reason, added_by=user.user_id)
    db.add(entry)
    audit.record(db, "allowlist.add", user.user_id, ip_range=body.ip_range)
    db.commit()
    return {"entry_id": entry.entry_id, "ip_range": entry.ip_range, "reason": entry.reason}


@router.delete("/allowlist/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_allowlist(entry_id: int, db: Session = Depends(get_db), user: User = Depends(admin)):
    entry = db.get(AllowlistEntry, entry_id)
    if entry is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "There is no such entry.")
    audit.record(db, "allowlist.remove", user.user_id, ip_range=entry.ip_range)
    db.delete(entry)
    db.commit()


@router.get("/audit")
def audit_log(limit: int = 200, db: Session = Depends(get_db), _: User = Depends(admin)):
    rows = db.query(AuditEntry).order_by(AuditEntry.entry_id.desc()).limit(min(max(limit, 1), 1000))
    return [{"entry_id": r.entry_id, "user_id": r.user_id, "action": r.action, "detail": r.detail, "logged_at": r.logged_at.isoformat() + "Z"} for r in rows]


@router.get("/stats/summary")
def summary(db: Session = Depends(get_db), _: User = Depends(current_user)):
    """Figures for the dashboard (FR-40)."""
    since = utcnow() - timedelta(hours=24)
    recent = db.query(Alert).filter(Alert.created_at >= since)
    count_by = lambda column: dict(recent.with_entities(column, func.count()).group_by(column).all())  # noqa: E731
    top = lambda column: [{"address": a, "alerts": n} for a, n in recent.with_entities(column, func.count()).filter(column.is_not(None))  # noqa: E731
                          .group_by(column).order_by(func.count().desc()).limit(5)]
    sensors = [{"name": s.name, "last_seen": s.last_seen.isoformat() + "Z" if s.last_seen else None,
                "silent": s.last_seen is None or s.last_seen < utcnow() - timedelta(seconds=60)} for s in db.query(Sensor)]  # NFR-13
    return {"alerts_24h": recent.count(), "by_severity": count_by(Alert.severity), "by_attack_type": count_by(Alert.attack_type),
            "top_sources": top(Alert.source_ip), "top_targets": top(Alert.target_ip),
            "open_incidents": db.query(Incident).filter(Incident.status.in_(("new", "investigating"))).count(), "sensors": sensors}
