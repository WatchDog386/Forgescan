"""Groups alerts into incidents and moves incidents between states (SDS 6.7)."""
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from ..engine.risk import SEVERITY_ORDER
from ..models import Incident

GROUP_WITHIN = timedelta(minutes=15)   # FR-34
TRANSITIONS = {"new": {"investigating", "false_positive"}, "investigating": {"resolved", "false_positive"},
               "resolved": set(), "false_positive": set()}


def incident_for(db: Session, source_ip: str, attack_type: str, when: datetime, risk_score: int, severity: str) -> tuple[Incident, bool]:
    """Return the open incident this alert belongs to, creating one if needed."""
    recent = (db.query(Incident)
              .filter(Incident.source_ip == source_ip, Incident.status.in_(("new", "investigating")),
                      Incident.last_alert_at >= when - GROUP_WITHIN)
              .order_by(Incident.incident_id.desc()).all())
    incident = next((i for i in recent if i.attack_type == attack_type), None)
    if incident is None and recent:
        # Unusual traffic of unknown type is part of whatever that source is already doing, not a second incident.
        if attack_type == "anomaly":
            incident = recent[0]
        elif any(i.attack_type == "anomaly" for i in recent):
            incident = next(i for i in recent if i.attack_type == "anomaly")
            incident.attack_type = attack_type   # the attack now has a name
    if incident is None:
        incident = Incident(source_ip=source_ip, attack_type=attack_type, severity=severity, risk_score=risk_score,
                            opened_at=when, last_alert_at=when)
        db.add(incident)
        db.flush()
        return incident, True
    incident.last_alert_at = max(incident.last_alert_at, when)
    if risk_score > incident.risk_score:
        incident.risk_score = risk_score
    if SEVERITY_ORDER.index(severity) > SEVERITY_ORDER.index(incident.severity):
        incident.severity = severity
    return incident, False


def earlier_incidents(db: Session, source_ip: str, when: datetime, exclude_id: int | None = None) -> int:
    query = db.query(Incident).filter(Incident.source_ip == source_ip, Incident.opened_at >= when - timedelta(hours=24),
                                      Incident.status != "false_positive")
    if exclude_id is not None:
        query = query.filter(Incident.incident_id != exclude_id)
    return query.count()
