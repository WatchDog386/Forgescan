"""Decides whether to block a source, and does it only when every safeguard allows it (SDS 6.6)."""
import ipaddress
from datetime import timedelta

from sqlalchemy.orm import Session

from .. import audit, runtime
from ..config import get_settings
from ..models import AllowlistEntry, Incident, Response, utcnow
from .firewall import Firewall, FirewallError


class ResponseEngine:
    def __init__(self, firewall: Firewall) -> None:
        self.firewall = firewall

    # ---- safeguards ----
    def refusal(self, db: Session, ip: str) -> str | None:
        """Return the reason this address must not be blocked, or None if it may be."""
        address = ipaddress.ip_address(ip)
        if address not in ipaddress.ip_network(get_settings().monitored_network):
            return "outside the monitored network"          # FR-31
        for entry in db.query(AllowlistEntry).all():
            if address in ipaddress.ip_network(entry.ip_range, strict=False):
                return "on the allowlist"                    # FR-30
        return None

    def active_blocks(self, db: Session) -> list[Response]:
        self.expire(db)
        return db.query(Response).filter(Response.action == "block", Response.status == "applied").all()

    def expire(self, db: Session) -> None:
        """The firewall drops expired entries by itself (NFR-15); this keeps the records in step."""
        for response in db.query(Response).filter(Response.action == "block", Response.status == "applied", Response.expires_at <= utcnow()):
            response.status = "expired"

    # ---- actions ----
    def block(self, db: Session, ip: str, incident: Incident | None, automatic: bool, user_id: int | None = None) -> Response:
        settings = runtime.get_all(db)
        minutes = settings["block_minutes"]
        response = Response(incident_id=incident.incident_id if incident else None, action="block", target_ip=ip,
                            automatic=automatic, performed_by=user_id, status="refused")
        reason = self.refusal(db, ip)
        active = self.active_blocks(db)
        if reason:
            response.detail = reason
        elif any(r.target_ip == ip for r in active):
            response.detail = "already blocked"
        elif automatic and len(active) >= settings["max_active_blocks"]:
            response.detail = "limit on active blocks reached"  # FR-32
        elif automatic and not settings["auto_response"]:
            response.status, response.detail = "dry_run", "automatic response is switched off"
        else:
            try:
                self.firewall.block(ip, minutes)
                response.status, response.expires_at = "applied", utcnow() + timedelta(minutes=minutes)
            except FirewallError as error:
                response.status, response.detail = "failed", str(error)[:200]  # NFR-14: tell a person, never guess
        db.add(response)
        audit.record(db, "response.block", user_id, ip=ip, status=response.status, detail=response.detail, automatic=automatic)
        return response

    def release(self, db: Session, ip: str, user_id: int | None, incident: Incident | None = None) -> Response:
        response = Response(incident_id=incident.incident_id if incident else None, action="release", target_ip=ip,
                            automatic=user_id is None, performed_by=user_id, status="applied")
        try:
            self.firewall.unblock(ip)
            for block in db.query(Response).filter(Response.action == "block", Response.target_ip == ip, Response.status == "applied"):
                block.status = "reversed"
        except FirewallError as error:
            response.status, response.detail = "failed", str(error)[:200]
        db.add(response)
        audit.record(db, "response.release", user_id, ip=ip, status=response.status)
        return response
