"""Every action by a user or by the system itself is written here (FR-44, FR-45)."""
from sqlalchemy.orm import Session

from .models import AuditEntry


def record(db: Session, action: str, user_id: int | None = None, **detail) -> None:
    db.add(AuditEntry(user_id=user_id, action=action, detail=detail or None))
