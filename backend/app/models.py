"""Database tables (SDS section 5.2)."""
from datetime import datetime, timezone

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base

ROLES = ("viewer", "analyst", "administrator")  # each role can do everything the one before it can
ATTACK_TYPES = ("port_scan", "brute_force", "dos", "anomaly")
SEVERITIES = ("low", "medium", "high", "critical")
INCIDENT_STATES = ("new", "investigating", "resolved", "false_positive")
BigId = BigInteger().with_variant(Integer, "sqlite")


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"
    user_id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    email: Mapped[str] = mapped_column(String(255), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20))
    totp_secret: Mapped[str | None] = mapped_column(String(255))  # stored encrypted (NFR-09)
    status: Mapped[str] = mapped_column(String(20), default="active")
    failed_logins: Mapped[int] = mapped_column(default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime)


class Sensor(Base):
    __tablename__ = "sensors"
    sensor_id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(50), unique=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    network: Mapped[str] = mapped_column(String(43))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime)


class FlowWindow(Base):
    __tablename__ = "flow_windows"
    window_id: Mapped[int] = mapped_column(BigId, primary_key=True)
    sensor_id: Mapped[int | None] = mapped_column(ForeignKey("sensors.sensor_id"))
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    window_start: Mapped[datetime] = mapped_column(DateTime, index=True)
    window_seconds: Mapped[int]
    features: Mapped[dict] = mapped_column(JSON)
    label: Mapped[str | None] = mapped_column(String(20))  # known label, for training


class ModelVersion(Base):
    __tablename__ = "model_versions"
    model_id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(30))
    version: Mapped[str] = mapped_column(String(40))
    file_path: Mapped[str] = mapped_column(String(255))
    f1_score: Mapped[float | None] = mapped_column(Float)
    false_positive_rate: Mapped[float | None] = mapped_column(Float)
    active: Mapped[bool] = mapped_column(Boolean, default=False)
    trained_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Incident(Base):
    __tablename__ = "incidents"
    incident_id: Mapped[int] = mapped_column(primary_key=True)
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    attack_type: Mapped[str] = mapped_column(String(20))
    severity: Mapped[str] = mapped_column(String(10))
    risk_score: Mapped[int]
    status: Mapped[str] = mapped_column(String(20), default="new")
    assigned_to: Mapped[int | None] = mapped_column(ForeignKey("users.user_id"))
    opened_at: Mapped[datetime] = mapped_column(DateTime)
    last_alert_at: Mapped[datetime] = mapped_column(DateTime)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime)

    alerts: Mapped[list["Alert"]] = relationship(back_populates="incident", order_by="Alert.alert_id")
    notes: Mapped[list["IncidentNote"]] = relationship(order_by="IncidentNote.note_id")
    responses: Mapped[list["Response"]] = relationship(order_by="Response.response_id")


class Alert(Base):
    __tablename__ = "alerts"
    alert_id: Mapped[int] = mapped_column(BigId, primary_key=True)
    window_id: Mapped[int] = mapped_column(ForeignKey("flow_windows.window_id"))
    model_id: Mapped[int | None] = mapped_column(ForeignKey("model_versions.model_id"))
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.incident_id"))
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    target_ip: Mapped[str | None] = mapped_column(String(45))
    attack_type: Mapped[str] = mapped_column(String(20))
    confidence: Mapped[float] = mapped_column(Float)
    risk_score: Mapped[int]
    severity: Mapped[str] = mapped_column(String(10))
    rule_match: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, index=True)

    incident: Mapped[Incident] = relationship(back_populates="alerts")


class IncidentNote(Base):
    __tablename__ = "incident_notes"
    note_id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.incident_id"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.user_id"))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Response(Base):
    __tablename__ = "responses"
    response_id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.incident_id"))
    action: Mapped[str] = mapped_column(String(20))        # block, release or notify
    target_ip: Mapped[str | None] = mapped_column(String(45))
    automatic: Mapped[bool] = mapped_column(Boolean)
    performed_by: Mapped[int | None] = mapped_column(ForeignKey("users.user_id"))
    status: Mapped[str] = mapped_column(String(20))        # applied, failed, refused, dry_run, expired or reversed
    detail: Mapped[str | None] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime)


class AllowlistEntry(Base):
    __tablename__ = "allowlist"
    entry_id: Mapped[int] = mapped_column(primary_key=True)
    ip_range: Mapped[str] = mapped_column(String(43), unique=True)
    reason: Mapped[str] = mapped_column(String(200))
    added_by: Mapped[int | None] = mapped_column(ForeignKey("users.user_id"))


class AuditEntry(Base):
    __tablename__ = "audit_log"
    entry_id: Mapped[int] = mapped_column(BigId, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.user_id"))  # empty for the system itself
    action: Mapped[str] = mapped_column(String(40))
    detail: Mapped[dict | None] = mapped_column(JSON)
    logged_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(50), primary_key=True)
    value: Mapped[str] = mapped_column(String(200))
