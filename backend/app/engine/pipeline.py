"""The detection pipeline: records in, feature windows, detections, risk, incidents and responses out."""
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .. import runtime
from ..models import Alert, FlowWindow, ModelVersion, Sensor, utcnow
from ..response.engine import ResponseEngine
from ..services.incidents import earlier_incidents, incident_for
from . import detectors, risk
from .detectors import Detection, Detector
from .features import ConnRecord, FeatureExtractor, FeatureWindow

log = logging.getLogger(__name__)
MAX_BATCH = 20000


def _when(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)


class Pipeline:
    def __init__(self, responder: ResponseEngine, main: Detector | None = None, anomaly: Detector | None = None) -> None:
        self.extractor = FeatureExtractor()
        self.responder, self.main, self.anomaly = responder, main, anomaly
        self.model_ids: dict[str, int] = {}

    def load_models(self, db: Session) -> None:
        """Load the model versions an administrator has marked active (FR-20)."""
        self.main = self.anomaly = None
        for row in db.query(ModelVersion).filter(ModelVersion.active.is_(True)).order_by(ModelVersion.model_id):
            try:
                detector = detectors.load(row.file_path)
            except Exception:  # keep running with whatever still loads (SDS section 9)
                log.exception("Model %s %s could not be loaded", row.name, row.version)
                continue
            self.model_ids[f"{detector.name}:{detector.version}"] = row.model_id
            if row.name == "isolation_forest":
                self.anomaly = detector
            else:
                self.main = detector

    def detect(self, window: FeatureWindow, threshold: float) -> Detection | None:
        """Name the attack, or return None for normal traffic (SDS 6.4)."""
        sure_normal = False
        if self.main is not None:
            found = self.main.predict(window)
            if found.label != "normal" and found.confidence >= threshold:
                return found
            sure_normal = found.label == "normal" and found.confidence >= threshold
        if self.anomaly is not None and not sure_normal:
            found = self.anomaly.predict(window)
            if found.label == "anomaly":
                return found
        return None

    def process(self, db: Session, sensor: Sensor | None, raw_records: list[dict]) -> dict:
        """Take a batch of Zeek connection records and return what happened, as events for the dashboard."""
        records, skipped = [], 0
        for raw in raw_records[:MAX_BATCH]:
            try:
                records.append(ConnRecord.from_zeek(raw))
            except (KeyError, TypeError, ValueError):
                skipped += 1  # one unreadable record must not stop the rest
        settings = runtime.get_all(db)
        events: list[dict] = []
        windows = self.extractor.add(records)
        for window in windows:
            row = FlowWindow(sensor_id=sensor.sensor_id if sensor else None, source_ip=window.source_ip,
                             window_start=_when(window.window_end - window.window_seconds),
                             window_seconds=window.window_seconds, features=window.features)
            db.add(row)
            found = self.detect(window, settings["detection_threshold"])
            if found is None:
                continue
            db.flush()
            when = _when(window.window_end)
            incident, created = incident_for(db, window.source_ip, found.label, when, 0, "low")
            hosts = int(window.features["unique_destinations"])
            score = risk.score(found.confidence, found.label, hosts, earlier_incidents(db, window.source_ip, when, incident.incident_id), settings)
            severity = risk.severity_for(score)
            if score > incident.risk_score:
                incident.risk_score, incident.severity = score, severity
            alert = Alert(window_id=row.window_id, model_id=self.model_ids.get(found.model_version), incident_id=incident.incident_id,
                          source_ip=window.source_ip, target_ip=window.target_ip, attack_type=found.label,
                          confidence=round(found.confidence, 3), risk_score=score, severity=severity, created_at=when)
            db.add(alert)
            db.flush()
            events.append({"type": "alert", "alert_id": alert.alert_id, "incident_id": incident.incident_id, "new_incident": created,
                           "source_ip": alert.source_ip, "target_ip": alert.target_ip, "attack_type": alert.attack_type,
                           "confidence": alert.confidence, "risk_score": score, "severity": severity,
                           "created_at": when.isoformat() + "Z"})
            already_answered = any(r.action == "block" and r.automatic for r in incident.responses)
            if severity == "critical" and not already_answered:
                response = self.responder.block(db, window.source_ip, incident, automatic=True)
                db.flush()
                db.refresh(incident)
                events.append({"type": "response", "response_id": response.response_id, "incident_id": incident.incident_id,
                               "action": "block", "target_ip": response.target_ip, "status": response.status, "detail": response.detail})
        if sensor is not None:
            sensor.last_seen = utcnow()
        db.commit()
        return {"received": len(records), "skipped": skipped, "windows": len(windows), "events": events}
