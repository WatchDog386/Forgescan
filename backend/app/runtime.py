"""Settings an administrator can change while the system runs (stored in the settings table)."""
from sqlalchemy.orm import Session

from .models import Setting

DEFAULTS: dict[str, float | int | bool] = {
    "detection_threshold": 0.80,   # FR-19
    "auto_response": False,        # off until the system has been tested in the laboratory
    "block_minutes": 30,           # FR-29
    "max_active_blocks": 50,       # FR-32
    "weight_confidence": 0.50,     # FR-25, FR-27
    "weight_attack": 0.35,
    "weight_spread": 0.075,
    "weight_repeat": 0.075,
}
LIMITS = {"detection_threshold": (0.5, 0.99), "block_minutes": (1, 1440), "max_active_blocks": (1, 500),
          "weight_confidence": (0, 1), "weight_attack": (0, 1), "weight_spread": (0, 1), "weight_repeat": (0, 1)}


def _parse(key: str, raw: str):
    default = DEFAULTS[key]
    if isinstance(default, bool):
        return raw == "true"
    return type(default)(raw)


def get_all(db: Session) -> dict:
    stored = {s.key: s.value for s in db.query(Setting).all()}
    return {key: _parse(key, stored[key]) if key in stored else default for key, default in DEFAULTS.items()}


def get(db: Session, key: str):
    return get_all(db)[key]


def put(db: Session, key: str, value) -> None:
    if key not in DEFAULTS:
        raise KeyError(key)
    default = DEFAULTS[key]
    if isinstance(default, bool):
        if not isinstance(value, bool):
            raise ValueError(f"{key} must be true or false")
        raw = "true" if value else "false"
    else:
        value = type(default)(value)
        low, high = LIMITS[key]
        if not low <= value <= high:
            raise ValueError(f"{key} must be between {low} and {high}")
        raw = str(value)
    row = db.get(Setting, key) or Setting(key=key, value=raw)
    row.value = raw
    db.add(row)
