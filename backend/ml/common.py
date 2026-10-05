"""Shared training code: fit a model on labelled feature windows, measure it, save it and register it."""
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score
from sklearn.model_selection import train_test_split

from app.config import get_settings
from app.engine.features import FEATURES
from app.models import ModelVersion


def _classifier(name: str):
    if name == "random_forest":
        return RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=7, n_jobs=-1)
    if name == "xgboost":
        from xgboost import XGBClassifier  # imported here so the rest works without XGBoost installed

        return XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1, subsample=0.9, random_state=7)
    raise ValueError(f"Unknown model: {name}")


def train_classifier(X: np.ndarray, labels: list[str], name: str, version: str) -> tuple[dict, dict]:
    """Return (bundle to save, metrics on held-out data)."""
    classes = sorted(set(labels))
    y = np.array([classes.index(label) for label in labels])
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, stratify=y, random_state=7)
    model = _classifier(name).fit(X_train, y_train)
    predicted = model.predict(X_test)
    metrics = {"f1_score": float(f1_score(y_test, predicted, average="macro")), "false_positive_rate": None}
    if "normal" in classes:
        normal = classes.index("normal")
        truly_normal = y_test == normal
        if truly_normal.any():
            metrics["false_positive_rate"] = float((predicted[truly_normal] != normal).mean())
    metrics["confusion_matrix"] = confusion_matrix(y_test, predicted).tolist()
    return {"model": model, "classes": classes, "features": FEATURES, "name": name, "version": version}, metrics


def train_anomaly(X_normal: np.ndarray, version: str) -> dict:
    model = IsolationForest(n_estimators=200, contamination=0.02, random_state=7).fit(X_normal)
    return {"model": model, "features": FEATURES, "name": "isolation_forest", "version": version}


def save_and_register(db, bundle: dict, metrics: dict | None = None, activate: bool = True) -> ModelVersion:
    folder = Path(get_settings().model_dir)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{bundle['name']}_{bundle['version']}.joblib"
    joblib.dump(bundle, path)
    if activate:
        kind = bundle["name"] == "isolation_forest"
        for row in db.query(ModelVersion).filter(ModelVersion.active.is_(True)):
            if (row.name == "isolation_forest") == kind:
                row.active = False
    row = ModelVersion(name=bundle["name"], version=bundle["version"], file_path=str(path), active=activate,
                       f1_score=(metrics or {}).get("f1_score"), false_positive_rate=(metrics or {}).get("false_positive_rate"))
    db.add(row)
    db.commit()
    return row
