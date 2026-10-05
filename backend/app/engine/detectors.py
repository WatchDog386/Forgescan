"""Detection models behind one common interface (SDS 6.1, 6.3)."""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np

from .features import FEATURES, FeatureWindow


@dataclass
class Detection:
    label: str            # "normal", "port_scan", "brute_force", "dos" or "anomaly"
    confidence: float     # 0 to 1
    model_version: str


class Detector(ABC):
    name: str = ""
    version: str = ""

    @abstractmethod
    def predict(self, window: FeatureWindow) -> Detection: ...


class ClassifierDetector(Detector):
    """A trained classifier (Random Forest or XGBoost) that names the kind of traffic."""

    def __init__(self, bundle: dict) -> None:
        self.model, self.classes = bundle["model"], list(bundle["classes"])
        self.name, self.version = bundle["name"], bundle["version"]
        if bundle["features"] != FEATURES:
            raise ValueError("The model was trained on a different set of features. Train it again.")

    def predict(self, window: FeatureWindow) -> Detection:
        probabilities = self.model.predict_proba(np.array([window.vector()]))[0]
        best = int(np.argmax(probabilities))
        return Detection(self.classes[best], float(probabilities[best]), f"{self.name}:{self.version}")


class IsolationForestDetector(Detector):
    """Flags windows unlike the normal traffic it was trained on."""

    def __init__(self, bundle: dict) -> None:
        self.model, self.name, self.version = bundle["model"], bundle["name"], bundle["version"]

    def predict(self, window: FeatureWindow) -> Detection:
        score = float(self.model.decision_function(np.array([window.vector()]))[0])  # below zero means unusual
        if score >= 0:
            return Detection("normal", min(1.0, 0.5 + score), f"{self.name}:{self.version}")
        return Detection("anomaly", min(1.0, 0.5 + abs(score) * 2), f"{self.name}:{self.version}")


def load(path: Path) -> Detector:
    """Load a model file. Only load files from the project's own models folder: a model file can run code."""
    bundle = joblib.load(path)
    return IsolationForestDetector(bundle) if bundle["name"] == "isolation_forest" else ClassifierDetector(bundle)
