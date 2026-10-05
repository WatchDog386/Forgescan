"""Builds a first model from SIMULATED traffic, so the whole pipeline can run before real data exists.

This model is a placeholder. Its scores describe the simulator, not real attacks.
Replace it with `python -m ml.train` once labelled windows from CIC-IDS2017 and the
laboratory are in the database.
"""
import random

import numpy as np

from app.engine import simulate
from app.engine.features import ConnRecord, FeatureExtractor

from .common import save_and_register, train_anomaly, train_classifier


def simulated_windows(per_class: int = 200, seed: int = 7) -> tuple[np.ndarray, list[str]]:
    rng = random.Random(seed)
    X, labels = [], []
    for label, generate in simulate.GENERATORS.items():
        made = 0
        while made < per_class:
            source = f"192.168.56.{rng.randint(100, 250)}"
            records = generate(source, rng.choice(simulate.SERVERS), 1_000_000.0, 75, rng)
            if label != "normal" and rng.random() < 0.5:  # an attacker's machine also makes ordinary connections
                records += simulate.normal(source, 1_000_000.0, 75, rng)
            windows = FeatureExtractor().add([ConnRecord.from_zeek(r) for r in sorted(records, key=lambda r: r["ts"])])
            if windows:
                # Any window of the burst, so the model also learns what the first seconds of an attack look like.
                X.append(rng.choice(windows).vector())
                labels.append(label)
                made += 1
    return np.array(X), labels


def run(db, per_class: int = 200, version: str = "bootstrap-1") -> dict:
    X, labels = simulated_windows(per_class)
    bundle, metrics = train_classifier(X, labels, "random_forest", version)
    save_and_register(db, bundle, metrics)
    normal = X[[label == "normal" for label in labels]]
    save_and_register(db, train_anomaly(normal, version))
    return metrics
