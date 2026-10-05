"""Trains a model from the labelled feature windows in the database.

    python -m ml.train --model xgboost --version v1

Windows get their labels in the laboratory (from the test schedule) and from CIC-IDS2017
(from the dataset's published attack schedule), and when an analyst marks an incident as
a false positive.
"""
import argparse

import numpy as np

from app.database import SessionLocal
from app.engine.features import FEATURES
from app.models import FlowWindow

from .common import save_and_register, train_anomaly, train_classifier


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", choices=["xgboost", "random_forest"], default="xgboost")
    parser.add_argument("--version", required=True)
    parser.add_argument("--no-activate", action="store_true", help="save the model without switching the system to it")
    args = parser.parse_args()

    db = SessionLocal()
    rows = db.query(FlowWindow).filter(FlowWindow.label.is_not(None)).all()
    labels = [row.label for row in rows]
    if len(set(labels)) < 2 or len(rows) < 200:
        raise SystemExit(f"Not enough labelled windows to train on ({len(rows)} found). Label laboratory traffic first.")
    X = np.array([[row.features[name] for name in FEATURES] for row in rows])
    bundle, metrics = train_classifier(X, labels, args.model, args.version)
    save_and_register(db, bundle, metrics, activate=not args.no_activate)
    save_and_register(db, train_anomaly(X[[label == "normal" for label in labels]], args.version), activate=not args.no_activate)
    print(f"Trained {args.model} {args.version} on {len(rows)} windows.")
    print(f"F1-score {metrics['f1_score']:.3f}, false positive rate {metrics['false_positive_rate']}")
    print("Confusion matrix (rows are true classes):", metrics["confusion_matrix"])


if __name__ == "__main__":
    main()
