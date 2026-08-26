"""
Isolation Forest Anomaly Detector Training
Trains an unsupervised anomaly detector on predominantly normal events.
Saves model + scaler to ml/models/.
Run: python ml/training/train_isolation_forest.py
"""
import sys
import os
import json
import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report

from ml.preprocessing.preprocessor import (
    FEATURE_COLUMNS, LABEL_TO_INT, INT_TO_LABEL, events_to_dataframe
)

MODELS_DIR   = os.path.join(os.path.dirname(__file__), "..", "models")
MODEL_PATH   = os.path.join(MODELS_DIR, "isolation_forest.joblib")
SCALER_PATH  = os.path.join(MODELS_DIR, "if_scaler.joblib")
METRICS_PATH = os.path.join(MODELS_DIR, "if_metrics.json")

# Isolation Forest considers score < threshold → anomaly
# We binarise: normal=0, anomaly=1
ANOMALY_THRESHOLD = 0.0   # sklearn IF: predict() returns -1 anomaly, 1 normal


def load_dataset():
    train_path = os.path.join(os.path.dirname(__file__), "..", "datasets", "train.csv")
    val_path   = os.path.join(os.path.dirname(__file__), "..", "datasets", "val.csv")
    if not os.path.exists(train_path):
        raise FileNotFoundError(
            "Dataset not found. Run `python ml/datasets/generate_dataset.py` first."
        )
    train_df = pd.read_csv(train_path)
    val_df   = pd.read_csv(val_path)
    return train_df, val_df


def main():
    os.makedirs(MODELS_DIR, exist_ok=True)
    print("Loading dataset…")
    train_df, val_df = load_dataset()

    X_train = train_df[FEATURE_COLUMNS].values
    X_val   = val_df[FEATURE_COLUMNS].values
    y_val_str = val_df["label_str"].values

    # Binary label: normal=0, anomaly=1
    y_val_binary = (y_val_str != "normal").astype(int)

    # ── Scale features ──────────────────────────────────────────────────────
    print("Fitting scaler…")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled   = scaler.transform(X_val)

    # ── Train Isolation Forest ───────────────────────────────────────────────
    # contamination ≈ ratio of anomalies in real-world SOC data
    n_normal  = (train_df["label_str"] == "normal").sum()
    n_total   = len(train_df)
    contamination = max(0.01, round(1.0 - n_normal / n_total, 3))
    print(f"Training Isolation Forest (contamination={contamination:.3f})…")

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        max_samples="auto",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train_scaled)

    # ── Evaluate ────────────────────────────────────────────────────────────
    # sklearn IF: predict returns 1 (normal) or -1 (anomaly)
    preds_raw = model.predict(X_val_scaled)          # 1 or -1
    y_pred_binary = (preds_raw == -1).astype(int)    # 1=anomaly, 0=normal

    scores = model.decision_function(X_val_scaled)   # higher = more normal

    report = classification_report(
        y_val_binary, y_pred_binary,
        target_names=["normal", "anomaly"],
        output_dict=True,
        zero_division=0,
    )
    print("\nIsolation Forest — Validation Report:")
    print(classification_report(
        y_val_binary, y_pred_binary,
        target_names=["normal", "anomaly"],
        zero_division=0,
    ))

    # ── Save ────────────────────────────────────────────────────────────────
    joblib.dump(model,  MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    metrics = {
        "model": "IsolationForest",
        "n_estimators": 200,
        "contamination": contamination,
        "n_train": int(n_total),
        "n_val": len(y_val_binary),
        "anomaly_precision": round(report.get("anomaly", {}).get("precision", 0), 4),
        "anomaly_recall":    round(report.get("anomaly", {}).get("recall", 0), 4),
        "anomaly_f1":        round(report.get("anomaly", {}).get("f1-score", 0), 4),
        "accuracy":          round(report.get("accuracy", 0), 4),
    }
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"\nModel saved:  {MODEL_PATH}")
    print(f"Scaler saved: {SCALER_PATH}")
    print(f"Metrics saved: {METRICS_PATH}")
    return metrics


if __name__ == "__main__":
    main()
