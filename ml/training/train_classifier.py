"""
XGBoost Multi-Class Threat Classifier Training
Trains a supervised classifier on all labelled synthetic events.
Saves model + scaler to ml/models/.
Run: python ml/training/train_classifier.py
"""
import sys
import os
import json
import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from xgboost import XGBClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score
)

from ml.preprocessing.preprocessor import (
    FEATURE_COLUMNS, LABEL_COLUMNS, INT_TO_LABEL
)

MODELS_DIR    = os.path.join(os.path.dirname(__file__), "..", "models")
MODEL_PATH    = os.path.join(MODELS_DIR, "xgb_classifier.joblib")
SCALER_PATH   = os.path.join(MODELS_DIR, "xgb_scaler.joblib")
METRICS_PATH  = os.path.join(MODELS_DIR, "xgb_metrics.json")
CLASSES_PATH  = os.path.join(MODELS_DIR, "class_labels.json")


def load_dataset():
    train_path = os.path.join(os.path.dirname(__file__), "..", "datasets", "train.csv")
    val_path   = os.path.join(os.path.dirname(__file__), "..", "datasets", "val.csv")
    if not os.path.exists(train_path):
        raise FileNotFoundError(
            "Dataset not found. Run `python ml/datasets/generate_dataset.py` first."
        )
    return pd.read_csv(train_path), pd.read_csv(val_path)


def main():
    os.makedirs(MODELS_DIR, exist_ok=True)
    print("Loading dataset…")
    train_df, val_df = load_dataset()

    X_train = train_df[FEATURE_COLUMNS].values
    y_train = train_df["label_int"].values
    X_val   = val_df[FEATURE_COLUMNS].values
    y_val   = val_df["label_int"].values

    print(f"  Train: {len(X_train)} | Val: {len(X_val)}")
    print(f"  Classes: {LABEL_COLUMNS}")

    # ── Scale ───────────────────────────────────────────────────────────────
    print("Fitting scaler…")
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_val_s   = scaler.transform(X_val)

    # ── Class weights for imbalance ──────────────────────────────────────────
    from collections import Counter
    counts = Counter(y_train)
    n_total = len(y_train)
    sample_weights = np.array([n_total / (len(LABEL_COLUMNS) * counts[y]) for y in y_train])

    # ── Train XGBoost ────────────────────────────────────────────────────────
    print("Training XGBoost classifier…")
    model = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        use_label_encoder=False,
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=-1,
        verbosity=0,
    )
    model.fit(
        X_train_s, y_train,
        sample_weight=sample_weights,
        eval_set=[(X_val_s, y_val)],
        verbose=False,
    )

    # ── Evaluate ─────────────────────────────────────────────────────────────
    y_pred = model.predict(X_val_s)
    y_pred_proba = model.predict_proba(X_val_s)
    acc = accuracy_score(y_val, y_pred)

    report = classification_report(
        y_val, y_pred,
        target_names=LABEL_COLUMNS,
        output_dict=True,
        zero_division=0,
    )
    print("\nXGBoost Classifier — Validation Report:")
    print(classification_report(y_val, y_pred, target_names=LABEL_COLUMNS, zero_division=0))
    print(f"Overall Accuracy: {acc:.4f}")

    # Feature importance
    importances = dict(zip(FEATURE_COLUMNS, model.feature_importances_.tolist()))
    top_features = sorted(importances.items(), key=lambda x: -x[1])[:10]
    print("\nTop 10 Features:")
    for feat, imp in top_features:
        print(f"  {feat:40s} {imp:.4f}")

    # ── Save ─────────────────────────────────────────────────────────────────
    joblib.dump(model,  MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    with open(CLASSES_PATH, "w") as f:
        json.dump(LABEL_COLUMNS, f)

    per_class = {
        label: {
            "precision": round(report.get(label, {}).get("precision", 0), 4),
            "recall":    round(report.get(label, {}).get("recall", 0), 4),
            "f1":        round(report.get(label, {}).get("f1-score", 0), 4),
        }
        for label in LABEL_COLUMNS
    }
    metrics = {
        "model": "XGBClassifier",
        "n_estimators": 300,
        "max_depth": 6,
        "n_train": len(X_train),
        "n_val": len(X_val),
        "overall_accuracy": round(float(acc), 4),
        "per_class": per_class,
        "top_features": {k: round(v, 6) for k, v in top_features},
    }
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"\nModel saved:  {MODEL_PATH}")
    print(f"Scaler saved: {SCALER_PATH}")
    print(f"Metrics:      {METRICS_PATH}")
    return metrics


if __name__ == "__main__":
    main()
