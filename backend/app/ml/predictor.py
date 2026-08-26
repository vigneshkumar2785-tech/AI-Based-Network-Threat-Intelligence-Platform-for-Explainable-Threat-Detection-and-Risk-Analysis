"""
ML Inference Predictor — reusable at inference time (FastAPI, CLI, demo).
Loads trained models once (cached) and exposes predict() for raw event dicts.
"""
import os
import json
import joblib
import numpy as np
from typing import Optional

# Lazy-load — models loaded on first call, cached in module globals
_if_model   = None
_if_scaler  = None
_xgb_model  = None
_xgb_scaler = None
_class_labels: list[str] = []

MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "ml", "models")


def _abs(path: str) -> str:
    return os.path.normpath(os.path.join(os.path.dirname(__file__), path))


def _load_models():
    global _if_model, _if_scaler, _xgb_model, _xgb_scaler, _class_labels
    if _xgb_model is not None:
        return  # already loaded

    models_dir = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "ml", "models")
    )

    if_path  = os.path.join(models_dir, "isolation_forest.joblib")
    ifs_path = os.path.join(models_dir, "if_scaler.joblib")
    xgb_path = os.path.join(models_dir, "xgb_classifier.joblib")
    xgbs_path = os.path.join(models_dir, "xgb_scaler.joblib")
    cls_path  = os.path.join(models_dir, "class_labels.json")

    for p in [if_path, ifs_path, xgb_path, xgbs_path, cls_path]:
        if not os.path.exists(p):
            raise FileNotFoundError(
                f"Model file not found: {p}\n"
                "Run `python ml/training/train_all.py` first."
            )

    _if_model   = joblib.load(if_path)
    _if_scaler  = joblib.load(ifs_path)
    _xgb_model  = joblib.load(xgb_path)
    _xgb_scaler = joblib.load(xgbs_path)
    with open(cls_path) as f:
        _class_labels = json.load(f)


def predict(event: dict) -> dict:
    """
    Full inference pipeline for a single raw network event.

    Returns:
        {
          "is_anomaly": bool,
          "anomaly_score": float,       # IF decision score (lower = more anomalous)
          "classification": str,        # predicted threat label
          "confidence": float,          # max class probability (0.0–1.0)
          "all_probabilities": dict,    # {label: probability}
          "eicar_detected": bool,
        }
    """
    from ml.preprocessing.preprocessor import preprocess_event, FEATURE_COLUMNS
    from simulation.network_events.generator import detect_eicar_in_event

    _load_models()

    # Preprocessing
    X = preprocess_event(event)   # shape (1, n_features)

    # ── Isolation Forest (anomaly detection) ─────────────────────────────────
    X_if = _if_scaler.transform(X)
    if_pred  = _if_model.predict(X_if)[0]         # 1=normal, -1=anomaly
    if_score = float(_if_model.decision_function(X_if)[0])
    is_anomaly = bool(if_pred == -1)

    # ── XGBoost (classification) ─────────────────────────────────────────────
    X_xgb = _xgb_scaler.transform(X)
    xgb_pred  = int(_xgb_model.predict(X_xgb)[0])
    xgb_proba = _xgb_model.predict_proba(X_xgb)[0]

    classification = _class_labels[xgb_pred]
    confidence     = float(xgb_proba[xgb_pred])
    all_probs      = {_class_labels[i]: round(float(p), 4) for i, p in enumerate(xgb_proba)}

    # ── EICAR string check (inert text only) ─────────────────────────────────
    eicar_detected = detect_eicar_in_event(event)
    if eicar_detected:
        classification = "eicar_test"
        confidence = 1.0
        is_anomaly = True

    return {
        "is_anomaly":       is_anomaly,
        "anomaly_score":    round(if_score, 6),
        "classification":   classification,
        "confidence":       round(confidence, 4),
        "all_probabilities": all_probs,
        "eicar_detected":   eicar_detected,
    }


def predict_batch(events: list[dict]) -> list[dict]:
    """Run predict() on a list of events."""
    return [predict(e) for e in events]


def models_loaded() -> bool:
    """Return True if models are already loaded into memory."""
    return _xgb_model is not None
