"""
XAI Explanation Engine — SHAP + LIME
Generates post-hoc explanations for XGBoost threat classification predictions.
Lazy-loads models and background data on first call.
"""
import os
import json
import numpy as np
import pandas as pd
from typing import Optional

# ── Module-level caches ────────────────────────────────────────────────────────
_shap_explainer = None
_lime_explainer = None
_xgb_model      = None
_xgb_scaler     = None
_class_labels: list[str] = []
_background_data: Optional[np.ndarray] = None

_MODELS_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "ml", "models")
)
_DATASETS_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "ml", "datasets")
)


def _load_explainers():
    """Lazy-load models and build SHAP + LIME explainers (once)."""
    global _shap_explainer, _lime_explainer, _xgb_model, _xgb_scaler
    global _class_labels, _background_data

    if _shap_explainer is not None:
        return

    import joblib
    import shap
    from lime.lime_tabular import LimeTabularExplainer
    from ml.preprocessing.preprocessor import FEATURE_COLUMNS

    # Load model & scaler
    _xgb_model  = joblib.load(os.path.join(_MODELS_DIR, "xgb_classifier.joblib"))
    _xgb_scaler = joblib.load(os.path.join(_MODELS_DIR, "xgb_scaler.joblib"))
    with open(os.path.join(_MODELS_DIR, "class_labels.json")) as f:
        _class_labels = json.load(f)

    # Load background data (first 300 rows of training set, scaled)
    train_path = os.path.join(_DATASETS_DIR, "train.csv")
    if os.path.exists(train_path):
        bg_df = pd.read_csv(train_path)[FEATURE_COLUMNS].head(300).values
        _background_data = _xgb_scaler.transform(bg_df).astype(np.float32)
    else:
        # Fallback: small zero background
        _background_data = np.zeros((50, len(FEATURE_COLUMNS)), dtype=np.float32)

    # ── SHAP TreeExplainer ───────────────────────────────────────────────────
    _shap_explainer = shap.TreeExplainer(
        _xgb_model,
        data=_background_data,
        feature_perturbation="interventional",
    )

    # ── LIME Tabular Explainer ───────────────────────────────────────────────
    _lime_explainer = LimeTabularExplainer(
        training_data=_background_data,
        feature_names=FEATURE_COLUMNS,
        class_names=_class_labels,
        mode="classification",
        random_state=42,
        discretize_continuous=True,
    )


def explain_shap(event_features_scaled: np.ndarray, predicted_class_idx: int, top_n: int = 8) -> list[dict]:
    """
    Generate SHAP feature attributions for the predicted class.

    Returns top_n features sorted by |shap_value| descending.
    """
    _load_explainers()
    from ml.preprocessing.preprocessor import FEATURE_COLUMNS

    try:
        # shap_values shape: (n_samples, n_features, n_classes) for multi-class XGB
        shap_vals = _shap_explainer.shap_values(event_features_scaled)

        if isinstance(shap_vals, list):
            # Older SHAP returns list of arrays (one per class)
            class_shap = shap_vals[predicted_class_idx][0]
        elif shap_vals.ndim == 3:
            # Newer SHAP returns (n_samples, n_features, n_classes)
            class_shap = shap_vals[0, :, predicted_class_idx]
        else:
            class_shap = shap_vals[0]

        feature_vals = event_features_scaled[0]
        explanations = []
        for i, (fname, sv, fv) in enumerate(zip(FEATURE_COLUMNS, class_shap, feature_vals)):
            explanations.append({
                "feature":     fname,
                "feature_value": round(float(fv), 4),
                "shap_value":  round(float(sv), 6),
                "direction":   "positive" if sv > 0 else "negative",
                "abs_impact":  round(abs(float(sv)), 6),
            })

        # Sort by absolute SHAP value
        explanations.sort(key=lambda x: -x["abs_impact"])
        return explanations[:top_n]

    except Exception as e:
        return [{"feature": "shap_error", "shap_value": 0.0,
                 "direction": "unknown", "abs_impact": 0.0,
                 "error": str(e)}]


def explain_lime(event_features_scaled: np.ndarray, predicted_class_idx: int, top_n: int = 6) -> list[dict]:
    """
    Generate LIME feature attributions for the predicted class.
    Returns top_n features sorted by |weight| descending.
    """
    _load_explainers()
    from ml.preprocessing.preprocessor import FEATURE_COLUMNS

    try:
        def predict_fn(X):
            return _xgb_model.predict_proba(X)

        lime_exp = _lime_explainer.explain_instance(
            data_row=event_features_scaled[0],
            predict_fn=predict_fn,
            num_features=top_n,
            labels=[predicted_class_idx],
        )
        raw = lime_exp.as_list(label=predicted_class_idx)
        explanations = []
        for condition, weight in raw:
            explanations.append({
                "condition": condition,
                "weight":    round(float(weight), 6),
                "direction": "positive" if weight > 0 else "negative",
                "abs_weight": round(abs(float(weight)), 6),
            })
        explanations.sort(key=lambda x: -x["abs_weight"])
        return explanations

    except Exception as e:
        return [{"condition": "lime_error", "weight": 0.0,
                 "direction": "unknown", "abs_weight": 0.0,
                 "error": str(e)}]


def _build_natural_language_explanation(
    classification: str,
    shap_features: list[dict],
    confidence: float,
) -> str:
    """Convert top SHAP features into a one-sentence human-readable explanation."""
    if not shap_features:
        return f"Classified as {classification} with {confidence*100:.1f}% confidence."

    top = [f for f in shap_features if f["direction"] == "positive"][:3]
    if not top:
        top = shap_features[:2]

    feature_names = [f["feature"].replace("_log", "").replace("_", " ") for f in top]
    label_map = {
        "port_scan":    "port scanning / network reconnaissance",
        "failed_auth":  "brute-force credential attack",
        "dns_anomaly":  "DNS tunneling or DGA activity",
        "traffic_spike": "abnormal traffic volume",
        "c2_beacon":    "C2 beaconing behavior",
        "data_exfil":   "data exfiltration",
        "eicar_test":   "EICAR test string (malware simulation artifact)",
        "normal":       "benign network activity",
    }
    label_str = label_map.get(classification, classification)
    feat_str  = ", ".join(feature_names[:2])
    return (
        f"Event classified as {label_str} with {confidence*100:.1f}% confidence. "
        f"Primary indicators: {feat_str}."
    )


def explain(event: dict, prediction: dict) -> dict:
    """
    Full XAI explanation for an event + prediction pair.

    Args:
        event:      Raw network event dict.
        prediction: Output from backend.app.ml.predictor.predict()

    Returns:
        {shap_features, lime_features, natural_language_explanation}
    """
    from ml.preprocessing.preprocessor import preprocess_event, LABEL_TO_INT
    import joblib

    _load_explainers()

    classification = prediction.get("classification", "normal")
    confidence     = prediction.get("confidence", 0.0)
    class_idx      = LABEL_TO_INT.get(classification, 0)

    # Scale features (XGB scaler)
    X_raw    = preprocess_event(event)           # (1, n_features) float32
    X_scaled = _xgb_scaler.transform(X_raw)     # (1, n_features)

    shap_features = explain_shap(X_scaled, class_idx, top_n=8)
    lime_features = explain_lime(X_scaled, class_idx, top_n=6)
    explanation   = _build_natural_language_explanation(classification, shap_features, confidence)

    return {
        "shap_features":              shap_features,
        "lime_features":              lime_features,
        "natural_language_explanation": explanation,
        "predicted_class":            classification,
        "predicted_class_idx":        class_idx,
    }
