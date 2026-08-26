"""
Main Correlation Service — Block C Orchestrator
Runs a raw network event through the full intelligence pipeline:

  Event → ML Predict → IOC Extract → MITRE Map → CVE Correlate
       → Risk Score → XAI Explain → Incident Create → Structured Result

This is the single callable that Blocks D and E will invoke.
"""
import sys
import os

# Make threat_intelligence importable from repo root context
_REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)


def process_event(event: dict, include_xai: bool = True) -> dict:
    """
    Full Block C intelligence pipeline for a single raw network event.

    Args:
        event:       Raw network event dict (from generator or ingestion).
        include_xai: Set False to skip SHAP/LIME (faster, used in bulk processing).

    Returns:
        Structured result answering:
          1. WHAT happened?      → event_type, classification
          2. WHY suspicious?     → xai.natural_language_explanation, xai.shap_features
          3. WHAT threat?        → classification, mitre_techniques
          4. HOW serious?        → risk_score, risk_level, cves
          5. WHAT to do?         → incident.recommended_actions
    """
    from backend.app.ml.predictor import predict
    from ml.preprocessing.preprocessor import extract_features
    from threat_intelligence.ioc.extractor import extract_iocs, score_ioc_set
    from threat_intelligence.mitre.mapper import map_techniques
    from threat_intelligence.cve.correlator import correlate_cves
    from backend.app.services.risk_scorer import compute_risk_score
    from backend.app.response.incident_engine import create_incident

    # ── Step 1: ML Prediction ────────────────────────────────────────────────
    prediction = predict(event)
    classification = prediction["classification"]
    confidence     = prediction["confidence"]
    is_anomaly     = prediction["is_anomaly"]
    anomaly_score  = prediction["anomaly_score"]
    eicar_detected = prediction["eicar_detected"]

    # ── Step 2: Feature extraction (needed for MITRE evidence gating) ────────
    features = extract_features(event)

    # ── Step 3: IOC Extraction ───────────────────────────────────────────────
    iocs = extract_iocs(event)
    ioc_threat_score = score_ioc_set(iocs)

    # ── Step 4: MITRE ATT&CK Mapping (evidence-gated) ───────────────────────
    mitre_techniques = map_techniques(event, classification, features)

    # ── Step 5: CVE Correlation ──────────────────────────────────────────────
    cves = correlate_cves(event)

    # ── Step 6: Risk Scoring ─────────────────────────────────────────────────
    risk = compute_risk_score(
        classification=classification,
        confidence=confidence,
        is_anomaly=is_anomaly,
        anomaly_score=anomaly_score,
        ioc_threat_score=ioc_threat_score,
        cves=cves,
        mitre_techniques=mitre_techniques,
        eicar_detected=eicar_detected,
    )

    # ── Step 7: XAI Explanations ─────────────────────────────────────────────
    xai_result = {}
    if include_xai:
        try:
            from backend.app.xai.explainer import explain
            xai_result = explain(event, prediction)
        except Exception as e:
            xai_result = {
                "shap_features": [],
                "lime_features": [],
                "natural_language_explanation": f"XAI unavailable: {e}",
                "predicted_class": classification,
            }

    # ── Step 8: Incident Creation ─────────────────────────────────────────────
    incident = create_incident(
        event=event,
        classification=classification,
        risk_score=risk["risk_score"],
        risk_level=risk["risk_level"],
        mitre_techniques=mitre_techniques,
        iocs=iocs,
        cves=cves,
    )

    # ── Assemble Final Result ─────────────────────────────────────────────────
    return {
        # Identity
        "event_id":      event.get("event_id", ""),
        "timestamp":     event.get("timestamp", ""),
        "event_type":    event.get("event_type", ""),

        # Network fields
        "src_ip":        event.get("src_ip", ""),
        "dst_ip":        event.get("dst_ip", ""),
        "dst_port":      event.get("dst_port"),
        "protocol":      event.get("protocol", ""),
        "byte_count":    event.get("byte_count", 0),
        "packet_count":  event.get("packet_count", 0),

        # ML Prediction (Block B)
        "is_anomaly":           is_anomaly,
        "anomaly_score":        anomaly_score,
        "classification":       classification,
        "confidence":           confidence,
        "all_probabilities":    prediction.get("all_probabilities", {}),
        "eicar_detected":       eicar_detected,

        # IOC Layer
        "iocs":              iocs,
        "ioc_threat_score":  ioc_threat_score,

        # MITRE ATT&CK
        "mitre_techniques":  mitre_techniques,

        # CVE
        "cves":              cves,

        # Risk
        "risk_score":        risk["risk_score"],
        "risk_level":        risk["risk_level"],
        "risk_color":        risk["risk_color"],
        "score_breakdown":   risk["score_breakdown"],

        # XAI
        "xai":               xai_result,

        # Incident
        "incident":          incident,
    }
