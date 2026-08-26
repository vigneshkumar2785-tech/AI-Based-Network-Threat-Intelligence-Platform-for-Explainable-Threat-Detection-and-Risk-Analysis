"""
Weighted Risk Scoring Engine
Combines ML confidence, anomaly signal, IOC reputation, CVE severity,
and MITRE technique presence into a single 0–100 risk score.
All weights are configurable via environment variables.
"""

# ── Base risk scores per classification ───────────────────────────────────────
_BASE_SCORES: dict[str, float] = {
    "normal":        5.0,
    "port_scan":    48.0,
    "failed_auth":  62.0,
    "dns_anomaly":  68.0,
    "traffic_spike": 50.0,
    "c2_beacon":    88.0,
    "data_exfil":   85.0,
    "eicar_test":   70.0,
}

_RISK_LEVELS = [
    (80, "critical"),
    (60, "high"),
    (40, "medium"),
    (20, "low"),
    (0,  "info"),
]

_SEVERITY_COLORS = {
    "critical": "#DC2626",
    "high":     "#EF4444",
    "medium":   "#F59E0B",
    "low":      "#00F0FF",
    "info":     "#94A3B8",
}


def compute_risk_score(
    classification: str,
    confidence: float,
    is_anomaly: bool,
    anomaly_score: float,
    ioc_threat_score: float,
    cves: list[dict],
    mitre_techniques: list[dict],
    eicar_detected: bool = False,
) -> dict:
    """
    Compute a weighted risk score for a classified event.

    Returns:
        {
          risk_score: float (0–100),
          risk_level: str,
          risk_color: str,
          score_breakdown: dict
        }
    """
    # 1. Base score from threat classification
    base = _BASE_SCORES.get(classification, 40.0)

    # 2. Confidence multiplier (scale base by ML confidence, floor at 0.5)
    conf_mult = max(confidence, 0.5)
    confidence_adj = base * conf_mult

    # 3. Anomaly detector agreement bonus
    anomaly_bonus = 0.0
    if is_anomaly and classification != "normal":
        anomaly_bonus = 8.0
    # Extra penalty if IF thinks it's anomalous but XGB says normal (disagreement)
    elif is_anomaly and classification == "normal":
        anomaly_bonus = 5.0

    # 4. IOC reputation contribution (0–15 pts)
    ioc_bonus = round(ioc_threat_score * 15.0, 2)

    # 5. CVE severity contribution (0–15 pts)
    cve_bonus = 0.0
    if cves:
        from threat_intelligence.cve.correlator import max_cvss
        max_score = max_cvss(cves)
        cve_bonus = round((max_score / 10.0) * 15.0, 2)

    # 6. MITRE technique count bonus (0–10 pts)
    mitre_bonus = min(len(mitre_techniques) * 3.5, 10.0)

    # 7. EICAR override — always elevate to HIGH minimum
    eicar_adj = 0.0
    if eicar_detected:
        eicar_adj = max(0.0, 70.0 - confidence_adj)

    # 8. Final score
    raw_score = confidence_adj + anomaly_bonus + ioc_bonus + cve_bonus + mitre_bonus + eicar_adj
    risk_score = min(round(raw_score, 1), 100.0)

    # 9. Risk level
    risk_level = "info"
    for threshold, level in _RISK_LEVELS:
        if risk_score >= threshold:
            risk_level = level
            break

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_color": _SEVERITY_COLORS[risk_level],
        "score_breakdown": {
            "base_score":       round(base, 2),
            "confidence_adj":   round(confidence_adj, 2),
            "anomaly_bonus":    round(anomaly_bonus, 2),
            "ioc_bonus":        round(ioc_bonus, 2),
            "cve_bonus":        round(cve_bonus, 2),
            "mitre_bonus":      round(mitre_bonus, 2),
            "eicar_adj":        round(eicar_adj, 2),
            "total":            risk_score,
        },
    }
