"""
MITRE ATT&CK Evidence-Gated Mapper
Maps network events to ATT&CK techniques only when real evidence exists.
Never maps speculatively — requires concrete field thresholds to be met.
"""
import json
import os
from typing import Any

_CATALOG_PATH = os.path.join(os.path.dirname(__file__), "mitre_catalog.json")
_catalog: dict | None = None


def _load_catalog() -> dict:
    global _catalog
    if _catalog is None:
        with open(_CATALOG_PATH) as f:
            _catalog = json.load(f)
    return _catalog


def _check_evidence(rule: dict, event: dict, features: dict) -> tuple[bool, list[str]]:
    """
    Evaluate all evidence_fields rules against the raw event + extracted features.
    Returns (passes, list_of_evidence_strings).
    """
    evidence_notes: list[str] = []
    for field, constraint in rule.items():
        op = constraint["operator"]
        threshold = constraint["threshold"] if "threshold" in constraint else None
        values = constraint.get("values")

        # Resolve field value from event (raw fields take priority, then features)
        raw_val = event.get(field)
        feat_val = features.get(field)
        val = raw_val if raw_val is not None else feat_val
        if val is None:
            return False, []

        try:
            val = float(val)
        except (TypeError, ValueError):
            # String comparison for "in" operator
            pass

        if op == "gte":
            if not (isinstance(val, (int, float)) and val >= threshold):
                return False, []
            evidence_notes.append(f"{field}={val:.2f} >= {threshold}")

        elif op == "lte":
            if not (isinstance(val, (int, float)) and val <= threshold):
                return False, []
            evidence_notes.append(f"{field}={val:.2f} <= {threshold}")

        elif op == "eq":
            if not (isinstance(val, (int, float)) and val == threshold):
                return False, []
            evidence_notes.append(f"{field}={val}")

        elif op == "in":
            # values is a list; match raw string or numeric
            raw_str = event.get(field, "")
            raw_num = event.get(field)
            matched = (str(raw_str).upper() in [str(v).upper() for v in values] or
                       raw_num in values)
            if not matched:
                return False, []
            evidence_notes.append(f"{field} in {values}")

    return True, evidence_notes


def map_techniques(event: dict, classification: str, features: dict | None = None) -> list[dict]:
    """
    Evidence-gated MITRE ATT&CK technique mapping.

    Args:
        event:          Raw network event dict.
        classification: Predicted threat label from XGBoost.
        features:       Extracted feature dict (from preprocessor). Optional.

    Returns:
        List of matched technique dicts, each with evidence trail.
        Empty list if no techniques can be evidenced — never speculates.
    """
    catalog = _load_catalog()
    features = features or {}
    matched: list[dict] = []

    for technique_id, tech in catalog["techniques"].items():
        # Fast pre-filter: only consider techniques hinted for this classification
        hints: list[str] = tech.get("event_type_hints", [])
        if classification not in hints and "normal" == classification:
            continue
        # If classification is normal, skip all attack techniques
        if classification == "normal":
            continue

        passes, evidence_notes = _check_evidence(
            tech.get("evidence_fields", {}), event, features
        )
        if passes:
            matched.append({
                "technique_id":  technique_id,
                "technique_name": tech["name"],
                "tactic":        tech["tactic"],
                "tactic_id":     tech["tactic_id"],
                "evidence":      evidence_notes,
                "detection_note": tech["detection_note"],
                "platforms":     tech["platforms"],
            })

    return matched
