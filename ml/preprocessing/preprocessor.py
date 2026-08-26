"""
Feature Engineering & Preprocessing Pipeline
Transforms raw network event dicts into ML-ready feature vectors.
All functions are pure (stateless) — safe to call from inference or training.
"""
import math
import numpy as np
import pandas as pd
from typing import Optional

# ── Feature Columns (canonical order) ─────────────────────────────────────────
# These are the exact columns the models expect — order matters for joblib arrays.
FEATURE_COLUMNS = [
    "byte_count_log",
    "packet_count_log",
    "duration_ms_log",
    "bytes_per_packet",
    "bytes_per_ms",
    "packets_per_ms",
    "unique_dst_ports_log",
    "failed_attempts_log",
    "dns_query_length",
    "dns_subdomain_count",
    "dns_entropy",
    "connection_interval_std_log",
    "bytes_out_ratio",
    "is_external_dst",
    "proto_TCP",
    "proto_UDP",
    "proto_DNS",
    "proto_HTTP",
    "proto_HTTPS",
    "proto_SMTP",
    "proto_FTP",
    "proto_ICMP",
    "proto_OTHER",
    "dst_port_22",
    "dst_port_53",
    "dst_port_80",
    "dst_port_443",
    "dst_port_3389",
    "dst_port_other",
    "has_payload",
    "payload_entropy",
]

LABEL_COLUMNS = [
    "normal", "port_scan", "failed_auth", "dns_anomaly",
    "traffic_spike", "c2_beacon", "data_exfil", "eicar_test",
]

LABEL_TO_INT = {label: i for i, label in enumerate(LABEL_COLUMNS)}
INT_TO_LABEL = {i: label for label, i in LABEL_TO_INT.items()}


def _safe_log(x: float, base: float = 10.0, floor: float = 1e-6) -> float:
    """Log-transform with floor to avoid log(0)."""
    return math.log10(max(x, floor)) if base == 10.0 else math.log(max(x, floor))


def _entropy(s: str) -> float:
    """Shannon entropy — used for payload / DNS query analysis."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _proto_flags(protocol: str) -> dict[str, int]:
    """One-hot encode protocol."""
    proto = (protocol or "OTHER").upper()
    valid = {"TCP", "UDP", "DNS", "HTTP", "HTTPS", "SMTP", "FTP", "ICMP"}
    return {
        "proto_TCP":   int(proto == "TCP"),
        "proto_UDP":   int(proto == "UDP"),
        "proto_DNS":   int(proto == "DNS"),
        "proto_HTTP":  int(proto == "HTTP"),
        "proto_HTTPS": int(proto == "HTTPS"),
        "proto_SMTP":  int(proto == "SMTP"),
        "proto_FTP":   int(proto == "FTP"),
        "proto_ICMP":  int(proto == "ICMP"),
        "proto_OTHER": int(proto not in valid),
    }


def _port_flags(dst_port: int) -> dict[str, int]:
    """Flag notable destination ports."""
    known = {22, 53, 80, 443, 3389}
    return {
        "dst_port_22":    int(dst_port == 22),
        "dst_port_53":    int(dst_port == 53),
        "dst_port_80":    int(dst_port == 80),
        "dst_port_443":   int(dst_port == 443),
        "dst_port_3389":  int(dst_port == 3389),
        "dst_port_other": int(dst_port not in known),
    }


def extract_features(event: dict) -> dict:
    """
    Extract ML features from a single raw network event dict.
    Returns a flat dict keyed by FEATURE_COLUMNS.
    """
    byte_count       = max(float(event.get("byte_count", 1)), 1)
    packet_count     = max(float(event.get("packet_count", 1)), 1)
    duration_ms      = max(float(event.get("duration_ms", 1)), 1)
    unique_dst_ports = max(float(event.get("unique_dst_ports", 1)), 1)
    failed_attempts  = max(float(event.get("failed_attempts", 0)), 0)
    conn_std         = max(float(event.get("connection_interval_std", 0)), 0)

    bytes_per_packet = byte_count / packet_count
    bytes_per_ms     = byte_count / duration_ms
    packets_per_ms   = packet_count / duration_ms

    payload = event.get("payload_snippet") or ""
    has_payload = int(bool(payload))
    payload_entropy = _entropy(payload) if payload else 0.0

    features: dict = {
        "byte_count_log":            _safe_log(byte_count),
        "packet_count_log":          _safe_log(packet_count),
        "duration_ms_log":           _safe_log(duration_ms),
        "bytes_per_packet":          bytes_per_packet,
        "bytes_per_ms":              bytes_per_ms,
        "packets_per_ms":            packets_per_ms,
        "unique_dst_ports_log":      _safe_log(unique_dst_ports),
        "failed_attempts_log":       _safe_log(failed_attempts + 1),
        "dns_query_length":          float(event.get("dns_query_length", 0)),
        "dns_subdomain_count":       float(event.get("dns_subdomain_count", 0)),
        "dns_entropy":               float(event.get("dns_entropy", 0.0)),
        "connection_interval_std_log": _safe_log(conn_std + 1),
        "bytes_out_ratio":           float(event.get("bytes_out_ratio", 0.5)),
        "is_external_dst":           float(event.get("is_external_dst", 0)),
        "has_payload":               float(has_payload),
        "payload_entropy":           payload_entropy,
    }
    features.update(_proto_flags(event.get("protocol", "")))
    features.update(_port_flags(int(event.get("dst_port", 0))))

    # Ensure canonical column order
    return {col: features.get(col, 0.0) for col in FEATURE_COLUMNS}


def events_to_dataframe(events: list[dict]) -> pd.DataFrame:
    """Convert a list of raw events to a feature DataFrame (no label)."""
    rows = [extract_features(e) for e in events]
    return pd.DataFrame(rows, columns=FEATURE_COLUMNS)


def events_to_xy(events: list[dict]) -> tuple[pd.DataFrame, pd.Series]:
    """
    Convert labelled events to (X_features, y_labels) for supervised training.
    Events without a 'label' field are skipped.
    """
    labelled = [e for e in events if e.get("label") in LABEL_TO_INT]
    X = events_to_dataframe(labelled)
    y = pd.Series([LABEL_TO_INT[e["label"]] for e in labelled], name="label")
    return X, y


def preprocess_event(event: dict) -> np.ndarray:
    """
    Full preprocessing pipeline for a single event at inference time.
    Returns a (1, n_features) numpy array ready for model.predict().
    """
    features = extract_features(event)
    return np.array([[features[col] for col in FEATURE_COLUMNS]], dtype=np.float32)


def get_feature_names() -> list[str]:
    """Return the canonical feature column list."""
    return list(FEATURE_COLUMNS)


def get_label_names() -> list[str]:
    """Return the canonical label list (index == class integer)."""
    return list(LABEL_COLUMNS)
