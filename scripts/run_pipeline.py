"""
End-to-End Pipeline CLI Test
Usage:
  python scripts/run_pipeline.py
  python scripts/run_pipeline.py --event-type port_scan
  python scripts/run_pipeline.py --event-type eicar_test
  python scripts/run_pipeline.py --all-types

Tests the full path: raw event → preprocess → anomaly detect → classify → print result
"""
import sys
import os
import json
import argparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from simulation.network_events.generator import (
    generate_event, GENERATORS, LABEL_DESCRIPTIONS
)
from ml.preprocessing.preprocessor import extract_features, FEATURE_COLUMNS
from backend.app.ml.predictor import predict


SEVERITY_MAP = {
    "normal":       "INFO",
    "port_scan":    "MEDIUM",
    "failed_auth":  "HIGH",
    "dns_anomaly":  "HIGH",
    "traffic_spike":"MEDIUM",
    "c2_beacon":    "CRITICAL",
    "data_exfil":   "CRITICAL",
    "eicar_test":   "HIGH",
}

SEVERITY_COLORS = {
    "INFO":     "\033[36m",      # cyan
    "MEDIUM":   "\033[33m",      # amber
    "HIGH":     "\033[31m",      # red
    "CRITICAL": "\033[1;31m",    # bold red
}
RESET = "\033[0m"


def run_single(event_type: str, verbose: bool = False):
    print(f"\n{'─'*62}")
    print(f"  EVENT TYPE   : {event_type.upper()}")
    print(f"  DESCRIPTION  : {LABEL_DESCRIPTIONS.get(event_type, 'Unknown')}")
    print(f"{'─'*62}")

    # Step 1 — Generate
    event = generate_event(event_type)
    print(f"  [1] Event generated  → ID: {event['event_id'][:16]}…")
    print(f"       src_ip={event['src_ip']}  dst_ip={event['dst_ip']}")
    print(f"       protocol={event['protocol']}  dst_port={event['dst_port']}")
    print(f"       bytes={event['byte_count']:,}  packets={event['packet_count']:,}")

    # Step 2 — Preprocess
    features = extract_features(event)
    print(f"  [2] Preprocessing    → {len(features)} features extracted")
    if verbose:
        for k, v in features.items():
            if v != 0.0:
                print(f"       {k:38s} = {v:.4f}")

    # Step 3 — Predict
    result = predict(event)
    severity = SEVERITY_MAP.get(result["classification"], "MEDIUM")
    color    = SEVERITY_COLORS.get(severity, "")

    print(f"\n  [3] Anomaly Detection → {'⚠ ANOMALY' if result['is_anomaly'] else '✓ NORMAL'}")
    print(f"       IF score = {result['anomaly_score']:.4f} (lower = more anomalous)")
    print(f"\n  [4] Classification   → {color}{result['classification'].upper()}{RESET}")
    print(f"       Confidence = {result['confidence'] * 100:.1f}%")
    print(f"       Severity   = {color}{severity}{RESET}")

    if result["eicar_detected"]:
        print(f"\n  [!] EICAR TEST STRING DETECTED (inert text — not executed)")

    print(f"\n  Top threat probabilities:")
    sorted_probs = sorted(result["all_probabilities"].items(), key=lambda x: -x[1])
    for label, prob in sorted_probs[:4]:
        bar = "█" * int(prob * 30)
        print(f"       {label:20s} {bar:<30s} {prob*100:5.1f}%")

    # Verify ground truth
    true_label = event.get("label", "unknown")
    match = "✓" if true_label == result["classification"] else "✗"
    print(f"\n  Ground Truth: {true_label} | Predicted: {result['classification']} {match}")
    print(f"{'─'*62}")
    return result


def main():
    parser = argparse.ArgumentParser(description="AI Threat Intelligence Pipeline CLI Test")
    parser.add_argument("--event-type", default="port_scan",
                        choices=list(GENERATORS.keys()),
                        help="Event type to test")
    parser.add_argument("--all-types", action="store_true",
                        help="Run one event of every type")
    parser.add_argument("--verbose", action="store_true",
                        help="Print all non-zero features")
    args = parser.parse_args()

    print("\n" + "═"*62)
    print("  AI NETWORK THREAT INTELLIGENCE — END-TO-END PIPELINE TEST")
    print("═"*62)

    types_to_test = list(GENERATORS.keys()) if args.all_types else [args.event_type]
    results = []

    for etype in types_to_test:
        r = run_single(etype, verbose=args.verbose)
        results.append((etype, r))

    if args.all_types:
        print("\n" + "═"*62)
        print("  SUMMARY — ALL TYPES")
        print("═"*62)
        correct = sum(1 for et, r in results if r["classification"] == et)
        print(f"  Accuracy: {correct}/{len(results)} ({correct/len(results)*100:.0f}%)")
        for etype, r in results:
            match = "✓" if r["classification"] == etype else "✗"
            print(f"  {match} {etype:20s} → {r['classification']:20s} ({r['confidence']*100:.1f}%)")

    print("\n✓ Block B pipeline test complete.\n")


if __name__ == "__main__":
    main()
