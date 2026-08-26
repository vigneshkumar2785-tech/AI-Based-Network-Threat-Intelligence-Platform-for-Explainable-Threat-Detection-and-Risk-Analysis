"""
Block C End-to-End Pipeline CLI Test
Tests the full correlation pipeline:
  Event → ML → IOC → MITRE → CVE → Risk → XAI → Incident

Usage:
  python scripts/run_pipeline_c.py
  python scripts/run_pipeline_c.py --event-type c2_beacon
  python scripts/run_pipeline_c.py --event-type eicar_test --verbose
  python scripts/run_pipeline_c.py --all-types
"""
import sys
import os
import argparse
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from simulation.network_events.generator import generate_event, GENERATORS, LABEL_DESCRIPTIONS
from backend.app.services.correlator import process_event

SEVERITY_COLORS = {
    "info":     "\033[36m",
    "low":      "\033[96m",
    "medium":   "\033[33m",
    "high":     "\033[31m",
    "critical": "\033[1;31m",
}
RESET = "\033[0m"
CYAN  = "\033[36m"
GREEN = "\033[32m"
BOLD  = "\033[1m"


def fmt_severity(level: str) -> str:
    color = SEVERITY_COLORS.get(level, "")
    return f"{color}{level.upper()}{RESET}"


def print_result(result: dict, verbose: bool = False):
    cls  = result["classification"]
    risk = result["risk_score"]
    lvl  = result["risk_level"]
    inc  = result["incident"]

    print(f"\n{'='*64}")
    print(f"  {BOLD}INTELLIGENCE PIPELINE RESULT{RESET}")
    print(f"{'='*64}")

    # ── Identity ─────────────────────────────────────────────────────────────
    print(f"\n  {CYAN}[IDENTITY]{RESET}")
    print(f"    Event ID     : {result['event_id'][:16]}...")
    print(f"    Event Type   : {result['event_type'].upper()}")
    print(f"    Source IP    : {result['src_ip']}")
    print(f"    Destination  : {result['dst_ip']}:{result['dst_port']}")
    print(f"    Protocol     : {result['protocol']}")
    print(f"    Bytes        : {result['byte_count']:,}  Packets: {result['packet_count']:,}")

    # ── ML Prediction ────────────────────────────────────────────────────────
    print(f"\n  {CYAN}[ML DETECTION]{RESET}")
    print(f"    Anomaly      : {'YES' if result['is_anomaly'] else 'NO'} (IF score={result['anomaly_score']:.4f})")
    print(f"    Classification: {BOLD}{cls.upper()}{RESET} ({result['confidence']*100:.1f}% confidence)")
    if result["eicar_detected"]:
        print(f"    [!] EICAR TEST STRING DETECTED (inert text — not executed)")

    # ── IOCs ─────────────────────────────────────────────────────────────────
    print(f"\n  {CYAN}[IOCs — {len(result['iocs'])} found]{RESET}")
    for ioc in result["iocs"][:5]:
        rep_color = "\033[31m" if ioc["reputation"] in ("malicious", "suspicious", "test_artifact") else ""
        print(f"    {ioc['type']:15s} {rep_color}{ioc['value'][:40]}{RESET}  rep={ioc['reputation']}  score={ioc['score']:.2f}")
    if len(result["iocs"]) > 5:
        print(f"    ... and {len(result['iocs'])-5} more")

    # ── MITRE ATT&CK ─────────────────────────────────────────────────────────
    print(f"\n  {CYAN}[MITRE ATT&CK — {len(result['mitre_techniques'])} technique(s)]{RESET}")
    for tech in result["mitre_techniques"]:
        print(f"    {tech['technique_id']:12s} {tech['technique_name']}")
        print(f"                 Tactic: {tech['tactic']}")
        if verbose:
            print(f"                 Evidence: {', '.join(tech['evidence'])}")
            print(f"                 Note: {tech['detection_note']}")

    # ── CVEs ─────────────────────────────────────────────────────────────────
    print(f"\n  {CYAN}[CVEs — {len(result['cves'])} matched]{RESET}")
    for cve in result["cves"][:3]:
        sev_color = "\033[31m" if cve["cvss_v3"] >= 9.0 else "\033[33m" if cve["cvss_v3"] >= 7.0 else ""
        print(f"    {cve['cve_id']:20s} CVSS={sev_color}{cve['cvss_v3']:.1f}{RESET}  {cve['service']}")
        if verbose:
            print(f"                       {cve['description'][:70]}...")

    # ── Risk Score ───────────────────────────────────────────────────────────
    print(f"\n  {CYAN}[RISK SCORE]{RESET}")
    bar_len = int(risk / 2)
    bar = "\033[31m" + "█" * bar_len + RESET + "░" * (50 - bar_len)
    print(f"    Score : {BOLD}{risk:.1f}/100{RESET}  [{bar}]")
    print(f"    Level : {fmt_severity(lvl)}")
    if verbose:
        bd = result["score_breakdown"]
        print(f"    Breakdown: base={bd['base_score']} conf={bd['confidence_adj']:.1f} "
              f"anomaly={bd['anomaly_bonus']} ioc={bd['ioc_bonus']:.1f} "
              f"cve={bd['cve_bonus']:.1f} mitre={bd['mitre_bonus']:.1f}")

    # ── XAI ──────────────────────────────────────────────────────────────────
    xai = result.get("xai", {})
    print(f"\n  {CYAN}[XAI EXPLANATION]{RESET}")
    print(f"    {xai.get('natural_language_explanation','N/A')}")
    print(f"\n    Top SHAP Features:")
    for feat in xai.get("shap_features", [])[:5]:
        direction = "+" if feat["direction"] == "positive" else "-"
        bar_len   = int(feat["abs_impact"] * 300)
        bar       = GREEN + "█" * min(bar_len, 25) + RESET
        print(f"      {direction}  {feat['feature']:38s} {bar} {feat['shap_value']:+.4f}")

    # ── Incident ─────────────────────────────────────────────────────────────
    print(f"\n  {CYAN}[INCIDENT]{RESET}")
    print(f"    ID        : {inc['incident_id']}")
    print(f"    State     : {inc['state'].upper()}")
    print(f"    Severity  : {fmt_severity(inc['severity'])}")
    print(f"    Actions   : {len(inc['recommended_actions'])} recommended")
    for action in inc["recommended_actions"][:3]:
        print(f"      [{action['priority']}] {action['action']:25s} {action['description']}")

    print(f"\n{'='*64}")


def run_single(event_type: str, verbose: bool = False) -> dict:
    print(f"\nGenerating {event_type} event and running full intelligence pipeline...")
    event  = generate_event(event_type)
    result = process_event(event, include_xai=True)
    print_result(result, verbose=verbose)
    return result


def main():
    parser = argparse.ArgumentParser(description="Block C — Intelligence Pipeline Test")
    parser.add_argument("--event-type", default="c2_beacon",
                        choices=list(GENERATORS.keys()))
    parser.add_argument("--all-types", action="store_true")
    parser.add_argument("--verbose",   action="store_true")
    args = parser.parse_args()

    print(f"\n{BOLD}AI NETWORK THREAT INTELLIGENCE — BLOCK C PIPELINE TEST{RESET}")
    print("=" * 64)

    types_to_test = list(GENERATORS.keys()) if args.all_types else [args.event_type]
    results = []

    for etype in types_to_test:
        r = run_single(etype, verbose=args.verbose)
        results.append((etype, r))

    if args.all_types:
        print(f"\n{BOLD}SUMMARY — ALL {len(results)} TYPES{RESET}")
        print("=" * 64)
        for etype, r in results:
            print(f"  {r['risk_level']:8s}  {r['risk_score']:5.1f}/100  "
                  f"{r['classification']:20s}  MITRE={len(r['mitre_techniques'])}  "
                  f"CVE={len(r['cves'])}  IOC={len(r['iocs'])}")

    print(f"\n{GREEN}Block C pipeline test complete.{RESET}\n")


if __name__ == "__main__":
    main()
