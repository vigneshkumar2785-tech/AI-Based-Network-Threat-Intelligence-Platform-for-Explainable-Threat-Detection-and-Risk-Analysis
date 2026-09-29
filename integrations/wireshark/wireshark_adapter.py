"""
Wireshark Packet Integration Adapter
AI Network Threat Intelligence Platform

Converts Wireshark packet captures (CSV/JSON exports) or raw PCAP summaries
into normalized feature dictionaries compatible with the backend ML pipeline.
"""
import sys
import os
import json
import csv
import math
import uuid
import urllib.request
import urllib.error
from datetime import datetime, timezone

# Target Backend Ingestion Endpoint
DEFAULT_API_URL = "http://localhost:8000/api/v1/events/ingest"


def safe_entropy(s: str) -> float:
    """Calculate Shannon entropy for DNS queries or payload snippets."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def parse_wireshark_csv(filepath: str) -> list[dict]:
    """
    Parses Wireshark exported CSV (File -> Export Packet Dissections -> As CSV).
    Expected typical headers: "No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"
    """
    events = []
    if not os.path.exists(filepath):
        print(f"[!] Warning: File '{filepath}' not found.")
        return events

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            packets = list(reader)

        if not packets:
            print("[!] CSV file is empty.")
            return events

        # Aggregate packets by flow (src_ip, dst_ip, protocol)
        flows = {}
        for pkt in packets:
            src_ip = pkt.get("Source") or pkt.get("ip.src") or "192.168.1.100"
            dst_ip = pkt.get("Destination") or pkt.get("ip.dst") or "10.0.0.1"
            protocol = (pkt.get("Protocol") or pkt.get("_ws.col.Protocol") or "TCP").upper()
            try:
                length = int(pkt.get("Length") or pkt.get("frame.len") or 64)
            except ValueError:
                length = 64

            info = pkt.get("Info") or ""
            key = (src_ip, dst_ip, protocol)

            if key not in flows:
                flows[key] = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "byte_count": 0,
                    "packet_count": 0,
                    "info_samples": [],
                }
            flows[key]["byte_count"] += length
            flows[key]["packet_count"] += 1
            if info and len(flows[key]["info_samples"]) < 5:
                flows[key]["info_samples"].append(info)

        # Build normalized events
        for (src_ip, dst_ip, protocol), data in flows.items():
            info_str = " ".join(data["info_samples"])
            dst_port = 80
            if "443" in info_str or protocol == "HTTPS":
                dst_port = 443
            elif "22" in info_str or protocol == "SSH":
                dst_port = 22
            elif "53" in info_str or protocol == "DNS":
                dst_port = 53
            elif "21" in info_str or protocol == "FTP":
                dst_port = 21

            dns_query = ""
            if protocol == "DNS" or dst_port == 53:
                for sample in data["info_samples"]:
                    if "Standard query" in sample:
                        parts = sample.split(" ")
                        if len(parts) > 4:
                            dns_query = parts[4]

            event = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": 49152,
                "dst_port": dst_port,
                "protocol": protocol,
                "byte_count": data["byte_count"],
                "packet_count": data["packet_count"],
                "duration_ms": max(data["packet_count"] * 15, 10),
                "unique_dst_ports": 1,
                "failed_attempts": 0,
                "dns_query": dns_query,
                "dns_query_length": len(dns_query),
                "dns_subdomain_count": dns_query.count(".") if dns_query else 0,
                "dns_entropy": safe_entropy(dns_query),
                "connection_interval_std": 50.0,
                "bytes_out_ratio": 0.8,
                "is_external_dst": 1 if not dst_ip.startswith(("10.", "192.168.", "172.16.")) else 0,
                "payload_snippet": info_str[:200] if info_str else None,
                "event_type": "wireshark_capture",
            }
            events.append(event)
    except Exception as e:
        print(f"[!] Error parsing Wireshark CSV: {e}")

    return events


def create_sample_wireshark_packet() -> dict:
    """Generates a sample normalized Wireshark packet for quick demonstration."""
    return {
        "src_ip": "192.168.1.105",
        "dst_ip": "185.220.101.45",
        "src_port": 52140,
        "dst_port": 4444,
        "protocol": "TCP",
        "byte_count": 1450,
        "packet_count": 8,
        "duration_ms": 120,
        "unique_dst_ports": 1,
        "failed_attempts": 0,
        "dns_query": "",
        "dns_query_length": 0,
        "dns_subdomain_count": 0,
        "dns_entropy": 0.0,
        "connection_interval_std": 12.5,
        "bytes_out_ratio": 0.85,
        "is_external_dst": 1,
        "payload_snippet": "Wireshark Captured Traffic: C2 Beacon Handshake",
        "event_type": "wireshark_ingest"
    }

def send_to_backend(
    event: dict,
    api_url: str = DEFAULT_API_URL,
    timeout: int = 60,
    retries: int = 3
) -> dict:
    """POST a normalized event to FastAPI with timeout and retry handling."""

    headers = {"Content-Type": "application/json"}
    data = json.dumps(event).encode("utf-8")

    for attempt in range(1, retries + 1):
        req = urllib.request.Request(
            api_url,
            data=data,
            headers=headers,
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                res_body = response.read().decode("utf-8")
                return json.loads(res_body)

        except TimeoutError:
            print(
                f"    [!] Request timed out "
                f"(attempt {attempt}/{retries}, timeout={timeout}s)"
            )

        except urllib.error.URLError as err:
            print(
                f"    [!] API connection error "
                f"(attempt {attempt}/{retries}): {err}"
            )

        except Exception as err:
            print(
                f"    [!] Unexpected API error "
                f"(attempt {attempt}/{retries}): {err}"
            )

        if attempt < retries:
            import time
            print("    [*] Retrying in 5 seconds...")
            time.sleep(5)

    return {
        "status": "failed",
        "message": "Event could not be processed after all retry attempts.",
        "event": event
    }
def main():
    print("=========================================================")
    print("   Aegis Threat Intelligence - Wireshark Integration    ")
    print("=========================================================\n")

    input_file = sys.argv[1] if len(sys.argv) > 1 else None

    if input_file and os.path.exists(input_file):
        print(f"[*] Processing Wireshark capture file: {input_file}")
        events = parse_wireshark_csv(input_file)
    else:
        print("[*] No input file specified or file not found.")
        print("[*] Generating sample Wireshark captured network packet for demonstration...")
        events = [create_sample_wireshark_packet()]

    print(f"[*] Successfully normalized {len(events)} event(s).\n")

    for i, evt in enumerate(events, 1):
        print(f"--- Event #{i} ---")
        print(f"    Source IP      : {evt['src_ip']}")
        print(f"    Destination IP : {evt['dst_ip']}:{evt['dst_port']}")
        print(f"    Protocol       : {evt['protocol']}")
        print(f"    Traffic Volume : {evt['byte_count']} bytes ({evt['packet_count']} packets)")
        print("[*] Transmitting to FastAPI Threat Intelligence Ingestion API...")

        res = send_to_backend(evt)
        if "classification" in res:
            print(f"    [+] Pipeline Result : {res['classification'].upper()}")
            print(f"    [+] Anomaly Status  : {'ANOMALY DETECTED' if res['is_anomaly'] else 'NORMAL'}")
            print(f"    [+] Risk Score      : {res['risk_score']}/100 ({res['risk_level'].upper()})")
            print(f"    [+] Incident ID     : {res.get('incident', {}).get('incident_id', 'N/A')}")
        else:
            print(f"    [!] Result: {res.get('message', 'Processed')}")
        print()

    print("[+] Wireshark Adapter execution complete.")


if __name__ == "__main__":
    main()
