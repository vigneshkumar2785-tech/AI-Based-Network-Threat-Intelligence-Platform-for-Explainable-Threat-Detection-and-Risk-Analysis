"""
Synthetic Network Event Generator
Generates realistic behavioral network security events for training and simulation.
All events are SYNTHETIC - no real attack payloads or malicious code.
"""
import random
import uuid
import time
import math
from datetime import datetime, timezone, timedelta
from typing import Optional

# ── Constants ──────────────────────────────────────────────────────────────────
INTERNAL_SUBNETS = ["10.0.0", "10.0.1", "192.168.1", "172.16.0"]
EXTERNAL_IPS = [
    "185.220.101.45", "91.108.4.0", "195.123.226.12", "45.142.212.100",
    "103.235.46.39", "198.251.90.12", "77.83.247.50", "5.42.92.18",
    "194.165.16.5", "188.72.205.80", "23.83.133.80", "37.120.222.4",
]
BENIGN_EXTERNAL = [
    "8.8.8.8", "1.1.1.1", "208.67.222.222", "151.101.65.140",
    "93.184.216.34", "104.16.0.0", "172.217.14.206", "13.227.220.100",
]
PROTOCOLS = ["TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS", "SMTP", "FTP"]
COMMON_PORTS = [80, 443, 22, 21, 25, 53, 3389, 8080, 8443, 445, 139, 3306]
SCAN_PORT_RANGES = list(range(20, 1024)) + [3389, 5900, 8080, 8443, 27017, 6379]
DNS_LEGIT_DOMAINS = [
    "google.com", "microsoft.com", "amazon.com", "cloudflare.com",
    "github.com", "stackoverflow.com", "ubuntu.com", "pypi.org",
]
DNS_SUSPICIOUS_BASES = [
    "update-svc", "analytics-beacon", "cdn-edge", "api-v2",
    "telemetry-collector", "sync-service", "heartbeat-api",
]

EICAR_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def _rand_internal_ip() -> str:
    subnet = random.choice(INTERNAL_SUBNETS)
    return f"{subnet}.{random.randint(2, 254)}"


def _rand_external_ip(suspicious: bool = True) -> str:
    if suspicious:
        return random.choice(EXTERNAL_IPS)
    return random.choice(BENIGN_EXTERNAL)


def _rand_ts(hours_back: int = 72) -> str:
    delta = timedelta(seconds=random.randint(0, hours_back * 3600))
    ts = datetime.now(timezone.utc) - delta
    return ts.isoformat()


def _entropy(s: str) -> float:
    """Shannon entropy of a string (used for DNS query length analysis)."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


# ── Event Generators ───────────────────────────────────────────────────────────

def generate_normal_event(ts: Optional[str] = None) -> dict:
    """Routine HTTP/HTTPS or DNS traffic — benign baseline."""
    src_ip = _rand_internal_ip()
    dst_ip = _rand_external_ip(suspicious=False)
    proto = random.choice(["HTTP", "HTTPS", "DNS"])
    dst_port = 443 if proto == "HTTPS" else (80 if proto == "HTTP" else 53)
    byte_count = random.randint(200, 50_000)
    packet_count = random.randint(4, 200)
    duration_ms = random.randint(10, 2_000)

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": ts or _rand_ts(),
        "event_type": "normal",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(49152, 65535),
        "dst_port": dst_port,
        "protocol": proto,
        "byte_count": byte_count,
        "packet_count": packet_count,
        "duration_ms": duration_ms,
        "unique_dst_ports": 1,
        "failed_attempts": 0,
        "dns_query": random.choice(DNS_LEGIT_DOMAINS),
        "dns_query_length": len(random.choice(DNS_LEGIT_DOMAINS)),
        "dns_subdomain_count": 0,
        "dns_entropy": _entropy(random.choice(DNS_LEGIT_DOMAINS)),
        "connection_interval_std": random.uniform(100, 5000),
        "bytes_out_ratio": round(random.uniform(0.3, 0.7), 4),
        "is_external_dst": 1,
        "payload_snippet": None,
        "label": "normal",
    }


def generate_port_scan_event(ts: Optional[str] = None) -> dict:
    """One source IP scanning many destination ports — classic recon."""
    src_ip = _rand_external_ip(suspicious=True)
    dst_ip = _rand_internal_ip()
    num_ports = random.randint(50, 500)
    scanned_ports = random.sample(SCAN_PORT_RANGES, min(num_ports, len(SCAN_PORT_RANGES)))
    byte_count = num_ports * random.randint(40, 80)
    packet_count = num_ports * random.randint(1, 3)
    duration_ms = random.randint(500, 30_000)

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": ts or _rand_ts(),
        "event_type": "port_scan",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(1024, 65535),
        "dst_port": scanned_ports[0],
        "protocol": "TCP",
        "byte_count": byte_count,
        "packet_count": packet_count,
        "duration_ms": duration_ms,
        "unique_dst_ports": num_ports,
        "failed_attempts": 0,
        "dns_query": "",
        "dns_query_length": 0,
        "dns_subdomain_count": 0,
        "dns_entropy": 0.0,
        "connection_interval_std": random.uniform(0.5, 50),
        "bytes_out_ratio": round(random.uniform(0.7, 1.0), 4),
        "is_external_dst": 0,
        "payload_snippet": None,
        "label": "port_scan",
    }


def generate_failed_auth_event(ts: Optional[str] = None) -> dict:
    """Repeated failed login attempts — brute force credential attack."""
    src_ip = _rand_external_ip(suspicious=True)
    dst_ip = _rand_internal_ip()
    dst_port = random.choice([22, 3389, 21, 25, 110, 8080])
    attempts = random.randint(20, 500)
    byte_count = attempts * random.randint(200, 800)
    packet_count = attempts * random.randint(2, 6)
    duration_ms = random.randint(5_000, 600_000)

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": ts or _rand_ts(),
        "event_type": "failed_auth",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(1024, 65535),
        "dst_port": dst_port,
        "protocol": "TCP",
        "byte_count": byte_count,
        "packet_count": packet_count,
        "duration_ms": duration_ms,
        "unique_dst_ports": 1,
        "failed_attempts": attempts,
        "dns_query": "",
        "dns_query_length": 0,
        "dns_subdomain_count": 0,
        "dns_entropy": 0.0,
        "connection_interval_std": random.uniform(200, 2000),
        "bytes_out_ratio": round(random.uniform(0.4, 0.7), 4),
        "is_external_dst": 0,
        "payload_snippet": None,
        "label": "failed_auth",
    }


def generate_dns_anomaly_event(ts: Optional[str] = None) -> dict:
    """DNS tunneling or DGA — long subdomains, high entropy, unusual TLDs."""
    src_ip = _rand_internal_ip()
    dst_ip = "8.8.8.8"  # uses legit DNS resolver to avoid detection
    subdomain_parts = random.randint(4, 8)
    subdomain = ".".join(
        "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=random.randint(8, 16)))
        for _ in range(subdomain_parts)
    )
    base = random.choice(DNS_SUSPICIOUS_BASES) + ".xyz"
    query = f"{subdomain}.{base}"
    byte_count = random.randint(60, 3_000)
    packet_count = random.randint(2, 40)

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": ts or _rand_ts(),
        "event_type": "dns_anomaly",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(49152, 65535),
        "dst_port": 53,
        "protocol": "DNS",
        "byte_count": byte_count,
        "packet_count": packet_count,
        "duration_ms": random.randint(5, 500),
        "unique_dst_ports": 1,
        "failed_attempts": 0,
        "dns_query": query,
        "dns_query_length": len(query),
        "dns_subdomain_count": subdomain_parts,
        "dns_entropy": _entropy(query),
        "connection_interval_std": random.uniform(0, 10),
        "bytes_out_ratio": round(random.uniform(0.5, 0.9), 4),
        "is_external_dst": 1,
        "payload_snippet": None,
        "label": "dns_anomaly",
    }


def generate_traffic_spike_event(ts: Optional[str] = None) -> dict:
    """Sudden large data transfer — possible exfil staging or DDoS."""
    src_ip = _rand_internal_ip()
    dst_ip = _rand_external_ip(suspicious=random.choice([True, False]))
    byte_count = random.randint(500_000_000, 5_000_000_000)  # 500MB–5GB
    packet_count = random.randint(300_000, 3_000_000)
    duration_ms = random.randint(10_000, 600_000)

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": ts or _rand_ts(),
        "event_type": "traffic_spike",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(49152, 65535),
        "dst_port": random.choice([80, 443, 8080, 21]),
        "protocol": random.choice(["TCP", "HTTP", "HTTPS"]),
        "byte_count": byte_count,
        "packet_count": packet_count,
        "duration_ms": duration_ms,
        "unique_dst_ports": random.randint(1, 5),
        "failed_attempts": 0,
        "dns_query": "",
        "dns_query_length": 0,
        "dns_subdomain_count": 0,
        "dns_entropy": 0.0,
        "connection_interval_std": random.uniform(10, 1000),
        "bytes_out_ratio": round(random.uniform(0.8, 1.0), 4),
        "is_external_dst": 1,
        "payload_snippet": None,
        "label": "traffic_spike",
    }


def generate_c2_beacon_event(ts: Optional[str] = None) -> dict:
    """Simulated C2 beacon — periodic low-byte connections to suspicious external IP."""
    src_ip = _rand_internal_ip()
    dst_ip = _rand_external_ip(suspicious=True)
    # Beacons are highly regular (low interval std-dev)
    beacon_interval_ms = random.choice([30_000, 60_000, 120_000, 300_000])
    jitter = beacon_interval_ms * random.uniform(0.02, 0.10)
    byte_count = random.randint(64, 1_500)
    packet_count = random.randint(2, 8)

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": ts or _rand_ts(),
        "event_type": "c2_beacon",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(49152, 65535),
        "dst_port": random.choice([443, 80, 8080, 8443, 4444, 1337]),
        "protocol": random.choice(["HTTPS", "HTTP", "TCP"]),
        "byte_count": byte_count,
        "packet_count": packet_count,
        "duration_ms": random.randint(50, 2_000),
        "unique_dst_ports": 1,
        "failed_attempts": 0,
        "dns_query": "",
        "dns_query_length": 0,
        "dns_subdomain_count": 0,
        "dns_entropy": 0.0,
        "connection_interval_std": round(jitter, 2),   # low = regular = suspicious
        "bytes_out_ratio": round(random.uniform(0.5, 0.95), 4),
        "is_external_dst": 1,
        "payload_snippet": None,
        "label": "c2_beacon",
    }


def generate_data_exfil_event(ts: Optional[str] = None) -> dict:
    """Simulated data exfiltration — internal→external large transfer, unusual hour."""
    src_ip = _rand_internal_ip()
    dst_ip = _rand_external_ip(suspicious=True)
    byte_count = random.randint(10_000_000, 500_000_000)  # 10MB–500MB
    packet_count = random.randint(5_000, 500_000)
    duration_ms = random.randint(5_000, 300_000)

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": ts or _rand_ts(),
        "event_type": "data_exfil",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(49152, 65535),
        "dst_port": random.choice([443, 21, 22, 25, 993]),
        "protocol": random.choice(["HTTPS", "FTP", "SMTP"]),
        "byte_count": byte_count,
        "packet_count": packet_count,
        "duration_ms": duration_ms,
        "unique_dst_ports": random.randint(1, 3),
        "failed_attempts": 0,
        "dns_query": "",
        "dns_query_length": 0,
        "dns_subdomain_count": 0,
        "dns_entropy": 0.0,
        "connection_interval_std": random.uniform(500, 50_000),
        "bytes_out_ratio": round(random.uniform(0.85, 1.0), 4),
        "is_external_dst": 1,
        "payload_snippet": None,
        "label": "data_exfil",
    }


def generate_eicar_event(ts: Optional[str] = None) -> dict:
    """
    EICAR test string — treated as INERT TEXT DATA only.
    Simulates a file transfer event whose payload contains the standard EICAR test string.
    Never executed as a program.
    """
    src_ip = _rand_internal_ip()
    dst_ip = _rand_internal_ip()
    byte_count = len(EICAR_STRING) + random.randint(0, 200)

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": ts or _rand_ts(),
        "event_type": "eicar_test",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(49152, 65535),
        "dst_port": random.choice([21, 80, 445, 8080]),
        "protocol": random.choice(["FTP", "HTTP", "SMB"]),
        "byte_count": byte_count,
        "packet_count": random.randint(2, 10),
        "duration_ms": random.randint(10, 500),
        "unique_dst_ports": 1,
        "failed_attempts": 0,
        "dns_query": "",
        "dns_query_length": 0,
        "dns_subdomain_count": 0,
        "dns_entropy": _entropy(EICAR_STRING),
        "connection_interval_std": 0.0,
        "bytes_out_ratio": 1.0,
        "is_external_dst": 0,
        # EICAR string stored as plain text/data — NEVER executed
        "payload_snippet": EICAR_STRING,
        "label": "eicar_test",
    }


# ── EICAR Detection ────────────────────────────────────────────────────────────

def detect_eicar_in_event(event: dict) -> bool:
    """
    Check if an event's payload contains the EICAR test string (inert text check).
    Returns True if EICAR string is detected as text content only.
    """
    payload = event.get("payload_snippet") or ""
    return EICAR_STRING in payload


# ── Public API ────────────────────────────────────────────────────────────────

GENERATORS = {
    "normal": generate_normal_event,
    "port_scan": generate_port_scan_event,
    "failed_auth": generate_failed_auth_event,
    "dns_anomaly": generate_dns_anomaly_event,
    "traffic_spike": generate_traffic_spike_event,
    "c2_beacon": generate_c2_beacon_event,
    "data_exfil": generate_data_exfil_event,
    "eicar_test": generate_eicar_event,
}

LABEL_DESCRIPTIONS = {
    "normal": "Routine benign network traffic",
    "port_scan": "Port scan / network reconnaissance",
    "failed_auth": "Brute-force credential attack",
    "dns_anomaly": "DNS tunneling / DGA anomaly",
    "traffic_spike": "Abnormal traffic volume spike",
    "c2_beacon": "Simulated C2 beaconing behavior",
    "data_exfil": "Simulated data exfiltration",
    "eicar_test": "EICAR test string detected (inert text)",
}


def generate_event(event_type: str = "normal", ts: Optional[str] = None) -> dict:
    """Generate a single synthetic event of the given type."""
    generator = GENERATORS.get(event_type)
    if not generator:
        raise ValueError(f"Unknown event type '{event_type}'. Valid: {list(GENERATORS)}")
    return generator(ts=ts)


def generate_dataset(
    n_normal: int = 3000,
    n_per_attack: int = 400,
    seed: int = 42,
) -> list[dict]:
    """
    Generate a labelled synthetic dataset for ML training.
    Maintains class imbalance realistic of real SOC environments (~75% normal).
    """
    random.seed(seed)
    events = []
    # Normal traffic (majority class)
    for _ in range(n_normal):
        events.append(generate_normal_event())
    # Attack classes
    for etype in ["port_scan", "failed_auth", "dns_anomaly", "traffic_spike",
                   "c2_beacon", "data_exfil", "eicar_test"]:
        for _ in range(n_per_attack):
            events.append(generate_event(etype))
    # Shuffle
    random.shuffle(events)
    return events
