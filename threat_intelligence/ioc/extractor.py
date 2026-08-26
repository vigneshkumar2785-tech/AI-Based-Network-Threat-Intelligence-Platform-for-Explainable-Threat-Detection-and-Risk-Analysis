"""
IOC (Indicator of Compromise) Extraction Engine
Extracts and classifies IOCs from raw network events.
IOC types: ip, domain, hash, eicar_string
"""
import re
import hashlib
from typing import Optional

# ── Known threat IP lists (synthetic — replace with real threat feeds in production) ──
_MALICIOUS_IP_PREFIXES = [
    "185.220.", "91.108.", "195.123.", "45.142.", "103.235.",
    "198.251.", "77.83.", "5.42.", "194.165.", "188.72.",
    "23.83.", "37.120.",
]

_BENIGN_DNS_SERVERS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "208.67.222.222"}

_KNOWN_CLEAN_DOMAINS = {
    "google.com", "microsoft.com", "amazon.com", "cloudflare.com",
    "github.com", "stackoverflow.com", "ubuntu.com", "pypi.org",
    "apple.com", "windows.com", "office.com", "live.com",
}

_SUSPICIOUS_TLDS = {".xyz", ".top", ".gq", ".ml", ".cf", ".tk", ".pw",
                    ".cc", ".ru", ".cn", ".io", ".onion"}

# Standard EICAR test string (inert text — never executed)
EICAR_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_MD5    = hashlib.md5(EICAR_STRING.encode()).hexdigest()
EICAR_SHA256 = hashlib.sha256(EICAR_STRING.encode()).hexdigest()


def _ip_reputation(ip: str) -> tuple[str, float]:
    """Return (reputation_label, score 0.0–1.0). Score near 1 = malicious."""
    if ip in _BENIGN_DNS_SERVERS:
        return "benign", 0.05
    for prefix in _MALICIOUS_IP_PREFIXES:
        if ip.startswith(prefix):
            return "malicious", 0.92
    # Private ranges are neutral
    if ip.startswith(("10.", "192.168.", "172.16.", "172.17.")):
        return "internal", 0.10
    return "unknown", 0.40


def _domain_reputation(domain: str) -> tuple[str, float]:
    """Return (reputation_label, score 0.0–1.0)."""
    if not domain:
        return "none", 0.0
    domain_lower = domain.lower()
    if domain_lower in _KNOWN_CLEAN_DOMAINS:
        return "benign", 0.05
    # High-entropy or very long domain → suspicious
    parts = domain_lower.split(".")
    if len(parts) > 5:
        return "suspicious", 0.75
    if len(domain_lower) > 60:
        return "suspicious", 0.80
    for tld in _SUSPICIOUS_TLDS:
        if domain_lower.endswith(tld):
            return "suspicious", 0.70
    return "unknown", 0.35


def _is_public_ip(ip: str) -> bool:
    return not ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "127."))


def extract_iocs(event: dict) -> list[dict]:
    """
    Extract all IOCs from a raw network event.

    Returns a list of IOC dicts:
        {type, value, reputation, score, context}
    """
    iocs: list[dict] = []
    seen_values: set[str] = set()

    def add_ioc(ioc_type: str, value: str, reputation: str, score: float, context: str):
        key = f"{ioc_type}:{value}"
        if key in seen_values or not value:
            return
        seen_values.add(key)
        iocs.append({
            "type":       ioc_type,
            "value":      value,
            "reputation": reputation,
            "score":      round(score, 4),
            "context":    context,
        })

    # ── IP IOCs ────────────────────────────────────────────────────────────
    src_ip = event.get("src_ip", "")
    dst_ip = event.get("dst_ip", "")

    if src_ip and _is_public_ip(src_ip):
        rep, score = _ip_reputation(src_ip)
        add_ioc("ip", src_ip, rep, score, f"Source IP in event {event.get('event_type','?')}")

    if dst_ip and _is_public_ip(dst_ip) and dst_ip not in _BENIGN_DNS_SERVERS:
        rep, score = _ip_reputation(dst_ip)
        add_ioc("ip", dst_ip, rep, score, f"Destination IP in event {event.get('event_type','?')}")

    # ── Domain IOCs ────────────────────────────────────────────────────────
    dns_query = event.get("dns_query", "")
    if dns_query:
        rep, score = _domain_reputation(dns_query)
        add_ioc("domain", dns_query, rep, score,
                f"DNS query in {event.get('event_type','?')} event")

    # ── EICAR IOC ──────────────────────────────────────────────────────────
    payload = event.get("payload_snippet", "") or ""
    if EICAR_STRING in payload:
        add_ioc(
            "eicar_string",
            EICAR_SHA256[:16] + "...",
            "test_artifact",
            1.0,
            "EICAR standard anti-virus test string (inert text — not executed)"
        )
        add_ioc("hash_md5",    EICAR_MD5,    "test_artifact", 1.0, "EICAR MD5 hash")
        add_ioc("hash_sha256", EICAR_SHA256, "test_artifact", 1.0, "EICAR SHA-256 hash")

    return iocs


def score_ioc_set(iocs: list[dict]) -> float:
    """
    Aggregate IOC threat score (0.0–1.0) from a list of IOCs.
    Weighted max + small bonus for volume of malicious IOCs.
    """
    if not iocs:
        return 0.0
    scores = [ioc["score"] for ioc in iocs]
    max_score = max(scores)
    malicious_count = sum(1 for ioc in iocs if ioc["reputation"] in ("malicious", "suspicious", "test_artifact"))
    volume_bonus = min(malicious_count * 0.03, 0.15)
    return min(round(max_score + volume_bonus, 4), 1.0)
