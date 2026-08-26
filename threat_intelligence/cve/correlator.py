"""
CVE Correlation Engine
Correlates network events to known CVEs based on destination port and protocol.
Uses a static CVE database — replace with NVD API calls in production.
"""
import json
import os

_DB_PATH = os.path.join(os.path.dirname(__file__), "cve_db.json")
_db: dict | None = None

_PROTO_TO_SERVICE = {
    "FTP": "FTP", "SMTP": "SMTP", "HTTP": "HTTP", "HTTPS": "HTTPS",
    "DNS": "DNS", "SMB": "SMB", "SSH": "SSH", "RDP": "RDP",
}


def _load_db() -> dict:
    global _db
    if _db is None:
        with open(_DB_PATH) as f:
            _db = json.load(f)
    return _db


def correlate_cves(event: dict) -> list[dict]:
    """
    Return CVEs relevant to this event based on destination port and protocol.
    Only returns CVEs when there is a clear port/service match.
    """
    db = _load_db()
    found: list[dict] = []
    seen_ids: set[str] = set()

    dst_port = str(event.get("dst_port", ""))
    protocol = (event.get("protocol") or "").upper()

    # Port-based lookup
    port_cves = db.get("by_port", {}).get(dst_port, [])
    for cve in port_cves:
        cve_id = cve["cve_id"]
        if cve_id not in seen_ids:
            seen_ids.add(cve_id)
            found.append({**cve, "match_reason": f"dst_port={dst_port}"})

    # Protocol/service-based lookup (secondary)
    service = _PROTO_TO_SERVICE.get(protocol)
    if service:
        service_cve_ids = db.get("by_service", {}).get(service, [])
        for cve_id in service_cve_ids:
            if cve_id not in seen_ids:
                # Find full CVE record from by_port entries
                for port_entry in db.get("by_port", {}).values():
                    for cve_rec in port_entry:
                        if cve_rec["cve_id"] == cve_id:
                            seen_ids.add(cve_id)
                            found.append({**cve_rec, "match_reason": f"protocol={protocol}"})

    # Sort by CVSS score descending
    found.sort(key=lambda x: x.get("cvss_v3", 0), reverse=True)
    return found


def max_cvss(cves: list[dict]) -> float:
    """Return the maximum CVSS v3 score from a list of CVEs, or 0.0."""
    if not cves:
        return 0.0
    return max(c.get("cvss_v3", 0.0) for c in cves)
