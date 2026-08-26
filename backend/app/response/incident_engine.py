"""
Incident Response Engine
State machine for SOC incident management.
States: new → investigating → contained → resolved
All response actions are RECOMMENDATIONS/SIMULATIONS — never real system commands.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

# ── Response playbooks per threat classification ──────────────────────────────
_PLAYBOOKS: dict[str, list[dict]] = {
    "port_scan": [
        {"priority": 1, "action": "BLOCK_IP",         "description": "Block source IP at perimeter firewall [SIMULATION]", "automated": False},
        {"priority": 2, "action": "ALERT_SOC",         "description": "Alert SOC team of active reconnaissance activity"},
        {"priority": 3, "action": "INCREASE_LOGGING",  "description": "Enable verbose logging on targeted hosts"},
        {"priority": 4, "action": "THREAT_HUNT",       "description": "Check for lateral movement from source IP in last 24h"},
    ],
    "failed_auth": [
        {"priority": 1, "action": "BLOCK_IP",           "description": "Block brute-force source IP at firewall [SIMULATION]", "automated": False},
        {"priority": 2, "action": "LOCK_ACCOUNT",       "description": "Temporarily lock targeted account [SIMULATION]", "automated": False},
        {"priority": 3, "action": "ENABLE_MFA",         "description": "Enforce MFA on targeted service"},
        {"priority": 4, "action": "ALERT_SOC",          "description": "Notify SOC — credential attack in progress"},
        {"priority": 5, "action": "PASSWORD_RESET",     "description": "Initiate emergency password reset for targeted accounts"},
    ],
    "dns_anomaly": [
        {"priority": 1, "action": "BLOCK_DOMAIN",       "description": "Block suspicious DNS domain at DNS resolver [SIMULATION]", "automated": False},
        {"priority": 2, "action": "QUARANTINE_HOST",    "description": "Isolate source host from network [SIMULATION]", "automated": False},
        {"priority": 3, "action": "DNS_SINKHHOLE",      "description": "Redirect C2 domain to sinkhole [SIMULATION]"},
        {"priority": 4, "action": "FORENSIC_CAPTURE",   "description": "Capture full DNS query logs from affected host"},
        {"priority": 5, "action": "MALWARE_SCAN",       "description": "Run endpoint malware scan on source host"},
    ],
    "traffic_spike": [
        {"priority": 1, "action": "RATE_LIMIT",         "description": "Apply rate limiting on affected interface [SIMULATION]"},
        {"priority": 2, "action": "ALERT_NOC",          "description": "Alert Network Operations Center — potential DDoS"},
        {"priority": 3, "action": "CAPTCHA_CHALLENGE",  "description": "Enable CAPTCHA/challenge pages for affected services"},
        {"priority": 4, "action": "UPSTREAM_FILTER",    "description": "Contact upstream provider for traffic scrubbing"},
    ],
    "c2_beacon": [
        {"priority": 1, "action": "QUARANTINE_HOST",    "description": "IMMEDIATE: Isolate compromised host from network [SIMULATION]", "automated": False},
        {"priority": 2, "action": "BLOCK_IP",           "description": "Block C2 server IP at all egress points [SIMULATION]", "automated": False},
        {"priority": 3, "action": "MEMORY_DUMP",        "description": "Capture memory dump from compromised host for forensics"},
        {"priority": 4, "action": "CREDENTIAL_RESET",   "description": "Reset all credentials on compromised host"},
        {"priority": 5, "action": "INCIDENT_RESPONSE",  "description": "Escalate to Incident Response team — active C2 channel"},
        {"priority": 6, "action": "THREAT_HUNT",        "description": "Hunt for lateral movement from compromised host"},
    ],
    "data_exfil": [
        {"priority": 1, "action": "BLOCK_EGRESS",       "description": "IMMEDIATE: Block all outbound connections from source host [SIMULATION]", "automated": False},
        {"priority": 2, "action": "QUARANTINE_HOST",    "description": "Isolate source host immediately [SIMULATION]", "automated": False},
        {"priority": 3, "action": "DLP_REVIEW",         "description": "Review DLP logs to identify exfiltrated data scope"},
        {"priority": 4, "action": "LEGAL_NOTIFY",       "description": "Assess breach notification requirements (GDPR/HIPAA/etc.)"},
        {"priority": 5, "action": "FORENSIC_CAPTURE",   "description": "Preserve forensic evidence before remediation"},
        {"priority": 6, "action": "EXECUTIVE_BRIEF",    "description": "Brief executive team on potential data breach"},
    ],
    "eicar_test": [
        {"priority": 1, "action": "QUARANTINE_FILE",    "description": "Quarantine file containing EICAR test string [SIMULATION]"},
        {"priority": 2, "action": "AV_SCAN",            "description": "Run full AV scan on affected host"},
        {"priority": 3, "action": "ALERT_SOC",          "description": "Alert SOC — EICAR test artifact detected (verify not real malware delivery test)"},
        {"priority": 4, "action": "AUDIT_USER",         "description": "Identify user who transferred the file"},
    ],
    "normal": [
        {"priority": 1, "action": "LOG_EVENT",          "description": "Log event for baseline and audit purposes"},
    ],
}

_STATE_TRANSITIONS = {
    "new":           ["investigating", "closed"],
    "investigating": ["contained", "escalated", "closed"],
    "contained":     ["resolved", "escalated"],
    "escalated":     ["investigating", "contained", "resolved"],
    "resolved":      ["closed"],
    "closed":        [],
}

_SEVERITY_FROM_RISK = [
    (80, "critical"),
    (60, "high"),
    (40, "medium"),
    (20, "low"),
    (0,  "info"),
]


def _severity_from_score(risk_score: float) -> str:
    for threshold, sev in _SEVERITY_FROM_RISK:
        if risk_score >= threshold:
            return sev
    return "info"


def create_incident(
    event: dict,
    classification: str,
    risk_score: float,
    risk_level: str,
    mitre_techniques: list[dict],
    iocs: list[dict],
    cves: list[dict],
) -> dict:
    """
    Create a new SOC incident from a classified/scored event.

    Returns a structured incident dict with state=new, recommended actions,
    and full event context.
    """
    incident_id  = "INC-" + str(uuid.uuid4())[:8].upper()
    severity     = _severity_from_score(risk_score)
    playbook     = _PLAYBOOKS.get(classification, _PLAYBOOKS["normal"])
    now          = datetime.now(timezone.utc).isoformat()

    return {
        "incident_id":    incident_id,
        "state":          "new",
        "severity":       severity,
        "risk_score":     risk_score,
        "risk_level":     risk_level,
        "classification": classification,
        "event_id":       event.get("event_id", ""),
        "src_ip":         event.get("src_ip", ""),
        "dst_ip":         event.get("dst_ip", ""),
        "dst_port":       event.get("dst_port"),
        "protocol":       event.get("protocol", ""),
        "created_at":     now,
        "updated_at":     now,
        "recommended_actions": playbook,
        "mitre_techniques": [
            {"technique_id": t["technique_id"], "technique_name": t["technique_name"],
             "tactic": t["tactic"]}
            for t in mitre_techniques
        ],
        "ioc_count":      len(iocs),
        "cve_count":      len(cves),
        "audit_trail": [
            {
                "timestamp": now,
                "actor":     "system",
                "action":    "INCIDENT_CREATED",
                "detail":    f"Auto-created incident for {classification} event {event.get('event_id','')[:16]}",
            }
        ],
    }


def transition_state(incident: dict, new_state: str, actor: str = "analyst", note: str = "") -> dict:
    """
    Transition incident to a new state with audit trail entry.
    Raises ValueError if transition is not allowed.
    """
    current = incident.get("state", "new")
    allowed = _STATE_TRANSITIONS.get(current, [])
    if new_state not in allowed:
        raise ValueError(f"Invalid transition: {current} → {new_state}. Allowed: {allowed}")

    now = datetime.now(timezone.utc).isoformat()
    incident = {**incident, "state": new_state, "updated_at": now}
    incident["audit_trail"].append({
        "timestamp": now,
        "actor":     actor,
        "action":    f"STATE_TRANSITION:{current}→{new_state}",
        "detail":    note or f"Transitioned from {current} to {new_state}",
    })
    return incident


def add_audit_entry(incident: dict, actor: str, action: str, detail: str) -> dict:
    """Append an audit trail entry to an existing incident."""
    now = datetime.now(timezone.utc).isoformat()
    incident = {**incident}
    incident["audit_trail"] = incident.get("audit_trail", []) + [{
        "timestamp": now,
        "actor":     actor,
        "action":    action,
        "detail":    detail,
    }]
    incident["updated_at"] = now
    return incident
