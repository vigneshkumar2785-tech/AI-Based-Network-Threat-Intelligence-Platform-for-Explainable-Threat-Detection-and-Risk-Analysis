from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Any
from datetime import datetime

# ── Auth & User Schemas ────────────────────────────────────────────────────────
class UserCreate(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = None
    role: Optional[str] = "analyst"

class UserResponse(BaseModel):
    id: str
    email: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True

class LoginRequest(BaseModel):
    username: str  # OAuth2 password flow uses 'username' (can be email)
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class TokenData(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None

# ── Event Schemas ──────────────────────────────────────────────────────────────
class TriggerEventRequest(BaseModel):
    event_type: str = "port_scan"  # normal, port_scan, failed_auth, dns_anomaly, traffic_spike, c2_beacon, data_exfil, eicar_test

class IngestRawEventRequest(BaseModel):
    src_ip: Optional[str] = "192.168.1.100"
    dst_ip: Optional[str] = "10.0.0.1"
    src_port: Optional[int] = 49152
    dst_port: Optional[int] = 80
    protocol: Optional[str] = "TCP"
    byte_count: Optional[int] = 1000
    packet_count: Optional[int] = 10
    duration_ms: Optional[int] = 100
    unique_dst_ports: Optional[int] = 1
    failed_attempts: Optional[int] = 0
    dns_query: Optional[str] = ""
    dns_query_length: Optional[int] = 0
    dns_subdomain_count: Optional[int] = 0
    dns_entropy: Optional[float] = 0.0
    connection_interval_std: Optional[float] = 100.0
    bytes_out_ratio: Optional[float] = 0.5
    is_external_dst: Optional[int] = 1
    payload_snippet: Optional[str] = None
    event_type: Optional[str] = "external_ingest"

class EventResponse(BaseModel):
    id: str
    event_id: str
    timestamp: datetime
    event_type: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    byte_count: Optional[int] = None
    packet_count: Optional[int] = None

    is_anomaly: bool
    anomaly_score: float
    classification: str
    confidence: float
    risk_score: float
    risk_level: str

    iocs_json: Optional[Any] = None
    mitre_json: Optional[Any] = None
    cve_json: Optional[Any] = None
    xai_json: Optional[Any] = None

    class Config:
        from_attributes = True

# ── Incident Schemas ───────────────────────────────────────────────────────────
class StateTransitionRequest(BaseModel):
    new_state: str  # new, investigating, contained, resolved, closed
    note: Optional[str] = ""

class IncidentResponse(BaseModel):
    id: str
    incident_id: str
    state: str
    severity: str
    risk_score: float
    risk_level: str
    classification: str

    event_id: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None

    recommended_actions: Optional[Any] = None
    mitre_techniques: Optional[Any] = None
    audit_trail: Optional[Any] = None

    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

# ── IOC Schemas ────────────────────────────────────────────────────────────────
class IOCResponse(BaseModel):
    id: str
    ioc_type: str
    value: str
    reputation: str
    score: float
    context: Optional[str] = None
    first_seen: datetime
    last_seen: datetime

    class Config:
        from_attributes = True
