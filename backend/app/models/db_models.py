import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, JSON
from app.core.database import Base

class User(Base):
    __tablename__ = "users"
    __table_args__ = {'extend_existing': True}

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    role = Column(String(50), default="analyst", nullable=False)  # admin, analyst, viewer
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = {'extend_existing': True}

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id = Column(String(64), index=True, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    event_type = Column(String(50), index=True)
    src_ip = Column(String(45), index=True)
    dst_ip = Column(String(45), index=True)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String(20))
    byte_count = Column(Integer)
    packet_count = Column(Integer)
    duration_ms = Column(Integer)

    # Detection & Intel
    is_anomaly = Column(Boolean, default=False)
    anomaly_score = Column(Float, default=0.0)
    classification = Column(String(50), index=True)
    confidence = Column(Float, default=0.0)
    risk_score = Column(Float, default=0.0, index=True)
    risk_level = Column(String(20), index=True)
    
    # JSON Blobs for complete record
    iocs_json = Column(JSON, nullable=True)
    mitre_json = Column(JSON, nullable=True)
    cve_json = Column(JSON, nullable=True)
    xai_json = Column(JSON, nullable=True)
    raw_event_json = Column(JSON, nullable=True)
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = {'extend_existing': True}

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(String(32), unique=True, index=True, nullable=False)
    state = Column(String(30), default="new", index=True)  # new, investigating, contained, resolved, closed
    severity = Column(String(20), index=True)  # critical, high, medium, low, info
    risk_score = Column(Float, default=0.0, index=True)
    risk_level = Column(String(20))
    classification = Column(String(50), index=True)

    event_id = Column(String(64), nullable=True)
    src_ip = Column(String(45))
    dst_ip = Column(String(45))
    dst_port = Column(Integer)
    protocol = Column(String(20))

    recommended_actions = Column(JSON, nullable=True)
    mitre_techniques = Column(JSON, nullable=True)
    audit_trail = Column(JSON, nullable=True)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class IOCRecord(Base):
    __tablename__ = "ioc_records"
    __table_args__ = {'extend_existing': True}

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ioc_type = Column(String(30), index=True, nullable=False)  # ip, domain, hash, eicar_string
    value = Column(String(512), index=True, nullable=False)
    reputation = Column(String(30), index=True)  # malicious, suspicious, internal, benign, test_artifact
    score = Column(Float, default=0.0)
    context = Column(Text, nullable=True)
    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
