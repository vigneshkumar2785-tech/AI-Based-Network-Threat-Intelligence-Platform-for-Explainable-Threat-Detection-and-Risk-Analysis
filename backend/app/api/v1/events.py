from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime, timezone
import json

from app.core.database import get_db
from app.models.db_models import SecurityEvent, Incident, IOCRecord
from app.schemas.schemas import EventResponse, TriggerEventRequest
from app.api.deps import get_current_user
from simulation.network_events.generator import generate_event, GENERATORS
from app.services.correlator import process_event

router = APIRouter(prefix="/events", tags=["Security Events"])


@router.get("", response_model=List[EventResponse])
def list_events(
    limit: int = Query(50, ge=1, le=500),
    classification: Optional[str] = None,
    anomaly_only: bool = False,
    min_risk: float = 0.0,
    db: Session = Depends(get_db)
):
    query = db.query(SecurityEvent)
    if classification:
        query = query.filter(SecurityEvent.classification == classification)
    if anomaly_only:
        query = query.filter(SecurityEvent.is_anomaly == True)
    if min_risk > 0:
        query = query.filter(SecurityEvent.risk_score >= min_risk)

    events = query.order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
    return events


@router.post("/trigger")
def trigger_synthetic_event(
    req: TriggerEventRequest,
    db: Session = Depends(get_db)
):
    """
    Generate a synthetic event of the specified type, process it through the complete
    Block C intelligence pipeline, persist event, IOCs, and Incident to DB, and return.
    """
    event_type = req.event_type
    if event_type not in GENERATORS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid event_type '{event_type}'. Valid options: {list(GENERATORS.keys())}"
        )

    # 1. Generate raw event
    raw_event = generate_event(event_type)

    # 2. Run full Block C correlation pipeline
    result = process_event(raw_event, include_xai=True)

    # 3. Persist Event to DB
    sec_event = SecurityEvent(
        event_id=result["event_id"],
        timestamp=datetime.fromisoformat(result["timestamp"]) if isinstance(result["timestamp"], str) else datetime.now(timezone.utc),
        event_type=result["event_type"],
        src_ip=result["src_ip"],
        dst_ip=result["dst_ip"],
        src_port=raw_event.get("src_port"),
        dst_port=result["dst_port"],
        protocol=result["protocol"],
        byte_count=result["byte_count"],
        packet_count=result["packet_count"],
        duration_ms=raw_event.get("duration_ms"),
        is_anomaly=result["is_anomaly"],
        anomaly_score=result["anomaly_score"],
        classification=result["classification"],
        confidence=result["confidence"],
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        iocs_json=result["iocs"],
        mitre_json=result["mitre_techniques"],
        cve_json=result["cves"],
        xai_json=result["xai"],
        raw_event_json=raw_event
    )
    db.add(sec_event)

    # 4. Persist IOCs
    for ioc in result["iocs"]:
        existing_ioc = db.query(IOCRecord).filter(
            IOCRecord.ioc_type == ioc["type"],
            IOCRecord.value == ioc["value"]
        ).first()
        if existing_ioc:
            existing_ioc.last_seen = datetime.now(timezone.utc)
            existing_ioc.score = max(existing_ioc.score, ioc["score"])
        else:
            new_ioc = IOCRecord(
                ioc_type=ioc["type"],
                value=ioc["value"],
                reputation=ioc["reputation"],
                score=ioc["score"],
                context=ioc["context"],
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc)
            )
            db.add(new_ioc)

    # 5. Persist Incident (if not normal or if risk > 40)
    inc_data = result["incident"]
    if result["classification"] != "normal" or result["risk_score"] >= 40.0:
        db_incident = Incident(
            incident_id=inc_data["incident_id"],
            state=inc_data["state"],
            severity=inc_data["severity"],
            risk_score=inc_data["risk_score"],
            risk_level=inc_data["risk_level"],
            classification=inc_data["classification"],
            event_id=result["event_id"],
            src_ip=result["src_ip"],
            dst_ip=result["dst_ip"],
            dst_port=result["dst_port"],
            protocol=result["protocol"],
            recommended_actions=inc_data["recommended_actions"],
            mitre_techniques=inc_data["mitre_techniques"],
            audit_trail=inc_data["audit_trail"]
        )
        db.add(db_incident)

    db.commit()
    db.refresh(sec_event)

    return result
