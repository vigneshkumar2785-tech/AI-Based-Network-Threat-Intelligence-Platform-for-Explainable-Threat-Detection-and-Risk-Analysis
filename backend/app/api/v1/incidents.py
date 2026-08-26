from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime, timezone

from app.core.database import get_db
from app.models.db_models import Incident, SecurityEvent
from app.schemas.schemas import IncidentResponse, StateTransitionRequest
from app.api.deps import get_current_user
from app.response.incident_engine import transition_state, add_audit_entry

router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.get("", response_model=List[IncidentResponse])
def list_incidents(
    state: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    query = db.query(Incident)
    if state:
        query = query.filter(Incident.state == state)
    if severity:
        query = query.filter(Incident.severity == severity)
    return query.order_by(Incident.created_at.desc()).limit(limit).all()


@router.get("/{incident_id}")
def get_incident_detail(
    incident_id: str,
    db: Session = Depends(get_db)
):
    incident = db.query(Incident).filter(
        (Incident.incident_id == incident_id) | (Incident.id == incident_id)
    ).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Fetch associated event details if event_id is linked
    event = None
    if incident.event_id:
        event_rec = db.query(SecurityEvent).filter(SecurityEvent.event_id == incident.event_id).first()
        if event_rec:
            event = {
                "id": event_rec.id,
                "event_id": event_rec.event_id,
                "timestamp": event_rec.timestamp,
                "event_type": event_rec.event_type,
                "src_ip": event_rec.src_ip,
                "dst_ip": event_rec.dst_ip,
                "dst_port": event_rec.dst_port,
                "protocol": event_rec.protocol,
                "byte_count": event_rec.byte_count,
                "packet_count": event_rec.packet_count,
                "is_anomaly": event_rec.is_anomaly,
                "anomaly_score": event_rec.anomaly_score,
                "classification": event_rec.classification,
                "confidence": event_rec.confidence,
                "risk_score": event_rec.risk_score,
                "iocs": event_rec.iocs_json,
                "mitre": event_rec.mitre_json,
                "cve": event_rec.cve_json,
                "xai": event_rec.xai_json,
            }

    return {
        "incident": incident,
        "event": event
    }


@router.post("/{incident_id}/transition", response_model=IncidentResponse)
def transition_incident_state(
    incident_id: str,
    req: StateTransitionRequest,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    incident = db.query(Incident).filter(
        (Incident.incident_id == incident_id) | (Incident.id == incident_id)
    ).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    inc_dict = {
        "incident_id": incident.incident_id,
        "state": incident.state,
        "audit_trail": incident.audit_trail or []
    }

    try:
        updated = transition_state(
            incident=inc_dict,
            new_state=req.new_state,
            actor=current_user.email if hasattr(current_user, 'email') else "analyst",
            note=req.note or f"Status changed to {req.new_state}"
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    incident.state = updated["state"]
    incident.audit_trail = updated["audit_trail"]
    incident.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(incident)
    return incident
