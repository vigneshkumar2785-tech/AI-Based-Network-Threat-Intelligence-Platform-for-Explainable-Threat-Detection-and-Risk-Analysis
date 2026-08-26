from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.core.database import get_db
from app.models.db_models import SecurityEvent, Incident, IOCRecord

router = APIRouter(prefix="/dashboard", tags=["Dashboard Summary"])


@router.get("/summary")
def get_dashboard_summary(db: Session = Depends(get_db)):
    total_events = db.query(SecurityEvent).count()
    total_anomalies = db.query(SecurityEvent).filter(SecurityEvent.is_anomaly == True).count()
    total_incidents = db.query(Incident).count()
    active_incidents = db.query(Incident).filter(Incident.state.in_(["new", "investigating"])).count()

    # Severity counts
    critical_count = db.query(Incident).filter(Incident.severity == "critical").count()
    high_count = db.query(Incident).filter(Incident.severity == "high").count()
    medium_count = db.query(Incident).filter(Incident.severity == "medium").count()
    low_count = db.query(Incident).filter(Incident.severity == "low").count()
    info_count = db.query(Incident).filter(Incident.severity == "info").count()

    # Classification breakdown
    cls_query = db.query(
        SecurityEvent.classification, func.count(SecurityEvent.id)
    ).group_by(SecurityEvent.classification).all()
    classification_breakdown = {cls: count for cls, count in cls_query}

    # Avg Risk Score
    avg_risk = db.query(func.avg(SecurityEvent.risk_score)).scalar() or 0.0

    # Total IOC count
    total_iocs = db.query(IOCRecord).count()
    malicious_iocs = db.query(IOCRecord).filter(IOCRecord.reputation.in_(["malicious", "test_artifact"])).count()

    return {
        "metrics": {
            "total_events": total_events,
            "total_anomalies": total_anomalies,
            "total_incidents": total_incidents,
            "active_incidents": active_incidents,
            "avg_risk_score": round(float(avg_risk), 1),
            "total_iocs": total_iocs,
            "malicious_iocs": malicious_iocs,
        },
        "severity_breakdown": {
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "info": info_count,
        },
        "classification_breakdown": classification_breakdown,
        "system_status": "OPERATIONAL",
    }
