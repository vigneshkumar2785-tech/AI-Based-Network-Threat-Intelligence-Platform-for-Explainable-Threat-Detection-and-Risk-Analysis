from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import Optional, List

from app.core.database import get_db
from app.models.db_models import IOCRecord
from app.schemas.schemas import IOCResponse

router = APIRouter(prefix="/iocs", tags=["Indicators of Compromise"])


@router.get("", response_model=List[IOCResponse])
def list_iocs(
    reputation: Optional[str] = None,
    ioc_type: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    query = db.query(IOCRecord)
    if reputation:
        query = query.filter(IOCRecord.reputation == reputation)
    if ioc_type:
        query = query.filter(IOCRecord.ioc_type == ioc_type)
    return query.order_by(IOCRecord.last_seen.desc()).limit(limit).all()


@router.get("/search", response_model=List[IOCResponse])
def search_iocs(
    q: str = Query(..., min_length=2),
    db: Session = Depends(get_db)
):
    pattern = f"%{q}%"
    return db.query(IOCRecord).filter(
        (IOCRecord.value.ilike(pattern)) | (IOCRecord.context.ilike(pattern))
    ).limit(50).all()
