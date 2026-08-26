from fastapi import APIRouter
import json
import os

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities (CVE)"])

_CVE_DB_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "threat_intelligence", "cve", "cve_db.json")
)

@router.get("")
def get_cve_catalog():
    if os.path.exists(_CVE_DB_PATH):
        with open(_CVE_DB_PATH) as f:
            return json.load(f)
    return {"by_port": {}, "by_service": {}}
