from fastapi import APIRouter
import json
import os

router = APIRouter(prefix="/mitre", tags=["MITRE ATT&CK"])

_CATALOG_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "threat_intelligence", "mitre", "mitre_catalog.json")
)

@router.get("/catalog")
def get_mitre_catalog():
    if os.path.exists(_CATALOG_PATH):
        with open(_CATALOG_PATH) as f:
            return json.load(f)
    return {"techniques": {}, "tactics": {}}
