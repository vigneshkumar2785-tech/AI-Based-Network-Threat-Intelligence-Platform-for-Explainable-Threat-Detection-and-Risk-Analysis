from fastapi import APIRouter
from app.api.v1 import auth, events, incidents, iocs, dashboard, mitre, vulnerabilities, xai

api_router = APIRouter(prefix="/v1")

api_router.include_router(auth.router)
api_router.include_router(events.router)
api_router.include_router(incidents.router)
api_router.include_router(iocs.router)
api_router.include_router(dashboard.router)
api_router.include_router(mitre.router)
api_router.include_router(vulnerabilities.router)
api_router.include_router(xai.router)
