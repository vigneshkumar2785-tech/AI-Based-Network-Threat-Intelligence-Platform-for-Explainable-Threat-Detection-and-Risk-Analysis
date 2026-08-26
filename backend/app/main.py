import sys
import os

# Ensure repo root and backend directory are in Python path
_REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
_BACKEND_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
for p in [_REPO_ROOT, _BACKEND_DIR]:
    if p not in sys.path:
        sys.path.insert(0, p)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.core.config import settings
from app.core.limiter import limiter
from app.core.database import engine, Base, SessionLocal
from app.api.v1 import api_router

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url="/api/openapi.json",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# State for slowapi
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(api_router, prefix="/api")


@app.on_event("startup")
def on_startup():
    # 1. Create DB tables if they don't exist
    Base.metadata.create_all(bind=engine)

    # 2. Seed initial data (default analyst user & sample events) if empty
    db = SessionLocal()
    try:
        from app.models.db_models import User, SecurityEvent
        from app.core.security import get_password_hash
        from simulation.network_events.generator import GENERATORS
        from app.services.correlator import process_event
        from app.schemas.schemas import TriggerEventRequest
        from app.api.v1.events import trigger_synthetic_event

        # Check user
        user = db.query(User).filter(User.email == "analyst@threatintel.io").first()
        if not user:
            demo_user = User(
                email="analyst@threatintel.io",
                hashed_password=get_password_hash("Cyber2026!"),
                full_name="Lead Threat Analyst",
                role="analyst",
                is_active=True
            )
            admin_user = User(
                email="admin@threatintel.io",
                hashed_password=get_password_hash("Admin2026!"),
                full_name="SOC Administrator",
                role="admin",
                is_active=True
            )
            db.add_all([demo_user, admin_user])
            db.commit()

        # Seed sample events if event table is empty
        event_count = db.query(SecurityEvent).count()
        if event_count == 0:
            sample_types = ["port_scan", "failed_auth", "dns_anomaly", "c2_beacon", "data_exfil", "eicar_test", "normal"]
            for etype in sample_types:
                try:
                    trigger_synthetic_event(TriggerEventRequest(event_type=etype), db=db)
                except Exception as e:
                    print(f"Startup seed warning for {etype}: {e}")
    except Exception as err:
        print(f"Startup seed error: {err}")
    finally:
        db.close()


@app.get("/health")
def health_check():
    """Health check endpoint — returns 200 OK with app info."""
    return {
        "status": "ok",
        "app": settings.PROJECT_NAME,
        "environment": settings.ENVIRONMENT,
        "rate_limit_demo_per_min": settings.RATE_LIMIT_DEMO_PER_MINUTE,
    }
