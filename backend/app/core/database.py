from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.exc import OperationalError
import os
from app.core.config import settings

db_url = settings.DATABASE_URL
sqlite_file = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "soc_platform.db"))
sqlite_url = f"sqlite:///{sqlite_file}"

engine = None

# Attempt primary DB URL first
try:
    if "postgresql" in db_url:
        temp_engine = create_engine(db_url, pool_pre_ping=True, echo=False)
        # Test connection
        with temp_engine.connect() as conn:
            pass
        engine = temp_engine
    else:
        engine = create_engine(db_url, connect_args={"check_same_thread": False}, pool_pre_ping=True, echo=False)
except Exception:
    # Graceful fallback to SQLite for local dev when Postgres container is not running
    engine = create_engine(sqlite_url, connect_args={"check_same_thread": False}, pool_pre_ping=True, echo=False)

if engine is None:
    engine = create_engine(sqlite_url, connect_args={"check_same_thread": False}, pool_pre_ping=True, echo=False)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
