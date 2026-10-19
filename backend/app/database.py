"""
Database Connection and Session Management
Supports PostgreSQL (recommended for production) and SQLite (for tests and zero-dependency local runs).
Enforces foreign keys, connection health checks, and transaction boundaries.
"""

import logging
from collections.abc import Generator

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from backend.app.config import settings

logger = logging.getLogger(__name__)

# Normalize DATABASE_URL if someone specifies postgres:// instead of postgresql://
db_url = settings.DATABASE_URL
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql+psycopg://", 1)
elif db_url.startswith("postgresql://") and "+psycopg" not in db_url and "+asyncpg" not in db_url:
    db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)

from typing import Any

engine_kwargs: dict[str, Any] = {
    "pool_pre_ping": True,
}

if db_url.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(db_url, **engine_kwargs)

# For SQLite, enforce foreign key constraints explicitly
if db_url.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for transaction-safe database sessions."""
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


from sqlalchemy.exc import SQLAlchemyError


def check_db_connection() -> bool:
    """Verifies that the database is reachable and responsive."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except (SQLAlchemyError, OSError) as e:
        logger.error(f"Database health check failed: {e}")
        return False
