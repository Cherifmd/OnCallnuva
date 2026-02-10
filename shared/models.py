"""
Shared database models and connection utilities.
PostgreSQL as single source of truth.
"""
import os
import time
import logging
from datetime import datetime
from contextlib import asynccontextmanager

from sqlalchemy import (
    Column, String, Integer, Float, DateTime, Text, ForeignKey,
    create_engine, Index, Enum as SAEnum
)
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base, relationship
import enum

logger = logging.getLogger(__name__)

Base = declarative_base()


class SeverityLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IncidentStatus(str, enum.Enum):
    TRIGGERED = "triggered"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(64), primary_key=True)
    source = Column(String(128), nullable=False)
    service_name = Column(String(128), nullable=False, index=True)
    severity = Column(String(16), nullable=False, index=True)
    title = Column(String(512), nullable=False)
    description = Column(Text)
    labels = Column(Text)  # JSON string
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    incident_id = Column(String(64), ForeignKey("incidents.id"), nullable=True)

    __table_args__ = (
        Index("ix_alerts_correlation", "service_name", "severity", "timestamp"),
    )


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(64), primary_key=True)
    title = Column(String(512), nullable=False)
    description = Column(Text)
    severity = Column(String(16), nullable=False, index=True)
    status = Column(String(16), nullable=False, default=IncidentStatus.TRIGGERED, index=True)
    service_name = Column(String(128), nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    acknowledged_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    assigned_to = Column(String(128), nullable=True)
    escalation_level = Column(Integer, default=0)
    resolution_note = Column(Text, nullable=True)
    alert_count = Column(Integer, default=1)

    alerts = relationship("Alert", backref="incident", lazy="selectin")

    @property
    def mtta_seconds(self) -> float:
        """Mean Time To Acknowledge."""
        if self.acknowledged_at and self.created_at:
            return (self.acknowledged_at - self.created_at).total_seconds()
        return 0.0

    @property
    def mttr_seconds(self) -> float:
        """Mean Time To Resolve."""
        if self.resolved_at and self.created_at:
            return (self.resolved_at - self.created_at).total_seconds()
        return 0.0


class OnCallSchedule(Base):
    __tablename__ = "oncall_schedules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    service_name = Column(String(128), nullable=False, index=True)
    user_id = Column(String(64), nullable=False)
    user_name = Column(String(128), nullable=False)
    escalation_level = Column(Integer, nullable=False, default=0)
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=False)
    phone = Column(String(32), nullable=True)
    email = Column(String(128), nullable=True)

    __table_args__ = (
        Index("ix_oncall_lookup", "service_name", "escalation_level", "start_time", "end_time"),
    )


class EscalationLog(Base):
    __tablename__ = "escalation_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(64), ForeignKey("incidents.id"), nullable=False)
    from_user = Column(String(128))
    to_user = Column(String(128))
    level = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow)


def get_db_url(async_mode: bool = True) -> str:
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5432")
    db = os.getenv("POSTGRES_DB", "incidents_db")
    user = os.getenv("POSTGRES_USER", "oncall_admin")
    password = os.getenv("POSTGRES_PASSWORD", "s3cur3_p4ssw0rd_2026")
    driver = "postgresql+asyncpg" if async_mode else "postgresql+psycopg2"
    return f"{driver}://{user}:{password}@{host}:{port}/{db}"


def create_async_db_engine():
    return create_async_engine(
        get_db_url(async_mode=True),
        echo=False,
        pool_size=20,
        max_overflow=10,
        pool_pre_ping=True,
    )


def create_sync_engine():
    return create_engine(
        get_db_url(async_mode=False),
        echo=False,
        pool_size=10,
        max_overflow=5,
        pool_pre_ping=True,
    )


def get_async_session_factory(engine=None):
    if engine is None:
        engine = create_async_db_engine()
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db(engine=None):
    """Create all tables. Call at service startup."""
    if engine is None:
        engine = create_async_db_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables initialized.")
    return engine


async def wait_for_db(max_retries: int = 30, delay: float = 2.0):
    """Wait for PostgreSQL to be ready."""
    engine = create_async_db_engine()
    for attempt in range(max_retries):
        try:
            async with engine.begin() as conn:
                await conn.execute(
                    __import__("sqlalchemy").text("SELECT 1")
                )
            logger.info("Database connection established.")
            return engine
        except Exception as e:
            logger.warning(f"DB not ready (attempt {attempt + 1}/{max_retries}): {e}")
            time.sleep(delay)
    raise ConnectionError("Could not connect to PostgreSQL after max retries.")
