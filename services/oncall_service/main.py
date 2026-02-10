"""
Service 3 - On-Call Service (Port 8003)
Manages on-call schedules and escalation logic.
  - If no acknowledgement within X seconds → escalate to next level.
  - Caches schedules in Redis for fast lookup.
  - gRPC server for Incident Management to query on-call / trigger escalation.
"""
import os
import sys
import json
import logging
import asyncio
from datetime import datetime, timedelta
from concurrent import futures
from contextlib import asynccontextmanager
from typing import Optional, List

import grpc
from grpc import aio as grpc_aio
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from prometheus_client import (
    Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST
)
from starlette.responses import Response
from sqlalchemy import select, and_, delete
from sqlalchemy.ext.asyncio import AsyncSession

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from shared.models import (
    wait_for_db, init_db, get_async_session_factory,
    OnCallSchedule, EscalationLog
)
from shared.redis_client import cache_set, cache_get, cache_delete

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("oncall-service")

# ======================== PROMETHEUS METRICS ========================
ESCALATIONS_TOTAL = Counter("escalations_total", "Total escalations triggered", ["service"])
ONCALL_QUERIES = Counter("oncall_queries_total", "On-call lookups")
SCHEDULE_UPDATES = Counter("schedule_updates_total", "Schedule modifications")
CACHE_HITS = Counter("oncall_cache_hits_total", "Redis cache hits")
CACHE_MISSES = Counter("oncall_cache_misses_total", "Redis cache misses")

# ======================== GLOBAL STATE ========================
_db_engine = None
_session_factory = None

MAX_ESCALATION_LEVEL = 3  # L0 → L1 → L2 → L3


async def get_session() -> AsyncSession:
    global _session_factory
    if _session_factory is None:
        _session_factory = get_async_session_factory(_db_engine)
    return _session_factory()


# ======================== CORE LOGIC ========================

async def get_current_oncall(service_name: str) -> Optional[dict]:
    """
    Get the current on-call responder for a service.
    1. Check Redis cache first (fast path).
    2. Fall back to PostgreSQL query.
    3. Cache the result for 5 minutes.
    """
    cache_key = f"oncall:{service_name}:current"

    # Try cache
    cached = await cache_get(cache_key)
    if cached:
        CACHE_HITS.inc()
        return cached

    CACHE_MISSES.inc()
    ONCALL_QUERIES.inc()

    session = await get_session()
    try:
        now = datetime.utcnow()
        result = await session.execute(
            select(OnCallSchedule).where(
                and_(
                    OnCallSchedule.service_name == service_name,
                    OnCallSchedule.start_time <= now,
                    OnCallSchedule.end_time >= now,
                )
            ).order_by(OnCallSchedule.escalation_level.asc()).limit(1)
        )
        schedule = result.scalar_one_or_none()

        if schedule:
            data = {
                "user_id": schedule.user_id,
                "user_name": schedule.user_name,
                "phone": schedule.phone or "",
                "email": schedule.email or "",
                "escalation_level": schedule.escalation_level,
            }
            await cache_set(cache_key, data, ttl=300)
            return data

        # Return a default on-call if none configured
        default = {
            "user_id": "default-admin",
            "user_name": "System Admin",
            "phone": "+33600000000",
            "email": "admin@oncall.local",
            "escalation_level": 0,
        }
        return default
    finally:
        await session.close()


async def trigger_escalation(incident_id: str, service_name: str, current_level: int) -> dict:
    """
    Escalation Logic:
    Find the next on-call responder at (current_level + 1).
    If max level reached, loop back to level 0 with a warning.
    """
    next_level = current_level + 1
    if next_level > MAX_ESCALATION_LEVEL:
        next_level = 0  # Loop back
        logger.warning(f"Max escalation reached for {service_name}, looping to L0")

    session = await get_session()
    try:
        now = datetime.utcnow()
        result = await session.execute(
            select(OnCallSchedule).where(
                and_(
                    OnCallSchedule.service_name == service_name,
                    OnCallSchedule.escalation_level == next_level,
                    OnCallSchedule.start_time <= now,
                    OnCallSchedule.end_time >= now,
                )
            ).limit(1)
        )
        schedule = result.scalar_one_or_none()

        if schedule:
            # Log escalation
            log_entry = EscalationLog(
                incident_id=incident_id,
                from_user=f"L{current_level}",
                to_user=schedule.user_name,
                level=next_level,
                timestamp=now,
            )
            session.add(log_entry)
            await session.commit()
            ESCALATIONS_TOTAL.labels(service=service_name).inc()

            # Invalidate cache
            await cache_delete(f"oncall:{service_name}:current")

            return {
                "success": True,
                "next_user_id": schedule.user_id,
                "next_user_name": schedule.user_name,
                "new_level": next_level,
            }
        else:
            return {
                "success": False,
                "next_user_id": "",
                "next_user_name": "",
                "new_level": current_level,
            }
    finally:
        await session.close()


# ======================== gRPC SERVER ========================

class OnCallServiceImpl:
    async def GetCurrentOnCall(self, request, context):
        from generated import incidents_pb2
        data = await get_current_oncall(request.service_name)
        if data:
            return incidents_pb2.OnCallResponse(
                user_id=data["user_id"],
                user_name=data["user_name"],
                phone=data.get("phone", ""),
                email=data.get("email", ""),
                escalation_level=data["escalation_level"],
            )
        context.abort(grpc.StatusCode.NOT_FOUND, "No on-call schedule found")

    async def TriggerEscalation(self, request, context):
        from generated import incidents_pb2
        result = await trigger_escalation(
            incident_id=request.incident_id,
            service_name=request.service_name,
            current_level=request.current_level,
        )
        return incidents_pb2.EscalationResponse(
            success=result["success"],
            next_user_id=result["next_user_id"],
            next_user_name=result["next_user_name"],
            new_level=result["new_level"],
        )

    async def SetSchedule(self, request, context):
        from generated import incidents_pb2
        session = await get_session()
        try:
            # Delete existing schedule for this service
            await session.execute(
                delete(OnCallSchedule).where(
                    OnCallSchedule.service_name == request.service_name
                )
            )
            # Insert new entries
            for entry in request.entries:
                schedule = OnCallSchedule(
                    service_name=request.service_name,
                    user_id=entry.user_id,
                    user_name=entry.user_name,
                    escalation_level=entry.escalation_level,
                    start_time=datetime.utcfromtimestamp(entry.start_time),
                    end_time=datetime.utcfromtimestamp(entry.end_time),
                    phone=entry.phone,
                    email=entry.email,
                )
                session.add(schedule)
            await session.commit()
            SCHEDULE_UPDATES.inc()
            await cache_delete(f"oncall:{request.service_name}:current")
            return incidents_pb2.ScheduleResponse(success=True, message="Schedule updated")
        except Exception as e:
            await session.rollback()
            return incidents_pb2.ScheduleResponse(success=False, message=str(e))
        finally:
            await session.close()

    async def GetSchedule(self, request, context):
        from generated import incidents_pb2
        session = await get_session()
        try:
            result = await session.execute(
                select(OnCallSchedule).where(
                    OnCallSchedule.service_name == request.service_name
                ).order_by(OnCallSchedule.escalation_level)
            )
            schedules = result.scalars().all()
            entries = [
                incidents_pb2.ScheduleEntry(
                    user_id=s.user_id,
                    user_name=s.user_name,
                    escalation_level=s.escalation_level,
                    start_time=int(s.start_time.timestamp()),
                    end_time=int(s.end_time.timestamp()),
                    phone=s.phone or "",
                    email=s.email or "",
                )
                for s in schedules
            ]
            return incidents_pb2.ScheduleDetail(
                service_name=request.service_name,
                entries=entries,
            )
        finally:
            await session.close()


async def start_grpc_server():
    try:
        from generated import incidents_pb2_grpc
        server = grpc_aio.server(futures.ThreadPoolExecutor(max_workers=10))
        incidents_pb2_grpc.add_OnCallServiceServicer_to_server(OnCallServiceImpl(), server)
        port = os.getenv("ONCALL_GRPC_PORT", "50053")
        server.add_insecure_port(f"0.0.0.0:{port}")
        await server.start()
        logger.info(f"gRPC server started on port {port}")
        return server
    except ImportError:
        logger.warning("gRPC stubs not available, skipping gRPC server.")
        return None


# ======================== REST API ========================

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _db_engine, _session_factory
    logger.info("On-Call Service starting...")
    _db_engine = await wait_for_db(max_retries=15, delay=2.0)
    await init_db(_db_engine)
    _session_factory = get_async_session_factory(_db_engine)

    # Seed default schedules
    await _seed_default_schedules()

    grpc_server = await start_grpc_server()
    yield
    if grpc_server:
        await grpc_server.stop(grace=5)
    logger.info("On-Call Service shutdown complete.")


app = FastAPI(title="On-Call Service", version="1.0.0", lifespan=lifespan)


class ScheduleEntryModel(BaseModel):
    user_id: str
    user_name: str
    escalation_level: int = Field(ge=0, le=3)
    start_time: int  # Unix timestamp
    end_time: int
    phone: str = ""
    email: str = ""


class ScheduleSetRequest(BaseModel):
    service_name: str
    entries: List[ScheduleEntryModel]


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "oncall-service", "timestamp": datetime.utcnow().isoformat()}


@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/api/v1/oncall/{service_name}")
async def api_get_oncall(service_name: str):
    data = await get_current_oncall(service_name)
    if data:
        return data
    raise HTTPException(status_code=404, detail="No on-call found")


@app.get("/api/v1/schedules/{service_name}")
async def api_get_schedule(service_name: str):
    session = await get_session()
    try:
        result = await session.execute(
            select(OnCallSchedule).where(
                OnCallSchedule.service_name == service_name
            ).order_by(OnCallSchedule.escalation_level)
        )
        schedules = result.scalars().all()
        return {
            "service_name": service_name,
            "entries": [
                {
                    "user_id": s.user_id,
                    "user_name": s.user_name,
                    "escalation_level": s.escalation_level,
                    "start_time": s.start_time.isoformat(),
                    "end_time": s.end_time.isoformat(),
                    "phone": s.phone,
                    "email": s.email,
                }
                for s in schedules
            ],
        }
    finally:
        await session.close()


@app.post("/api/v1/schedules")
async def api_set_schedule(req: ScheduleSetRequest):
    session = await get_session()
    try:
        await session.execute(
            delete(OnCallSchedule).where(
                OnCallSchedule.service_name == req.service_name
            )
        )
        for entry in req.entries:
            s = OnCallSchedule(
                service_name=req.service_name,
                user_id=entry.user_id,
                user_name=entry.user_name,
                escalation_level=entry.escalation_level,
                start_time=datetime.utcfromtimestamp(entry.start_time),
                end_time=datetime.utcfromtimestamp(entry.end_time),
                phone=entry.phone,
                email=entry.email,
            )
            session.add(s)
        await session.commit()
        SCHEDULE_UPDATES.inc()
        await cache_delete(f"oncall:{req.service_name}:current")
        return {"success": True, "message": "Schedule updated"}
    finally:
        await session.close()


async def _seed_default_schedules():
    """Seed demo on-call schedules if none exist."""
    from sqlalchemy import func as sqlfunc
    session = await get_session()
    try:
        result = await session.execute(select(sqlfunc.count(OnCallSchedule.id)))
        count = result.scalar()
        if count and count > 0:
            return

        now = datetime.utcnow()
        far_future = now + timedelta(days=365)

        demo_services = ["api-gateway", "payment-service", "auth-service", "database-service"]
        demo_users = [
            ("user-001", "Alice Martin", "+33601010101", "alice@oncall.local"),
            ("user-002", "Bob Dupont", "+33602020202", "bob@oncall.local"),
            ("user-003", "Charlie Leclerc", "+33603030303", "charlie@oncall.local"),
            ("user-004", "Diana Prince", "+33604040404", "diana@oncall.local"),
        ]

        for svc in demo_services:
            for level, (uid, name, phone, email) in enumerate(demo_users):
                if level > MAX_ESCALATION_LEVEL:
                    break
                schedule = OnCallSchedule(
                    service_name=svc,
                    user_id=uid,
                    user_name=name,
                    escalation_level=level,
                    start_time=now,
                    end_time=far_future,
                    phone=phone,
                    email=email,
                )
                session.add(schedule)
        await session.commit()
        logger.info("Default on-call schedules seeded.")
    except Exception as e:
        logger.warning(f"Seed schedules failed: {e}")
        await session.rollback()
    finally:
        await session.close()


if __name__ == "__main__":
    import uvicorn
    from sqlalchemy import func
    port = int(os.getenv("ONCALL_HTTP_PORT", "8003"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
