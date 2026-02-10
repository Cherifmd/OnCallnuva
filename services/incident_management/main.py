"""
Service 2 - Incident Management (Port 8002)
Core of the system. Implements:
  - Alert correlation algorithm (group by service + severity over 5-min window)
  - MTTA / MTTR computation
  - gRPC server for receiving alerts from Alert Ingestion
  - REST API for incident queries, acknowledge, resolve
"""
import os
import sys
import uuid
import time
import json
import logging
import asyncio
from datetime import datetime, timedelta
from concurrent import futures
from contextlib import asynccontextmanager
from typing import Optional, List

import grpc
from grpc import aio as grpc_aio
from fastapi import FastAPI, HTTPException, Query, Request
from pydantic import BaseModel
from prometheus_client import (
    Counter, Histogram, Gauge, Summary, generate_latest, CONTENT_TYPE_LATEST
)
from starlette.responses import Response
from sqlalchemy import select, func, and_, update
from sqlalchemy.ext.asyncio import AsyncSession

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from shared.models import (
    wait_for_db, init_db, get_async_session_factory,
    Alert, Incident, IncidentStatus, SeverityLevel
)
from shared.redis_client import get_redis, cache_set, cache_get, cache_delete, publish_event
from shared.notifications import (
    send_notification_email, build_incident_email,
    dispatch_webhook, register_webhook, unregister_webhook, list_webhooks,
    load_webhooks_from_redis, save_webhooks_to_redis,
)
from shared.tracing import init_tracing, instrument_fastapi
from shared.loki_logger import setup_loki_logging
from shared.auth import verify_jwt_token, get_token_from_request

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("incident-management")

# JWT auth for API endpoints (enabled via env var)
JWT_AUTH_ENABLED = os.getenv("JWT_AUTH_API", "false").lower() == "true"


def _check_api_auth(request: Request):
    """Check JWT auth on API endpoints when enabled."""
    if not JWT_AUTH_ENABLED:
        return  # Skip auth check if not enabled
    token = get_token_from_request(request)
    if not token or not verify_jwt_token(token):
        raise HTTPException(status_code=401, detail="Authentication required. Provide a valid Bearer token.")

# ======================== PROMETHEUS METRICS ========================
INCIDENTS_TOTAL = Counter("incidents_total", "Total incident state transitions", ["status"])
INCIDENT_CREATIONS = Counter("incident_creations_total", "Total incidents created", ["severity"])
INCIDENTS_CORRELATED = Counter("alerts_correlated_total", "Alerts correlated or created", ["result"])
INCIDENTS_ACKNOWLEDGED = Counter("incidents_acknowledged_total", "Incidents acknowledged")
INCIDENTS_RESOLVED = Counter("incidents_resolved_total", "Incidents resolved")
NOTIFICATIONS_SENT = Counter("oncall_notifications_sent_total", "Total notifications sent", ["channel"])
MTTA_HISTOGRAM = Histogram("mtta_seconds", "Mean Time To Acknowledge", buckets=[30, 60, 120, 300, 600, 1800, 3600])
MTTR_HISTOGRAM = Histogram("mttr_seconds", "Mean Time To Resolve", buckets=[60, 300, 600, 1800, 3600, 7200, 14400])
OPEN_INCIDENTS = Gauge("open_incidents_count", "Current open incidents")
CORRELATION_TIME = Histogram("correlation_engine_seconds", "Correlation engine processing time")

# ======================== GLOBAL STATE ========================
_db_engine = None
_session_factory = None

CORRELATION_WINDOW = int(os.getenv("CORRELATION_WINDOW_SECONDS", "300"))

# ======================== CORRELATION ENGINE ========================

async def get_session() -> AsyncSession:
    global _session_factory
    if _session_factory is None:
        _session_factory = get_async_session_factory(_db_engine)
    return _session_factory()


async def correlate_alert(
    source: str,
    service_name: str,
    severity: str,
    title: str,
    description: str,
    labels: dict,
    timestamp: int,
) -> dict:
    """
    ╔══════════════════════════════════════════════════════════════════╗
    ║                 CORRELATION ALGORITHM                          ║
    ║                                                                ║
    ║  Purpose: Group related alerts into a single incident to       ║
    ║  reduce noise and provide actionable context.                  ║
    ║                                                                ║
    ║  Algorithm Steps:                                              ║
    ║  1. Compute a correlation key = hash(service_name + severity)  ║
    ║  2. Search for an OPEN incident (triggered/acknowledged)       ║
    ║     matching (service_name, severity) created within the       ║
    ║     last CORRELATION_WINDOW seconds (default: 5 minutes).      ║
    ║  3a. If a matching incident exists:                            ║
    ║      → Attach the alert to this incident (deduplicate)         ║
    ║      → Increment alert_count                                   ║
    ║      → Return status="correlated"                              ║
    ║  3b. If no matching incident:                                  ║
    ║      → Create a new incident                                   ║
    ║      → Link the alert to it                                    ║
    ║      → Trigger on-call notification via gRPC                   ║
    ║      → Return status="new_incident"                            ║
    ║                                                                ║
    ║  Complexity: O(1) amortized with DB index on                   ║
    ║  (service_name, severity, created_at)                          ║
    ╚══════════════════════════════════════════════════════════════════╝
    """
    start = time.time()
    alert_id = str(uuid.uuid4())
    alert_ts = datetime.utcfromtimestamp(timestamp)
    window_start = alert_ts - timedelta(seconds=CORRELATION_WINDOW)

    session = await get_session()
    try:
        # Step 1 & 2: Search for existing open incident within correlation window
        result = await session.execute(
            select(Incident).where(
                and_(
                    Incident.service_name == service_name,
                    Incident.severity == severity,
                    Incident.status.in_([IncidentStatus.TRIGGERED, IncidentStatus.ACKNOWLEDGED]),
                    Incident.created_at >= window_start,
                )
            ).order_by(Incident.created_at.desc()).limit(1)
        )
        existing_incident = result.scalar_one_or_none()

        # Create the alert record
        alert = Alert(
            id=alert_id,
            source=source,
            service_name=service_name,
            severity=severity,
            title=title,
            description=description,
            labels=json.dumps(labels) if labels else "{}",
            timestamp=alert_ts,
        )

        if existing_incident:
            # Step 3a: Correlate into existing incident
            alert.incident_id = existing_incident.id
            existing_incident.alert_count += 1
            session.add(alert)
            await session.commit()

            INCIDENTS_CORRELATED.labels(result="correlated").inc()
            logger.info(
                f"Alert {alert_id} correlated into incident {existing_incident.id} "
                f"(count: {existing_incident.alert_count})"
            )
            CORRELATION_TIME.observe(time.time() - start)
            return {
                "alert_id": alert_id,
                "status": "correlated",
                "incident_id": existing_incident.id,
            }
        else:
            # Step 3b: Create new incident
            incident_id = str(uuid.uuid4())
            incident = Incident(
                id=incident_id,
                title=f"[{severity.upper()}] {title}",
                description=description,
                severity=severity,
                status=IncidentStatus.TRIGGERED,
                service_name=service_name,
                created_at=alert_ts,
                alert_count=1,
            )
            alert.incident_id = incident_id
            session.add(incident)
            session.add(alert)
            await session.commit()

            INCIDENT_CREATIONS.labels(severity=severity).inc()
            INCIDENTS_TOTAL.labels(status="triggered").inc()
            INCIDENTS_CORRELATED.labels(result="new_incident").inc()
            OPEN_INCIDENTS.inc()
            logger.info(f"New incident {incident_id} created from alert {alert_id}")

            # Publish event for real-time UI
            await publish_event("incidents:new", {
                "incident_id": incident_id,
                "severity": severity,
                "service_name": service_name,
                "title": incident.title,
            })

            # Webhook notification (Bonus 2)
            NOTIFICATIONS_SENT.labels(channel="webhook").inc()
            asyncio.create_task(dispatch_webhook("incident.new", {
                "incident_id": incident_id,
                "title": incident.title,
                "severity": severity,
                "service_name": service_name,
            }))

            # Trigger on-call notification (async, non-blocking)
            asyncio.create_task(_notify_oncall(incident_id, service_name, severity))

            CORRELATION_TIME.observe(time.time() - start)
            return {
                "alert_id": alert_id,
                "status": "new_incident",
                "incident_id": incident_id,
            }
    except Exception as e:
        await session.rollback()
        logger.error(f"Correlation error: {e}")
        raise
    finally:
        await session.close()


async def _notify_oncall(incident_id: str, service_name: str, severity: str):
    """Notify on-call service about a new incident via gRPC."""
    try:
        from generated import incidents_pb2, incidents_pb2_grpc
        host = os.getenv("ONCALL_HOST", "oncall-service")
        port = os.getenv("ONCALL_GRPC_PORT", "50053")
        async with grpc_aio.insecure_channel(f"{host}:{port}") as channel:
            stub = incidents_pb2_grpc.OnCallServiceStub(channel)
            response = await stub.GetCurrentOnCall(
                incidents_pb2.OnCallQuery(service_name=service_name),
                timeout=5.0,
            )
            if response.user_id:
                # Update incident assignment
                session = await get_session()
                try:
                    await session.execute(
                        update(Incident).where(Incident.id == incident_id).values(
                            assigned_to=response.user_name,
                            escalation_level=response.escalation_level,
                        )
                    )
                    await session.commit()
                finally:
                    await session.close()
                logger.info(f"Incident {incident_id} assigned to {response.user_name}")

                # Bonus 1: Send email notification to on-call responder
                if response.email:
                    subject, html = build_incident_email(
                        incident_id, f"[{severity.upper()}] Alert on {service_name}",
                        severity, service_name, response.user_name, event="new"
                    )
                    NOTIFICATIONS_SENT.labels(channel="email").inc()
                    asyncio.create_task(send_notification_email(response.email, subject, html))
    except Exception as e:
        logger.warning(f"On-call notification failed for {incident_id}: {e}")


# ======================== gRPC SERVER ========================

class AlertServiceImpl:
    """gRPC implementation of AlertService - receives alerts from Alert Ingestion."""

    async def IngestAlert(self, request, context):
        from generated import incidents_pb2
        try:
            result = await correlate_alert(
                source=request.source,
                service_name=request.service_name,
                severity=request.severity,
                title=request.title,
                description=request.description,
                labels=dict(request.labels),
                timestamp=request.timestamp or int(time.time()),
            )
            return incidents_pb2.AlertResponse(
                alert_id=result["alert_id"],
                status=result["status"],
                incident_id=result["incident_id"],
            )
        except Exception as e:
            context.abort(grpc.StatusCode.INTERNAL, str(e))

    async def IngestAlertBatch(self, request, context):
        from generated import incidents_pb2
        responses = []
        accepted = 0
        rejected = 0
        for alert_req in request.alerts:
            try:
                result = await correlate_alert(
                    source=alert_req.source,
                    service_name=alert_req.service_name,
                    severity=alert_req.severity,
                    title=alert_req.title,
                    description=alert_req.description,
                    labels=dict(alert_req.labels),
                    timestamp=alert_req.timestamp or int(time.time()),
                )
                responses.append(incidents_pb2.AlertResponse(
                    alert_id=result["alert_id"],
                    status=result["status"],
                    incident_id=result["incident_id"],
                ))
                accepted += 1
            except Exception:
                responses.append(incidents_pb2.AlertResponse(
                    alert_id="", status="rejected", incident_id=""
                ))
                rejected += 1
        return incidents_pb2.AlertBatchResponse(
            responses=responses,
            accepted_count=accepted,
            rejected_count=rejected,
        )


async def start_grpc_server():
    """Start the async gRPC server."""
    try:
        from generated import incidents_pb2_grpc
        server = grpc_aio.server(
            futures.ThreadPoolExecutor(max_workers=10),
            options=[
                ("grpc.max_send_message_length", 50 * 1024 * 1024),
                ("grpc.max_receive_message_length", 50 * 1024 * 1024),
            ]
        )
        incidents_pb2_grpc.add_AlertServiceServicer_to_server(AlertServiceImpl(), server)
        port = os.getenv("INCIDENT_MGMT_GRPC_PORT", "50052")
        server.add_insecure_port(f"0.0.0.0:{port}")
        await server.start()
        logger.info(f"gRPC server started on port {port}")
        return server
    except ImportError:
        logger.warning("gRPC stubs not available, skipping gRPC server.")
        return None


# ======================== REST API (FastAPI) ========================

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _db_engine, _session_factory
    logger.info("Incident Management Service starting...")

    # Bonus 6: Initialize distributed tracing
    init_tracing("incident-management")

    # Bonus 5: Ship logs to Loki
    setup_loki_logging("incident-management")

    _db_engine = await wait_for_db(max_retries=15, delay=2.0)
    await init_db(_db_engine)
    _session_factory = get_async_session_factory(_db_engine)

    # Start gRPC server in background
    grpc_server = await start_grpc_server()

    # Load webhooks from Redis
    await load_webhooks_from_redis()

    # Start escalation monitor
    escalation_task = asyncio.create_task(_escalation_monitor())

    yield

    if grpc_server:
        await grpc_server.stop(grace=5)
    escalation_task.cancel()
    logger.info("Incident Management Service shutdown complete.")


app = FastAPI(title="Incident Management Service", version="1.0.0", lifespan=lifespan)

# Bonus 6: Instrument FastAPI for distributed tracing (must be before startup)
instrument_fastapi(app)


class AcknowledgeRequest(BaseModel):
    user_id: str


class ResolveRequest(BaseModel):
    user_id: str
    resolution_note: Optional[str] = ""


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "incident-management", "timestamp": datetime.utcnow().isoformat()}


@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/api/v1/incidents")
async def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    service_name: Optional[str] = None,
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
):
    """List incidents with optional filters."""
    session = await get_session()
    try:
        query = select(Incident)
        if status:
            query = query.where(Incident.status == status)
        if severity:
            query = query.where(Incident.severity == severity)
        if service_name:
            query = query.where(Incident.service_name == service_name)

        # Count
        count_query = select(func.count()).select_from(query.subquery())
        count_result = await session.execute(count_query)
        total = count_result.scalar()

        # Fetch
        query = query.order_by(Incident.created_at.desc()).limit(limit).offset(offset)
        result = await session.execute(query)
        incidents = result.scalars().all()

        return {
            "total": total,
            "incidents": [
                {
                    "id": inc.id,
                    "title": inc.title,
                    "severity": inc.severity,
                    "status": inc.status,
                    "service_name": inc.service_name,
                    "created_at": inc.created_at.isoformat() if inc.created_at else None,
                    "acknowledged_at": inc.acknowledged_at.isoformat() if inc.acknowledged_at else None,
                    "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
                    "assigned_to": inc.assigned_to,
                    "alert_count": inc.alert_count,
                    "escalation_level": inc.escalation_level,
                    "mtta_seconds": inc.mtta_seconds,
                    "mttr_seconds": inc.mttr_seconds,
                }
                for inc in incidents
            ],
        }
    finally:
        await session.close()


@app.get("/api/v1/incidents/{incident_id}")
async def get_incident(incident_id: str):
    session = await get_session()
    try:
        result = await session.execute(
            select(Incident).where(Incident.id == incident_id)
        )
        inc = result.scalar_one_or_none()
        if not inc:
            raise HTTPException(status_code=404, detail="Incident not found")

        # Fetch associated alerts
        alerts_result = await session.execute(
            select(Alert).where(Alert.incident_id == incident_id)
        )
        alerts = alerts_result.scalars().all()

        return {
            "id": inc.id,
            "title": inc.title,
            "description": inc.description,
            "severity": inc.severity,
            "status": inc.status,
            "service_name": inc.service_name,
            "created_at": inc.created_at.isoformat() if inc.created_at else None,
            "acknowledged_at": inc.acknowledged_at.isoformat() if inc.acknowledged_at else None,
            "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
            "assigned_to": inc.assigned_to,
            "alert_count": inc.alert_count,
            "escalation_level": inc.escalation_level,
            "mtta_seconds": inc.mtta_seconds,
            "mttr_seconds": inc.mttr_seconds,
            "resolution_note": inc.resolution_note,
            "alerts": [
                {
                    "id": a.id,
                    "source": a.source,
                    "title": a.title,
                    "severity": a.severity,
                    "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                }
                for a in alerts
            ],
        }
    finally:
        await session.close()


@app.post("/api/v1/incidents/{incident_id}/acknowledge")
async def acknowledge_incident(incident_id: str, req: AcknowledgeRequest, request: Request):
    """Acknowledge an incident - computes MTTA."""
    _check_api_auth(request)
    session = await get_session()
    try:
        result = await session.execute(
            select(Incident).where(Incident.id == incident_id)
        )
        inc = result.scalar_one_or_none()
        if not inc:
            raise HTTPException(status_code=404, detail="Incident not found")
        if inc.status == IncidentStatus.RESOLVED:
            raise HTTPException(status_code=400, detail="Incident already resolved")
        if inc.status == IncidentStatus.ACKNOWLEDGED:
            raise HTTPException(status_code=400, detail="Incident already acknowledged")

        now = datetime.utcnow()
        inc.status = IncidentStatus.ACKNOWLEDGED
        inc.acknowledged_at = now
        inc.assigned_to = req.user_id
        await session.commit()

        mtta = inc.mtta_seconds
        MTTA_HISTOGRAM.observe(mtta)
        INCIDENTS_ACKNOWLEDGED.inc()
        INCIDENTS_TOTAL.labels(status="acknowledged").inc()

        await publish_event("incidents:ack", {
            "incident_id": incident_id,
            "user_id": req.user_id,
            "mtta_seconds": mtta,
        })

        # Webhook notification (Bonus 2)
        NOTIFICATIONS_SENT.labels(channel="webhook").inc()
        asyncio.create_task(dispatch_webhook("incident.acknowledged", {
            "incident_id": incident_id,
            "user_id": req.user_id,
            "mtta_seconds": mtta,
        }))

        return {"success": True, "mtta_seconds": mtta, "message": "Incident acknowledged"}
    finally:
        await session.close()


@app.post("/api/v1/incidents/{incident_id}/resolve")
async def resolve_incident(incident_id: str, req: ResolveRequest, request: Request):
    """Resolve an incident - computes MTTR."""
    _check_api_auth(request)
    session = await get_session()
    try:
        result = await session.execute(
            select(Incident).where(Incident.id == incident_id)
        )
        inc = result.scalar_one_or_none()
        if not inc:
            raise HTTPException(status_code=404, detail="Incident not found")
        if inc.status == IncidentStatus.RESOLVED:
            raise HTTPException(status_code=400, detail="Incident already resolved")

        now = datetime.utcnow()
        inc.status = IncidentStatus.RESOLVED
        inc.resolved_at = now
        inc.resolution_note = req.resolution_note
        if not inc.acknowledged_at:
            inc.acknowledged_at = now
        await session.commit()

        mttr = inc.mttr_seconds
        MTTR_HISTOGRAM.observe(mttr)
        INCIDENTS_RESOLVED.inc()
        INCIDENTS_TOTAL.labels(status="resolved").inc()
        OPEN_INCIDENTS.dec()

        # Clear cache
        await cache_delete(f"incident:{incident_id}")

        await publish_event("incidents:resolved", {
            "incident_id": incident_id,
            "user_id": req.user_id,
            "mttr_seconds": mttr,
        })

        # Webhook notification (Bonus 2)
        NOTIFICATIONS_SENT.labels(channel="webhook").inc()
        asyncio.create_task(dispatch_webhook("incident.resolved", {
            "incident_id": incident_id,
            "user_id": req.user_id,
            "mttr_seconds": mttr,
            "resolution_note": req.resolution_note,
        }))

        return {"success": True, "mttr_seconds": mttr, "message": "Incident resolved"}
    finally:
        await session.close()


@app.get("/api/v1/stats")
async def get_stats():
    """Aggregate statistics for the dashboard."""
    session = await get_session()
    try:
        # Try cache first
        cached = await cache_get("stats:dashboard")
        if cached:
            return cached

        total = (await session.execute(select(func.count(Incident.id)))).scalar() or 0
        open_count = (await session.execute(
            select(func.count(Incident.id)).where(Incident.status == IncidentStatus.TRIGGERED)
        )).scalar() or 0
        ack_count = (await session.execute(
            select(func.count(Incident.id)).where(Incident.status == IncidentStatus.ACKNOWLEDGED)
        )).scalar() or 0
        resolved_count = (await session.execute(
            select(func.count(Incident.id)).where(Incident.status == IncidentStatus.RESOLVED)
        )).scalar() or 0

        # Average MTTA (only for acknowledged incidents)
        avg_mtta_result = await session.execute(
            select(
                func.avg(
                    func.extract("epoch", Incident.acknowledged_at) -
                    func.extract("epoch", Incident.created_at)
                )
            ).where(Incident.acknowledged_at.isnot(None))
        )
        avg_mtta = avg_mtta_result.scalar() or 0.0

        # Average MTTR (only for resolved incidents)
        avg_mttr_result = await session.execute(
            select(
                func.avg(
                    func.extract("epoch", Incident.resolved_at) -
                    func.extract("epoch", Incident.created_at)
                )
            ).where(Incident.resolved_at.isnot(None))
        )
        avg_mttr = avg_mttr_result.scalar() or 0.0

        stats = {
            "total_incidents": total,
            "open_incidents": open_count,
            "acknowledged_incidents": ack_count,
            "resolved_incidents": resolved_count,
            "avg_mtta_seconds": round(float(avg_mtta), 2),
            "avg_mttr_seconds": round(float(avg_mttr), 2),
        }

        await cache_set("stats:dashboard", stats, ttl=30)
        return stats
    finally:
        await session.close()


async def _escalation_monitor():
    """
    Background task: Check for unacknowledged incidents past the escalation timeout
    and trigger escalation via the On-Call service.
    """
    timeout = int(os.getenv("ESCALATION_TIMEOUT_SECONDS", "120"))
    while True:
        try:
            await asyncio.sleep(30)  # Check every 30 seconds
            session = await get_session()
            try:
                cutoff = datetime.utcnow() - timedelta(seconds=timeout)
                result = await session.execute(
                    select(Incident).where(
                        and_(
                            Incident.status == IncidentStatus.TRIGGERED,
                            Incident.created_at <= cutoff,
                        )
                    )
                )
                stale_incidents = result.scalars().all()
                for inc in stale_incidents:
                    logger.info(f"Escalating incident {inc.id} (no ack after {timeout}s)")
                    try:
                        from generated import incidents_pb2, incidents_pb2_grpc
                        host = os.getenv("ONCALL_HOST", "oncall-service")
                        port = os.getenv("ONCALL_GRPC_PORT", "50053")
                        async with grpc_aio.insecure_channel(f"{host}:{port}") as channel:
                            stub = incidents_pb2_grpc.OnCallServiceStub(channel)
                            resp = await stub.TriggerEscalation(
                                incidents_pb2.EscalationRequest(
                                    incident_id=inc.id,
                                    service_name=inc.service_name,
                                    current_level=inc.escalation_level,
                                ),
                                timeout=5.0,
                            )
                            if resp.success:
                                inc.escalation_level = resp.new_level
                                inc.assigned_to = resp.next_user_name
                                await session.commit()
                                INCIDENTS_TOTAL.labels(status="escalated").inc()
                                # Dispatch escalation webhook + email (Bonus 1 & 2)
                                NOTIFICATIONS_SENT.labels(channel="webhook").inc()
                                asyncio.create_task(dispatch_webhook("incident.escalated", {
                                    "incident_id": inc.id,
                                    "service_name": inc.service_name,
                                    "new_level": resp.new_level,
                                    "assigned_to": resp.next_user_name,
                                }))
                    except Exception as e:
                        logger.warning(f"Escalation gRPC call failed: {e}")
            finally:
                await session.close()
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Escalation monitor error: {e}")


# ======================== WEBHOOK API (Bonus 2) ========================

class WebhookRegisterRequest(BaseModel):
    url: str
    events: List[str]
    secret: Optional[str] = ""


@app.post("/api/v1/webhooks")
async def api_register_webhook(req: WebhookRegisterRequest, request: Request):
    """Register a webhook endpoint for incident events."""
    _check_api_auth(request)
    result = register_webhook(req.url, req.events, req.secret or "")
    await save_webhooks_to_redis()
    return result


@app.get("/api/v1/webhooks")
async def api_list_webhooks():
    """List all registered webhooks."""
    return {"webhooks": list_webhooks()}


@app.delete("/api/v1/webhooks/{webhook_id}")
async def api_delete_webhook(webhook_id: str, request: Request):
    """Remove a webhook."""
    _check_api_auth(request)
    removed = unregister_webhook(webhook_id)
    if removed:
        await save_webhooks_to_redis()
        return {"success": True, "message": "Webhook removed"}
    raise HTTPException(status_code=404, detail="Webhook not found")


# ======================== HISTORICAL ANALYTICS (Bonus 4) ========================

@app.get("/api/v1/analytics/trends")
async def analytics_trends(
    period: str = Query(default="7d", description="Period: 1d, 7d, 30d, 90d"),
    bucket: str = Query(default="1d", description="Bucket: 1h, 6h, 1d"),
):
    """
    Historical incident analytics - time-bucketed trends.
    Returns incidents per bucket with MTTA/MTTR trends.
    """
    period_map = {"1d": 1, "7d": 7, "30d": 30, "90d": 90}
    bucket_map = {"1h": 1, "6h": 6, "1d": 24, "1w": 168}

    days = period_map.get(period, 7)
    bucket_hours = bucket_map.get(bucket, 24)

    session = await get_session()
    try:
        start_date = datetime.utcnow() - timedelta(days=days)

        # Fetch all incidents in the period
        result = await session.execute(
            select(Incident).where(Incident.created_at >= start_date).order_by(Incident.created_at)
        )
        incidents = result.scalars().all()

        # Time-bucket aggregation
        buckets = {}
        current = start_date
        now = datetime.utcnow()
        while current < now:
            bucket_key = current.strftime("%Y-%m-%dT%H:00:00")
            buckets[bucket_key] = {
                "timestamp": bucket_key,
                "incidents_created": 0,
                "incidents_resolved": 0,
                "critical": 0, "high": 0, "medium": 0, "low": 0,
                "mtta_values": [],
                "mttr_values": [],
            }
            current += timedelta(hours=bucket_hours)

        for inc in incidents:
            bk = inc.created_at.replace(
                hour=(inc.created_at.hour // bucket_hours) * bucket_hours,
                minute=0, second=0, microsecond=0
            ).strftime("%Y-%m-%dT%H:00:00")
            if bk in buckets:
                buckets[bk]["incidents_created"] += 1
                sev = inc.severity if inc.severity in ("critical", "high", "medium", "low") else "low"
                buckets[bk][sev] += 1
                if inc.resolved_at:
                    buckets[bk]["incidents_resolved"] += 1
                if inc.mtta_seconds > 0:
                    buckets[bk]["mtta_values"].append(inc.mtta_seconds)
                if inc.mttr_seconds > 0:
                    buckets[bk]["mttr_values"].append(inc.mttr_seconds)

        # Compute averages per bucket
        trend_data = []
        for bk in sorted(buckets.keys()):
            b = buckets[bk]
            mtta_vals = b.pop("mtta_values")
            mttr_vals = b.pop("mttr_values")
            b["avg_mtta_seconds"] = round(sum(mtta_vals) / len(mtta_vals), 2) if mtta_vals else 0
            b["avg_mttr_seconds"] = round(sum(mttr_vals) / len(mttr_vals), 2) if mttr_vals else 0
            trend_data.append(b)

        # Top services by incident count
        service_counts = {}
        for inc in incidents:
            service_counts[inc.service_name] = service_counts.get(inc.service_name, 0) + 1
        top_services = sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "period": period,
            "bucket_size": bucket,
            "total_incidents": len(incidents),
            "total_resolved": sum(1 for i in incidents if i.resolved_at),
            "trends": trend_data,
            "top_services": [{"service": s, "count": c} for s, c in top_services],
        }
    finally:
        await session.close()


@app.get("/api/v1/analytics/mttr-distribution")
async def analytics_mttr_distribution():
    """MTTR distribution histogram for resolved incidents."""
    session = await get_session()
    try:
        result = await session.execute(
            select(Incident).where(Incident.resolved_at.isnot(None))
        )
        incidents = result.scalars().all()

        # Buckets in minutes
        distribution = {"<5m": 0, "5-15m": 0, "15-30m": 0, "30-60m": 0, "1-4h": 0, ">4h": 0}
        for inc in incidents:
            mttr_min = inc.mttr_seconds / 60
            if mttr_min < 5:
                distribution["<5m"] += 1
            elif mttr_min < 15:
                distribution["5-15m"] += 1
            elif mttr_min < 30:
                distribution["15-30m"] += 1
            elif mttr_min < 60:
                distribution["30-60m"] += 1
            elif mttr_min < 240:
                distribution["1-4h"] += 1
            else:
                distribution[">4h"] += 1

        return {"distribution": distribution, "total_resolved": len(incidents)}
    finally:
        await session.close()


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("INCIDENT_MGMT_HTTP_PORT", "8002"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
