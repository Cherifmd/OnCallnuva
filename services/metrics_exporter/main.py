"""
Service 5 - Metrics Exporter (Port 9090)
Dedicated service that aggregates business metrics from PostgreSQL
and exposes them in Prometheus exposition format.

Metrics exposed:
  - oncall_incidents_total{status, severity} – Incident counts
  - oncall_mtta_avg_seconds – Average MTTA
  - oncall_mttr_avg_seconds – Average MTTR
  - oncall_alerts_total – Total alert count
  - oncall_incidents_by_service{service} – Incidents per service
  - oncall_escalations_total – Total escalations
"""
import os
import sys
import logging
import asyncio
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI
from prometheus_client import (
    Gauge, Counter, generate_latest, CONTENT_TYPE_LATEST, CollectorRegistry, REGISTRY
)
from starlette.responses import Response
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from shared.models import (
    wait_for_db, init_db, get_async_session_factory,
    Incident, Alert, IncidentStatus, EscalationLog
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("metrics-exporter")

# ======================== BUSINESS METRICS (Prometheus Gauges) ========================
# Using Gauges since these are point-in-time aggregated values from the DB
INCIDENTS_TOTAL = Gauge("oncall_incidents_total", "Total incidents", ["status", "severity"])
INCIDENTS_OPEN = Gauge("oncall_incidents_open", "Open incidents count")
INCIDENTS_BY_SERVICE = Gauge("oncall_incidents_by_service", "Incidents per service", ["service", "status"])
ALERTS_TOTAL = Gauge("oncall_alerts_total", "Total alerts ingested")
AVG_MTTA = Gauge("oncall_mtta_avg_seconds", "Average Mean Time To Acknowledge")
AVG_MTTR = Gauge("oncall_mttr_avg_seconds", "Average Mean Time To Resolve")
P95_MTTA = Gauge("oncall_mtta_p95_seconds", "P95 MTTA")
P95_MTTR = Gauge("oncall_mttr_p95_seconds", "P95 MTTR")
ESCALATIONS_TOTAL = Gauge("oncall_escalations_total", "Total escalations performed")
SCRAPE_DURATION = Gauge("oncall_metrics_scrape_duration_seconds", "Time to collect metrics")

# ======================== GLOBAL STATE ========================
_db_engine = None
_session_factory = None
_refresh_interval = 10  # Refresh metrics from DB every 10s


async def get_session() -> AsyncSession:
    global _session_factory
    if _session_factory is None:
        _session_factory = get_async_session_factory(_db_engine)
    return _session_factory()


async def refresh_metrics():
    """Query PostgreSQL and update all Prometheus gauges."""
    import time
    start = time.time()

    session = await get_session()
    try:
        # ──── Incident counts by status & severity ────
        for status in ["triggered", "acknowledged", "resolved"]:
            for severity in ["critical", "high", "medium", "low"]:
                result = await session.execute(
                    select(func.count(Incident.id)).where(
                        and_(
                            Incident.status == status,
                            Incident.severity == severity,
                        )
                    )
                )
                count = result.scalar() or 0
                INCIDENTS_TOTAL.labels(status=status, severity=severity).set(count)

        # ──── Open incidents ────
        open_result = await session.execute(
            select(func.count(Incident.id)).where(
                Incident.status.in_([IncidentStatus.TRIGGERED, IncidentStatus.ACKNOWLEDGED])
            )
        )
        INCIDENTS_OPEN.set(open_result.scalar() or 0)

        # ──── Incidents by service ────
        svc_result = await session.execute(
            select(
                Incident.service_name,
                Incident.status,
                func.count(Incident.id)
            ).group_by(Incident.service_name, Incident.status)
        )
        for service_name, status, count in svc_result.all():
            INCIDENTS_BY_SERVICE.labels(service=service_name, status=status).set(count)

        # ──── Total alerts ────
        alerts_result = await session.execute(select(func.count(Alert.id)))
        ALERTS_TOTAL.set(alerts_result.scalar() or 0)

        # ──── Average MTTA ────
        avg_mtta_result = await session.execute(
            select(
                func.avg(
                    func.extract("epoch", Incident.acknowledged_at) -
                    func.extract("epoch", Incident.created_at)
                )
            ).where(Incident.acknowledged_at.isnot(None))
        )
        avg_mtta = avg_mtta_result.scalar()
        AVG_MTTA.set(float(avg_mtta) if avg_mtta else 0.0)

        # ──── Average MTTR ────
        avg_mttr_result = await session.execute(
            select(
                func.avg(
                    func.extract("epoch", Incident.resolved_at) -
                    func.extract("epoch", Incident.created_at)
                )
            ).where(Incident.resolved_at.isnot(None))
        )
        avg_mttr = avg_mttr_result.scalar()
        AVG_MTTR.set(float(avg_mttr) if avg_mttr else 0.0)

        # ──── P95 MTTA (approximate using percentile_cont) ────
        try:
            p95_mtta_result = await session.execute(
                select(
                    func.percentile_cont(0.95).within_group(
                        func.extract("epoch", Incident.acknowledged_at) -
                        func.extract("epoch", Incident.created_at)
                    )
                ).where(Incident.acknowledged_at.isnot(None))
            )
            p95_mtta = p95_mtta_result.scalar()
            P95_MTTA.set(float(p95_mtta) if p95_mtta else 0.0)
        except Exception:
            P95_MTTA.set(0.0)

        try:
            p95_mttr_result = await session.execute(
                select(
                    func.percentile_cont(0.95).within_group(
                        func.extract("epoch", Incident.resolved_at) -
                        func.extract("epoch", Incident.created_at)
                    )
                ).where(Incident.resolved_at.isnot(None))
            )
            p95_mttr = p95_mttr_result.scalar()
            P95_MTTR.set(float(p95_mttr) if p95_mttr else 0.0)
        except Exception:
            P95_MTTR.set(0.0)

        # ──── Escalations total ────
        esc_result = await session.execute(select(func.count(EscalationLog.id)))
        ESCALATIONS_TOTAL.set(esc_result.scalar() or 0)

        SCRAPE_DURATION.set(time.time() - start)
        logger.debug(f"Metrics refreshed in {time.time() - start:.3f}s")
    except Exception as e:
        logger.error(f"Error refreshing metrics: {e}")
    finally:
        await session.close()


async def _metrics_loop():
    """Background loop that refreshes metrics from DB periodically."""
    while True:
        try:
            await refresh_metrics()
        except Exception as e:
            logger.error(f"Metrics loop error: {e}")
        await asyncio.sleep(_refresh_interval)


# ======================== FASTAPI ========================
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _db_engine, _session_factory
    logger.info("Metrics Exporter starting...")
    _db_engine = await wait_for_db(max_retries=15, delay=2.0)
    await init_db(_db_engine)
    _session_factory = get_async_session_factory(_db_engine)

    task = asyncio.create_task(_metrics_loop())
    yield
    task.cancel()
    logger.info("Metrics Exporter shutdown.")


app = FastAPI(title="Metrics Exporter", version="1.0.0", lifespan=lifespan)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "metrics-exporter", "timestamp": datetime.utcnow().isoformat()}


@app.get("/metrics")
async def metrics():
    """Prometheus scrape endpoint."""
    # Force a refresh on scrape for freshness
    await refresh_metrics()
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("METRICS_HTTP_PORT", "9090"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
