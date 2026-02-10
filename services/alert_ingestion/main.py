"""
Service 1 - Alert Ingestion (Port 8001)
Receives HTTP alerts, validates the payload, and forwards them to
the Incident Management service via gRPC.
"""
import os
import sys
import uuid
import time
import json
import logging
import asyncio
from datetime import datetime
from contextlib import asynccontextmanager

import grpc
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from typing import Optional, Dict, List
from prometheus_client import (
    Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
)
from starlette.responses import Response

# Add parent to path for shared modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from shared.models import wait_for_db, init_db
from shared.redis_client import publish_event
from shared.tracing import init_tracing, instrument_fastapi
from shared.loki_logger import setup_loki_logging

# ======================== LOGGING ========================
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("alert-ingestion")

# ======================== PROMETHEUS METRICS ========================
ALERTS_RECEIVED = Counter("alerts_received_total", "Total alerts received", ["source", "severity"])
ALERTS_ACCEPTED = Counter("alerts_accepted_total", "Total alerts accepted")
ALERTS_REJECTED = Counter("alerts_rejected_total", "Total alerts rejected", ["reason"])
ALERT_PROCESSING_TIME = Histogram("alert_processing_seconds", "Alert processing latency")
GRPC_ERRORS = Counter("grpc_forward_errors_total", "gRPC forwarding errors")
ACTIVE_CONNECTIONS = Gauge("active_connections", "Current active connections")

# ======================== PYDANTIC MODELS ========================
VALID_SEVERITIES = {"critical", "high", "medium", "low"}


class AlertPayload(BaseModel):
    source: str = Field(..., min_length=1, max_length=128)
    service_name: str = Field(..., min_length=1, max_length=128)
    severity: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1, max_length=512)
    description: Optional[str] = ""
    labels: Optional[Dict[str, str]] = {}
    timestamp: Optional[int] = None

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v):
        if v.lower() not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {VALID_SEVERITIES}")
        return v.lower()

    @field_validator("source")
    @classmethod
    def sanitize_source(cls, v):
        # Basic SQL injection pattern check
        dangerous = ["'", '"', ";", "--", "/*", "*/", "xp_", "exec(", "union "]
        for pattern in dangerous:
            if pattern.lower() in v.lower():
                raise ValueError(f"Potentially dangerous pattern detected in source")
        return v


class AlertBatchPayload(BaseModel):
    alerts: List[AlertPayload] = Field(..., min_length=1, max_length=100)


# ======================== gRPC STUB ========================
# Generated protobuf stubs will be imported here
_grpc_channel = None
_grpc_stub = None


def _get_grpc_stub():
    """Lazy initialization of gRPC stub to Incident Management service."""
    global _grpc_channel, _grpc_stub
    if _grpc_stub is None:
        host = os.getenv("INCIDENT_MGMT_HOST", "incident-management")
        port = os.getenv("INCIDENT_MGMT_GRPC_PORT", "50052")
        _grpc_channel = grpc.insecure_channel(
            f"{host}:{port}",
            options=[
                ("grpc.keepalive_time_ms", 10000),
                ("grpc.keepalive_timeout_ms", 5000),
                ("grpc.max_send_message_length", 50 * 1024 * 1024),
                ("grpc.max_receive_message_length", 50 * 1024 * 1024),
            ]
        )
        # Import generated stubs
        try:
            from generated import incidents_pb2_grpc
            _grpc_stub = incidents_pb2_grpc.AlertServiceStub(_grpc_channel)
        except ImportError:
            logger.warning("gRPC stubs not generated yet. Running in HTTP-only mode.")
            _grpc_stub = None
    return _grpc_stub


async def forward_to_incident_manager(alert_payload: AlertPayload) -> dict:
    """Forward validated alert to Incident Management service via gRPC."""
    try:
        from generated import incidents_pb2
        stub = _get_grpc_stub()
        if stub is None:
            return {"alert_id": str(uuid.uuid4()), "status": "accepted_local", "incident_id": ""}

        request = incidents_pb2.AlertRequest(
            source=alert_payload.source,
            service_name=alert_payload.service_name,
            severity=alert_payload.severity,
            title=alert_payload.title,
            description=alert_payload.description or "",
            labels=alert_payload.labels or {},
            timestamp=alert_payload.timestamp or int(time.time()),
        )

        response = stub.IngestAlert(request, timeout=5.0)
        return {
            "alert_id": response.alert_id,
            "status": response.status,
            "incident_id": response.incident_id,
        }
    except grpc.RpcError as e:
        GRPC_ERRORS.inc()
        logger.error(f"gRPC error forwarding alert: {e.code()} - {e.details()}")
        raise HTTPException(status_code=503, detail=f"Incident Manager unavailable: {e.details()}")
    except ImportError:
        # Fallback: accept alert locally
        alert_id = str(uuid.uuid4())
        logger.info(f"gRPC stubs unavailable, accepted alert locally: {alert_id}")
        return {"alert_id": alert_id, "status": "accepted_local", "incident_id": ""}


# ======================== FASTAPI APP ========================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    logger.info("Alert Ingestion Service starting...")

    # Bonus 6: Initialize distributed tracing
    init_tracing("alert-ingestion")

    # Bonus 5: Ship logs to Loki
    setup_loki_logging("alert-ingestion")

    try:
        engine = await wait_for_db(max_retries=15, delay=2.0)
        await init_db(engine)
        logger.info("Database ready.")
    except Exception as e:
        logger.warning(f"DB init skipped (will retry on first request): {e}")
    yield
    logger.info("Alert Ingestion Service shutting down.")
    if _grpc_channel:
        _grpc_channel.close()


app = FastAPI(
    title="Alert Ingestion Service",
    version="1.0.0",
    lifespan=lifespan,
)

# Bonus 6: Instrument FastAPI for distributed tracing (must be before startup)
instrument_fastapi(app)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "alert-ingestion", "timestamp": datetime.utcnow().isoformat()}


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/api/v1/alerts", status_code=202)
async def ingest_alert(alert: AlertPayload, request: Request):
    """
    Ingest a single alert.
    Validates the payload, then forwards to Incident Management via gRPC.
    """
    ACTIVE_CONNECTIONS.inc()
    start = time.time()
    try:
        ALERTS_RECEIVED.labels(source=alert.source, severity=alert.severity).inc()

        if alert.timestamp is None:
            alert.timestamp = int(time.time())

        result = await forward_to_incident_manager(alert)
        ALERTS_ACCEPTED.inc()

        # Publish real-time event
        await publish_event("alerts:new", {
            "alert_id": result["alert_id"],
            "service": alert.service_name,
            "severity": alert.severity,
            "title": alert.title,
            "timestamp": alert.timestamp,
        })

        return {
            "alert_id": result["alert_id"],
            "status": result["status"],
            "incident_id": result.get("incident_id", ""),
            "message": "Alert accepted and forwarded for processing",
        }
    except HTTPException:
        raise
    except Exception as e:
        ALERTS_REJECTED.labels(reason="internal_error").inc()
        logger.error(f"Error processing alert: {e}")
        raise HTTPException(status_code=500, detail="Internal processing error")
    finally:
        ALERT_PROCESSING_TIME.observe(time.time() - start)
        ACTIVE_CONNECTIONS.dec()


@app.post("/api/v1/alerts/batch", status_code=202)
async def ingest_alert_batch(batch: AlertBatchPayload):
    """Ingest a batch of alerts."""
    results = []
    accepted = 0
    rejected = 0

    for alert in batch.alerts:
        try:
            if alert.timestamp is None:
                alert.timestamp = int(time.time())
            result = await forward_to_incident_manager(alert)
            results.append(result)
            accepted += 1
            ALERTS_ACCEPTED.inc()
        except Exception as e:
            results.append({"alert_id": "", "status": "rejected", "error": str(e)})
            rejected += 1
            ALERTS_REJECTED.labels(reason="batch_item_error").inc()

    return {
        "accepted": accepted,
        "rejected": rejected,
        "total": len(batch.alerts),
        "results": results,
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("ALERT_INGESTION_HTTP_PORT", "8001"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
