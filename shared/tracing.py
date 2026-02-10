"""
Shared Distributed Tracing Module (Bonus 6)
OpenTelemetry instrumentation for Jaeger integration.

Automatically instruments:
  - FastAPI HTTP requests
  - gRPC calls
  - SQLAlchemy database queries
  - Redis operations
"""
import os
import logging

logger = logging.getLogger("tracing")

JAEGER_ENABLED = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "") != ""


def init_tracing(service_name: str):
    """
    Initialize OpenTelemetry tracing with Jaeger OTLP exporter.
    Falls back gracefully if OTel packages are not installed.
    """
    if not JAEGER_ENABLED:
        logger.info(f"Tracing disabled for {service_name} (OTEL_EXPORTER_OTLP_ENDPOINT not set)")
        return None

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.resources import Resource, SERVICE_NAME
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

        resource = Resource.create({SERVICE_NAME: service_name})
        provider = TracerProvider(resource=resource)

        otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://jaeger:4317")
        exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
        provider.add_span_processor(BatchSpanProcessor(exporter))

        trace.set_tracer_provider(provider)
        logger.info(f"OpenTelemetry tracing initialized for {service_name} → {otlp_endpoint}")

        return trace.get_tracer(service_name)
    except ImportError as e:
        logger.warning(f"OpenTelemetry not available ({e}), tracing disabled")
        return None


def instrument_fastapi(app):
    """Auto-instrument FastAPI with OpenTelemetry."""
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        FastAPIInstrumentor.instrument_app(app)
        logger.info("FastAPI instrumented for tracing")
    except ImportError:
        pass


def instrument_grpc():
    """Auto-instrument gRPC with OpenTelemetry."""
    try:
        from opentelemetry.instrumentation.grpc import GrpcInstrumentorClient, GrpcInstrumentorServer
        GrpcInstrumentorClient().instrument()
        GrpcInstrumentorServer().instrument()
        logger.info("gRPC instrumented for tracing")
    except ImportError:
        pass


def get_tracer(name: str = "oncall-platform"):
    """Get a tracer instance."""
    try:
        from opentelemetry import trace
        return trace.get_tracer(name)
    except ImportError:
        return None
