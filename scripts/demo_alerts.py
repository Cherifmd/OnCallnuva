#!/usr/bin/env python3
"""
Demo script: Send sample alerts to test the platform.
Run after deploying with `docker compose up -d`.
"""
import requests
import time
import random
import json

BASE_URL = "http://localhost:80"

SAMPLE_ALERTS = [
    {
        "source": "prometheus",
        "service_name": "api-gateway",
        "severity": "critical",
        "title": "High CPU usage on api-gateway",
        "description": "CPU usage exceeded 95% for the last 5 minutes on node-1",
        "labels": {"host": "node-1", "region": "eu-west-1", "cluster": "prod"},
    },
    {
        "source": "grafana",
        "service_name": "payment-service",
        "severity": "high",
        "title": "Payment API latency > 2s",
        "description": "P99 latency has spiked to 2.3s. Possible downstream issue.",
        "labels": {"endpoint": "/api/v1/payments", "method": "POST"},
    },
    {
        "source": "prometheus",
        "service_name": "auth-service",
        "severity": "critical",
        "title": "Auth service returning 503",
        "description": "Multiple 503 errors detected. Service may be down.",
        "labels": {"error_rate": "45%", "host": "node-2"},
    },
    {
        "source": "custom",
        "service_name": "database-service",
        "severity": "medium",
        "title": "Connection pool at 80%",
        "description": "PostgreSQL connection pool is nearing capacity.",
        "labels": {"pool_size": "100", "active": "80"},
    },
    {
        "source": "prometheus",
        "service_name": "api-gateway",
        "severity": "critical",
        "title": "Memory usage critical on api-gateway",
        "description": "RSS memory at 3.8GB / 4GB limit. OOM imminent.",
        "labels": {"host": "node-1", "memory_pct": "95%"},
    },
    {
        "source": "grafana",
        "service_name": "payment-service",
        "severity": "low",
        "title": "Slow query detected in payment-service",
        "description": "Query took 1.2s (threshold: 500ms)",
        "labels": {"query": "SELECT ...payments...", "duration_ms": "1200"},
    },
]


def main():
    print("=" * 60)
    print("  OnCall Platform - Demo Alert Generator")
    print("=" * 60)

    # Check service health via Traefik
    try:
        resp = requests.get(f"{BASE_URL}/api/v1/alerts", timeout=3)
        print(f"\n  Alert Ingestion: reachable via Traefik")
    except Exception as e:
        print(f"\n  ERROR: Cannot reach Alert Ingestion at {BASE_URL}")
        print(f"  Make sure services are running: docker compose up -d")
        return

    print(f"\n  Sending {len(SAMPLE_ALERTS)} sample alerts...\n")

    for i, alert in enumerate(SAMPLE_ALERTS, 1):
        try:
            resp = requests.post(
                f"{BASE_URL}/api/v1/alerts",
                json=alert,
                timeout=5,
            )
            result = resp.json()
            status = result.get("status", "unknown")
            inc_id = result.get("incident_id", "")[:8]
            print(f"  [{i}/{len(SAMPLE_ALERTS)}] {alert['severity']:8s} | {alert['title'][:45]:45s} | "
                  f"Status: {status:15s} | Incident: {inc_id}...")
        except Exception as e:
            print(f"  [{i}] ERROR: {e}")

        # Small delay to test correlation window
        time.sleep(0.5)

    # Send a duplicate to test correlation
    print(f"\n  Sending duplicate alert (should correlate)...")
    time.sleep(1)
    dup = SAMPLE_ALERTS[0].copy()
    dup["title"] = "High CPU usage on api-gateway (repeat)"
    try:
        resp = requests.post(f"{BASE_URL}/api/v1/alerts", json=dup, timeout=5)
        result = resp.json()
        print(f"  → Status: {result.get('status')} | Incident: {result.get('incident_id', '')[:8]}...")
    except Exception as e:
        print(f"  ERROR: {e}")

    print(f"\n  Done! View dashboard at: http://localhost:8080")
    print(f"  View Grafana at: http://localhost:3000 (admin/admin)")
    print("=" * 60)


if __name__ == "__main__":
    main()
