"""
Unit tests for Alert Ingestion Service
"""
import pytest
import sys
import os
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestAlertPayloadValidation:
    """Test alert payload validation logic."""

    def test_valid_severities(self):
        from services.alert_ingestion.main import AlertPayload
        for sev in ["critical", "high", "medium", "low"]:
            alert = AlertPayload(
                source="prometheus",
                service_name="test-service",
                severity=sev,
                title="Test Alert",
            )
            assert alert.severity == sev

    def test_invalid_severity_rejected(self):
        from services.alert_ingestion.main import AlertPayload
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            AlertPayload(
                source="test",
                service_name="test-service",
                severity="invalid",
                title="Test",
            )

    def test_severity_case_insensitive(self):
        from services.alert_ingestion.main import AlertPayload
        alert = AlertPayload(
            source="test",
            service_name="svc",
            severity="CRITICAL",
            title="Test",
        )
        assert alert.severity == "critical"

    def test_sql_injection_in_source_rejected(self):
        from services.alert_ingestion.main import AlertPayload
        from pydantic import ValidationError
        dangerous_inputs = [
            "test'; DROP TABLE alerts;--",
            'test" OR "1"="1',
            "test; exec(cmd)",
        ]
        for dangerous in dangerous_inputs:
            with pytest.raises(ValidationError):
                AlertPayload(
                    source=dangerous,
                    service_name="test-service",
                    severity="low",
                    title="Test",
                )

    def test_empty_source_rejected(self):
        from services.alert_ingestion.main import AlertPayload
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            AlertPayload(
                source="",
                service_name="test",
                severity="low",
                title="Test",
            )

    def test_timestamp_defaults_to_none(self):
        from services.alert_ingestion.main import AlertPayload
        alert = AlertPayload(
            source="test",
            service_name="svc",
            severity="low",
            title="Test",
        )
        assert alert.timestamp is None

    def test_labels_default_empty(self):
        from services.alert_ingestion.main import AlertPayload
        alert = AlertPayload(
            source="test",
            service_name="svc",
            severity="low",
            title="Test",
        )
        assert alert.labels == {}

    def test_batch_max_100(self):
        from services.alert_ingestion.main import AlertBatchPayload, AlertPayload
        from pydantic import ValidationError
        alerts = [
            AlertPayload(source="t", service_name="s", severity="low", title=f"Alert {i}")
            for i in range(101)
        ]
        with pytest.raises(ValidationError):
            AlertBatchPayload(alerts=alerts)


class TestAlertIngestionEndpoints:
    """Test Alert Ingestion HTTP endpoints."""

    @pytest.fixture
    def client(self):
        from services.alert_ingestion.main import app
        from fastapi.testclient import TestClient
        return TestClient(app, raise_server_exceptions=False)

    def test_health_endpoint(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "alert-ingestion"

    def test_metrics_endpoint(self, client):
        response = client.get("/metrics")
        assert response.status_code == 200
        assert "alerts_received_total" in response.text or response.status_code == 200
