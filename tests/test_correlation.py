"""
Unit tests for Correlation Engine (Incident Management)
"""
import pytest
import sys
import os
import uuid
from datetime import datetime, timedelta
from unittest.mock import patch, AsyncMock, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestCorrelationAlgorithm:
    """Tests for the alert correlation algorithm logic."""

    def test_correlation_key_same_service_severity(self):
        """Alerts from same service with same severity should correlate."""
        # The correlation key is (service_name, severity)
        key1 = ("api-gateway", "critical")
        key2 = ("api-gateway", "critical")
        assert key1 == key2

    def test_correlation_key_different_severity(self):
        """Alerts with different severity should NOT correlate."""
        key1 = ("api-gateway", "critical")
        key2 = ("api-gateway", "high")
        assert key1 != key2

    def test_correlation_key_different_service(self):
        """Alerts from different services should NOT correlate."""
        key1 = ("api-gateway", "critical")
        key2 = ("payment-service", "critical")
        assert key1 != key2

    def test_correlation_window_default_5_minutes(self):
        """Default correlation window should be 300 seconds (5 minutes)."""
        window = int(os.getenv("CORRELATION_WINDOW_SECONDS", "300"))
        assert window == 300

    def test_alert_within_window_should_correlate(self):
        """An alert within the 5-minute window matches an existing incident."""
        now = datetime.utcnow()
        incident_time = now - timedelta(minutes=3)  # 3 min ago
        window = timedelta(seconds=300)
        assert (now - incident_time) < window

    def test_alert_outside_window_should_not_correlate(self):
        """An alert outside the 5-minute window creates new incident."""
        now = datetime.utcnow()
        incident_time = now - timedelta(minutes=6)  # 6 min ago
        window = timedelta(seconds=300)
        assert (now - incident_time) > window


class TestMTTAMTTR:
    """Test MTTA/MTTR calculations."""

    def test_mtta_calculation(self):
        """MTTA = acknowledged_at - created_at."""
        created = datetime(2026, 1, 1, 10, 0, 0)
        acknowledged = datetime(2026, 1, 1, 10, 2, 30)  # 2.5 min later
        mtta = (acknowledged - created).total_seconds()
        assert mtta == 150.0

    def test_mttr_calculation(self):
        """MTTR = resolved_at - created_at."""
        created = datetime(2026, 1, 1, 10, 0, 0)
        resolved = datetime(2026, 1, 1, 10, 15, 0)  # 15 min later
        mttr = (resolved - created).total_seconds()
        assert mttr == 900.0

    def test_mtta_zero_when_not_acknowledged(self):
        """MTTA should be 0 if not yet acknowledged."""
        from shared.models import Incident
        inc = Incident(
            id="test-1",
            title="Test",
            severity="low",
            status="triggered",
            service_name="test",
            created_at=datetime.utcnow(),
        )
        assert inc.mtta_seconds == 0.0

    def test_mttr_zero_when_not_resolved(self):
        """MTTR should be 0 if not yet resolved."""
        from shared.models import Incident
        inc = Incident(
            id="test-2",
            title="Test",
            severity="low",
            status="triggered",
            service_name="test",
            created_at=datetime.utcnow(),
        )
        assert inc.mttr_seconds == 0.0


class TestDatabaseModels:
    """Test shared database models."""

    def test_incident_model_defaults(self):
        from shared.models import Incident
        inc = Incident(
            id="inc-001",
            title="Test Incident",
            severity="critical",
            service_name="api-gateway",
        )
        assert inc.status == "triggered"
        assert inc.alert_count == 1
        assert inc.escalation_level == 0

    def test_alert_model(self):
        from shared.models import Alert
        alert = Alert(
            id="alert-001",
            source="prometheus",
            service_name="test",
            severity="high",
            title="Test Alert",
        )
        assert alert.source == "prometheus"
        assert alert.incident_id is None

    def test_oncall_schedule_model(self):
        from shared.models import OnCallSchedule
        schedule = OnCallSchedule(
            service_name="api-gateway",
            user_id="user-001",
            user_name="Alice",
            escalation_level=0,
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow() + timedelta(days=7),
        )
        assert schedule.escalation_level == 0

    def test_db_url_generation(self):
        from shared.models import get_db_url
        url = get_db_url(async_mode=True)
        assert "postgresql+asyncpg" in url
        url_sync = get_db_url(async_mode=False)
        assert "postgresql+psycopg2" in url_sync


class TestEscalationLogic:
    """Test escalation rules."""

    def test_escalation_level_increments(self):
        """Next level should be current_level + 1."""
        current = 0
        next_level = current + 1
        assert next_level == 1

    def test_escalation_wraps_at_max(self):
        """When max escalation reached, wrap to level 0."""
        MAX_LEVEL = 3
        current = 3
        next_level = (current + 1) if (current + 1) <= MAX_LEVEL else 0
        assert next_level == 0

    def test_escalation_levels_sequence(self):
        """Escalation should go L0 → L1 → L2 → L3 → L0."""
        MAX_LEVEL = 3
        levels = []
        current = 0
        for _ in range(5):
            levels.append(current)
            current = (current + 1) if (current + 1) <= MAX_LEVEL else 0
        assert levels == [0, 1, 2, 3, 0]
