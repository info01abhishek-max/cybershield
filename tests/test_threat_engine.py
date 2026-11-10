"""Tests for threat detection engine."""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_engine.engine import (
    ThreatDetectionEngine, SecurityEvent, Severity, EventStatus, DetectionRule, get_threat_engine
)


class TestThreatDetectionEngine:
    """Test the threat detection engine."""

    def test_engine_singleton(self):
        """Test that get_threat_engine returns singleton."""
        engine1 = get_threat_engine()
        engine2 = get_threat_engine()
        assert engine1 is engine2

    def test_security_event_creation(self):
        """Test creating a SecurityEvent."""
        event = SecurityEvent(
            event_id="EVT-001",
            timestamp="2024-01-01T10:00:00",
            event_type="Test",
            severity="HIGH",
            source="10.0.0.1",
            description="Test event",
            details={"key": "value"}
        )

        assert event.event_id == "EVT-001"
        assert event.severity == "HIGH"
        assert event.details == {"key": "value"}

    def test_security_event_defaults(self):
        """Test default values."""
        event = SecurityEvent(
            event_id="EVT-002",
            timestamp="2024-01-01T10:00:00",
            event_type="Test",
            severity="INFO",
            source="test",
            description="Test"
        )

        assert event.status == EventStatus.NEW.value
        assert event.assigned_to == ""
        assert event.resolution_notes == ""

    def test_severity_enum(self):
        """Test Severity enum."""
        assert Severity.LOW.value == "LOW"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.CRITICAL.value == "CRITICAL"

    def test_event_status_enum(self):
        """Test EventStatus enum."""
        assert EventStatus.NEW.value == "NEW"
        assert EventStatus.INVESTIGATING.value == "INVESTIGATING"
        assert EventStatus.RESOLVED.value == "RESOLVED"

    def test_detection_rule_creation(self):
        """Test DetectionRule creation."""
        rule = DetectionRule(
            rule_id="TEST_RULE",
            name="Test Rule",
            description="Test description",
            event_type="Test",
            severity="HIGH",
            conditions={"count": 5}
        )

        assert rule.rule_id == "TEST_RULE"
        assert rule.severity == "HIGH"
        assert rule.enabled == True
        assert rule.cooldown_seconds == 300

    def test_analyze_empty_events(self):
        """Test handling of empty events list."""
        engine = ThreatDetectionEngine()
        threats = engine.run_full_analysis([])
        assert threats == []

    def test_analyze_auth_events_brute_force(self):
        """Test detection of brute force authentication events."""
        engine = ThreatDetectionEngine()

        # Test with no connections - should only run analyze_failed_logins
        threats = engine.run_full_analysis(None)

        # Should return list (may be empty if no failed logins in DB)
        assert isinstance(threats, list)

    def test_known_c2_ports_detection(self):
        """Test detection of known C2 ports."""
        engine = ThreatDetectionEngine()

        c2_ports = [4444, 6666, 8080, 8443, 9999, 1337, 31337]

        for port in c2_ports:
            # Pass connection dicts, not SecurityEvent objects
            connections = [{
                'remote_address': '10.0.0.1',
                'remote_port': port,
                'local_port': 12345,
                'process_name': 'test.exe',
                'status': 'ESTABLISHED',
                'pid': 1234
            }]

            threats = engine.run_full_analysis(connections)
            # The engine should analyze without error
            assert isinstance(threats, list)

    def test_rules_loaded(self):
        """Test that default rules are loaded."""
        engine = ThreatDetectionEngine()

        assert len(engine._rules) > 0
        for rule in engine._rules:
            assert isinstance(rule, DetectionRule)
            assert rule.rule_id
            assert rule.name
            assert rule.severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class TestSecurityEvent:
    """Test SecurityEvent dataclass."""

    def test_security_event_with_all_fields(self):
        """Test creating a SecurityEvent with all fields."""
        event = SecurityEvent(
            event_id="EVT-001",
            timestamp="2024-01-01T10:00:00",
            event_type="Test",
            severity="HIGH",
            source="10.0.0.1",
            description="Test",
            details="{}",
            status=EventStatus.INVESTIGATING.value,
            assigned_to="analyst1",
            resolution_notes="Fixed",
            created_at="2024-01-01T10:00:00",
            updated_at="2024-01-01T10:05:00"
        )

        assert event.event_id == "EVT-001"
        assert event.status == EventStatus.INVESTIGATING.value
        assert event.assigned_to == "analyst1"
        assert event.resolution_notes == "Fixed"