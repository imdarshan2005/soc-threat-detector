"""
Unit tests for SOC Sentinel detection rules and detection engine.
"""
from datetime import datetime, timedelta
from src.database.models import NormalizedEvent
from src.detection.rules.brute_force import BruteForceRule
from src.detection.rules.port_scan import PortScanRule
from src.detection.rules.web_attacks import WebAttackRule
from src.detection.rules.off_hours_login import OffHoursLoginRule
from src.detection.rules.impossible_travel import ImpossibleTravelRule
from src.detection.rules.priv_escalation import PrivilegeEscalationRule
from src.detection.engine import DetectionEngine

def test_brute_force_rule():
    rule = BruteForceRule(failure_threshold=5, window_seconds=60)
    now = datetime(2026, 9, 6, 12, 0, 0)
    events = []
    # 5 failures from same IP within 30 seconds
    for i in range(5):
        events.append(NormalizedEvent(
            timestamp=now + timedelta(seconds=i * 5),
            source_ip="192.0.2.100",
            dest_ip="10.0.1.10",
            user="root",
            action="AUTH_FAILURE",
            status="FAILURE",
            event_type="AUTHENTICATION",
            raw_log=f"Failed attempt {i}"
        ))

    alerts = rule.evaluate(events)
    assert len(alerts) == 1
    assert alerts[0].mitre_technique_id == "T1110"
    assert alerts[0].source_ip == "192.0.2.100"
    assert alerts[0].severity == "HIGH"

def test_brute_force_compromise_escalation():
    rule = BruteForceRule(failure_threshold=5, window_seconds=60)
    now = datetime(2026, 9, 6, 12, 0, 0)
    events = []
    for i in range(5):
        events.append(NormalizedEvent(
            timestamp=now + timedelta(seconds=i * 5),
            source_ip="192.0.2.100",
            dest_ip="10.0.1.10",
            user="root",
            action="AUTH_FAILURE",
            status="FAILURE",
            event_type="AUTHENTICATION",
            raw_log=f"Failed attempt {i}"
        ))
    # Followed by success
    events.append(NormalizedEvent(
        timestamp=now + timedelta(seconds=35),
        source_ip="192.0.2.100",
        dest_ip="10.0.1.10",
        user="root",
        action="AUTH_SUCCESS",
        status="SUCCESS",
        event_type="AUTHENTICATION",
        raw_log="Accepted password"
    ))

    alerts = rule.evaluate(events)
    assert len(alerts) == 1
    assert alerts[0].severity == "CRITICAL"

def test_port_scan_rule():
    rule = PortScanRule(port_threshold=5, window_seconds=60)
    now = datetime(2026, 9, 6, 12, 0, 0)
    events = []
    # Touch 6 distinct ports
    for i, port in enumerate([21, 22, 80, 443, 3306, 8080]):
        events.append(NormalizedEvent(
            timestamp=now + timedelta(seconds=i * 2),
            source_ip="45.33.32.156",
            dest_ip="10.0.1.10",
            dest_port=port,
            action="FIREWALL_DROP",
            status="DENY",
            event_type="NETWORK",
            raw_log=f"Port scan packet to {port}"
        ))

    alerts = rule.evaluate(events)
    assert len(alerts) == 1
    assert alerts[0].mitre_technique_id == "T1046"
    assert alerts[0].source_ip == "45.33.32.156"

def test_web_attack_rule():
    rule = WebAttackRule()
    now = datetime(2026, 9, 6, 12, 0, 0)
    events = [
        NormalizedEvent(
            timestamp=now,
            source_ip="203.0.113.45",
            action="HTTP_ATTACK_ATTEMPT",
            status="SUCCESS",
            event_type="WEB",
            details={"detected_attacks": ["SQL_INJECTION"], "uri": "/api?id=1 UNION SELECT"},
            raw_log="SQLi log"
        )
    ]
    alerts = rule.evaluate(events)
    assert len(alerts) == 1
    assert alerts[0].mitre_technique_id == "T1190"
    assert "SQL_INJECTION" in alerts[0].title

def test_impossible_travel_rule():
    rule = ImpossibleTravelRule(max_delta_minutes=30)
    now = datetime(2026, 9, 6, 12, 0, 0)
    events = [
        NormalizedEvent(
            timestamp=now,
            source_ip="198.51.100.23", # External IP 1
            user="alice",
            action="AUTH_SUCCESS",
            status="SUCCESS",
            event_type="AUTHENTICATION",
            raw_log="Login from Moscow"
        ),
        NormalizedEvent(
            timestamp=now + timedelta(minutes=10),
            source_ip="203.0.113.45", # External IP 2
            user="alice",
            action="AUTH_SUCCESS",
            status="SUCCESS",
            event_type="AUTHENTICATION",
            raw_log="Login from Amsterdam"
        )
    ]
    alerts = rule.evaluate(events)
    assert len(alerts) == 1
    assert alerts[0].user == "alice"
    assert alerts[0].severity == "CRITICAL"
