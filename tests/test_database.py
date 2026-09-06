"""
Unit tests for DatabaseManager and SQLite interactions.
"""
from datetime import datetime
import pytest
from src.database.db_manager import DatabaseManager
from src.database.models import NormalizedEvent, Alert

@pytest.fixture
def temp_db(tmp_path):
    db_file = tmp_path / "test_soc.db"
    return DatabaseManager(db_file)

def test_insert_events(temp_db):
    events = [
        NormalizedEvent(
            timestamp=datetime(2026, 9, 6, 10, 0, 0),
            source_ip="10.0.1.50",
            dest_ip="10.0.1.10",
            action="AUTH_SUCCESS",
            status="SUCCESS",
            event_type="AUTHENTICATION",
            raw_log="Sample test log"
        )
    ]
    inserted = temp_db.insert_events(events)
    assert inserted == 1

    queried = temp_db.get_events(limit=10)
    assert len(queried) == 1
    assert queried[0]["source_ip"] == "10.0.1.50"

def test_insert_alert_and_triage(temp_db):
    alert = Alert(
        rule_name="Test Rule",
        mitre_tactic="Initial Access",
        mitre_technique_id="T1190",
        mitre_technique_name="Exploit Public Facing Application",
        severity="HIGH",
        title="Test Alert Title",
        description="Test Alert Description",
        source_ip="203.0.113.45",
        user="testuser",
        status="New"
    )
    alert_id = temp_db.insert_alert(alert)
    assert alert_id is not None

    # Retrieve alert
    alerts = temp_db.get_alerts(status="New")
    assert len(alerts) == 1
    assert alerts[0]["title"] == "Test Alert Title"

    # Update triage status
    temp_db.update_alert_status(alert_id, "Contained", "Host firewall rule enacted")
    updated_alerts = temp_db.get_alerts(status="Contained")
    assert len(updated_alerts) == 1
    assert updated_alerts[0]["analyst_notes"] == "Host firewall rule enacted"
