"""
Off-Hours Anomalous Login Detection Rule (MITRE ATT&CK T1078).
Detects administrative authentications outside standard operating hours (22:00 to 06:00 or weekends).
"""
from typing import List
from src.database.models import NormalizedEvent, Alert
from src.detection.base_rule import BaseRule

class OffHoursLoginRule(BaseRule):
    rule_name: str = "Suspicious Off-Hours Privileged Login"
    mitre_technique_id: str = "T1078"
    severity: str = "MEDIUM"

    def __init__(self, start_hour: int = 22, end_hour: int = 6):
        super().__init__()
        self.start_hour = start_hour
        self.end_hour = end_hour
        self.privileged_users = {"root", "admin", "administrator", "wheel"}

    def is_off_hours(self, dt) -> bool:
        # Check weekend (5=Saturday, 6=Sunday)
        if dt.weekday() in [5, 6]:
            return True
        # Check night window
        return dt.hour >= self.start_hour or dt.hour < self.end_hour

    def evaluate(self, events: List[NormalizedEvent]) -> List[Alert]:
        alerts = []
        for e in events:
            if e.event_type == "AUTHENTICATION" and e.status == "SUCCESS":
                user_lower = (e.user or "").lower()
                if user_lower in self.privileged_users and self.is_off_hours(e.timestamp):
                    # Check if internal or external IP
                    is_external = not (e.source_ip.startswith("10.") or e.source_ip.startswith("192.168.") or e.source_ip == "127.0.0.1")
                    severity = "HIGH" if is_external else "MEDIUM"

                    title = f"Off-Hours Login by '{e.user}' from {e.source_ip}"
                    desc = (
                        f"Privileged user '{e.user}' logged in at {e.timestamp.strftime('%Y-%m-%d %H:%M:%S')} "
                        f"(Off-hours/Night/Weekend) from {'external' if is_external else 'internal'} IP {e.source_ip}."
                    )
                    rec_action = f"Verify with user '{e.user}' if this session was authorized. Check MFA telemetry."

                    alerts.append(Alert(
                        rule_name=self.rule_name,
                        mitre_tactic=self.mitre_tactic,
                        mitre_technique_id=self.mitre_technique_id,
                        mitre_technique_name=self.mitre_technique_name,
                        severity=severity,
                        title=title,
                        description=desc,
                        source_ip=e.source_ip,
                        dest_ip=e.dest_ip,
                        user=e.user,
                        event_count=1,
                        first_seen=e.timestamp,
                        last_seen=e.timestamp,
                        status="New",
                        recommended_action=rec_action,
                        evidence_json=[e.raw_log]
                    ))
        return alerts
