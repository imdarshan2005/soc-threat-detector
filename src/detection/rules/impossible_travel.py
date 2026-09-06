"""
Impossible Travel / Geo-Velocity Anomaly Detection Rule (MITRE ATT&CK T1078.004).
Detects rapid geographic or network subnet shifts for the same user account.
"""
from collections import defaultdict
from datetime import timedelta
from typing import List
from src.database.models import NormalizedEvent, Alert
from src.detection.base_rule import BaseRule

class ImpossibleTravelRule(BaseRule):
    rule_name: str = "Impossible Travel / Geo-Velocity Anomaly"
    mitre_technique_id: str = "T1078"
    severity: str = "CRITICAL"

    def __init__(self, max_delta_minutes: int = 60):
        super().__init__()
        self.max_delta = timedelta(minutes=max_delta_minutes)

    def _is_private_ip(self, ip: str) -> bool:
        if not ip:
            return True
        return ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.") or ip == "127.0.0.1"

    def evaluate(self, events: List[NormalizedEvent]) -> List[Alert]:
        alerts = []
        user_logins = defaultdict(list)

        for e in sorted(events, key=lambda x: x.timestamp):
            if e.event_type == "AUTHENTICATION" and e.status == "SUCCESS" and e.user:
                if not self._is_private_ip(e.source_ip):
                    user_logins[e.user].append(e)

        for user, logins in user_logins.items():
            if len(logins) < 2:
                continue

            for i in range(len(logins) - 1):
                first = logins[i]
                second = logins[i+1]

                delta = second.timestamp - first.timestamp
                # If from different external IPs within max_delta
                if first.source_ip != second.source_ip and delta <= self.max_delta and delta.total_seconds() > 0:
                    title = f"Impossible Travel Detected for User '{user}'"
                    desc = (
                        f"User '{user}' successfully logged in from {first.source_ip} at {first.timestamp.strftime('%H:%M:%S')} "
                        f"and then from {second.source_ip} at {second.timestamp.strftime('%H:%M:%S')} "
                        f"(within {int(delta.total_seconds() / 60)} minutes). Infeasible physical velocity."
                    )
                    rec_action = (
                        f"Lock account '{user}' immediately. Terminate active session tokens and require MFA re-enrollment."
                    )
                    evidence = [first.raw_log, second.raw_log]

                    alerts.append(Alert(
                        rule_name=self.rule_name,
                        mitre_tactic=self.mitre_tactic,
                        mitre_technique_id=self.mitre_technique_id,
                        mitre_technique_name=self.mitre_technique_name,
                        severity=self.severity,
                        title=title,
                        description=desc,
                        source_ip=second.source_ip,
                        dest_ip=second.dest_ip,
                        user=user,
                        event_count=2,
                        first_seen=first.timestamp,
                        last_seen=second.timestamp,
                        status="New",
                        recommended_action=rec_action,
                        evidence_json=evidence
                    ))

        return alerts
