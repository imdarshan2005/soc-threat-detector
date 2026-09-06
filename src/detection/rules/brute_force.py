"""
Brute-Force Authentication Attack Detection Rule (MITRE ATT&CK T1110).
Detects password guessing or credential stuffing attacks using a sliding time window.
"""
from collections import defaultdict
from datetime import timedelta
from typing import List
from src.database.models import NormalizedEvent, Alert
from src.detection.base_rule import BaseRule

class BruteForceRule(BaseRule):
    rule_name: str = "Brute-Force Authentication Attempt"
    mitre_technique_id: str = "T1110"
    severity: str = "HIGH"

    def __init__(self, failure_threshold: int = 5, window_seconds: int = 120):
        super().__init__()
        self.failure_threshold = failure_threshold
        self.window_seconds = window_seconds

    def evaluate(self, events: List[NormalizedEvent]) -> List[Alert]:
        alerts = []
        if not events:
            return alerts

        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        # Group auth events by source IP
        ip_auth_events = defaultdict(list)
        for e in sorted_events:
            if e.event_type == "AUTHENTICATION" and e.source_ip:
                ip_auth_events[e.source_ip].append(e)

        for ip, evts in ip_auth_events.items():
            failed_in_window: List[NormalizedEvent] = []

            for i, evt in enumerate(evts):
                if evt.status == "FAILURE":
                    failed_in_window.append(evt)
                    # Evict events outside sliding window
                    cutoff = evt.timestamp - timedelta(seconds=self.window_seconds)
                    failed_in_window = [e for e in failed_in_window if e.timestamp >= cutoff]

                    if len(failed_in_window) >= self.failure_threshold:
                        # Check if any subsequent event is AUTH_SUCCESS (Compromise confirmed)
                        subsequent_success = any(
                            s.status == "SUCCESS" and s.timestamp >= failed_in_window[0].timestamp
                            for s in evts[i+1:i+10]
                        )

                        targeted_users = list(set(e.user for e in failed_in_window if e.user))
                        first_seen = failed_in_window[0].timestamp
                        last_seen = failed_in_window[-1].timestamp

                        severity = "CRITICAL" if subsequent_success else "HIGH"
                        title = f"Compromised Account: SSH/Auth Brute-Force Successful from {ip}" if subsequent_success else f"SSH/Auth Brute-Force Attack Detected from {ip}"
                        desc = (
                            f"Observed {len(failed_in_window)} failed authentication attempts from IP {ip} within {self.window_seconds}s window. "
                            f"Targeted usernames: {', '.join(targeted_users) if targeted_users else 'N/A'}. "
                            f"{'CRITICAL: Followed by successful login! Potential account takeover.' if subsequent_success else 'Ongoing brute-force activity.'}"
                        )
                        rec_action = (
                            f"IMMEDIATE: Block IP {ip} on edge firewall. "
                            f"If account '{targeted_users[0] if targeted_users else 'unknown'}' was compromised, revoke active sessions and force password reset."
                        )
                        evidence = [e.raw_log for e in failed_in_window]

                        alerts.append(Alert(
                            rule_name=self.rule_name,
                            mitre_tactic=self.mitre_tactic,
                            mitre_technique_id=self.mitre_technique_id,
                            mitre_technique_name=self.mitre_technique_name,
                            severity=severity,
                            title=title,
                            description=desc,
                            source_ip=ip,
                            dest_ip=failed_in_window[0].dest_ip,
                            user=targeted_users[0] if targeted_users else None,
                            event_count=len(failed_in_window),
                            first_seen=first_seen,
                            last_seen=last_seen,
                            status="New",
                            recommended_action=rec_action,
                            evidence_json=evidence
                        ))
                        # Clear window to avoid duplicate trigger for exact same cluster
                        failed_in_window = []

        return alerts
