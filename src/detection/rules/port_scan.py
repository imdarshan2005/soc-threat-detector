"""
Port Scan and Network Reconnaissance Detection Rule (MITRE ATT&CK T1046).
Detects horizontal/vertical port sweeps touching multiple ports from a single IP.
"""
from collections import defaultdict
from datetime import timedelta
from typing import List
from src.database.models import NormalizedEvent, Alert
from src.detection.base_rule import BaseRule

class PortScanRule(BaseRule):
    rule_name: str = "Network Port Scan / Reconnaissance"
    mitre_technique_id: str = "T1046"
    severity: str = "HIGH"

    def __init__(self, port_threshold: int = 5, window_seconds: int = 60):
        super().__init__()
        self.port_threshold = port_threshold
        self.window_seconds = window_seconds

    def evaluate(self, events: List[NormalizedEvent]) -> List[Alert]:
        alerts = []
        if not events:
            return alerts

        sorted_events = sorted(events, key=lambda e: e.timestamp)
        ip_events = defaultdict(list)
        for e in sorted_events:
            if e.event_type == "NETWORK" and e.source_ip and e.dest_port:
                ip_events[e.source_ip].append(e)

        for ip, evts in ip_events.items():
            window: List[NormalizedEvent] = []
            for evt in evts:
                window.append(evt)
                cutoff = evt.timestamp - timedelta(seconds=self.window_seconds)
                window = [e for e in window if e.timestamp >= cutoff]

                unique_ports = list(set(e.dest_port for e in window if e.dest_port))
                if len(unique_ports) >= self.port_threshold:
                    first_seen = window[0].timestamp
                    last_seen = window[-1].timestamp
                    evidence = [e.raw_log for e in window]

                    title = f"Port Scan Detected from {ip} ({len(unique_ports)} ports)"
                    desc = (
                        f"Host {ip} performed port sweep targeting {len(unique_ports)} distinct ports "
                        f"({', '.join(map(str, unique_ports[:10]))}{'...' if len(unique_ports) > 10 else ''}) "
                        f"within {self.window_seconds}s window."
                    )
                    rec_action = f"Apply temporary dynamic rate-limiting or null-route IP {ip} at network edge."

                    alerts.append(Alert(
                        rule_name=self.rule_name,
                        mitre_tactic=self.mitre_tactic,
                        mitre_technique_id=self.mitre_technique_id,
                        mitre_technique_name=self.mitre_technique_name,
                        severity=self.severity,
                        title=title,
                        description=desc,
                        source_ip=ip,
                        dest_ip=window[0].dest_ip,
                        user=None,
                        event_count=len(window),
                        first_seen=first_seen,
                        last_seen=last_seen,
                        status="New",
                        recommended_action=rec_action,
                        evidence_json=evidence
                    ))
                    window = [] # Reset window

        return alerts
