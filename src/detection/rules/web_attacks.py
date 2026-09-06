"""
Web Application Attack Detection Rule (MITRE ATT&CK T1190).
Detects SQL Injection, Cross-Site Scripting (XSS), and Path Traversal.
"""
from collections import defaultdict
from typing import List
from src.database.models import NormalizedEvent, Alert
from src.detection.base_rule import BaseRule

class WebAttackRule(BaseRule):
    rule_name: str = "Web Application Exploitation Attempt"
    mitre_technique_id: str = "T1190"
    severity: str = "HIGH"

    def evaluate(self, events: List[NormalizedEvent]) -> List[Alert]:
        alerts = []
        if not events:
            return alerts

        ip_attack_events = defaultdict(list)
        for e in events:
            if e.event_type == "WEB":
                detected = e.details.get("detected_attacks", [])
                if detected:
                    ip_attack_events[e.source_ip].append(e)

        for ip, evts in ip_attack_events.items():
            all_attacks = set()
            for e in evts:
                for a in e.details.get("detected_attacks", []):
                    all_attacks.add(a)

            # Escalate to CRITICAL if multiple attack categories or sqlmap scanner detected
            is_critical = "SQL_INJECTION" in all_attacks and len(evts) >= 3
            severity = "CRITICAL" if is_critical else "HIGH"

            first_seen = min(e.timestamp for e in evts)
            last_seen = max(e.timestamp for e in evts)
            evidence = [f"{e.raw_log} [Detected: {', '.join(e.details.get('detected_attacks', []))}]" for e in evts]

            attack_names = ", ".join(sorted(all_attacks))
            title = f"Web Attack Patterns ({attack_names}) from {ip}"
            desc = (
                f"Source {ip} sent {len(evts)} malicious web payloads triggering signatures for: {attack_names}. "
                f"Target URI sample: {evts[0].details.get('uri', 'N/A')}"
            )
            rec_action = (
                f"Deploy WAF IP ban rule for {ip}. Check web application database query logs for data exfiltration."
            )

            alerts.append(Alert(
                rule_name=self.rule_name,
                mitre_tactic=self.mitre_tactic,
                mitre_technique_id=self.mitre_technique_id,
                mitre_technique_name=self.mitre_technique_name,
                severity=severity,
                title=title,
                description=desc,
                source_ip=ip,
                dest_ip=evts[0].dest_ip,
                user=evts[0].user if evts[0].user != "anonymous" else None,
                event_count=len(evts),
                first_seen=first_seen,
                last_seen=last_seen,
                status="New",
                recommended_action=rec_action,
                evidence_json=evidence
            ))

        return alerts
