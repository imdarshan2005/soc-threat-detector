"""
Privilege Escalation Detection Rule (MITRE ATT&CK T1548.003).
Detects unauthorized sudo abuse, shell spawning, and sensitive privilege token assignments.
"""
from typing import List
from src.database.models import NormalizedEvent, Alert
from src.detection.base_rule import BaseRule

class PrivilegeEscalationRule(BaseRule):
    rule_name: str = "Suspicious Privilege Escalation / Sudo Abuse"
    mitre_technique_id: str = "T1548"
    severity: str = "HIGH"

    def evaluate(self, events: List[NormalizedEvent]) -> List[Alert]:
        alerts = []
        suspicious_users = {"www-data", "apache", "nginx", "nobody", "daemon"}
        suspicious_commands = ["/bin/bash", "/bin/sh", "/bin/cat /etc/shadow", "chmod -R 777", "visudo", "su -", "nc -e"]

        for e in events:
            if e.action == "PRIVILEGE_ELEVATION":
                cmd = e.details.get("command", "")
                user = e.user or "unknown"
                privileges = e.details.get("privileges", [])

                is_critical = user.lower() in suspicious_users or any(sc in cmd for sc in ["/bin/bash", "/bin/sh", "/etc/shadow", "chmod -R 777"])
                severity = "CRITICAL" if is_critical else "HIGH"

                title = f"Privilege Escalation: Suspicious Execution by '{user}'"
                desc = (
                    f"User '{user}' executed elevated command '{cmd or ', '.join(privileges)}'. "
                    f"{'HIGH-RISK: Service account executing root shell or sensitive file access!' if is_critical else 'Sensitive privilege grant.'}"
                )
                rec_action = (
                    f"Isolate host '{e.dest_ip}'. Terminate process and audit sudoers configuration for '{user}'."
                )

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
                    user=user,
                    event_count=1,
                    first_seen=e.timestamp,
                    last_seen=e.timestamp,
                    status="New",
                    recommended_action=rec_action,
                    evidence_json=[e.raw_log]
                ))

        return alerts
