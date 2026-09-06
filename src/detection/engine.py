"""
Threat Detection Engine for SOC Sentinel.
Orchestrates rule evaluations, threat intelligence enrichment, and alert dispatch.
"""
from typing import List, Optional
from src.database.models import NormalizedEvent, Alert
from src.database.db_manager import DatabaseManager
from src.detection.rules import (
    BruteForceRule,
    PortScanRule,
    WebAttackRule,
    OffHoursLoginRule,
    ImpossibleTravelRule,
    PrivilegeEscalationRule
)

class DetectionEngine:
    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.db = db_manager or DatabaseManager()
        self.rules = [
            BruteForceRule(),
            PortScanRule(),
            WebAttackRule(),
            OffHoursLoginRule(),
            ImpossibleTravelRule(),
            PrivilegeEscalationRule()
        ]

    def analyze_events(self, events: List[NormalizedEvent], persist: bool = True) -> List[Alert]:
        """Runs all rules against events, enriches with Threat Intel, and optionally saves to DB."""
        if not events:
            return []

        all_alerts: List[Alert] = []

        for rule in self.rules:
            try:
                rule_alerts = rule.evaluate(events)
                for alert in rule_alerts:
                    # Enrich with Threat Intel if source_ip exists
                    if alert.source_ip:
                        ioc_info = self.db.lookup_threat_intel(alert.source_ip)
                        if ioc_info:
                            alert.description += (
                                f"\n[THREAT INTEL MATCH]: IP {alert.source_ip} is flagged as '{ioc_info.get('threat_type')}' "
                                f"associated with '{ioc_info.get('threat_actor')}' (Confidence: {ioc_info.get('confidence')}%)."
                            )
                            # Elevate severity if high-confidence IOC
                            if ioc_info.get("confidence", 0) >= 85 and alert.severity not in ["CRITICAL"]:
                                alert.severity = "CRITICAL"

                    all_alerts.append(alert)
                    if persist:
                        alert_id = self.db.insert_alert(alert)
                        alert.id = alert_id
            except Exception as e:
                print(f"[DetectionEngine Error] Rule {rule.rule_name} evaluation failed: {e}")

        return all_alerts
