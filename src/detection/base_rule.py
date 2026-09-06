"""
Abstract Base Rule for Threat Detection in SOC Sentinel.
"""
from abc import ABC, abstractmethod
from typing import List
from src.database.models import NormalizedEvent, Alert
from src.detection.mitre_mapping import get_mitre_info

class BaseRule(ABC):
    rule_name: str = "BaseRule"
    mitre_technique_id: str = "T0000"
    severity: str = "MEDIUM"

    def __init__(self):
        self.mitre_info = get_mitre_info(self.mitre_technique_id)
        self.mitre_tactic = self.mitre_info.get("tactic", "Unknown")
        self.mitre_technique_name = self.mitre_info.get("technique_name", "Unknown")

    @abstractmethod
    def evaluate(self, events: List[NormalizedEvent]) -> List[Alert]:
        """
        Analyzes a sequence/window of normalized security events
        and returns any generated Alerts.
        """
        pass
