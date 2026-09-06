"""
Data models and dataclasses for SOC Sentinel platform.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List

@dataclass
class NormalizedEvent:
    timestamp: datetime
    source_ip: str
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    user: Optional[str] = None
    action: str = "UNKNOWN"          # e.g., AUTH_SUCCESS, AUTH_FAILURE, HTTP_REQUEST, PACKET_DROP
    status: str = "UNKNOWN"          # SUCCESS, FAILURE, ALLOW, DENY
    event_type: str = "GENERIC"      # AUTHENTICATION, WEB, NETWORK, SYSTEM
    severity_hint: str = "LOW"       # INFO, LOW, MEDIUM, HIGH, CRITICAL
    details: Dict[str, Any] = field(default_factory=dict)
    raw_log: str = ""
    id: Optional[int] = None
    raw_log_id: Optional[int] = None

@dataclass
class Alert:
    rule_name: str
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str
    severity: str                    # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    user: Optional[str] = None
    event_count: int = 1
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    status: str = "New"              # New, Investigating, Contained, Resolved, False Positive
    analyst_notes: str = ""
    evidence_json: str = "[]"
    recommended_action: str = ""
    id: Optional[int] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

@dataclass
class ThreatIntelRecord:
    ip: str
    threat_type: str
    threat_actor: str
    confidence: int
    severity: str
    country: str
    city: str
    isp: str
    asn: str
    tags: List[str] = field(default_factory=list)
