"""
MITRE ATT&CK Matrix Taxonomy and Mapping for SOC Sentinel.
Maps threat detections to Enterprise Tactics and Techniques.
"""
from typing import Dict, Any

MITRE_TAXONOMY: Dict[str, Dict[str, Any]] = {
    "T1110": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "sub_techniques": ["T1110.001 - Password Guessing", "T1110.003 - Password Spraying"],
        "description": "Adversaries may use brute force techniques to attempt authentication credentials by password guessing or spraying."
    },
    "T1046": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "sub_techniques": ["T1046 - Port Scan"],
        "description": "Adversaries may attempt to get a listing of services running on hosts by scanning ports across network addresses."
    },
    "T1190": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "sub_techniques": ["T1190 - Web Application Exploitation (SQLi/XSS/LFI)"],
        "description": "Adversaries may attempt to exploit vulnerabilities in Internet-facing software to gain unauthorized execution or access."
    },
    "T1078": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion & Persistence",
        "tactic_id": "TA0005",
        "sub_techniques": ["T1078.003 - Local Accounts", "T1078.004 - Cloud Accounts"],
        "description": "Adversaries may obtain and abuse credentials of existing valid accounts during abnormal hours or anomalous locations."
    },
    "T1548": {
        "technique_id": "T1548.003",
        "technique_name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "sub_techniques": ["T1548.003 - Sudo Misconfiguration"],
        "description": "Adversaries may perform sudo abuse or take advantage of sudoers configurations to execute programs with elevated privileges."
    },
    "T1071": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "sub_techniques": ["T1071.001 - Web Protocols (C2 traffic)"],
        "description": "Adversaries may communicate using application layer protocols to blend in with normal network traffic."
    }
}

def get_mitre_info(technique_id: str) -> Dict[str, Any]:
    """Returns MITRE ATT&CK metadata for a given technique ID."""
    clean_id = technique_id.split('.')[0]
    return MITRE_TAXONOMY.get(clean_id, {
        "technique_id": technique_id,
        "technique_name": "Unknown Technique",
        "tactic": "Unknown Tactic",
        "tactic_id": "TA0000",
        "description": "Unclassified security event"
    })
