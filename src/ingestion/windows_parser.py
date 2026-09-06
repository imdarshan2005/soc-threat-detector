"""
Windows Security Event Log Parser (JSON format).
Handles Event IDs 4624 (Logon Success), 4625 (Logon Failure), and 4672 (Privilege Assignment).
"""
import json
from datetime import datetime
from typing import List, Optional
from pathlib import Path
from src.database.models import NormalizedEvent

class WindowsLogParser:
    def parse_event(self, entry: dict) -> Optional[NormalizedEvent]:
        try:
            event_id = entry.get("EventID")
            ts_str = entry.get("TimeCreated", "")
            if ts_str.endswith("Z"):
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
            else:
                ts = datetime.fromisoformat(ts_str)

            source_ip = entry.get("IpAddress", "127.0.0.1")
            user = entry.get("TargetUserName", "SYSTEM")
            computer = entry.get("Computer", "")

            if event_id == 4625:
                # Logon failure
                action = "AUTH_FAILURE"
                status = "FAILURE"
                severity = "MEDIUM"
                details = {
                    "event_id": 4625,
                    "failure_reason": entry.get("FailureReason", "Unknown"),
                    "status_code": entry.get("Status"),
                    "sub_status": entry.get("SubStatus"),
                    "workstation": entry.get("WorkstationName")
                }
            elif event_id == 4624:
                # Logon success
                action = "AUTH_SUCCESS"
                status = "SUCCESS"
                severity = "INFO"
                details = {
                    "event_id": 4624,
                    "logon_type": entry.get("LogonType"),
                    "auth_package": entry.get("AuthenticationPackageName"),
                    "workstation": entry.get("WorkstationName")
                }
            elif event_id == 4672:
                # Special privileges assigned
                action = "PRIVILEGE_ELEVATION"
                status = "SUCCESS"
                severity = "HIGH"
                details = {
                    "event_id": 4672,
                    "privileges": entry.get("PrivilegeList", [])
                }
            else:
                action = f"EVENT_{event_id}"
                status = "INFO"
                severity = "LOW"
                details = {"event_id": event_id}

            return NormalizedEvent(
                timestamp=ts,
                source_ip=source_ip,
                dest_ip=computer or "10.0.1.10",
                source_port=None,
                dest_port=3389 if entry.get("LogonType") == 10 else 445,
                protocol="TCP/SMB",
                user=user,
                action=action,
                status=status,
                event_type="AUTHENTICATION" if event_id in [4624, 4625] else "SYSTEM",
                severity_hint=severity,
                details=details,
                raw_log=json.dumps(entry)
            )
        except Exception:
            return None

    def parse_file(self, file_path: Path) -> List[NormalizedEvent]:
        events = []
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                for entry in data:
                    evt = self.parse_event(entry)
                    if evt:
                        events.append(evt)
            elif isinstance(data, dict):
                evt = self.parse_event(data)
                if evt:
                    events.append(evt)
        return events
