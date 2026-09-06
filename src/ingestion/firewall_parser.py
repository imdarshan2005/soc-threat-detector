"""
Firewall CSV log parser for network traffic and connection monitoring.
"""
import csv
from datetime import datetime
from typing import List, Optional
from pathlib import Path
from src.database.models import NormalizedEvent

class FirewallLogParser:
    def parse_row(self, row: dict) -> Optional[NormalizedEvent]:
        try:
            # Handle ISO or standard datetime strings
            ts_str = row.get("timestamp", "").strip()
            if "T" in ts_str:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
            else:
                ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")

            action = row.get("action", "ALLOW").upper()
            status = "DENY" if action in ["DENY", "DROP", "BLOCK", "REJECT"] else "ALLOW"
            dest_port = int(row["dest_port"]) if row.get("dest_port") else None
            source_port = int(row["source_port"]) if row.get("source_port") else None

            severity = "MEDIUM" if status == "DENY" else "LOW"

            return NormalizedEvent(
                timestamp=ts,
                source_ip=row.get("source_ip", "0.0.0.0"),
                dest_ip=row.get("dest_ip", "10.0.1.10"),
                source_port=source_port,
                dest_port=dest_port,
                protocol=row.get("protocol", "TCP").upper(),
                user=None,
                action="FIREWALL_DROP" if status == "DENY" else "FIREWALL_PASS",
                status=status,
                event_type="NETWORK",
                severity_hint=severity,
                details={
                    "rule_id": row.get("rule_id", ""),
                    "packet_size": int(row.get("packet_size", 0)) if row.get("packet_size") else 0,
                    "interface": row.get("interface", "")
                },
                raw_log=",".join(f"{k}={v}" for k, v in row.items())
            )
        except Exception:
            return None

    def parse_file(self, file_path: Path) -> List[NormalizedEvent]:
        events = []
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                evt = self.parse_row(row)
                if evt:
                    events.append(evt)
        return events
