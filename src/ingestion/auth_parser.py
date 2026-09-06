"""
Linux auth.log and Syslog parser for SSH events and sudo executions.
"""
from datetime import datetime
from typing import List, Optional
from pathlib import Path
from src.database.models import NormalizedEvent
from src.ingestion.regex_patterns import (
    SSH_FAILED_PASSWORD_RE,
    SSH_ACCEPTED_RE,
    SUDO_COMMAND_RE
)

class AuthLogParser:
    MONTH_MAP = {
        'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
        'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
    }

    def __init__(self, default_year: int = 2026):
        self.default_year = default_year

    def _parse_syslog_timestamp(self, month_str: str, day_str: str, time_str: str) -> datetime:
        month = self.MONTH_MAP.get(month_str, 9)
        day = int(day_str)
        parts = [int(p) for p in time_str.split(':')]
        return datetime(self.default_year, month, day, parts[0], parts[1], parts[2])

    def parse_line(self, line: str) -> Optional[NormalizedEvent]:
        line = line.strip()
        if not line:
            return None

        # 1. Check SSH Failed Password
        match = SSH_FAILED_PASSWORD_RE.search(line)
        if match:
            ts = self._parse_syslog_timestamp(match.group("month"), match.group("day"), match.group("time"))
            return NormalizedEvent(
                timestamp=ts,
                source_ip=match.group("source_ip"),
                dest_ip="10.0.1.10", # host IP
                source_port=int(match.group("port")),
                dest_port=22,
                protocol="TCP",
                user=match.group("user"),
                action="AUTH_FAILURE",
                status="FAILURE",
                event_type="AUTHENTICATION",
                severity_hint="MEDIUM",
                details={
                    "service": "sshd",
                    "hostname": match.group("hostname"),
                    "auth_method": "password"
                },
                raw_log=line
            )

        # 2. Check SSH Accepted
        match = SSH_ACCEPTED_RE.search(line)
        if match:
            ts = self._parse_syslog_timestamp(match.group("month"), match.group("day"), match.group("time"))
            return NormalizedEvent(
                timestamp=ts,
                source_ip=match.group("source_ip"),
                dest_ip="10.0.1.10",
                source_port=int(match.group("port")),
                dest_port=22,
                protocol="TCP",
                user=match.group("user"),
                action="AUTH_SUCCESS",
                status="SUCCESS",
                event_type="AUTHENTICATION",
                severity_hint="INFO",
                details={
                    "service": "sshd",
                    "hostname": match.group("hostname"),
                    "auth_method": match.group("auth_method")
                },
                raw_log=line
            )

        # 3. Check Sudo Command
        match = SUDO_COMMAND_RE.search(line)
        if match:
            ts = self._parse_syslog_timestamp(match.group("month"), match.group("day"), match.group("time"))
            caller = match.group("user")
            cmd = match.group("command")
            target_user = match.group("target_user")

            # Assess severity hint based on sensitive sudo command
            is_suspicious = any(s in cmd for s in ["/bin/bash", "/bin/sh", "/bin/cat /etc/shadow", "chmod 777", "visudo"]) or caller in ["www-data", "apache", "nobody"]
            severity = "HIGH" if is_suspicious else "LOW"

            return NormalizedEvent(
                timestamp=ts,
                source_ip="127.0.0.1",
                dest_ip="10.0.1.10",
                source_port=None,
                dest_port=None,
                protocol="LOCAL",
                user=caller,
                action="PRIVILEGE_ELEVATION",
                status="SUCCESS",
                event_type="SYSTEM",
                severity_hint=severity,
                details={
                    "service": "sudo",
                    "hostname": match.group("hostname"),
                    "target_user": target_user,
                    "command": cmd,
                    "tty": match.group("tty"),
                    "pwd": match.group("pwd")
                },
                raw_log=line
            )

        return None

    def parse_file(self, file_path: Path) -> List[NormalizedEvent]:
        events = []
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                evt = self.parse_line(line)
                if evt:
                    events.append(evt)
        return events
