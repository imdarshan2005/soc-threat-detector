"""
Apache / Nginx Combined Log Format parser with payload threat analysis.
"""
from datetime import datetime
from typing import List, Optional
from pathlib import Path
from urllib.parse import unquote
from src.database.models import NormalizedEvent
from src.ingestion.regex_patterns import (
    COMBINED_LOG_RE,
    SQLI_PATTERN_RE,
    XSS_PATTERN_RE,
    PATH_TRAVERSAL_PATTERN_RE
)

class WebLogParser:
    def parse_clf_timestamp(self, ts_str: str) -> datetime:
        # e.g., "06/Sep/2026:04:10:12 +0000"
        # strip timezone for simplicity
        clean_ts = ts_str.split(' ')[0]
        return datetime.strptime(clean_ts, "%d/%b/%Y:%H:%M:%S")

    def parse_line(self, line: str) -> Optional[NormalizedEvent]:
        line = line.strip()
        if not line:
            return None

        match = COMBINED_LOG_RE.search(line)
        if not match:
            return None

        source_ip = match.group("source_ip")
        auth_user = match.group("auth_user")
        user = auth_user if auth_user != "-" else "anonymous"
        raw_ts = match.group("timestamp")
        method = match.group("method")
        uri = match.group("uri")
        status_code = int(match.group("status"))
        user_agent = match.group("user_agent")

        try:
            ts = self.parse_clf_timestamp(raw_ts)
        except Exception:
            ts = datetime.now()

        # URL decode URI to inspect payloads
        decoded_uri = unquote(uri)

        # Detect attack indicators
        detected_attacks = []
        if SQLI_PATTERN_RE.search(decoded_uri):
            detected_attacks.append("SQL_INJECTION")
        if XSS_PATTERN_RE.search(decoded_uri):
            detected_attacks.append("CROSS_SITE_SCRIPTING")
        if PATH_TRAVERSAL_PATTERN_RE.search(decoded_uri):
            detected_attacks.append("DIRECTORY_TRAVERSAL")
        if "sqlmap" in user_agent.lower() or "nikto" in user_agent.lower():
            detected_attacks.append("VULNERABILITY_SCANNER")

        severity = "HIGH" if detected_attacks else "INFO"
        action = "HTTP_ATTACK_ATTEMPT" if detected_attacks else "HTTP_REQUEST"
        status = "DENY" if status_code in [401, 403] else ("FAILURE" if status_code >= 400 else "SUCCESS")

        return NormalizedEvent(
            timestamp=ts,
            source_ip=source_ip,
            dest_ip="10.0.1.10",
            source_port=None,
            dest_port=80 if uri.startswith("http://") or ":80" in uri else 443,
            protocol="TCP/HTTP",
            user=user,
            action=action,
            status=status,
            event_type="WEB",
            severity_hint=severity,
            details={
                "method": method,
                "uri": uri,
                "decoded_uri": decoded_uri,
                "status_code": status_code,
                "user_agent": user_agent,
                "detected_attacks": detected_attacks
            },
            raw_log=line
        )

    def parse_file(self, file_path: Path) -> List[NormalizedEvent]:
        events = []
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                evt = self.parse_line(line)
                if evt:
                    events.append(evt)
        return events
