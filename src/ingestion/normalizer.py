"""
Log Normalization Engine for SOC Sentinel.
Automatically identifies log types and normalizes them into standard schema events.
"""
from pathlib import Path
from typing import List, Union
from src.database.models import NormalizedEvent
from src.ingestion.auth_parser import AuthLogParser
from src.ingestion.web_parser import WebLogParser
from src.ingestion.firewall_parser import FirewallLogParser
from src.ingestion.windows_parser import WindowsLogParser

class LogNormalizer:
    def __init__(self):
        self.auth_parser = AuthLogParser()
        self.web_parser = WebLogParser()
        self.firewall_parser = FirewallLogParser()
        self.windows_parser = WindowsLogParser()

    def parse_file(self, file_path: Union[str, Path]) -> List[NormalizedEvent]:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")

        # Check by extension first
        suffix = path.suffix.lower()
        if suffix == ".json":
            return self.windows_parser.parse_file(path)
        elif suffix == ".csv":
            return self.firewall_parser.parse_file(path)
        elif suffix in [".log", ".txt"]:
            # Sniff first few lines
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                head = [f.readline() for _ in range(5)]
            sample = "".join(head)

            if "sshd[" in sample or "sudo:" in sample:
                return self.auth_parser.parse_file(path)
            elif "HTTP/1." in sample or "GET /" in sample or "POST /" in sample:
                return self.web_parser.parse_file(path)
            elif "," in sample and ("source_ip" in sample or "protocol" in sample):
                return self.firewall_parser.parse_file(path)
            else:
                # Default fallback: try auth parser then web parser
                auth_res = self.auth_parser.parse_file(path)
                if auth_res:
                    return auth_res
                return self.web_parser.parse_file(path)

        return []

    def parse_raw_text(self, text: str, log_type: str = "auto") -> List[NormalizedEvent]:
        """Parses raw text pasted or streamed in real time."""
        lines = [line.strip() for line in text.strip().splitlines() if line.strip()]
        events = []

        for line in lines:
            evt = None
            if log_type == "auth" or (log_type == "auto" and ("sshd" in line or "sudo:" in line)):
                evt = self.auth_parser.parse_line(line)
            elif log_type == "web" or (log_type == "auto" and "HTTP/1." in line):
                evt = self.web_parser.parse_line(line)
            
            if evt:
                events.append(evt)
        return events
