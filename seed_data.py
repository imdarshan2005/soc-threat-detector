"""
Database Initializer and Sample Data Ingestor.
Loads threat intelligence, parses sample logs, and runs threat detection.
"""
import sys
import io

# Ensure UTF-8 output on Windows consoles
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from pathlib import Path
from src.database.db_manager import DatabaseManager
from src.ingestion.normalizer import LogNormalizer
from src.detection.engine import DetectionEngine

def seed_platform():
    base_dir = Path(__file__).resolve().parent
    db_path = base_dir / "data" / "soc_database.db"
    threat_intel_path = base_dir / "data" / "threat_intel" / "malicious_ips.json"
    sample_logs_dir = base_dir / "data" / "sample_logs"

    print("[SOC Sentinel] Initializing database and threat intelligence...")
    db = DatabaseManager(db_path)
    normalizer = LogNormalizer()
    engine = DetectionEngine(db)

    # 1. Load Threat Intel IOCs
    if threat_intel_path.exists():
        ioc_count = db.load_threat_intel_iocs(threat_intel_path)
        print(f"[+] Loaded {ioc_count} Threat Intelligence IOCs.")

    # 2. Ingest Sample Logs
    total_events = 0
    all_events = []
    log_files = [
        sample_logs_dir / "auth.log",
        sample_logs_dir / "web_access.log",
        sample_logs_dir / "firewall.csv",
        sample_logs_dir / "windows_events.json"
    ]

    for fpath in log_files:
        if fpath.exists():
            evts = normalizer.parse_file(fpath)
            all_events.extend(evts)
            print(f"[+] Parsed {len(evts)} events from {fpath.name}")

    if all_events:
        inserted = db.insert_events(all_events)
        print(f"[+] Ingested {inserted} normalized events into SQLite.")

        # 3. Run Detection Engine
        print("[*] Running Threat Detection Engine across ingested events...")
        alerts = engine.analyze_events(all_events, persist=True)
        print(f"[!] Generated {len(alerts)} security alerts correlated with MITRE ATT&CK!")

    print("[SUCCESS] Initialization complete. SOC Sentinel is ready for operation.")

if __name__ == "__main__":
    seed_platform()
