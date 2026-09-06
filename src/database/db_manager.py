"""
SQLite Database Manager for SOC Log Monitoring & Threat Detection Platform.
Handles schema initialization, batch ingestion, alert persistence, and SIEM analytics.
"""
import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from src.database.models import NormalizedEvent, Alert, ThreatIntelRecord

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "soc_database.db"

class DatabaseManager:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def init_schema(self):
        """Creates the tables if they don't exist."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Normalized Events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS normalized_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT,
                    dest_ip TEXT,
                    source_port INTEGER,
                    dest_port INTEGER,
                    protocol TEXT,
                    user TEXT,
                    action TEXT,
                    status TEXT,
                    event_type TEXT,
                    severity_hint TEXT,
                    details_json TEXT,
                    raw_log TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                );
            """)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON normalized_events(timestamp);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_source_ip ON normalized_events(source_ip);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_user ON normalized_events(user);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON normalized_events(event_type);")

            # Alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_name TEXT NOT NULL,
                    mitre_tactic TEXT NOT NULL,
                    mitre_technique_id TEXT NOT NULL,
                    mitre_technique_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    source_ip TEXT,
                    dest_ip TEXT,
                    user TEXT,
                    event_count INTEGER DEFAULT 1,
                    first_seen TEXT,
                    last_seen TEXT,
                    status TEXT DEFAULT 'New',
                    analyst_notes TEXT DEFAULT '',
                    recommended_action TEXT DEFAULT '',
                    evidence_json TEXT DEFAULT '[]',
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                );
            """)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);")

            # Threat Intel IOCs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_intel (
                    ip TEXT PRIMARY KEY,
                    threat_type TEXT,
                    threat_actor TEXT,
                    confidence INTEGER,
                    severity TEXT,
                    country TEXT,
                    city TEXT,
                    isp TEXT,
                    asn TEXT,
                    tags_json TEXT,
                    updated_at TEXT DEFAULT (datetime('now'))
                );
            """)

            conn.commit()

    def insert_events(self, events: List[NormalizedEvent]) -> int:
        """Batch inserts normalized events."""
        if not events:
            return 0
        with self.get_connection() as conn:
            cursor = conn.cursor()
            rows = [
                (
                    e.timestamp.isoformat() if isinstance(e.timestamp, datetime) else str(e.timestamp),
                    e.source_ip,
                    e.dest_ip,
                    e.source_port,
                    e.dest_port,
                    e.protocol,
                    e.user,
                    e.action,
                    e.status,
                    e.event_type,
                    e.severity_hint,
                    json.dumps(e.details),
                    e.raw_log
                )
                for e in events
            ]
            cursor.executemany("""
                INSERT INTO normalized_events (
                    timestamp, source_ip, dest_ip, source_port, dest_port,
                    protocol, user, action, status, event_type,
                    severity_hint, details_json, raw_log
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, rows)
            conn.commit()
            return cursor.rowcount

    def insert_alert(self, alert: Alert) -> int:
        """Inserts or correlates an alert into the database."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # Check for existing alert with same rule and source_ip/user within recent window to avoid duplicate noise
            cursor.execute("""
                SELECT id, event_count, evidence_json FROM alerts 
                WHERE rule_name = ? AND IFNULL(source_ip, '') = ? AND IFNULL(user, '') = ? AND status != 'Resolved'
                ORDER BY id DESC LIMIT 1
            """, (alert.rule_name, alert.source_ip or '', alert.user or ''))
            existing = cursor.fetchone()

            if existing:
                alert_id = existing["id"]
                new_count = existing["event_count"] + alert.event_count
                # Merge evidence
                try:
                    prev_evidence = json.loads(existing["evidence_json"])
                except Exception:
                    prev_evidence = []
                try:
                    new_evidence = json.loads(alert.evidence_json) if isinstance(alert.evidence_json, str) else alert.evidence_json
                except Exception:
                    new_evidence = []
                merged_evidence = (prev_evidence + new_evidence)[-20:] # Keep latest 20 evidence logs

                cursor.execute("""
                    UPDATE alerts SET 
                        event_count = ?,
                        last_seen = ?,
                        evidence_json = ?,
                        updated_at = datetime('now')
                    WHERE id = ?
                """, (
                    new_count,
                    alert.last_seen.isoformat() if isinstance(alert.last_seen, datetime) else str(alert.last_seen),
                    json.dumps(merged_evidence),
                    alert_id
                ))
                conn.commit()
                return alert_id
            else:
                cursor.execute("""
                    INSERT INTO alerts (
                        rule_name, mitre_tactic, mitre_technique_id, mitre_technique_name,
                        severity, title, description, source_ip, dest_ip, user,
                        event_count, first_seen, last_seen, status, analyst_notes,
                        recommended_action, evidence_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert.rule_name,
                    alert.mitre_tactic,
                    alert.mitre_technique_id,
                    alert.mitre_technique_name,
                    alert.severity,
                    alert.title,
                    alert.description,
                    alert.source_ip,
                    alert.dest_ip,
                    alert.user,
                    alert.event_count,
                    alert.first_seen.isoformat() if isinstance(alert.first_seen, datetime) else str(alert.first_seen),
                    alert.last_seen.isoformat() if isinstance(alert.last_seen, datetime) else str(alert.last_seen),
                    alert.status,
                    alert.analyst_notes,
                    alert.recommended_action,
                    alert.evidence_json if isinstance(alert.evidence_json, str) else json.dumps(alert.evidence_json)
                ))
                conn.commit()
                return cursor.lastrowid

    def update_alert_status(self, alert_id: int, status: str, notes: Optional[str] = None):
        """Updates alert status and optionally appends analyst notes."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if notes is not None:
                cursor.execute("""
                    UPDATE alerts SET status = ?, analyst_notes = ?, updated_at = datetime('now')
                    WHERE id = ?
                """, (status, notes, alert_id))
            else:
                cursor.execute("""
                    UPDATE alerts SET status = ?, updated_at = datetime('now')
                    WHERE id = ?
                """, (status, alert_id))
            conn.commit()

    def get_alerts(self, status: Optional[str] = None, severity: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieves alerts with optional filters."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM alerts WHERE 1=1"
            params = []
            if status and status != "All":
                query += " AND status = ?"
                params.append(status)
            if severity and severity != "All":
                query += " AND severity = ?"
                params.append(severity)
            query += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END, updated_at DESC LIMIT ?"
            params.append(limit)
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_events(self, query_filter: Optional[str] = None, event_type: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
        """Queries normalized security events for log hunting."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM normalized_events WHERE 1=1"
            params = []
            if event_type and event_type != "All":
                query += " AND event_type = ?"
                params.append(event_type)
            if query_filter:
                query += " AND (raw_log LIKE ? OR source_ip LIKE ? OR user LIKE ? OR action LIKE ?)"
                wildcard = f"%{query_filter}%"
                params.extend([wildcard, wildcard, wildcard, wildcard])
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_telemetry_metrics(self) -> Dict[str, Any]:
        """Calculates high-level SOC dashboard metrics."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) as cnt FROM normalized_events")
            total_events = cursor.fetchone()["cnt"]

            cursor.execute("SELECT COUNT(*) as cnt FROM alerts")
            total_alerts = cursor.fetchone()["cnt"]

            cursor.execute("SELECT COUNT(*) as cnt FROM alerts WHERE status NOT IN ('Resolved', 'False Positive')")
            active_alerts = cursor.fetchone()["cnt"]

            cursor.execute("SELECT COUNT(*) as cnt FROM alerts WHERE severity = 'CRITICAL' AND status NOT IN ('Resolved', 'False Positive')")
            critical_alerts = cursor.fetchone()["cnt"]

            cursor.execute("SELECT COUNT(DISTINCT source_ip) as cnt FROM alerts WHERE status = 'Contained'")
            blocked_ips = cursor.fetchone()["cnt"]

            # Severity counts
            cursor.execute("SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity")
            severity_counts = {row["severity"]: row["cnt"] for row in cursor.fetchall()}

            # MITRE tactics breakdown
            cursor.execute("SELECT mitre_tactic, COUNT(*) as cnt FROM alerts GROUP BY mitre_tactic")
            mitre_tactics = {row["mitre_tactic"]: row["cnt"] for row in cursor.fetchall()}

            # Recent alert timeline
            cursor.execute("""
                SELECT strftime('%Y-%m-%d %H:00', timestamp) as hour_bucket, COUNT(*) as event_count
                FROM normalized_events
                GROUP BY hour_bucket
                ORDER BY hour_bucket ASC
                LIMIT 24
            """)
            timeline_data = [{"time": row["hour_bucket"], "count": row["event_count"]} for row in cursor.fetchall()]

            return {
                "total_events": total_events,
                "total_alerts": total_alerts,
                "active_alerts": active_alerts,
                "critical_alerts": critical_alerts,
                "blocked_ips": blocked_ips,
                "severity_counts": severity_counts,
                "mitre_tactics": mitre_tactics,
                "timeline_data": timeline_data
            }

    def load_threat_intel_iocs(self, json_path: Path) -> int:
        """Loads Threat Intelligence IOCs from a JSON file."""
        if not json_path.exists():
            return 0
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        with self.get_connection() as conn:
            cursor = conn.cursor()
            for ip, info in data.items():
                cursor.execute("""
                    INSERT OR REPLACE INTO threat_intel (
                        ip, threat_type, threat_actor, confidence, severity,
                        country, city, isp, asn, tags_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ip,
                    info.get("threat_type", "Unknown"),
                    info.get("threat_actor", "Unknown"),
                    info.get("confidence", 50),
                    info.get("severity", "MEDIUM"),
                    info.get("country", "ZZ"),
                    info.get("city", "Unknown"),
                    info.get("isp", "Unknown"),
                    info.get("asn", "Unknown"),
                    json.dumps(info.get("tags", []))
                ))
            conn.commit()
            return len(data)

    def lookup_threat_intel(self, ip: str) -> Optional[Dict[str, Any]]:
        """Looks up an IP in the Threat Intel table."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM threat_intel WHERE ip = ?", (ip,))
            row = cursor.fetchone()
            if row:
                d = dict(row)
                d["tags"] = json.loads(d.get("tags_json", "[]"))
                return d
            return None

    def clear_all(self):
        """Clears events and alerts for testing or fresh reset."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM normalized_events")
            cursor.execute("DELETE FROM alerts")
            conn.commit()
