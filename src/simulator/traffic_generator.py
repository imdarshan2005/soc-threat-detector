"""
Live Traffic and Attack Simulator for SOC Sentinel.
Generates synthetic benign telemetry and active cyber attack campaigns for live demos.
"""
import random
from datetime import datetime, timedelta
from typing import List, Dict, Any
from src.database.models import NormalizedEvent

class TrafficSimulator:
    ATTACKER_IPS = ["198.51.100.23", "203.0.113.45", "192.0.2.100", "185.220.101.5", "45.33.32.156"]
    INTERNAL_IPS = ["10.0.1.50", "10.0.1.55", "10.0.2.14", "10.0.3.102"]
    NORMAL_USERS = ["alice", "bob", "devuser", "carol", "john"]

    @classmethod
    def generate_benign_traffic(cls, count: int = 15, base_time: datetime = None) -> List[NormalizedEvent]:
        """Generates realistic benign traffic across auth, web, and network."""
        now = base_time or datetime.now()
        events = []
        for i in range(count):
            t = now - timedelta(seconds=(count - i) * 10)
            category = random.choice(["WEB", "AUTH", "NETWORK"])
            user = random.choice(cls.NORMAL_USERS)
            internal_ip = random.choice(cls.INTERNAL_IPS)

            if category == "WEB":
                uri = random.choice(["/index.html", "/api/v1/status", "/dashboard", "/static/app.js", "/products"])
                evt = NormalizedEvent(
                    timestamp=t,
                    source_ip=internal_ip,
                    dest_ip="10.0.1.10",
                    source_port=random.randint(40000, 65000),
                    dest_port=443,
                    protocol="TCP/HTTPS",
                    user=user,
                    action="HTTP_REQUEST",
                    status="SUCCESS",
                    event_type="WEB",
                    severity_hint="INFO",
                    details={"method": "GET", "uri": uri, "status_code": 200, "user_agent": "Mozilla/5.0"},
                    raw_log=f'{internal_ip} - {user} [{t.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {uri} HTTP/1.1" 200 4120 "-" "Mozilla/5.0"'
                )
            elif category == "AUTH":
                evt = NormalizedEvent(
                    timestamp=t,
                    source_ip=internal_ip,
                    dest_ip="10.0.1.10",
                    source_port=random.randint(40000, 65000),
                    dest_port=22,
                    protocol="TCP",
                    user=user,
                    action="AUTH_SUCCESS",
                    status="SUCCESS",
                    event_type="AUTHENTICATION",
                    severity_hint="INFO",
                    details={"service": "sshd", "auth_method": "publickey"},
                    raw_log=f'{t.strftime("%b %d %H:%M:%S")} server-prod-01 sshd[{random.randint(1000, 9999)}]: Accepted publickey for {user} from {internal_ip} port {random.randint(40000, 65000)} ssh2'
                )
            else: # NETWORK
                evt = NormalizedEvent(
                    timestamp=t,
                    source_ip=internal_ip,
                    dest_ip="8.8.8.8",
                    source_port=random.randint(40000, 65000),
                    dest_port=53,
                    protocol="UDP",
                    user=None,
                    action="FIREWALL_PASS",
                    status="ALLOW",
                    event_type="NETWORK",
                    severity_hint="LOW",
                    details={"rule_id": "FW-OUTBOUND-DNS", "packet_size": 64},
                    raw_log=f'timestamp={t.strftime("%Y-%m-%d %H:%M:%S")},source_ip={internal_ip},dest_ip=8.8.8.8,dest_port=53,protocol=UDP,action=ALLOW'
                )
            events.append(evt)
        return events

    @classmethod
    def generate_attack_campaign(cls, scenario: str, base_time: datetime = None) -> List[NormalizedEvent]:
        """Generates specific multi-stage attack scenarios."""
        now = base_time or datetime.now()
        events = []

        if scenario == "SSH_BRUTE_FORCE":
            attacker = "192.0.2.100"
            for i in range(7):
                t = now - timedelta(seconds=(10 - i) * 3)
                user = "admin" if i < 4 else "root"
                events.append(NormalizedEvent(
                    timestamp=t,
                    source_ip=attacker,
                    dest_ip="10.0.1.10",
                    source_port=45000 + i,
                    dest_port=22,
                    protocol="TCP",
                    user=user,
                    action="AUTH_FAILURE",
                    status="FAILURE",
                    event_type="AUTHENTICATION",
                    severity_hint="MEDIUM",
                    details={"service": "sshd", "auth_method": "password"},
                    raw_log=f'{t.strftime("%b %d %H:%M:%S")} server-prod-01 sshd[{3000+i}]: Failed password for invalid user {user} from {attacker} port {45000+i} ssh2'
                ))
            # Followed by compromise
            t_comp = now + timedelta(seconds=2)
            events.append(NormalizedEvent(
                timestamp=t_comp,
                source_ip=attacker,
                dest_ip="10.0.1.10",
                source_port=45010,
                dest_port=22,
                protocol="TCP",
                user="root",
                action="AUTH_SUCCESS",
                status="SUCCESS",
                event_type="AUTHENTICATION",
                severity_hint="HIGH",
                details={"service": "sshd", "auth_method": "password"},
                raw_log=f'{t_comp.strftime("%b %d %H:%M:%S")} server-prod-01 sshd[3010]: Accepted password for root from {attacker} port 45010 ssh2'
            ))

        elif scenario == "PORT_SCAN":
            attacker = "45.33.32.156"
            target_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]
            for i, p in enumerate(target_ports):
                t = now - timedelta(seconds=(len(target_ports) - i))
                events.append(NormalizedEvent(
                    timestamp=t,
                    source_ip=attacker,
                    dest_ip="10.0.1.10",
                    source_port=50000 + i,
                    dest_port=p,
                    protocol="TCP",
                    user=None,
                    action="FIREWALL_DROP",
                    status="DENY",
                    event_type="NETWORK",
                    severity_hint="MEDIUM",
                    details={"rule_id": "FW-BLOCK-DEFAULT", "packet_size": 64},
                    raw_log=f'timestamp={t.strftime("%Y-%m-%d %H:%M:%S")},source_ip={attacker},dest_ip=10.0.1.10,dest_port={p},protocol=TCP,action=DENY'
                ))

        elif scenario == "WEB_SQLI_ATTACK":
            attacker = "203.0.113.45"
            payloads = [
                ("GET /login.php HTTP/1.1", 200, []),
                ("POST /login.php HTTP/1.1", 401, ["SQL_INJECTION"]),
                ("GET /products.php?id=1%20UNION%20SELECT%201,username,password%20FROM%20admin-- HTTP/1.1", 200, ["SQL_INJECTION"]),
                ("GET /api/search?q=%27%20OR%20%271%27=%271 HTTP/1.1", 200, ["SQL_INJECTION"]),
                ("GET /download.php?file=../../../../etc/passwd HTTP/1.1", 200, ["DIRECTORY_TRAVERSAL"]),
            ]
            for i, (uri, status_code, attacks) in enumerate(payloads):
                t = now - timedelta(seconds=(len(payloads) - i) * 4)
                events.append(NormalizedEvent(
                    timestamp=t,
                    source_ip=attacker,
                    dest_ip="10.0.1.10",
                    source_port=52000 + i,
                    dest_port=443,
                    protocol="TCP/HTTPS",
                    user="anonymous",
                    action="HTTP_ATTACK_ATTEMPT" if attacks else "HTTP_REQUEST",
                    status="DENY" if status_code >= 400 else "SUCCESS",
                    event_type="WEB",
                    severity_hint="CRITICAL" if attacks else "INFO",
                    details={
                        "method": uri.split()[0],
                        "uri": uri.split()[1],
                        "status_code": status_code,
                        "user_agent": "sqlmap/1.6#stable",
                        "detected_attacks": attacks
                    },
                    raw_log=f'{attacker} - - [{t.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{uri}" {status_code} 4500 "-" "sqlmap/1.6#stable"'
                ))

        elif scenario == "SUDO_PRIV_ESCALATION":
            t = now
            events.append(NormalizedEvent(
                timestamp=t,
                source_ip="127.0.0.1",
                dest_ip="10.0.1.10",
                source_port=None,
                dest_port=None,
                protocol="LOCAL",
                user="www-data",
                action="PRIVILEGE_ELEVATION",
                status="SUCCESS",
                event_type="SYSTEM",
                severity_hint="CRITICAL",
                details={
                    "service": "sudo",
                    "hostname": "server-prod-01",
                    "target_user": "root",
                    "command": "/bin/bash",
                    "tty": "pts/2",
                    "pwd": "/var/www/html"
                },
                raw_log=f'{t.strftime("%b %d %H:%M:%S")} server-prod-01 sudo: www-data : TTY=pts/2 ; PWD=/var/www/html ; USER=root ; COMMAND=/bin/bash'
            ))

        return events
