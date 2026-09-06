"""
Unit tests for SOC Sentinel log parsers and normalizer.
"""
from datetime import datetime
from src.ingestion.auth_parser import AuthLogParser
from src.ingestion.web_parser import WebLogParser
from src.ingestion.firewall_parser import FirewallLogParser
from src.ingestion.windows_parser import WindowsLogParser
from src.ingestion.normalizer import LogNormalizer

def test_auth_parser_ssh_failed():
    parser = AuthLogParser(default_year=2026)
    log = "Sep  6 03:12:01 server-prod-01 sshd[2841]: Failed password for invalid user admin from 192.0.2.100 port 44210 ssh2"
    event = parser.parse_line(log)
    assert event is not None
    assert event.source_ip == "192.0.2.100"
    assert event.user == "admin"
    assert event.action == "AUTH_FAILURE"
    assert event.status == "FAILURE"
    assert event.dest_port == 22

def test_auth_parser_ssh_accepted():
    parser = AuthLogParser(default_year=2026)
    log = "Sep  6 08:30:15 server-prod-01 sshd[3100]: Accepted publickey for devuser from 10.0.1.50 port 51200 ssh2"
    event = parser.parse_line(log)
    assert event is not None
    assert event.source_ip == "10.0.1.50"
    assert event.user == "devuser"
    assert event.action == "AUTH_SUCCESS"
    assert event.status == "SUCCESS"

def test_auth_parser_sudo():
    parser = AuthLogParser(default_year=2026)
    log = "Sep  6 03:14:10 server-prod-01 sudo: www-data : TTY=pts/1 ; PWD=/var/www/html ; USER=root ; COMMAND=/bin/bash"
    event = parser.parse_line(log)
    assert event is not None
    assert event.user == "www-data"
    assert event.action == "PRIVILEGE_ELEVATION"
    assert event.severity_hint == "HIGH"
    assert event.details["target_user"] == "root"
    assert event.details["command"] == "/bin/bash"

def test_web_parser_sqli_detection():
    parser = WebLogParser()
    log = '203.0.113.45 - - [06/Sep/2026:04:10:24 +0000] "GET /products.php?id=1%20UNION%20SELECT%201,username,password%20FROM%20admin-- HTTP/1.1" 200 9850 "-" "sqlmap/1.6#stable"'
    event = parser.parse_line(log)
    assert event is not None
    assert event.source_ip == "203.0.113.45"
    assert "SQL_INJECTION" in event.details["detected_attacks"]
    assert "VULNERABILITY_SCANNER" in event.details["detected_attacks"]
    assert event.severity_hint == "HIGH"

def test_firewall_parser():
    parser = FirewallLogParser()
    row = {
        "timestamp": "2026-09-06 05:00:01",
        "source_ip": "45.33.32.156",
        "dest_ip": "10.0.1.10",
        "source_port": "54101",
        "dest_port": "21",
        "protocol": "TCP",
        "action": "DENY",
        "rule_id": "FW-BLOCK-DEFAULT",
        "packet_size": "64",
        "interface": "eth0"
    }
    event = parser.parse_row(row)
    assert event is not None
    assert event.source_ip == "45.33.32.156"
    assert event.dest_port == 21
    assert event.status == "DENY"
    assert event.event_type == "NETWORK"

def test_windows_parser():
    parser = WindowsLogParser()
    entry = {
        "EventID": 4625,
        "TimeCreated": "2026-09-06T04:30:10.000Z",
        "Computer": "DC-PROD-01.corp.local",
        "TargetUserName": "Administrator",
        "IpAddress": "198.51.100.23",
        "LogonType": 3,
        "FailureReason": "Unknown user name or bad password"
    }
    event = parser.parse_event(entry)
    assert event is not None
    assert event.source_ip == "198.51.100.23"
    assert event.user == "Administrator"
    assert event.action == "AUTH_FAILURE"
    assert event.status == "FAILURE"
