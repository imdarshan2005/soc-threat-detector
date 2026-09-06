"""
Regular Expression patterns used across SOC log parsers.
"""
import re

# Linux Syslog & SSH Patterns
# Example: Sep  6 03:12:01 server-prod-01 sshd[2841]: Failed password for invalid user admin from 192.0.2.100 port 44210 ssh2
SSH_FAILED_PASSWORD_RE = re.compile(
    r'^(?P<month>[A-Za-z]{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
    r'Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)'
)

# Example: Sep  6 03:12:35 server-prod-01 sshd[2872]: Accepted password for root from 192.0.2.100 port 44240 ssh2
SSH_ACCEPTED_RE = re.compile(
    r'^(?P<month>[A-Za-z]{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
    r'Accepted\s+(?P<auth_method>password|publickey)\s+for\s+(?P<user>\S+)\s+from\s+(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)'
)

# Example: Sep  6 03:14:10 server-prod-01 sudo: www-data : TTY=pts/1 ; PWD=/var/www/html ; USER=root ; COMMAND=/bin/bash
SUDO_COMMAND_RE = re.compile(
    r'^(?P<month>[A-Za-z]{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+sudo:\s+'
    r'(?P<user>\S+)\s+:\s+TTY=(?P<tty>\S+)\s+;\s+PWD=(?P<pwd>\S+)\s+;\s+USER=(?P<target_user>\S+)\s+;\s+COMMAND=(?P<command>.*)$'
)

# Apache / Nginx Combined Log Format
# Example: 203.0.113.45 - - [06/Sep/2026:04:10:12 +0000] "GET /index.php HTTP/1.1" 200 4521 "-" "Mozilla/5.0"
COMBINED_LOG_RE = re.compile(
    r'^(?P<source_ip>\S+)\s+\S+\s+(?P<auth_user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
)

# Web Attack Patterns
SQLI_PATTERN_RE = re.compile(
    r'(?i)(\bunion\s+(?:all\s+)?select\b|'
    r'(\%27|\')\s*(?:or|and)\s*(\%27|\')?\d+(\%27|\')?\s*=\s*(\%27|\')?\d+|'
    r'--|/\*|\*/|\bwaitfor\s+delay\b|\bsleep\s*\(|\bbenchmark\s*\(|\bdrop\s+table\b|\bexec\s*\()'
)

XSS_PATTERN_RE = re.compile(
    r'(?i)(<script[\s>]|javascript:|onload\s*=|onerror\s*=|document\.cookie|<img\s+[^>]*src=|<iframe[\s>])'
)

PATH_TRAVERSAL_PATTERN_RE = re.compile(
    r'(?i)(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|/windows/win\.ini|\.env\b|\bphpmyadmin\b|/server-status)'
)
