# 🎓 SOC Sentinel: Resume Placement & Interview Master Guide

This guide is designed to help you showcase **SOC Sentinel** on your resume and ace technical interviews for **Cybersecurity Analyst, SOC Analyst (Tier 1/2), SIEM Engineer, Security Operations, and Information Security** roles.

---

## 📄 1. Resume Bullet Points (Copy & Paste to CV)

### Format Option 1: Recommended Concise Resume Format (One-Page Friendly)
**SOC Sentinel — SIEM Log Monitoring & Threat Detection Platform**  
*Python, Streamlit, Pandas, SQLite, Regex, Plotly, MITRE ATT&CK, Pytest* | [GitHub Link](https://github.com/imdarshan2005/soc-threat-detector)
- Built a modular SIEM platform to ingest and normalize multi-source Linux, web server, Windows Security, and firewall logs into a unified event schema.
- Engineered a sliding-window correlation engine with 6 detection rules mapped to the MITRE ATT&CK framework, detecting brute-force attacks, port scans, web attacks, suspicious logins, and privilege escalation.
- Implemented compromise escalation that upgrades brute-force alerts after subsequent successful logins, with simulated threat-intelligence IOC enrichment.
- Developed an interactive Streamlit SOC dashboard for threat telemetry, alert triage, SIEM log hunting, attack simulation, and forensic report generation.
- Added 13 Pytest unit and integration tests covering log parsers, detection rules, and SQLite database operations.

---

## 🔑 2. High-Impact ATS Keywords for Your Resume
Ensure these keywords are included in your resume's Skills or Projects section:
- `Security Information and Event Management (SIEM)`
- `Security Operations Center (SOC)`
- `Threat Detection & Analysis`
- `Log Normalization & Parsing (Syslog, CLF, Windows Events)`
- `MITRE ATT&CK Framework (Tactics & Techniques)`
- `Incident Triage & Case Management`
- `Sliding-Window Correlation Algorithms`
- `Indicators of Compromise (IOCs) & Threat Intelligence`
- `Brute-Force & Credential Stuffing Detection`
- `Network Reconnaissance & Port Scanning (SYN/TCP Sweeps)`
- `Web Application Security (SQL Injection, XSS, Path Traversal)`
- `Privilege Escalation & Sudo Abuse`
- `Python, Pandas, SQLite, Streamlit, Regex`

---

## 🎯 3. Top 15 SOC & SIEM Interview Questions & Model Answers

### Q1: Can you give an architectural overview of your SOC Sentinel project?
> **Answer:**  
> "SOC Sentinel is structured into a 5-layer pipeline:
> 1. **Ingestion Layer**: Ingests unstructured and semi-structured logs from Linux auth.log, Apache/Nginx web access, Windows JSON event logs, and CSV firewall feeds.
> 2. **Normalization Layer**: Uses compiled regular expressions and format sniffers to transform varied formats into a unified Common Event Schema (`timestamp`, `source_ip`, `dest_ip`, `user`, `action`, `status`, `event_type`).
> 3. **Persistence Layer**: An indexed SQLite database for raw events, normalized telemetry, and alert states.
> 4. **Detection & Correlation Engine**: A modular sliding-window engine evaluating events against rules mapped to the MITRE ATT&CK framework, enriched with threat intelligence IOCs.
> 5. **Analyst Command Center**: A dark-mode Streamlit dashboard offering real-time telemetry, log hunting, alert triage workflows, and incident report generation."

---

### Q2: How does your sliding-window correlation work for detecting brute-force attacks?
> **Answer:**  
> "Instead of simply counting failures across an entire dataset, a real SOC needs temporal correlation. I implemented a sliding time window using `datetime.timedelta`.  
> When evaluating authentication events for a specific source IP, the algorithm groups failures and dynamically prunes any events older than the defined window (e.g., 120 seconds). If the count within the window exceeds the threshold ($\ge 5$ failures), an alert is triggered.  
> Furthermore, the rule checks the subsequent events: if a successful authentication (`AUTH_SUCCESS`) immediately follows a brute-force cluster from the same IP, the alert severity is automatically escalated from **HIGH** to **CRITICAL**, signaling an active account takeover."

---

### Q3: Why is log normalization critical in a SIEM?
> **Answer:**  
> "In an enterprise, every device writes logs differently. An Apache web server logs client IPs at the start of a Combined Log line; Linux auth.log uses `from <IP> port <PORT>`; Windows Event 4625 logs JSON or XML with `IpAddress`.  
> If an analyst or rule has to write custom logic for each format, detection rules cannot scale. By normalizing all disparate logs into a unified Common Security Event format (similar to Elastic Common Schema or Splunk CIM), our detection rules and queries operate on consistent fields (`source_ip`, `user`, `status`) regardless of the originating device."

---

### Q4: How does your platform map detections to the MITRE ATT&CK framework?
> **Answer:**  
> "Every detection rule in SOC Sentinel inherits from an abstract base class that explicitly requires a MITRE ATT&CK Technique ID. We maintain a taxonomy module mapping technique IDs to official Tactics:
> - T1110 (Brute Force) $\to$ Credential Access (`TA0006`)
> - T1046 (Port Scan) $\to$ Discovery (`TA0007`)
> - T1190 (Exploit Public-Facing Application) $\to$ Initial Access (`TA0001`)
> - T1078 (Valid Accounts / Off-Hours) $\to$ Defense Evasion (`TA0005`)
> - T1548.003 (Sudo Abuse) $\to$ Privilege Escalation (`TA0004`)  
> This allows SOC managers to visualize coverage gaps across the cyber kill chain via our dashboard's MITRE distribution charts."

---

### Q5: How do you detect port scanning in your firewall logs?
> **Answer:**  
> "Our Port Scan rule monitors network telemetry for distinct destination ports accessed by a single source IP within a rolling 60-second window.  
> If an external host sends packets to $\ge 5$ distinct destination ports (such as scanning 21, 22, 80, 445, 3389) within 60 seconds, the rule flags a network reconnaissance sweep (T1046) and attaches the list of probed ports as forensic evidence."

---

### Q6: How does the system detect Web Application Attacks?
> **Answer:**  
> "The web parser URL-decodes query strings and inspects HTTP request URIs using compiled regex signatures for common attack vectors:
> - **SQL Injection**: Patterns matching `UNION SELECT`, `' OR '1'='1'`, `waitfor delay`, and SQL commenting `--`.
> - **Cross-Site Scripting (XSS)**: Patterns matching `<script>`, `document.cookie`, `onerror=`, `onload=`.
> - **Path Traversal / LFI**: Patterns matching `../../etc/passwd` or `/windows/win.ini`.
> If user-agent strings contain automated scanners like `sqlmap` or `nikto`, the engine raises the alert severity to **CRITICAL**."

---

### Q7: What is Impossible Travel and how did you implement it?
> **Answer:**  
> "Impossible Travel (MITRE T1078.004) flags when the same user authenticates successfully from two geographically disparate IP addresses within a time delta that exceeds reasonable physical travel limits.  
> In our implementation, consecutive successful logins for a user from distinct external IP subnets occurring within 60 minutes trigger a **CRITICAL** alert, prompting the analyst to revoke session tokens and force credential rotation."

---

### Q8: How does Threat Intelligence enrichment assist SOC analysts during triage?
> **Answer:**  
> "Raw alerts often require analysts to perform manual lookups on VirusTotal or AbuseIPDB. Our detection engine automatically cross-references source IPs against a local Threat Intel IOC repository containing known C2 nodes, Tor exit points, and botnet IPs.  
> If an IP matches, the alert is automatically enriched with the threat actor name, threat type, confidence score, and GeoIP metadata. If the confidence exceeds 85%, the alert is elevated to **CRITICAL** before the analyst even opens the ticket."

---

### Q9: Walk me through your incident triage workflow in the dashboard.
> **Answer:**  
> "Our Alert Triage Workbench implements the industry-standard incident lifecycle:
> 1. **New**: Unreviewed alert generated by the detection engine.
> 2. **Investigating**: Analyst reviews correlated raw logs, threat intel scores, and user behavior.
> 3. **Contained**: The containment action has been initiated (e.g. firewall drop rule applied, user session terminated).
> 4. **Resolved**: Threat neutralized, root cause addressed, post-incident review completed.
> 5. **False Positive**: Legitimate activity confirmed (e.g. scheduled penetration test or approved off-hours maintenance)."

---

### Q10: How do you mitigate false positives in off-hours or web attack detection?
> **Answer:**  
> "To minimize false positive alerts:
> 1. In the **Off-Hours rule**, we whitelist internal subnet ranges (`10.0.0.0/8`, `192.168.0.0/16`) so automated batch backup jobs don't trigger alerts; alerts are primarily prioritized for external logins.
> 2. In the **Web Attack rule**, we differentiate between single anomalous characters and multi-clause SQL injection attacks, escalating severity only when malicious patterns are accompanied by high error frequencies or automated scanner user-agents."

---

### Q11: Why did you choose SQLite and what are its trade-offs compared to Elasticsearch?
> **Answer:**  
> "SQLite was selected to make the platform self-contained, lightweight, zero-dependency, and easy to run locally or demo during interviews. By creating targeted indexes on `timestamp`, `source_ip`, `user`, and `event_type`, queries remain sub-millisecond for tens of thousands of records.  
> In a large-scale enterprise environment with 50,000+ EPS, we would replace SQLite with a distributed search engine like Elasticsearch/OpenSearch or ClickHouse, backed by Kafka as a buffer queue."

---

### Q12: How did you test your detection rules and algorithms?
> **Answer:**  
> "We wrote a comprehensive test suite using **Pytest** with 13 automated tests across three modules:
> 1. `test_parsers.py`: Validates regex extraction against edge cases (malformed timestamps, special characters, various log formats).
> 2. `test_detection_engine.py`: Tests sliding-window boundary conditions, threshold triggers, compromise escalation, and impossible travel scenarios.
> 3. `test_database.py`: Verifies database migrations, batch inserts, and alert status updates."

---

### Q13: What does the Incident Forensics Report Generator provide?
> **Answer:**  
> "It generates an audit-ready, CISO-grade Incident Forensics Report formatted in Markdown. It compiles the Executive Summary, MITRE ATT&CK taxonomy classification, threat intelligence correlation, full correlated raw log evidence, and a 4-step containment checklist (Network Containment, Identity Isolation, Endpoint Triage, Threat Intel Feed Update)."

---

### Q14: How does the Live Attack Simulator work?
> **Answer:**  
> "The Live Attack Simulator allows the user or interviewer to inject synthetic attack traffic into the pipeline on demand. It includes pre-configured scenarios:
> - SSH Brute-Force & Compromise storm
> - Multi-port SYN reconnaissance sweep
> - SQLi and LFI web application exploit bursts
> - Unauthorized sudo privilege escalation  
> When triggered, events are ingested, normalized, evaluated against rules, and rendered in the dashboard within 1 second."

---

### Q15: What was the most technically challenging part of this project?
> **Answer:**  
> "The most challenging aspect was implementing accurate sliding-window state management across heterogeneous log streams without introducing significant CPU overhead.  
> By grouping events by entity (`source_ip` or `user`) and using time-bounded double-ended queues / pruned lists sorted by timestamp, we achieved $O(N)$ evaluation efficiency, ensuring real-time response even with high volumes of incoming logs."
